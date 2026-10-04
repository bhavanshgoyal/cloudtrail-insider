"""
run_pipeline.py
---------------
End-to-end pipeline orchestrator::

    python run_pipeline.py                      # W1_baseline, last rolling origin
    python run_pipeline.py --fast               # small dataset for a quick check
    python run_pipeline.py --workload W2_stealthy --seed 7

Steps
~~~~~
1. generate synthetic CloudTrail events (+ ground truth)
2. normalise the schema
3. build the causal (principal, day) feature matrix
4. build (principal, day) labels from ground truth
5. split into train / val / test windows (relative days, NO fallback to "all data")
6. train baselines (IF, LOF, Autoencoder, rules) and the proposed detector on TRAIN only
7. score the TEST window with every detector (+ the proposed detector's C4 incident selector)
8. legacy global top-B metrics (placeholder; per-day budget evaluation arrives with Phase 4)

Explanations (Phase 5), the triage study (Phase 8) and the final campaign
(Phase 6) are separate steps and are NOT run here.
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("pipeline")


def banner(step: int, title: str) -> None:
    log.info("=" * 60)
    log.info("  STEP %d: %s", step, title)
    log.info("=" * 60)


def main() -> None:
    t0 = time.time()
    parser = argparse.ArgumentParser()
    parser.add_argument("--fast", action="store_true", help="small dataset for a quick verification run")
    parser.add_argument("--workload", default=None, help="name from cfg['synthetic']['workloads']")
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--origin", type=int, default=None, help="rolling origin (default: last)")
    args = parser.parse_args()

    from cti.detectors.proposed import _incident_aggregation
    from cti.detectors.train import save_detector, train_on_split
    from cti.eval.evaluate import apply_budget_cap, evaluate_detector
    from cti.features.pipeline import build_features, make_labels
    from cti.ingest.normalise import normalise_columns, validate_schema
    from cti.ingest.synthetic import generate_workload
    from cti.util.config import load_config
    from cti.util.seeds import set_all_seeds
    from cti.util.splits import assert_test_positives, make_splits

    cfg = load_config()
    seed = cfg["random_seed"] if args.seed is None else args.seed
    set_all_seeds(seed)
    cfg["random_seed"] = seed
    budgets = cfg["budgets"]

    data_dir, feat_dir = Path("data/processed"), Path("data/features")
    models_dir, results_dir, figures_dir = Path("models"), Path("results"), Path("figures")
    for d in (data_dir, feat_dir, models_dir, results_dir, figures_dir):
        d.mkdir(parents=True, exist_ok=True)

    banner(1, "GENERATE SYNTHETIC DATA")
    df_events, ground_truth = generate_workload(cfg, args.workload, seed, fast=args.fast)
    df_events.to_parquet(data_dir / "events.parquet", index=False)
    with open(data_dir / "ground_truth.json", "w") as f:
        json.dump(ground_truth, f, indent=2)
    log.info("generated %d events, %d insiders", len(df_events), len(ground_truth))

    banner(2, "NORMALISE SCHEMA")
    df_events = normalise_columns(df_events)
    missing = validate_schema(df_events)
    if missing:
        log.error("missing required columns: %s", missing)
        sys.exit(1)

    banner(3, "BUILD FEATURES")
    df_feat = build_features(df_events, cfg)
    df_feat.to_parquet(feat_dir / "features.parquet", index=False)

    banner(4, "CREATE LABELS")
    df_labels = make_labels(df_events, df_feat)
    df_labels.to_parquet(feat_dir / "labels.parquet", index=False)
    n_pos = int(df_labels["label"].sum())
    log.info("labels: %d positive principal-days of %d (%.2f%%)", n_pos, len(df_labels),
             100 * n_pos / len(df_labels))

    banner(5, "TEMPORAL SPLIT")
    split = make_splits(df_feat["date"], cfg, args.origin)
    log.info(split.describe())
    n_ins = assert_test_positives(split, ground_truth, cfg)
    log.info("insiders with malicious activity in the test window: %d", n_ins)

    banner(6, "TRAIN ON TRAIN WINDOW ONLY")
    detectors = train_on_split(df_feat, cfg, split, events=df_events)
    for det in detectors:
        save_detector(det, models_dir / f"{det.name}.pkl")

    banner(7, "SCORE TEST WINDOW")
    df_test = split.select(df_feat, "test")
    log.info("test window: %d rows", len(df_test))
    all_scores = []
    for det in detectors:
        scores = det.score(df_test, df_events)
        df_s = df_test[["principal", "date"]].copy()
        df_s["detector"] = det.name
        df_s["score"] = scores
        if det.name.startswith("proposed"):
            # C4: per-principal-day incident aggregation + duplicate suppression
            tmp = df_s[["principal", "date", "score"]].rename(columns={"score": "fused_score"})
            inc = _incident_aggregation(tmp, "fused_score", suppress_days=cfg["suppress_days"])
            df_s = df_s.drop(columns="score").merge(
                inc[["principal", "date", "incident_score"]], on=["principal", "date"], how="left")
            df_s["score"] = df_s.pop("incident_score").fillna(0.0)
        all_scores.append(df_s)
        log.info("  %-34s min=%.3f max=%.3f mean=%.3f", det.name, scores.min(), scores.max(), scores.mean())
    df_all_scores = pd.concat(all_scores, ignore_index=True)
    df_all_scores.to_parquet(results_dir / "scores.parquet", index=False)

    banner(8, "LEGACY GLOBAL TOP-B METRICS (placeholder until the per-day evaluator lands)")
    log.warning("These numbers rank the whole test window globally; they are NOT per-day alert budgets.")
    cfg["eval"] = {**cfg["eval"], "bootstrap_iterations": 200}     # legacy evaluator is slow
    df_eval = df_all_scores.merge(df_labels, on=["principal", "date"], how="left")
    df_eval["label"] = df_eval["label"].fillna(0).astype(int)
    rows = []
    for det_name in df_eval["detector"].unique():
        sub = apply_budget_cap(df_eval[df_eval["detector"] == det_name].copy(),
                               "score", "principal", "date", cfg["max_alerts_per_principal_day"])
        rows.append(evaluate_detector(sub["score"].to_numpy(), sub["label"].to_numpy(), cfg, det_name))
    df_results = pd.concat(rows, ignore_index=True)
    df_results.to_csv(results_dir / "metrics_legacy.csv", index=False)
    print(df_results[df_results["metric"] == "precision_at_b"]
          .pivot(index="detector", columns="budget", values="value").round(3).to_string())

    print(f"\nPIPELINE COMPLETE - {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
