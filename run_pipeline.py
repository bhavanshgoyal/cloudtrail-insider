"""
run_pipeline.py
---------------
One-command reproduction of a single run::

    python run_pipeline.py                      # W1_baseline, seed 42, last rolling origin
    python run_pipeline.py --fast               # small dataset, quick check
    python run_pipeline.py --workload W2_stealthy --seed 7 --origin 0

Steps
~~~~~
1. generate synthetic CloudTrail events + ground truth (cached features)
2. temporal split (relative days; refuses to run if a window is empty)
3. fit every detector on train+val, score the TEST window
   (settings frozen by scripts/tune_proposed.py on validation windows only)
4. evaluate at fixed per-day budgets with bootstrap CIs; paired comparison vs Isolation Forest
5. explanations for every alert the proposed detector raises at the smallest budget (O3)
6. SHAP cross-check of those explanations

This is ONE run. The statistics reported in the paper come from the campaign
(Phase 6: workloads x seeds x origins), not from this script.
"""
from __future__ import annotations

import argparse
import json
import logging
import time
from pathlib import Path

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(name)s  %(message)s",
                    datefmt="%H:%M:%S")
logging.getLogger("cti.detectors.rules").setLevel(logging.WARNING)
logging.getLogger("shap").setLevel(logging.WARNING)
log = logging.getLogger("pipeline")


def main() -> None:
    t0 = time.time()
    ap = argparse.ArgumentParser()
    ap.add_argument("--fast", action="store_true", help="small dataset for a quick check")
    ap.add_argument("--workload", default=None)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--origin", type=int, default=None, help="rolling origin (default: last)")
    ap.add_argument("--shap-n", type=int, default=20, help="alerts in the SHAP cross-check (0 = skip)")
    args = ap.parse_args()

    from cti.detectors.train import build_detectors
    from cti.eval.evaluate import compare, emit_alerts, per_insider_table
    from cti.experiment import apply_frozen_configs, load_world, run_window
    from cti.explain.explain_proposed import explain_alerts, shap_crosscheck
    from cti.util.config import load_config
    from cti.util.seeds import set_all_seeds
    from cti.util.splits import assert_test_positives, make_splits

    cfg = apply_frozen_configs(load_config())
    seed = cfg["random_seed"] if args.seed is None else args.seed
    cfg["random_seed"] = seed
    set_all_seeds(seed)
    results_dir = Path("results/fast") if args.fast else Path("results")   # --fast never overwrites real outputs
    results_dir.mkdir(parents=True, exist_ok=True)

    log.info("STEP 1  data")
    world = load_world(cfg, args.workload, seed, fast=args.fast)

    log.info("STEP 2  temporal split")
    split = make_splits(world.features["date"], cfg, args.origin)
    log.info(split.describe())
    log.info("insiders active in the test window: %d", assert_test_positives(split, world.ground_truth, cfg))

    log.info("STEP 3-4  fit on train+val, score and evaluate the TEST window")
    run = run_window(world, cfg, split, "test", build_detectors(cfg))
    run.tidy.to_csv(results_dir / "metrics.csv", index=False)
    per_insider_table(run.results, run.ctx).to_csv(results_dir / "per_insider.csv", index=False)
    pd.concat([s.assign(detector=n) for n, s in run.scores.items()]).to_parquet(
        results_dir / "scores.parquet", index=False)

    prop = "proposed_budget_aware_conformal"
    comp = []
    for b in cfg["budgets"]:
        for row in compare(run.results[prop][b], run.results["isolation_forest"][b], cfg, seed):
            comp.append({"budget": b, "a": prop, "b": "isolation_forest", **row})
    pd.DataFrame(comp).to_csv(results_dir / "comparison_vs_if.csv", index=False)

    log.info("STEP 5  explanations for the proposed detector's alerts")
    b0 = min(cfg["budgets"])
    det = run.detectors[prop]
    alerts = emit_alerts(run.scores[prop], b0, det.suppress_days, seed)
    rows = alerts[["principal", "date"]].merge(world.features, on=["principal", "date"], how="left")
    expl = explain_alerts(det, rows, cfg["explain"]["top_k_features"])
    for e, a in zip(expl, alerts.itertuples(index=False)):
        e["score"], e["rank"] = float(a.score), int(a.rank)
    (results_dir / "explanations.json").write_text(json.dumps(
        {"budget": b0, "workload": world.workload, "seed": seed, "origin": split.origin,
         "alerts": expl}, indent=1))
    log.info("explained %d alerts (%.0f%% with >= 1 named feature)", len(expl),
             100 * sum(bool(e["top_features"]) for e in expl) / max(1, len(expl)))

    if args.shap_n:
        log.info("STEP 6  SHAP cross-check on %d alerts", args.shap_n)
        cc = shap_crosscheck(det, rows, expl, n=args.shap_n, seed=seed)
        (results_dir / "shap_crosscheck.json").write_text(json.dumps(cc, indent=1))
        log.info("SHAP top feature named by the explanation: %.0f%%; same family: %.0f%%",
                 100 * cc["top1_in_named"], 100 * cc["family_agreement"])

    t = run.tidy
    show = t[t["metric"].isin(["dr_at_b", "precision_at_b", "mttd_hours_median"]) & (t["budget"] > 0)]
    table = show.assign(cell=show.apply(
        lambda r: f"{r.value:.3f} [{r.ci_lo:.3f}, {r.ci_hi:.3f}]" if pd.notna(r.ci_lo) else f"{r.value:.3f}",
        axis=1)).pivot(index="detector", columns=["metric", "budget"], values="cell")
    print("\nTEST WINDOW - single run (", split.describe(), ")")
    print(table.to_string())
    auc = t[t["metric"] == "auc_roc"].set_index("detector")["value"].round(3)
    print("\nAUC-ROC (budget-free reference):\n" + auc.to_string())
    print(f"\nPIPELINE COMPLETE - {time.time() - t0:.1f}s. Outputs in {results_dir}/")


if __name__ == "__main__":
    main()
