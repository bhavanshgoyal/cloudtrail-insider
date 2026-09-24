"""
run_pipeline.py
---------------
End-to-end pipeline orchestrator for the Insider-Threat Detection project.

Runs every step from data generation to final results in one command::

    python run_pipeline.py

Steps
~~~~~
1.  Generate synthetic CloudTrail data (1000 principals, 180 days)
2.  Normalise column names to canonical schema
3.  Build per-principal-per-day feature matrix
4.  Create label vector from ground truth
5.  Train all baseline detectors (IF, LOF, Autoencoder, RuleBaseline)
6.  Train proposed detector (BudgetAwareConformal)
7.  Score all detectors on the test split
8.  Evaluate at budgets [10, 50, 100] with bootstrap CIs
9.  Generate SHAP explanations for top alerts
10. Produce results summary + figures
11. Generate triage study questionnaire

All outputs go to data/, models/, results/, figures/.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

# ── Setup logging ────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pipeline")


def banner(step: int, title: str) -> None:
    log.info("=" * 60)
    log.info("  STEP %d: %s", step, title)
    log.info("=" * 60)


def main() -> None:
    t0 = time.time()
    
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--fast", action="store_true", help="Run with a smaller dataset for quick verification")
    args = parser.parse_args()

    # ── Import project modules ───────────────────────────────────────────
    from cti.util.config import load_config
    from cti.util.seeds import set_all_seeds

    cfg = load_config()
    
    if args.fast:
        log.info("Running in FAST mode — scaling down synthetic data generation")
        cfg["synthetic"]["principals"] = 100
        cfg["synthetic"]["days"] = 30
        
    seed = cfg["random_seed"]
    set_all_seeds(seed)

    budgets = cfg["budgets"]  # [10, 50, 100]

    # Paths
    data_dir = Path("data/processed")
    feat_dir = Path("data/features")
    models_dir = Path("models")
    results_dir = Path("results")
    figures_dir = Path("figures")

    for d in [data_dir, feat_dir, models_dir, results_dir, figures_dir]:
        d.mkdir(parents=True, exist_ok=True)

    events_path = data_dir / "events.parquet"
    gt_path = data_dir / "ground_truth.json"
    features_path = feat_dir / "features.parquet"
    labels_path = feat_dir / "labels.parquet"

    # ─────────────────────────────────────────────────────────────────────
    # STEP 1: Generate synthetic CloudTrail data
    # ─────────────────────────────────────────────────────────────────────
    banner(1, "GENERATE SYNTHETIC DATA")

    from cti.ingest.synthetic import generate_dataset

    syn_cfg = cfg["synthetic"]
    df_events, ground_truth = generate_dataset(
        n_principals=syn_cfg["principals"],
        n_days=syn_cfg["days"],
        scenarios=syn_cfg["scenarios"],
        insider_rate=syn_cfg["insider_rate"],
        seed=seed,
    )

    df_events.to_parquet(events_path, index=False)
    with open(gt_path, "w") as f:
        json.dump(ground_truth, f, indent=2)

    log.info("Generated %d events, %d insiders", len(df_events), len(ground_truth))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 2: Normalise column names
    # ─────────────────────────────────────────────────────────────────────
    banner(2, "NORMALISE SCHEMA")

    from cti.ingest.normalise import normalise_columns, validate_schema

    df_events = normalise_columns(df_events)
    missing = validate_schema(df_events)
    if missing:
        log.error("Missing required columns: %s", missing)
        sys.exit(1)
    log.info("Schema normalised. Columns: %s", list(df_events.columns))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 3: Build feature matrix
    # ─────────────────────────────────────────────────────────────────────
    banner(3, "BUILD FEATURES")

    from cti.features.pipeline import build_features

    df_feat = build_features(df_events, cfg)
    df_feat.to_parquet(features_path, index=False)
    log.info("Feature matrix: %d rows × %d cols", len(df_feat), len(df_feat.columns))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 4: Create label vector from ground truth
    # ─────────────────────────────────────────────────────────────────────
    banner(4, "CREATE LABELS")

    # Ground truth tells us which principals are insiders
    insider_ids = {gt["principal_id"] for gt in ground_truth}
    log.info("Insider principals: %s", insider_ids)

    # Mark any principal-day that has at least one malicious event
    malicious_events = df_events[df_events["label"] == 1].copy()
    malicious_events["_date"] = malicious_events["eventTime"].dt.date

    malicious_days = (
        malicious_events.groupby(["principalId", "_date"])
        .size()
        .reset_index()
        .rename(columns={"principalId": "principal", "_date": "date", 0: "_count"})
    )
    malicious_days["date"] = pd.to_datetime(malicious_days["date"])

    df_labels = df_feat[["principal", "date"]].copy()
    df_labels = df_labels.merge(
        malicious_days[["principal", "date"]],
        on=["principal", "date"],
        how="left",
        indicator=True,
    )
    df_labels["label"] = (df_labels["_merge"] == "both").astype(int)
    df_labels = df_labels.drop(columns=["_merge"])
    df_labels.to_parquet(labels_path, index=False)

    n_pos = df_labels["label"].sum()
    n_neg = len(df_labels) - n_pos
    log.info("Labels: %d positive, %d negative (%.2f%% positive)", n_pos, n_neg, 100 * n_pos / len(df_labels))

    # ─────────────────────────────────────────────────────────────────────
    # STEP 5: Train baseline detectors
    # ─────────────────────────────────────────────────────────────────────
    banner(5, "TRAIN BASELINES")

    from cti.detectors.train import (
        IsoForestDetector,
        LOFDetector,
        AutoencoderDetector,
        RuleBaselineDetector,
        prepare_X,
        save_detector,
    )

    # Get training split
    splits = cfg["splits"]
    train_mask = (
        (df_feat["date"] >= pd.Timestamp(splits["train_start"]))
        & (df_feat["date"] <= pd.Timestamp(splits["train_end"]))
    )
    df_train = df_feat[train_mask]
    if df_train.empty:
        log.warning("Training split empty — using entire dataset")
        df_train = df_feat

    X_train, feat_cols = prepare_X(df_train)
    log.info("Training split: %d samples, %d features", *X_train.shape)

    baselines = [
        IsoForestDetector(cfg, seed),
        LOFDetector(cfg, seed),
        AutoencoderDetector(cfg, seed),
        RuleBaselineDetector(cfg, seed),
    ]

    for det in baselines:
        log.info("Training %s...", det.name)
        det.fit(X_train)
        save_detector(det, models_dir / f"{det.name}.pkl")
        log.info("  ✓ Saved %s", det.name)

    # ─────────────────────────────────────────────────────────────────────
    # STEP 6: Train proposed detector (BudgetAwareConformal)
    # ─────────────────────────────────────────────────────────────────────
    banner(6, "TRAIN PROPOSED DETECTOR")

    from cti.detectors.proposed import BudgetAwareConformal

    proposed = BudgetAwareConformal(cfg, seed)
    proposed.fit(X_train, df_train)
    save_detector(proposed, models_dir / f"{proposed.name}.pkl")
    log.info("  ✓ Saved %s", proposed.name)

    # ─────────────────────────────────────────────────────────────────────
    # STEP 7: Score all detectors on test split
    # ─────────────────────────────────────────────────────────────────────
    banner(7, "SCORE TEST SPLIT")

    test_mask = (
        (df_feat["date"] >= pd.Timestamp(splits["test_start"]))
        & (df_feat["date"] <= pd.Timestamp(splits["test_end"]))
    )
    df_test = df_feat[test_mask]
    if df_test.empty:
        log.warning("Test split empty — using entire dataset")
        df_test = df_feat

    X_test, _ = prepare_X(df_test)
    log.info("Test split: %d samples", len(X_test))

    all_scores = []
    for det in baselines:
        scores = det.score_samples(X_test)
        df_s = df_test[["principal", "date"]].copy()
        df_s["detector"] = det.name
        df_s["score"] = scores
        all_scores.append(df_s)
        log.info("  Scored %s: min=%.3f, max=%.3f, mean=%.3f",
                 det.name, scores.min(), scores.max(), scores.mean())

    # Proposed detector — use the full pipeline including C4 incident selection
    from cti.detectors.proposed import _incident_aggregation

    proposed_scores = proposed.score_samples(X_test, df_test)
    df_p = df_test[["principal", "date"]].copy()
    df_p["detector"] = proposed.name
    df_p["score"] = proposed_scores

    # C4: aggregate to per-principal-per-day incidents and suppress duplicates.
    # This is what makes the method budget-aware — without it, noisy principals
    # dominate the top-k list just like a global Isolation Forest.
    df_p_tmp = df_p[["principal", "date", "score"]].copy()
    df_p_tmp.rename(columns={"score": "fused_score"}, inplace=True)
    incidents = _incident_aggregation(
        df_p_tmp, "fused_score", suppress_days=cfg.get("suppress_days", 3)
    )
    # Build a lookup: (principal, date) -> incident_score for selected incidents
    incident_keys = set()
    incident_map = {}
    for _, inc_row in incidents.iterrows():
        key = (inc_row["principal"], inc_row["date"])
        incident_keys.add(key)
        incident_map[key] = inc_row["incident_score"]

    # Re-score: rows in selected incidents get the boosted incident_score,
    # all other rows get 0 so they don't interfere with the top-k ranking.
    boosted = np.zeros(len(df_p), dtype=np.float64)
    for i, (_, row) in enumerate(df_p.iterrows()):
        key = (row["principal"], row["date"])
        if key in incident_map:
            boosted[i] = incident_map[key]
    df_p["score"] = boosted

    all_scores.append(df_p)
    n_nonzero = (boosted > 0).sum()
    log.info("  Scored %s: %d incident rows (of %d), max=%.3f",
             proposed.name, n_nonzero, len(df_p), boosted.max())

    df_all_scores = pd.concat(all_scores, ignore_index=True)
    df_all_scores.to_parquet(results_dir / "scores.parquet", index=False)

    # ─────────────────────────────────────────────────────────────────────
    # STEP 8: Evaluate at fixed alert budgets
    # ─────────────────────────────────────────────────────────────────────
    banner(8, "EVALUATE AT FIXED BUDGETS")

    from cti.eval.evaluate import evaluate_detector, apply_budget_cap

    # Merge scores with labels
    df_eval = df_all_scores.merge(df_labels, on=["principal", "date"], how="left")
    df_eval["label"] = df_eval["label"].fillna(0).astype(int)

    cap = cfg["max_alerts_per_principal_day"]
    eval_results = []

    for det_name in df_eval["detector"].unique():
        sub = df_eval[df_eval["detector"] == det_name].copy()
        sub = apply_budget_cap(sub, "score", "principal", "date", cap)
        scores = sub["score"].to_numpy()
        labels = sub["label"].to_numpy()
        df_r = evaluate_detector(scores, labels, cfg, det_name)
        eval_results.append(df_r)
        log.info("  %s: evaluated at budgets %s", det_name, budgets)

    df_results = pd.concat(eval_results, ignore_index=True)
    df_results.to_parquet(results_dir / "metrics.parquet", index=False)
    df_results.to_csv(results_dir / "metrics.csv", index=False)

    # Summary table
    print("\n" + "=" * 80)
    print("  EVALUATION RESULTS — Fixed Alert Budgets")
    print("=" * 80)
    for det_name in df_results["detector"].unique():
        print(f"\n  {det_name}:")
        det_df = df_results[df_results["detector"] == det_name]
        for _, row in det_df.iterrows():
            print(f"    {row['metric']:>20s} @ B={row['budget']:>3d}: "
                  f"{row['value']:.4f}  [{row['ci_lo']:.4f}, {row['ci_hi']:.4f}]")

    # ─────────────────────────────────────────────────────────────────────
    # STEP 9: SHAP explanations
    # ─────────────────────────────────────────────────────────────────────
    banner(9, "GENERATE SHAP EXPLANATIONS")

    try:
        from cti.explain.shap_explain import (
            compute_shap_values,
            global_importance,
            save_global_bar,
            per_alert_explanations,
        )
        from cti.detectors.train import load_detector as _load

        # Load IF model for SHAP (TreeExplainer works with IF)
        if_model = _load(models_dir / "isolation_forest.pkl")
        X_all, feat_cols_all = prepare_X(df_feat)

        # Get top alerts from IF for explanation
        if_scores = df_all_scores[df_all_scores["detector"] == "isolation_forest"]
        if_top = if_scores.sort_values("score", ascending=False).head(budgets[0])
        df_explain = df_feat.merge(if_top[["principal", "date"]], on=["principal", "date"])
        X_explain, _ = prepare_X(df_explain)

        from cti.util.seeds import make_rng
        rng = make_rng(seed)
        shap_values = compute_shap_values(if_model, X_all, X_explain, cfg, rng)

        df_importance = global_importance(shap_values, feat_cols_all)
        save_global_bar(df_importance, figures_dir / "shap_global.png", cfg)

        alerts = per_alert_explanations(shap_values, feat_cols_all, df_explain, budgets[0])

        shap_output = {"budget": budgets[0], "alerts": alerts}
        with open(results_dir / "shap_alerts.json", "w") as f:
            json.dump(shap_output, f, indent=2)

        df_importance.to_parquet(results_dir / "shap_importance.parquet", index=False)
        log.info("SHAP explanations generated for top %d alerts", budgets[0])

    except Exception as e:
        log.warning("SHAP step failed (non-critical): %s", e)
        log.warning("Continuing without SHAP explanations")

    # ─────────────────────────────────────────────────────────────────────
    # STEP 10: Generate figures
    # ─────────────────────────────────────────────────────────────────────
    banner(10, "GENERATE FIGURES")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        # Budget curve: DR@B / Precision@B
        for metric_name in ["precision_at_b", "recall_at_b"]:
            fig, ax = plt.subplots(figsize=(8, 5))
            for det_name in df_results["detector"].unique():
                det_df = df_results[
                    (df_results["detector"] == det_name) &
                    (df_results["metric"] == metric_name)
                ].sort_values("budget")
                if not det_df.empty:
                    ax.errorbar(
                        det_df["budget"], det_df["value"],
                        yerr=[det_df["value"] - det_df["ci_lo"],
                              det_df["ci_hi"] - det_df["value"]],
                        label=det_name.replace("_", " "),
                        marker="o", capsize=4,
                    )
            ax.set_xlabel("Alert Budget B")
            ax.set_ylabel(metric_name.replace("_", " ").title())
            ax.set_title(f"{metric_name.replace('_', ' ').title()} vs Alert Budget")
            ax.set_xticks(budgets)
            ax.legend(fontsize=8)
            ax.set_ylim(0, 1.05)
            fig.tight_layout()
            fig.savefig(figures_dir / f"{metric_name}.png", dpi=150)
            plt.close(fig)
            log.info("Saved %s.png", metric_name)

        # Summary comparison bar chart at budget=10
        fig, ax = plt.subplots(figsize=(10, 5))
        sub = df_results[(df_results["metric"] == "precision_at_b") & (df_results["budget"] == 10)]
        if not sub.empty:
            dets = sub["detector"].tolist()
            vals = sub["value"].tolist()
            colors = ["#e74c3c" if "proposed" in d else "#3498db" for d in dets]
            bars = ax.bar(range(len(dets)), vals, color=colors)
            ax.set_xticks(range(len(dets)))
            ax.set_xticklabels([d.replace("_", " ") for d in dets], rotation=20, ha="right")
            ax.set_ylabel("Precision@10")
            ax.set_title("Detector Comparison at Budget = 10 Alerts/Day")
            ax.set_ylim(0, 1.05)
            for bar, val in zip(bars, vals):
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.02,
                        f"{val:.3f}", ha="center", fontsize=9)
            fig.tight_layout()
            fig.savefig(figures_dir / "comparison_at_10.png", dpi=150)
            plt.close(fig)
            log.info("Saved comparison_at_10.png")

    except Exception as e:
        log.warning("Figures step failed (non-critical): %s", e)

    # ─────────────────────────────────────────────────────────────────────
    # STEP 11: Generate triage study (if SHAP available)
    # ─────────────────────────────────────────────────────────────────────
    banner(11, "GENERATE TRIAGE STUDY")

    try:
        shap_path = results_dir / "shap_alerts.json"
        if shap_path.exists():
            from cti.triage.generate_study import generate_questionnaire, save_questionnaire

            # Use proposed detector scores for the study
            proposed_scores_df = df_all_scores[
                df_all_scores["detector"] == proposed.name
            ].copy()

            with open(shap_path) as f:
                shap_data = json.load(f)
            shap_alerts = shap_data.get("alerts", [])

            study = generate_questionnaire(
                proposed_scores_df, shap_alerts, df_labels, n_alerts=40
            )
            save_questionnaire(study, Path("docs/triage_study"))
            log.info("Triage study generated")
        else:
            log.warning("No SHAP alerts found — skipping triage study generation")
    except Exception as e:
        log.warning("Triage study generation failed (non-critical): %s", e)

    # ─────────────────────────────────────────────────────────────────────
    # DONE
    # ─────────────────────────────────────────────────────────────────────
    elapsed = time.time() - t0
    print("\n" + "=" * 80)
    print(f"  PIPELINE COMPLETE -- {elapsed:.1f}s elapsed")
    print("=" * 80)
    print(f"\n  Results:     {results_dir}/")
    print(f"  Figures:     {figures_dir}/")
    print(f"  Models:      {models_dir}/")
    print(f"  Features:    {feat_dir}/")
    print(f"\n  Key outputs:")
    print(f"    results/metrics.csv         - evaluation metrics at all budgets")
    print(f"    results/scores.parquet      - raw detector scores")
    print(f"    results/shap_alerts.json    - SHAP explanations for top alerts")
    print(f"    figures/comparison_at_10.png - detector comparison chart")
    print(f"    docs/triage_study/          - triage questionnaire for reviewers")


if __name__ == "__main__":
    main()
