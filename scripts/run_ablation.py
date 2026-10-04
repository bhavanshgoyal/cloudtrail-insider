"""
run_ablation.py
---------------
Ablation study: measures the contribution of each component (C1–C4) of the
BudgetAwareConformal detector by removing one component at a time.

Variants
~~~~~~~~
  Full:    C1 + C2 + C3 + C4   (proposed method)
  −C1:     Global IF (no per-principal)    → uses global IF scores
  −C2:     C1 + raw scores (no conformal)  → skips p-value calibration
  −C3:     C1 + C2 + max-family (no Fisher fusion) → takes min p-value
  −C4:     C1 + C2 + C3 + global top-k (no suppression) → no dedup

Output
~~~~~~
  results/ablation.csv       — metrics per variant
  figures/ablation.png       — grouped bar chart (P@10, R@10)

Usage::

    python scripts/run_ablation.py
"""
from __future__ import annotations

import sys
from pathlib import Path

# Ensure src is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import logging
import numpy as np
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ablation")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cti.util.config import load_config
from cti.util.seeds import set_all_seeds
from cti.detectors.train import prepare_X
from cti.detectors.proposed import (
    BudgetAwareConformal,
    _PerPrincipalIF,
    _conformal_pvalues,
    _fisher_fusion,
    _incident_aggregation,
    _family_columns,
    _FAMILIES,
)
from cti.eval.evaluate import precision_at_b, recall_at_b
from scipy.stats import chi2
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


def main():
    cfg = load_config()
    set_all_seeds(cfg["random_seed"])
    seed = cfg["random_seed"]

    # ── Load data ────────────────────────────────────────────────────────
    df_feat = pd.read_parquet("data/features/features.parquet")
    df_feat["date"] = pd.to_datetime(df_feat["date"])
    df_labels = pd.read_parquet("data/features/labels.parquet")
    df_labels["date"] = pd.to_datetime(df_labels["date"])

    splits = cfg["splits"]
    train_mask = (
        (df_feat["date"] >= pd.Timestamp(splits["train_start"]))
        & (df_feat["date"] <= pd.Timestamp(splits["train_end"]))
    )
    test_mask = (
        (df_feat["date"] >= pd.Timestamp(splits["test_start"]))
        & (df_feat["date"] <= pd.Timestamp(splits["test_end"]))
    )
    df_train = df_feat[train_mask].copy()
    df_test = df_feat[test_mask].copy()

    if df_train.empty:
        log.warning("Train split empty — using full dataset")
        df_train = df_feat.copy().reset_index(drop=True)
    else:
        df_train = df_train.reset_index(drop=True)
        
    if df_test.empty:
        log.warning("Test split empty — using full dataset")
        df_test = df_feat.copy().reset_index(drop=True)
    else:
        df_test = df_test.reset_index(drop=True)

    # Labels for test
    test_labels = df_test.merge(df_labels, on=["principal", "date"], how="left")
    labels = test_labels["label"].fillna(0).astype(int).to_numpy()

    feat_cols = [c for c in df_feat.columns if c not in {"principal", "date"}]
    X_train, _ = prepare_X(df_train)
    X_test, _ = prepare_X(df_test)

    # ── Train the full model (we need the internals) ─────────────────────
    det_cfg = cfg.get("detectors", {}).get("proposed", {})
    n_estimators = det_cfg.get("n_estimators", 100)
    contamination = det_cfg.get("contamination", 0.05)
    min_events = det_cfg.get("min_events", 30)
    cal_fraction = det_cfg.get("cal_fraction", 0.3)
    suppress_days = cfg.get("suppress_days", 3)

    # Temporal fit/cal split
    unique_dates = sorted(df_train["date"].unique())
    split_idx = int(len(unique_dates) * (1.0 - cal_fraction))
    fit_dates = set(unique_dates[:split_idx])
    cal_dates = set(unique_dates[split_idx:])
    df_fit = df_train[df_train["date"].isin(fit_dates)].copy().reset_index(drop=True)
    df_cal = df_train[df_train["date"].isin(cal_dates)].copy().reset_index(drop=True)

    # Train per-family per-principal IF models
    family_models = {}
    for family_name in _FAMILIES:
        fcols = _family_columns(feat_cols, family_name)
        if not fcols:
            continue
        model = _PerPrincipalIF(n_estimators=n_estimators, contamination=contamination, seed=seed)
        model.fit(df_fit, fcols, min_events=min_events)
        family_models[family_name] = model
    log.info("Trained %d family models", len(family_models))

    # Build calibration scores on held-out cal split
    cal_scores_dict = {}
    for family_name, model in family_models.items():
        fcols = _family_columns(feat_cols, family_name)
        raw = model.score(df_cal, fcols)
        cal_scores = {}
        for principal, group in df_cal.groupby("principal"):
            idx = group.index
            cal_scores[principal] = raw[idx.to_numpy()]
        cal_scores_dict[family_name] = cal_scores

    # Also train a global IF for the −C1 variant
    global_if = IsolationForest(
        n_estimators=200, contamination=0.02, random_state=seed, n_jobs=-1
    )
    global_if.fit(X_train)

    # ── Helper: apply C4 incident aggregation + suppression ──────────────
    def apply_c4(scores_arr, df_ref, do_suppress=True):
        """Apply C4 to per-row scores, return re-ranked scores."""
        df_tmp = df_ref[["principal", "date"]].copy()
        df_tmp["fused_score"] = scores_arr
        sup = suppress_days if do_suppress else 0
        incidents = _incident_aggregation(df_tmp, "fused_score", suppress_days=sup)
        incident_map = {}
        for _, row in incidents.iterrows():
            incident_map[(row["principal"], row["date"])] = row["incident_score"]
        boosted = np.zeros(len(df_ref), dtype=np.float64)
        for i, (_, row) in enumerate(df_ref.iterrows()):
            key = (row["principal"], row["date"])
            if key in incident_map:
                boosted[i] = incident_map[key]
        return boosted

    # ── Compute test scores for each variant ─────────────────────────────
    principals = df_test["principal"].to_numpy()
    n = len(df_test)

    # --- FULL: C1 + C2 + C3 + C4 ---
    log.info("Computing FULL variant (C1+C2+C3+C4)")
    pval_matrix = np.ones((n, len(family_models)), dtype=np.float64)
    for j, (fname, model) in enumerate(family_models.items()):
        fcols = _family_columns(feat_cols, fname)
        raw = model.score(df_test, fcols)
        cal = cal_scores_dict.get(fname, {})
        pval_matrix[:, j] = _conformal_pvalues(raw, principals, cal)
    fused_full = _fisher_fusion(pval_matrix)
    scores_full = apply_c4(fused_full, df_test, do_suppress=True)

    # --- −C1: Global IF instead of per-principal ---
    log.info("Computing −C1 variant (global IF, no per-principal)")
    global_scores = -global_if.score_samples(X_test)
    scores_no_c1 = apply_c4(global_scores, df_test, do_suppress=True)

    # --- −C2: Skip conformal calibration, use raw scores directly ---
    log.info("Computing −C2 variant (raw scores, no conformal)")
    raw_per_family = []
    for fname, model in family_models.items():
        fcols = _family_columns(feat_cols, fname)
        raw_per_family.append(model.score(df_test, fcols))
    # Stack and take mean of raw scores (no conformal)
    raw_matrix = np.column_stack(raw_per_family)
    raw_combined = np.mean(raw_matrix, axis=1)
    scores_no_c2 = apply_c4(raw_combined, df_test, do_suppress=True)

    # --- −C3: Skip Fisher fusion, take min p-value (most anomalous family) ---
    log.info("Computing −C3 variant (min p-value, no Fisher)")
    min_pval = np.min(pval_matrix, axis=1)  # lower p = more anomalous
    scores_no_fisher = 1.0 - min_pval  # flip so higher = more anomalous
    scores_no_c3 = apply_c4(scores_no_fisher, df_test, do_suppress=True)

    # --- −C4: No incident aggregation / suppression ---
    log.info("Computing −C4 variant (no suppression)")
    scores_no_c4 = fused_full.copy()  # raw fused scores without C4

    # ── Evaluate ─────────────────────────────────────────────────────────
    variants = {
        "Full (C1+C2+C3+C4)": scores_full,
        "−C1 (global IF)": scores_no_c1,
        "−C2 (no conformal)": scores_no_c2,
        "−C3 (no Fisher)": scores_no_c3,
        "−C4 (no suppression)": scores_no_c4,
    }

    budgets_eval = [10, 50, 100]
    rows = []
    for name, scores in variants.items():
        for b in budgets_eval:
            p = precision_at_b(scores, labels, b)
            r = recall_at_b(scores, labels, b)
            rows.append({"variant": name, "budget": b, "P@B": p, "R@B": r})
            log.info("  %s  @ B=%d:  P=%.3f  R=%.3f", name, b, p, r)

    df_ablation = pd.DataFrame(rows)

    results_dir = Path("results")
    results_dir.mkdir(exist_ok=True)
    df_ablation.to_csv(results_dir / "ablation.csv", index=False)
    log.info("Saved results/ablation.csv")

    # ── Generate figure ──────────────────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(15, 6))

    # Filter to budget=10 for the main ablation chart
    sub10 = df_ablation[df_ablation["budget"] == 10]
    variant_names = sub10["variant"].tolist()
    x = np.arange(len(variant_names))
    width = 0.35

    colors_p = ["#e74c3c" if "Full" in v else "#95a5a6" for v in variant_names]
    colors_r = ["#c0392b" if "Full" in v else "#7f8c8d" for v in variant_names]

    # P@10
    axes[0].bar(x, sub10["P@B"].values, width, color=colors_p, edgecolor="white", linewidth=0.5)
    axes[0].set_ylabel("Precision@10", fontsize=12)
    axes[0].set_title("Ablation: Precision@10", fontsize=14, fontweight="bold")
    axes[0].set_xticks(x)
    axes[0].set_xticklabels(variant_names, rotation=25, ha="right", fontsize=9)
    axes[0].set_ylim(0, 1.05)
    for i, v in enumerate(sub10["P@B"].values):
        axes[0].text(i, v + 0.02, f"{v:.3f}", ha="center", fontsize=9)

    # R@10
    axes[1].bar(x, sub10["R@B"].values, width, color=colors_r, edgecolor="white", linewidth=0.5)
    axes[1].set_ylabel("Recall@10", fontsize=12)
    axes[1].set_title("Ablation: Recall@10", fontsize=14, fontweight="bold")
    axes[1].set_xticks(x)
    axes[1].set_xticklabels(variant_names, rotation=25, ha="right", fontsize=9)
    axes[1].set_ylim(0, max(0.3, sub10["R@B"].max() * 1.3))
    for i, v in enumerate(sub10["R@B"].values):
        axes[1].text(i, v + 0.005, f"{v:.3f}", ha="center", fontsize=9)

    fig.suptitle("Component Ablation Study — BudgetAwareConformal", fontsize=16, fontweight="bold", y=1.02)
    fig.tight_layout()

    figures_dir = Path("figures")
    figures_dir.mkdir(exist_ok=True)
    fig.savefig(figures_dir / "ablation.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved figures/ablation.png")

    # ── Multi-budget ablation chart ──────────────────────────────────────
    fig2, ax2 = plt.subplots(figsize=(12, 6))
    variant_order = list(variants.keys())
    x2 = np.arange(len(variant_order))
    n_budgets = len(budgets_eval)
    total_width = 0.7
    bar_w = total_width / n_budgets

    cmap = ["#e74c3c", "#3498db", "#2ecc71"]
    for bi, b in enumerate(budgets_eval):
        sub = df_ablation[df_ablation["budget"] == b]
        vals = [sub[sub["variant"] == v]["P@B"].values[0] for v in variant_order]
        offset = (bi - n_budgets / 2 + 0.5) * bar_w
        ax2.bar(x2 + offset, vals, bar_w, label=f"P@{b}", color=cmap[bi], edgecolor="white")

    ax2.set_ylabel("Precision@B", fontsize=12)
    ax2.set_title("Ablation Study — Precision Across All Budgets", fontsize=14, fontweight="bold")
    ax2.set_xticks(x2)
    ax2.set_xticklabels(variant_order, rotation=25, ha="right", fontsize=9)
    ax2.set_ylim(0, 1.05)
    ax2.legend(fontsize=10)
    fig2.tight_layout()
    fig2.savefig(figures_dir / "ablation_multi_budget.png", dpi=150, bbox_inches="tight")
    plt.close(fig2)
    log.info("Saved figures/ablation_multi_budget.png")

    # Print summary
    print("\n" + "=" * 70)
    print("  ABLATION STUDY RESULTS")
    print("=" * 70)
    print(df_ablation.to_string(index=False))
    print()


if __name__ == "__main__":
    main()
