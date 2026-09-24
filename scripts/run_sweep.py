"""
run_sweep.py
------------
Parameter sweep: measures how the proposed detector's Precision@B and Recall@B
change across key hyperparameters.

Sweeps
~~~~~~
1. suppress_days ∈ {0, 1, 2, 3, 5, 7}
2. contamination ∈ {0.01, 0.02, 0.05, 0.10, 0.15}
3. Budget B ∈ {5, 10, 20, 50, 100}

Output
~~~~~~
  results/sweep.csv                    — all sweep results
  figures/sweep_suppress_days.png      — effect of suppress_days
  figures/sweep_contamination.png      — effect of contamination

Usage::

    python scripts/run_sweep.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import logging
import numpy as np
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("sweep")

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from cti.util.config import load_config
from cti.util.seeds import set_all_seeds
from cti.detectors.train import prepare_X
from cti.detectors.proposed import (
    BudgetAwareConformal,
    _incident_aggregation,
)
from cti.eval.evaluate import precision_at_b, recall_at_b


def run_single(cfg, df_train, df_test, labels, seed, **overrides):
    """Train + score the proposed detector with optional config overrides."""
    det_cfg = cfg.get("detectors", {}).get("proposed", {}).copy()
    det_cfg.update({k: v for k, v in overrides.items()
                    if k in ("n_estimators", "contamination", "min_events", "cal_fraction")})

    cfg_copy = {**cfg}
    cfg_copy["detectors"] = {**cfg.get("detectors", {}), "proposed": det_cfg}
    if "suppress_days" in overrides:
        cfg_copy["suppress_days"] = overrides["suppress_days"]

    proposed = BudgetAwareConformal(cfg_copy, seed)
    X_train, _ = prepare_X(df_train)
    proposed.fit(X_train, df_train)

    X_test, _ = prepare_X(df_test)
    fused = proposed.score_samples(X_test, df_test)

    # Apply C4
    df_tmp = df_test[["principal", "date"]].copy()
    df_tmp["fused_score"] = fused
    sup = cfg_copy.get("suppress_days", 3)
    incidents = _incident_aggregation(df_tmp, "fused_score", suppress_days=sup)
    incident_map = {}
    for _, row in incidents.iterrows():
        incident_map[(row["principal"], row["date"])] = row["incident_score"]

    boosted = np.zeros(len(df_test), dtype=np.float64)
    for i, (_, row) in enumerate(df_test.reset_index(drop=True).iterrows()):
        key = (row["principal"], row["date"])
        if key in incident_map:
            boosted[i] = incident_map[key]

    return boosted


def main():
    cfg = load_config()
    seed = cfg["random_seed"]
    set_all_seeds(seed)

    # Load data
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
        df_train = df_feat.copy()
    if df_test.empty:
        df_test = df_feat.copy()

    test_labels = df_test.merge(df_labels, on=["principal", "date"], how="left")
    labels = test_labels["label"].fillna(0).astype(int).to_numpy()

    results_dir = Path("results")
    figures_dir = Path("figures")
    results_dir.mkdir(exist_ok=True)
    figures_dir.mkdir(exist_ok=True)

    all_rows = []

    # ── Sweep 1: suppress_days ──────────────────────────────────────────
    log.info("=== Sweep: suppress_days ===")
    for sd in [0, 1, 2, 3, 5, 7]:
        log.info("  suppress_days=%d", sd)
        scores = run_single(cfg, df_train, df_test, labels, seed, suppress_days=sd)
        for b in [10, 50, 100]:
            p = precision_at_b(scores, labels, b)
            r = recall_at_b(scores, labels, b)
            all_rows.append({
                "sweep": "suppress_days", "param_value": sd,
                "budget": b, "P@B": p, "R@B": r
            })

    # ── Sweep 2: contamination ──────────────────────────────────────────
    log.info("=== Sweep: contamination ===")
    for cont in [0.01, 0.02, 0.05, 0.10, 0.15]:
        log.info("  contamination=%.2f", cont)
        scores = run_single(cfg, df_train, df_test, labels, seed, contamination=cont)
        for b in [10, 50, 100]:
            p = precision_at_b(scores, labels, b)
            r = recall_at_b(scores, labels, b)
            all_rows.append({
                "sweep": "contamination", "param_value": cont,
                "budget": b, "P@B": p, "R@B": r
            })

    df_sweep = pd.DataFrame(all_rows)
    df_sweep.to_csv(results_dir / "sweep.csv", index=False)
    log.info("Saved results/sweep.csv")

    # ── Figure: suppress_days ────────────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    for ax, metric, title in [
        (axes[0], "P@B", "Precision@B vs. suppress_days"),
        (axes[1], "R@B", "Recall@B vs. suppress_days"),
    ]:
        sub = df_sweep[df_sweep["sweep"] == "suppress_days"]
        for b in [10, 50, 100]:
            bsub = sub[sub["budget"] == b].sort_values("param_value")
            ax.plot(bsub["param_value"], bsub[metric], marker="o", label=f"B={b}")
        ax.set_xlabel("suppress_days", fontsize=12)
        ax.set_ylabel(metric, fontsize=12)
        ax.set_title(title, fontsize=13, fontweight="bold")
        ax.legend()
        ax.set_ylim(0, 1.05)

    fig.tight_layout()
    fig.savefig(figures_dir / "sweep_suppress_days.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved figures/sweep_suppress_days.png")

    # ── Figure: contamination ────────────────────────────────────────────
    fig, axes = plt.subplots(1, 2, figsize=(14, 5))

    for ax, metric, title in [
        (axes[0], "P@B", "Precision@B vs. contamination"),
        (axes[1], "R@B", "Recall@B vs. contamination"),
    ]:
        sub = df_sweep[df_sweep["sweep"] == "contamination"]
        for b in [10, 50, 100]:
            bsub = sub[sub["budget"] == b].sort_values("param_value")
            ax.plot(bsub["param_value"], bsub[metric], marker="s", label=f"B={b}")
        ax.set_xlabel("contamination", fontsize=12)
        ax.set_ylabel(metric, fontsize=12)
        ax.set_title(title, fontsize=13, fontweight="bold")
        ax.legend()
        ax.set_ylim(0, 1.05)

    fig.tight_layout()
    fig.savefig(figures_dir / "sweep_contamination.png", dpi=150, bbox_inches="tight")
    plt.close(fig)
    log.info("Saved figures/sweep_contamination.png")

    # Summary
    print("\n" + "=" * 70)
    print("  PARAMETER SWEEP RESULTS")
    print("=" * 70)
    print(df_sweep.to_string(index=False))
    print()


if __name__ == "__main__":
    main()
