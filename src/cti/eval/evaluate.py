"""
cti.eval.evaluate
-----------------
Fixed-budget evaluation: Precision@B, Recall@B, NDCG@B, MAP@B.

Hypothesis alignment
~~~~~~~~~~~~~~~~~~~~
H1 – precision@B improves over baselines across all budgets B ∈ {10, 50, 100}.
H2 – recall@B degrades gracefully as B decreases.
H3 – NDCG@B shows that the proposed method ranks true positives higher.

All metrics are computed via bootstrapped confidence intervals.
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd
from scipy.stats import bootstrap as scipy_bootstrap

from cti.util.config import load_config
from cti.util.run import RunContext
from cti.util.seeds import make_rng, set_all_seeds

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core metric functions (operate on ranked lists)
# ---------------------------------------------------------------------------

def precision_at_b(scores: np.ndarray, labels: np.ndarray, b: int) -> float:
    """Fraction of true positives in the top-B scored items."""
    if b == 0:
        return 0.0
    top_idx = np.argsort(scores)[::-1][:b]
    return float(labels[top_idx].sum()) / b


def recall_at_b(scores: np.ndarray, labels: np.ndarray, b: int) -> float:
    """Fraction of all positives that appear in the top-B."""
    total_pos = labels.sum()
    if total_pos == 0:
        return 0.0
    top_idx = np.argsort(scores)[::-1][:b]
    return float(labels[top_idx].sum()) / total_pos


def dcg_at_b(scores: np.ndarray, labels: np.ndarray, b: int) -> float:
    """Discounted Cumulative Gain at B."""
    top_idx = np.argsort(scores)[::-1][:b]
    gains = labels[top_idx].astype(float)
    discounts = np.log2(np.arange(2, len(gains) + 2))
    return float((gains / discounts).sum())


def ndcg_at_b(scores: np.ndarray, labels: np.ndarray, b: int) -> float:
    """Normalised DCG at B (ideal DCG computed from true labels)."""
    ideal_scores = labels.astype(float)
    idcg = dcg_at_b(ideal_scores, labels, b)
    if idcg == 0.0:
        return 0.0
    return dcg_at_b(scores, labels, b) / idcg


def average_precision(scores: np.ndarray, labels: np.ndarray) -> float:
    """Average precision (area under precision-recall curve)."""
    order = np.argsort(scores)[::-1]
    labels_sorted = labels[order]
    cum_tp = np.cumsum(labels_sorted)
    total_pos = labels.sum()
    if total_pos == 0:
        return 0.0
    ranks = np.arange(1, len(labels_sorted) + 1)
    precisions = cum_tp / ranks
    return float((precisions * labels_sorted).sum() / total_pos)


def map_at_b(scores: np.ndarray, labels: np.ndarray, b: int) -> float:
    """Mean Average Precision restricted to top-B items."""
    top_idx = np.argsort(scores)[::-1][:b]
    return average_precision(scores[top_idx], labels[top_idx])


# ---------------------------------------------------------------------------
# Budget suppression (max_alerts_per_principal_day)
# ---------------------------------------------------------------------------

def apply_budget_cap(
    df: pd.DataFrame,
    score_col: str,
    principal_col: str,
    date_col: str,
    max_per_day: int,
) -> pd.DataFrame:
    """Zero-out scores exceeding the per-principal-per-day cap.

    The cap prevents one noisy principal from monopolising the alert budget.
    """
    df = df.copy()
    df["_rank_within"] = (
        df.groupby([principal_col, date_col])[score_col]
        .rank(method="first", ascending=False)
    )
    mask = df["_rank_within"] > max_per_day
    df.loc[mask, score_col] = 0.0
    return df.drop(columns=["_rank_within"])


# ---------------------------------------------------------------------------
# Bootstrap confidence intervals
# ---------------------------------------------------------------------------

def bootstrap_ci(
    scores: np.ndarray,
    labels: np.ndarray,
    metric_fn,
    b: int,
    n_iter: int,
    conf: float,
    seed: int,
) -> tuple[float, float, float]:
    """Return (point_estimate, ci_low, ci_high) via non-parametric bootstrap."""
    rng = make_rng(seed)
    n = len(scores)
    point = metric_fn(scores, labels, b)
    resamples = np.array(
        [
            metric_fn(scores[idx], labels[idx], b)
            for idx in (rng.integers(0, n, size=n) for _ in range(n_iter))
        ]
    )
    alpha = 1.0 - conf
    ci_lo = float(np.percentile(resamples, 100 * alpha / 2))
    ci_hi = float(np.percentile(resamples, 100 * (1 - alpha / 2)))
    return point, ci_lo, ci_hi


# ---------------------------------------------------------------------------
# Evaluate one detector
# ---------------------------------------------------------------------------

def evaluate_detector(
    scores: np.ndarray,
    labels: np.ndarray,
    cfg: dict,
    detector_name: str,
) -> pd.DataFrame:
    """Compute all budget-gated metrics for one detector.

    Returns a tidy DataFrame with columns:
    detector | budget | metric | value | ci_lo | ci_hi
    """
    eval_cfg = cfg["eval"]
    budgets  = cfg["budgets"]
    n_iter   = eval_cfg["bootstrap_iterations"]
    conf     = eval_cfg["confidence_level"]
    seed     = cfg["random_seed"]

    metric_fns = {
        "precision_at_b": precision_at_b,
        "recall_at_b":    recall_at_b,
        "ndcg_at_b":      ndcg_at_b,
        "map_at_b":       map_at_b,
    }

    rows = []
    for b in budgets:
        for mname, fn in metric_fns.items():
            point, lo, hi = bootstrap_ci(scores, labels, fn, b, n_iter, conf, seed)
            rows.append(
                {
                    "detector": detector_name,
                    "budget":   b,
                    "metric":   mname,
                    "value":    point,
                    "ci_lo":    lo,
                    "ci_hi":    hi,
                }
            )
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    """CLI entrypoint: cti-eval."""
    parser = argparse.ArgumentParser(description="Evaluate detectors at fixed alert budgets")
    parser.add_argument("--config",  default=None)
    parser.add_argument("--scores",  required=True,  help="Parquet file with columns: principal, date, detector, score")
    parser.add_argument("--labels",  required=True,  help="Parquet file with columns: principal, date, label (0/1)")
    parser.add_argument("--output",  default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_all_seeds(cfg["random_seed"])

    df_scores = pd.read_parquet(args.scores)
    df_labels = pd.read_parquet(args.labels)

    df = df_scores.merge(df_labels, on=["principal", "date"], how="left")
    df["label"] = df["label"].fillna(0).astype(int)

    # Apply per-principal-day cap from config
    cap = cfg["max_alerts_per_principal_day"]

    results = []
    for det_name in df["detector"].unique():
        sub = df[df["detector"] == det_name].copy()
        sub = apply_budget_cap(sub, "score", "principal", "date", cap)
        scores = sub["score"].to_numpy()
        labels = sub["label"].to_numpy()
        results.append(evaluate_detector(scores, labels, cfg, det_name))

    df_results = pd.concat(results, ignore_index=True)

    out_path = Path(args.output or cfg["paths"]["results_dir"]) / "metrics.parquet"
    with RunContext(
        "evaluate",
        config_path=args.config,
        input_paths=[args.scores, args.labels],
    ) as ctx:
        ctx.save_artifact("metrics.parquet", df_results)
        ctx.register(n_rows=len(df_results))
        log.info("Evaluation results:\n%s", df_results.to_string())


if __name__ == "__main__":
    main()
