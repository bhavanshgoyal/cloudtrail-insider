"""
cti.triage.score_study
-----------------------
Score the triage study responses and compute evaluation metrics.

Input: CSV of reviewer responses with columns:
  reviewer, alert_id, verdict (TP or FP)

Output: balanced accuracy per arm, Cohen's kappa for inter-rater
agreement, and a summary table.

Usage::

    python -m cti.triage.score_study \\
        --responses docs/triage_study/responses.csv \\
        --answer-key docs/triage_study/answer_key.json \\
        --output results/triage_results.csv
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)


def _balanced_accuracy(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """Balanced accuracy: mean of per-class recall."""
    classes = np.unique(y_true)
    if len(classes) < 2:
        return float(np.mean(y_true == y_pred))

    recalls = []
    for c in classes:
        mask = y_true == c
        if mask.sum() > 0:
            recalls.append(np.mean(y_pred[mask] == c))
    return float(np.mean(recalls))


def _cohens_kappa(y1: np.ndarray, y2: np.ndarray) -> float:
    """Cohen's kappa for two raters on binary labels."""
    n = len(y1)
    if n == 0:
        return 0.0
    po = np.mean(y1 == y2)  # Observed agreement
    # Expected agreement by chance
    p1_pos = np.mean(y1 == 1)
    p2_pos = np.mean(y2 == 1)
    pe = p1_pos * p2_pos + (1 - p1_pos) * (1 - p2_pos)
    if pe == 1.0:
        return 1.0
    return float((po - pe) / (1 - pe))


def score_responses(
    df_responses: pd.DataFrame,
    answer_key: list[dict],
) -> dict:
    """Score triage responses.

    Parameters
    ----------
    df_responses : pd.DataFrame
        Columns: reviewer, arm (A or B), alert_id, verdict (TP or FP)
    answer_key : list[dict]
        Each dict has: alert_id, true_label (True Positive / False Positive)

    Returns
    -------
    dict with results per arm and inter-rater metrics
    """
    # Build truth lookup
    truth = {}
    for entry in answer_key:
        truth[entry["alert_id"]] = 1 if entry["true_label"] == "True Positive" else 0

    # Map verdicts to binary
    df = df_responses.copy()
    df["pred"] = df["verdict"].map({"TP": 1, "FP": 0, "True Positive": 1, "False Positive": 0})
    df["true"] = df["alert_id"].map(truth)

    # Drop rows with missing mappings
    df = df.dropna(subset=["pred", "true"])
    df["pred"] = df["pred"].astype(int)
    df["true"] = df["true"].astype(int)

    results = {"arms": {}, "inter_rater": {}}

    # Per-arm balanced accuracy
    for arm in df["arm"].unique():
        arm_df = df[df["arm"] == arm]
        y_true = arm_df["true"].to_numpy()
        y_pred = arm_df["pred"].to_numpy()

        ba = _balanced_accuracy(y_true, y_pred)
        accuracy = float(np.mean(y_true == y_pred))
        n_reviewers = arm_df["reviewer"].nunique()
        n_responses = len(arm_df)

        results["arms"][arm] = {
            "balanced_accuracy": round(ba, 4),
            "raw_accuracy": round(accuracy, 4),
            "n_reviewers": n_reviewers,
            "n_responses": n_responses,
        }

    # Inter-rater agreement (Cohen's kappa between pairs of reviewers)
    reviewers = df["reviewer"].unique()
    kappas = []
    for i in range(len(reviewers)):
        for j in range(i + 1, len(reviewers)):
            r1 = df[df["reviewer"] == reviewers[i]]
            r2 = df[df["reviewer"] == reviewers[j]]
            common = r1.merge(r2, on=["alert_id", "arm"], suffixes=("_1", "_2"))
            if len(common) > 0:
                k = _cohens_kappa(common["pred_1"].to_numpy(), common["pred_2"].to_numpy())
                kappas.append({
                    "reviewer_1": reviewers[i],
                    "reviewer_2": reviewers[j],
                    "kappa": round(k, 4),
                    "n_common": len(common),
                })

    results["inter_rater"] = {
        "pairwise_kappas": kappas,
        "mean_kappa": round(float(np.mean([k["kappa"] for k in kappas])), 4) if kappas else None,
    }

    return results


def print_results(results: dict) -> None:
    """Pretty-print triage study results."""
    print("\n" + "=" * 60)
    print("  TRIAGE STUDY RESULTS")
    print("=" * 60)

    print(f"\n{'Arm':<10} {'Balanced Acc':<15} {'Raw Acc':<12} {'Reviewers':<12} {'Responses'}")
    print("-" * 60)
    for arm, data in results["arms"].items():
        print(f"{arm:<10} {data['balanced_accuracy']:<15.4f} {data['raw_accuracy']:<12.4f} "
              f"{data['n_reviewers']:<12} {data['n_responses']}")

    # Improvement
    arms = list(results["arms"].keys())
    if len(arms) == 2:
        ba_a = results["arms"][arms[0]]["balanced_accuracy"]
        ba_b = results["arms"][arms[1]]["balanced_accuracy"]
        diff = ba_b - ba_a
        print(f"\n  Δ Balanced Accuracy (B - A) = {diff:+.4f} ({diff*100:+.1f} pp)")
        if diff > 0.20:
            print("  ✅ H3 SUPPORTED: Explanation arm is ≥20pp above score-only arm")
        else:
            print(f"  ⚠️  H3 requires ≥20pp improvement; observed {diff*100:.1f}pp")

    # Inter-rater
    ir = results["inter_rater"]
    if ir["mean_kappa"] is not None:
        print(f"\n  Mean Cohen's κ = {ir['mean_kappa']:.4f}")
        if ir["mean_kappa"] >= 0.6:
            print("  ✅ Substantial inter-rater agreement")
        elif ir["mean_kappa"] >= 0.4:
            print("  ⚠️  Moderate inter-rater agreement")
        else:
            print("  ⚠️  Fair/poor inter-rater agreement")

    print("=" * 60)


def main() -> None:
    parser = argparse.ArgumentParser(description="Score triage study responses")
    parser.add_argument("--responses", required=True, help="CSV: reviewer, arm, alert_id, verdict")
    parser.add_argument("--answer-key", required=True, help="JSON answer key")
    parser.add_argument("--output", default="results/triage_results.json")
    args = parser.parse_args()

    df = pd.read_csv(args.responses)
    with open(args.answer_key) as f:
        answer_key = json.load(f)

    results = score_responses(df, answer_key)
    print_results(results)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n📁 Results saved to {out_path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
