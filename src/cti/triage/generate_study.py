"""
cti.triage.generate_study
--------------------------
Generate a triage study questionnaire from pipeline results.

The study has two arms:
  Arm A (score-only):     reviewer sees anomaly score + principal + date
  Arm B (with explanation): reviewer sees score + SHAP-based explanation

Each reviewer classifies each alert as True Positive or False Positive.
The study measures whether explanations improve triage accuracy.

Usage::

    python -m cti.triage.generate_study \\
        --scores results/scores.parquet \\
        --shap   results/shap_alerts.json \\
        --labels data/features/labels.parquet \\
        --n-alerts 40 \\
        --output docs/triage_study/
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd

log = logging.getLogger(__name__)

# Feature name → human-readable description
_FEATURE_DESCRIPTIONS = {
    "vol_events_per_day":       "unusually high number of API calls",
    "div_unique_event_names":   "used many different API actions (unusual variety)",
    "div_unique_sources":       "accessed multiple AWS services (unusual breadth)",
    "div_unique_regions":       "operated across multiple AWS regions",
    "rar_fraction_rare_events": "high fraction of rarely-seen API actions",
    "tmp_after_hours_ratio":    "activity outside business hours (off-hours)",
    "tmp_burst_std_minutes":    "rapid burst of activity (short inter-arrival times)",
    "err_error_rate":           "high rate of access-denied errors",
}


def _explain_alert(shap_contrib: dict, top_k: int = 3) -> str:
    """Turn SHAP contributions into a human-readable explanation string."""
    sorted_feats = sorted(shap_contrib.items(), key=lambda x: abs(x[1]), reverse=True)
    parts = []
    for feat, value in sorted_feats[:top_k]:
        desc = _FEATURE_DESCRIPTIONS.get(feat, feat.replace("_", " "))
        direction = "high" if value > 0 else "low"
        parts.append(f"  • {desc} (contribution: {value:+.3f})")

    return "\n".join(parts)


def generate_questionnaire(
    df_scores: pd.DataFrame,
    shap_alerts: list[dict],
    df_labels: pd.DataFrame,
    n_alerts: int = 40,
) -> dict:
    """Generate the two-arm triage study.

    Returns a dict with:
      - arm_a: list of score-only alerts
      - arm_b: list of alerts with explanations
      - answer_key: ground truth labels
    """
    # Merge scores with labels
    df = df_scores.merge(df_labels, on=["principal", "date"], how="left")
    df["label"] = df["label"].fillna(0).astype(int)

    # Take top n_alerts by score
    df = df.sort_values("score", ascending=False).head(n_alerts).reset_index(drop=True)

    # Build SHAP lookup
    shap_lookup = {}
    for alert in shap_alerts:
        key = (alert.get("principal", ""), alert.get("date", ""))
        shap_lookup[key] = alert.get("shap", {})

    arm_a = []
    arm_b = []
    answer_key = []

    for i, row in df.iterrows():
        alert_id = i + 1
        principal = row["principal"]
        date = str(row["date"])[:10]
        score = float(row["score"])
        true_label = "True Positive" if row["label"] == 1 else "False Positive"

        # Arm A: Score only
        arm_a.append({
            "alert_id": alert_id,
            "text": (
                f"Alert #{alert_id}\n"
                f"  Principal: {principal}\n"
                f"  Date: {date}\n"
                f"  Anomaly Score: {score:.4f}\n"
                f"\n"
                f"  Is this a True Positive or False Positive? ___"
            ),
        })

        # Arm B: With explanation
        shap_contrib = shap_lookup.get((principal, date), {})
        if not shap_contrib:
            # Try with date string variations
            for key in shap_lookup:
                if key[0] == principal:
                    shap_contrib = shap_lookup[key]
                    break

        explanation = _explain_alert(shap_contrib) if shap_contrib else "  • (explanation not available)"

        arm_b.append({
            "alert_id": alert_id,
            "text": (
                f"Alert #{alert_id}\n"
                f"  Principal: {principal}\n"
                f"  Date: {date}\n"
                f"  Anomaly Score: {score:.4f}\n"
                f"\n"
                f"  WHY THIS WAS FLAGGED:\n"
                f"{explanation}\n"
                f"\n"
                f"  Is this a True Positive or False Positive? ___"
            ),
        })

        answer_key.append({
            "alert_id": alert_id,
            "principal": principal,
            "date": date,
            "true_label": true_label,
        })

    return {
        "arm_a": arm_a,
        "arm_b": arm_b,
        "answer_key": answer_key,
    }


def save_questionnaire(study: dict, output_dir: Path) -> None:
    """Save the questionnaire as markdown files and JSON."""
    output_dir.mkdir(parents=True, exist_ok=True)

    # Arm A markdown
    with open(output_dir / "arm_a_score_only.md", "w", encoding="utf-8") as f:
        f.write("# Triage Study — Arm A (Score Only)\n\n")
        f.write("**Instructions**: For each alert below, decide whether it is a\n")
        f.write("**True Positive** (real malicious activity) or a **False Positive**\n")
        f.write("(benign/normal behaviour). Base your decision ONLY on the information shown.\n\n")
        f.write("---\n\n")
        for alert in study["arm_a"]:
            f.write(f"```\n{alert['text']}\n```\n\n---\n\n")

    # Arm B markdown
    with open(output_dir / "arm_b_with_explanation.md", "w", encoding="utf-8") as f:
        f.write("# Triage Study — Arm B (With Explanation)\n\n")
        f.write("**Instructions**: For each alert below, decide whether it is a\n")
        f.write("**True Positive** (real malicious activity) or a **False Positive**\n")
        f.write("(benign/normal behaviour). You have both the anomaly score AND\n")
        f.write("an explanation of WHY the alert was generated.\n\n")
        f.write("---\n\n")
        for alert in study["arm_b"]:
            f.write(f"```\n{alert['text']}\n```\n\n---\n\n")

    # Answer key (for grading)
    with open(output_dir / "answer_key.json", "w", encoding="utf-8") as f:
        json.dump(study["answer_key"], f, indent=2)

    # Full study as JSON
    with open(output_dir / "triage_study.json", "w", encoding="utf-8") as f:
        json.dump(study, f, indent=2)

    log.info("Saved triage study to %s", output_dir)
    print(f"\n📋 Triage study saved to {output_dir}/")
    print(f"   - arm_a_score_only.md       (give to half the reviewers)")
    print(f"   - arm_b_with_explanation.md  (give to other half)")
    print(f"   - answer_key.json            (for scoring)")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate triage study questionnaire")
    parser.add_argument("--scores", required=True, help="Parquet with principal, date, score")
    parser.add_argument("--shap", required=True, help="JSON with SHAP alerts")
    parser.add_argument("--labels", required=True, help="Parquet with principal, date, label")
    parser.add_argument("--n-alerts", type=int, default=40)
    parser.add_argument("--output", default="docs/triage_study")
    args = parser.parse_args()

    df_scores = pd.read_parquet(args.scores)
    with open(args.shap) as f:
        shap_data = json.load(f)
    shap_alerts = shap_data.get("alerts", shap_data) if isinstance(shap_data, dict) else shap_data
    df_labels = pd.read_parquet(args.labels)

    study = generate_questionnaire(df_scores, shap_alerts, df_labels, args.n_alerts)
    save_questionnaire(study, Path(args.output))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
