"""
cti.explain.shap_explain
------------------------
SHAP-based explanations for the IsolationForest detector.

For each alert surfaced at budget B, produce:
- A global feature-importance bar chart (saved as PNG)
- Per-alert waterfall / force values (saved as JSON for the demo)

All display limits and background-sample counts come from cfg["explain"].
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd
import shap

from cti.detectors.train import IsoForestDetector, load_detector, prepare_X
from cti.util.config import load_config
from cti.util.run import RunContext
from cti.util.seeds import make_rng, set_all_seeds

log = logging.getLogger(__name__)


def compute_shap_values(
    detector: IsoForestDetector,
    X_background: np.ndarray,
    X_explain: np.ndarray,
    cfg: dict,
    rng: np.random.Generator,
) -> np.ndarray:
    """Compute SHAP values using TreeExplainer for IsolationForest.

    Falls back to KernelExplainer for non-tree models.
    """
    explain_cfg = cfg["explain"]
    n_bg = min(explain_cfg["background_samples"], len(X_background))
    idx = rng.choice(len(X_background), size=n_bg, replace=False)
    background = X_background[idx]

    try:
        explainer = shap.TreeExplainer(detector._model)
        shap_values = explainer.shap_values(X_explain)
    except Exception:
        log.warning("TreeExplainer failed; falling back to KernelExplainer (slow)")
        explainer = shap.KernelExplainer(
            lambda x: -detector._model.score_samples(x),
            background,
        )
        shap_values = explainer.shap_values(X_explain, nsamples=100)

    return shap_values


def global_importance(shap_values: np.ndarray, feat_cols: list[str]) -> pd.DataFrame:
    """Return mean |SHAP| per feature, sorted descending."""
    mean_abs = np.abs(shap_values).mean(axis=0)
    return (
        pd.DataFrame({"feature": feat_cols, "mean_abs_shap": mean_abs})
        .sort_values("mean_abs_shap", ascending=False)
        .reset_index(drop=True)
    )


def save_global_bar(df_importance: pd.DataFrame, path: Path, cfg: dict) -> None:
    """Save a horizontal bar chart of global SHAP importances."""
    import matplotlib.pyplot as plt

    top_n = cfg["explain"]["shap_max_display"]
    df_top = df_importance.head(top_n)

    fig, ax = plt.subplots(figsize=(8, max(3, top_n * 0.35)))
    ax.barh(df_top["feature"][::-1], df_top["mean_abs_shap"][::-1], color="#e74c3c")
    ax.set_xlabel("Mean |SHAP value|")
    ax.set_title("Global Feature Importance (IsolationForest)")
    ax.tick_params(axis="y", labelsize=8)
    fig.tight_layout()
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=150)
    plt.close(fig)
    log.info("Saved SHAP bar chart to %s", path)


def per_alert_explanations(
    shap_values: np.ndarray,
    feat_cols: list[str],
    df_explain: pd.DataFrame,
    budget: int,
) -> list[dict]:
    """Return a JSON-serialisable list of per-alert SHAP contributions."""
    records = []
    for i in range(min(budget, len(df_explain))):
        row = df_explain.iloc[i]
        contrib = {
            feat_cols[j]: float(shap_values[i, j])
            for j in range(len(feat_cols))
        }
        records.append(
            {
                "rank":      i + 1,
                "principal": str(row.get("principal", "")),
                "date":      str(row.get("date", "")),
                "score":     float(row.get("score", 0.0)),
                "shap":      contrib,
            }
        )
    return records


def main() -> None:
    """CLI entrypoint: cti-explain."""
    parser = argparse.ArgumentParser(description="Generate SHAP explanations")
    parser.add_argument("--config",   default=None)
    parser.add_argument("--features", default=None)
    parser.add_argument("--scores",   required=True)
    parser.add_argument("--model",    default=None, help="Path to IsoForest .pkl")
    parser.add_argument("--budget",   type=int, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_all_seeds(cfg["random_seed"])
    rng = make_rng(cfg["random_seed"])

    feat_path = Path(args.features or cfg["paths"]["feature_store"])
    model_path = Path(args.model or f"{cfg['paths']['models_dir']}/isolation_forest.pkl")
    budget = args.budget or cfg["demo"]["default_budget"]

    df_feat   = pd.read_parquet(feat_path)
    df_scores = pd.read_parquet(args.scores)

    detector: IsoForestDetector = load_detector(model_path)
    X_all, feat_cols = prepare_X(df_feat)

    # Get top-budget rows by score
    df_scores = df_scores.sort_values("score", ascending=False).head(budget)
    df_explain = df_feat.merge(df_scores[["principal", "date"]], on=["principal", "date"])
    X_explain, _ = prepare_X(df_explain)

    shap_values = compute_shap_values(detector, X_all, X_explain, cfg, rng)

    df_importance = global_importance(shap_values, feat_cols)
    log.info("Top-5 features:\n%s", df_importance.head())

    with RunContext(
        "explain",
        config_path=args.config,
        input_paths=[feat_path, args.scores],
    ) as ctx:
        fig_dir = Path(cfg["paths"]["figures_dir"])
        save_global_bar(df_importance, fig_dir / "shap_global.png", cfg)

        alerts = per_alert_explanations(shap_values, feat_cols, df_explain, budget)
        ctx.save_artifact("shap_alerts.json", {"budget": budget, "alerts": alerts})
        ctx.save_artifact("shap_importance.parquet", df_importance)
        ctx.register(budget=budget, n_explained=len(alerts))


if __name__ == "__main__":
    main()
