"""
cti.eval.figures
----------------
Generate paper-quality figures from evaluation results.

Produces:
  figures/precision_recall_budget.pdf  – P@B and R@B curves across budgets
  figures/ndcg_heatmap.pdf             – NDCG@B per detector per budget
  figures/ablation_bar.pdf             – ablation study bar chart
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from cti.util.config import load_config
from cti.util.run import RunContext
from cti.util.seeds import set_all_seeds

matplotlib.use("Agg")
log = logging.getLogger(__name__)

_COLORS = {
    "isolation_forest": "#e74c3c",
    "lof":              "#3498db",
    "autoencoder":      "#2ecc71",
}
_MARKERS = {"isolation_forest": "o", "lof": "s", "autoencoder": "^"}


def _load_metrics(results_dir: Path) -> pd.DataFrame:
    files = sorted(results_dir.glob("**/metrics.parquet"))
    if not files:
        raise FileNotFoundError(f"No metrics.parquet found under {results_dir}")
    return pd.read_parquet(files[-1])


def precision_recall_figure(df: pd.DataFrame, out_dir: Path, budgets: list[int]) -> None:
    """P@B and R@B side-by-side line plots."""
    fig, axes = plt.subplots(1, 2, figsize=(10, 4), sharey=False)
    for det in df["detector"].unique():
        sub = df[df["detector"] == det]
        color  = _COLORS.get(det, "grey")
        marker = _MARKERS.get(det, "x")

        for ax, metric in zip(axes, ["precision_at_b", "recall_at_b"]):
            m = sub[sub["metric"] == metric].sort_values("budget")
            ax.errorbar(
                m["budget"],
                m["value"],
                yerr=[m["value"] - m["ci_lo"], m["ci_hi"] - m["value"]],
                label=det.replace("_", " "),
                color=color,
                marker=marker,
                capsize=4,
            )

    axes[0].set_title("Precision@B")
    axes[1].set_title("Recall@B")
    for ax in axes:
        ax.set_xlabel("Alert Budget B")
        ax.set_xticks(budgets)
        ax.legend(fontsize=8)
        ax.set_ylim(0, 1.05)

    fig.tight_layout()
    out = out_dir / "precision_recall_budget.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(out)
    plt.close(fig)
    log.info("Saved %s", out)


def ndcg_heatmap(df: pd.DataFrame, out_dir: Path) -> None:
    """NDCG@B as a detector × budget heatmap."""
    pivot = (
        df[df["metric"] == "ndcg_at_b"]
        .pivot(index="detector", columns="budget", values="value")
        .fillna(0)
    )
    fig, ax = plt.subplots(figsize=(5, max(2, len(pivot) * 0.8)))
    im = ax.imshow(pivot.values, aspect="auto", cmap="YlOrRd", vmin=0, vmax=1)
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns)
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels([d.replace("_", " ") for d in pivot.index])
    ax.set_xlabel("Budget B")
    ax.set_title("NDCG@B")
    for (i, j), val in np.ndenumerate(pivot.values):
        ax.text(j, i, f"{val:.2f}", ha="center", va="center", fontsize=9)
    plt.colorbar(im, ax=ax)
    fig.tight_layout()
    out = out_dir / "ndcg_heatmap.pdf"
    fig.savefig(out)
    plt.close(fig)
    log.info("Saved %s", out)


def ablation_bar(df: pd.DataFrame, out_dir: Path, budget: int) -> None:
    """Bar chart for ablation study at default budget."""
    sub = df[(df["metric"] == "precision_at_b") & (df["budget"] == budget)]
    if sub.empty:
        log.warning("No ablation data for budget=%d", budget)
        return

    fig, ax = plt.subplots(figsize=(6, 3))
    dets = sub["detector"].tolist()
    vals = sub["value"].tolist()
    colors = [_COLORS.get(d, "grey") for d in dets]
    bars = ax.bar(range(len(dets)), vals, color=colors)
    ax.set_xticks(range(len(dets)))
    ax.set_xticklabels([d.replace("_", " ") for d in dets], rotation=15, ha="right")
    ax.set_ylabel(f"Precision@{budget}")
    ax.set_title(f"Ablation Study  ·  Budget = {budget}")
    ax.set_ylim(0, 1.05)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.01,
                f"{val:.2f}", ha="center", fontsize=9)
    fig.tight_layout()
    out = out_dir / "ablation_bar.pdf"
    fig.savefig(out)
    plt.close(fig)
    log.info("Saved %s", out)


def main() -> None:
    """CLI entrypoint (called by make figures)."""
    parser = argparse.ArgumentParser(description="Generate paper figures")
    parser.add_argument("--config",  default=None)
    parser.add_argument("--results", default=None)
    parser.add_argument("--output",  default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_all_seeds(cfg["random_seed"])

    results_dir = Path(args.results or cfg["paths"]["results_dir"])
    out_dir     = Path(args.output  or cfg["paths"]["figures_dir"])

    with RunContext("figures", config_path=args.config) as ctx:
        df = _load_metrics(results_dir)
        budgets = cfg["budgets"]
        precision_recall_figure(df, out_dir, budgets)
        ndcg_heatmap(df, out_dir)
        ablation_bar(df, out_dir, cfg["demo"]["default_budget"])
        ctx.register(figures_dir=str(out_dir))


if __name__ == "__main__":
    main()
