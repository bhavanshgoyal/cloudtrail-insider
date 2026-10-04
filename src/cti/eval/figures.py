"""
cti.eval.figures
----------------
All report figures, built from the aggregated CSVs (never from a single run).

Conventions
~~~~~~~~~~~
* One fixed colour + marker per detector across every figure (colour follows the entity).
  Palette = categorical slots 1-5 of the reference palette, validated with
  ``validate_palette.js`` (adjacent CVD dE >= 9.1, normal-vision dE >= 19.6). Three of the five
  sit under 3:1 contrast on the light surface, so every chart also carries a legend, distinct
  markers and a matching CSV table (relief rule).
* Error bars are 95% t-intervals over seeds (5 seeds for the campaign, 3 for sweeps/ablations);
  rolling origins are averaged within a seed first because their test windows overlap.
* Precision is always drawn next to its oracle ceiling (few malicious rows exist per day).
* Each figure is also written as CSV next to it (``<name>.csv``) - the table view.
"""
from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

SURFACE, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e3e2dd"
PROPOSED = "proposed_budget_aware_conformal"

STYLE = {
    PROPOSED:           dict(label="Proposed (BudgetAwareConformal)", color="#2a78d6", marker="o", ls="-"),
    "isolation_forest": dict(label="Isolation Forest",               color="#eb6834", marker="s", ls="--"),
    "lof":              dict(label="LOF",                            color="#1baf7a", marker="^", ls="-."),
    "autoencoder":      dict(label="Autoencoder",                    color="#eda100", marker="D", ls=":"),
    "rule_baseline":    dict(label="Rule signatures",                color="#e87ba4", marker="X", ls=(0, (1, 1))),
}
ORDER = [PROPOSED, "isolation_forest", "lof", "autoencoder", "rule_baseline"]
WORKLOAD_LABEL = {"W1_baseline": "W1 baseline", "W2_stealthy": "W2 stealthy", "W3_scale": "W3 scale (3000)",
                  "W4_noisy": "W4 noisy"}
DPI = 150


def _fig(w=7.0, h=4.2, **kw):
    fig, ax = plt.subplots(figsize=(w, h), facecolor=SURFACE, constrained_layout=True, **kw)
    for a in np.atleast_1d(ax).ravel():
        _style_ax(a)
    return fig, ax


def _style_ax(ax):
    ax.set_facecolor(SURFACE)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_color(INK2)
        ax.spines[s].set_linewidth(0.8)
    ax.grid(True, color=GRID, linewidth=0.7, zorder=0)
    ax.tick_params(colors=INK2, labelsize=9)
    ax.xaxis.label.set_color(INK2)
    ax.yaxis.label.set_color(INK2)
    ax.title.set_color(INK)


def _save(fig, path: Path, table: pd.DataFrame | None = None):
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(path, dpi=DPI, facecolor=SURFACE)
    plt.close(fig)
    if table is not None:
        table.to_csv(path.with_suffix(".csv"), index=False)


def _legend(ax, **kw):
    leg = ax.legend(frameon=False, fontsize=8.5, labelcolor=INK2, **kw)
    return leg


def _line(ax, df, x, det, ylabel_col="mean", offset=0.0, log=False):
    d = df[df["detector"] == det].sort_values(x)
    st = STYLE[det]
    xs = d[x].to_numpy(dtype=float)
    xs = xs * (1 + offset) if log else xs + offset
    lo = np.where(np.isfinite(d["ci_lo"]), d[ylabel_col] - d["ci_lo"], 0.0)
    hi = np.where(np.isfinite(d["ci_hi"]), d["ci_hi"] - d[ylabel_col], 0.0)
    ax.errorbar(xs, d[ylabel_col], yerr=[lo, hi], color=st["color"], marker=st["marker"], ls=st["ls"],
                lw=2, ms=7, capsize=3, elinewidth=1, mec=SURFACE, mew=1.2, label=st["label"], zorder=3)


def _pick(summ, **conds):
    m = pd.Series(True, index=summ.index)
    for k, v in conds.items():
        m &= summ[k].isin(v) if isinstance(v, (list, tuple, set)) else summ[k] == v
    return summ[m]


# ---------------------------------------------------------------------------
# Budget curves (R2 graph: baseline and proposed on the same axes)
# ---------------------------------------------------------------------------
def plot_budget_curves(summ: pd.DataFrame, out_dir: Path, workload="W1_baseline") -> None:
    d = _pick(summ, workload=workload, detector=ORDER)
    n = int(d["n_seeds"].max())
    for metric, name, ylab in (("dr_at_b", "dr_vs_budget", "Detection rate (share of insiders caught)"),
                               ("precision_at_b", "precision_vs_budget", "Precision (true alerts / alerts)")):
        fig, ax = _fig(7.0, 4.4)
        dm = d[d["metric"] == metric]
        for i, det in enumerate(ORDER):
            _line(ax, dm, "budget", det, offset=(i - 2) * 0.03, log=True)
        if metric == "precision_at_b":
            o = d[(d["metric"] == "precision_oracle_at_b") & (d["detector"] == PROPOSED)].sort_values("budget")
            ax.plot(o["budget"], o["mean"], color=INK2, ls=(0, (4, 3)), lw=1.4, label="Oracle ceiling", zorder=2)
            ax.set_yscale("log")
        else:
            ax.set_ylim(0, 1.05)
        ax.set_xscale("log")
        buds = sorted(dm["budget"].unique())
        ax.set_xticks(buds, [str(int(b)) for b in buds])
        ax.minorticks_off()
        ax.set_xlabel("Alert budget B (alerts reviewed per day)")
        ax.set_ylabel(ylab)
        ax.set_title(f"{WORKLOAD_LABEL.get(workload, workload)}: {ylab.split(' (')[0]} at fixed daily budgets\n"
                     f"mean over {n} seeds x 3 temporal origins, 95% CI over seeds", fontsize=10, loc="left")
        _legend(ax, loc="lower right" if metric == "dr_at_b" else "upper right")
        _save(fig, out_dir / f"{name}.png", dm[["detector", "budget", "n_seeds", "mean", "std", "ci_lo", "ci_hi"]])


def plot_mttd(summ: pd.DataFrame, out_dir: Path, workload="W1_baseline") -> None:
    d = _pick(summ, workload=workload, metric="mttd_hours_median", budget=10, detector=ORDER)
    fig, ax = _fig(7.0, 3.6)
    for i, det in enumerate(ORDER):
        r = d[d["detector"] == det]
        if r.empty:
            continue
        r = r.iloc[0]
        st = STYLE[det]
        lo = r["mean"] - r["ci_lo"] if np.isfinite(r["ci_lo"]) else 0
        hi = r["ci_hi"] - r["mean"] if np.isfinite(r["ci_hi"]) else 0
        ax.errorbar([r["mean"]], [len(ORDER) - 1 - i], xerr=[[lo], [hi]], color=st["color"], marker=st["marker"],
                    ms=8, capsize=3, lw=1.5, mec=SURFACE, mew=1.2, ls="none", zorder=3)
    ax.set_yticks(range(len(ORDER)), [STYLE[k]["label"] for k in reversed(ORDER)])
    ax.set_xlabel("Median hours, attack onset to alert (B = 10, detected insiders)")
    ax.set_title(f"{WORKLOAD_LABEL.get(workload, workload)}: time to detection\n"
                 "alerts are a daily batch, so ~12-24 h is the floor", fontsize=10, loc="left")
    ax.grid(axis="y", visible=False)
    _save(fig, out_dir / "mttd_at_10.png",
          d[["detector", "n_seeds", "mean", "std", "ci_lo", "ci_hi"]])


def plot_rank_reversal(summ: pd.DataFrame, out_dir: Path, workload=None) -> None:
    """Rank of each detector by AUC (whole curve) vs DR@10 and P@10, one panel per workload."""
    cols = [("auc_roc", 0, "AUC-ROC\n(curve)"), ("dr_at_b", 10, "DR\n@10/day"),
            ("precision_at_b", 10, "Precision\n@10/day")]
    ws = [w for w in WORKLOAD_LABEL if w in set(summ["workload"])] if workload is None else [workload]
    fig, axes = plt.subplots(1, len(ws), figsize=(2.6 * len(ws) + 1.6, 4.0), facecolor=SURFACE,
                             constrained_layout=True, sharey=True)
    axes = np.atleast_1d(axes)
    tables = []
    for ax, w in zip(axes, ws):
        _style_ax(ax)
        ranks = {}
        for metric, b, _ in cols:
            d = _pick(summ, workload=w, metric=metric, budget=b, detector=ORDER).set_index("detector")["mean"]
            ranks[metric] = d.rank(ascending=False, method="min")
        for det in ORDER:
            st = STYLE[det]
            ax.plot(range(3), [ranks[m].get(det, np.nan) for m, _, _ in cols], color=st["color"],
                    marker=st["marker"], ls=st["ls"], lw=2, ms=7, mec=SURFACE, mew=1.2, label=st["label"], zorder=3)
        ax.set_xticks(range(3), [c[2] for c in cols], fontsize=8)
        ax.set_xlim(-0.3, 2.3)
        ax.set_title(WORKLOAD_LABEL.get(w, w), fontsize=10, loc="left")
        tables.append(pd.DataFrame({m: ranks[m] for m, _, _ in cols}).reset_index().assign(workload=w))
    axes[0].set_yticks(range(1, 6))
    axes[0].invert_yaxis()
    axes[0].set_ylabel("Rank among 5 detectors (1 = best)")
    _legend(axes[-1], loc="center left", bbox_to_anchor=(1.0, 0.5))
    fig.suptitle("Ranking by the whole ROC curve vs at a fixed budget of 10 alerts/day (means over 5 seeds)",
                 fontsize=10, color=INK, x=0.01, ha="left")
    _save(fig, out_dir / "auc_vs_budget_rank.png", pd.concat(tables))


def plot_auc_vs_dr(summ: pd.DataFrame, out_dir: Path) -> None:
    """AUC (x) against DR@10 (y): similar AUCs can hide very different operating-point performance."""
    ws = [w for w in WORKLOAD_LABEL if w in set(summ["workload"])]
    fig, axes = plt.subplots(1, len(ws), figsize=(2.7 * len(ws) + 1.6, 3.6), facecolor=SURFACE,
                             constrained_layout=True, sharey=True, sharex=True)
    rows = []
    for ax, w in zip(np.atleast_1d(axes), ws):
        _style_ax(ax)
        for det in ORDER:
            a = _pick(summ, workload=w, metric="auc_roc", budget=0, detector=det)["mean"]
            d = _pick(summ, workload=w, metric="dr_at_b", budget=10, detector=det)
            if a.empty or d.empty:
                continue
            st = STYLE[det]
            y, lo, hi = d["mean"].iloc[0], d["ci_lo"].iloc[0], d["ci_hi"].iloc[0]
            ax.errorbar([a.iloc[0]], [y], yerr=[[y - lo], [hi - y]], color=st["color"], marker=st["marker"], ms=8,
                        ls="none", capsize=3, mec=SURFACE, mew=1.2, label=st["label"], zorder=3)
            rows.append(dict(workload=w, detector=det, auc_roc=a.iloc[0], dr_at_10=y, ci_lo=lo, ci_hi=hi))
        ax.set_title(WORKLOAD_LABEL.get(w, w), fontsize=10, loc="left")
        ax.set_xlabel("AUC-ROC (whole curve)", fontsize=8.5)
        ax.set_ylim(0, 1.05)
    np.atleast_1d(axes)[0].set_ylabel("Detection rate @ 10 alerts/day")
    _legend(np.atleast_1d(axes)[-1], loc="center left", bbox_to_anchor=(1.0, 0.5))
    _save(fig, out_dir / "auc_vs_dr10.png", pd.DataFrame(rows))


def plot_per_workload(summ: pd.DataFrame, out_dir: Path) -> None:
    ws = [w for w in WORKLOAD_LABEL if w in set(summ["workload"])]
    fig, axes = _fig(9.0, 4.2, ncols=2, sharey=False)
    for ax, (metric, title) in zip(axes, (("dr_at_b", "Detection rate @ 10"), ("precision_at_b", "Precision @ 10"))):
        d = _pick(summ, metric=metric, budget=10, detector=ORDER)
        for i, det in enumerate(ORDER):
            r = d[d["detector"] == det].set_index("workload").reindex(ws)
            x = np.arange(len(ws)) + (i - 2) * 0.11
            st = STYLE[det]
            lo = np.where(np.isfinite(r["ci_lo"]), r["mean"] - r["ci_lo"], 0)
            hi = np.where(np.isfinite(r["ci_hi"]), r["ci_hi"] - r["mean"], 0)
            ax.errorbar(x, r["mean"], yerr=[lo, hi], color=st["color"], marker=st["marker"], ls="none", ms=8,
                        capsize=3, mec=SURFACE, mew=1.2, label=st["label"], zorder=3)
        ax.set_xticks(range(len(ws)), [WORKLOAD_LABEL[w] for w in ws], fontsize=8.5)
        ax.set_title(title, fontsize=10, loc="left")
        if metric == "dr_at_b":
            ax.set_ylim(0, 1.05)
    axes[0].set_ylabel("mean over seeds, 95% CI")
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="outside lower center", ncol=5, frameon=False, fontsize=8.5, labelcolor=INK2)
    _save(fig, out_dir / "per_workload_dr10.png",
          _pick(summ, metric=["dr_at_b", "precision_at_b"], budget=10, detector=ORDER)[
              ["workload", "detector", "metric", "n_seeds", "mean", "std", "ci_lo", "ci_hi"]])


def plot_campaign(campaign_dir: Path = Path("results/campaign"), sweeps_dir: Path = Path("results/sweeps"),
                  out_dir: Path = Path("figures")) -> None:
    summ = pd.read_csv(campaign_dir / "summary.csv")
    budget_sweep = sweeps_dir / "sweeps_summary.csv"
    if budget_sweep.exists():                          # finer budget axis when the sweep has been run
        sw = pd.read_csv(budget_sweep)
        sw = sw[sw["sweep"] == "budget"].drop(columns=["sweep", "param", "x"]).assign(workload="W1_baseline")
        plot_budget_curves(sw, out_dir)
    else:
        plot_budget_curves(summ, out_dir)
    plot_mttd(summ, out_dir)
    plot_rank_reversal(summ, out_dir)
    plot_auc_vs_dr(summ, out_dir)
    plot_per_workload(summ, out_dir)


# ---------------------------------------------------------------------------
# Ablation
# ---------------------------------------------------------------------------
def plot_ablation(summ: pd.DataFrame, order: list[str], out_dir: Path = Path("figures")) -> None:
    workloads = sorted(summ["workload"].unique())
    fig, axes = _fig(11.0, 6.6, nrows=len(workloads), ncols=2)
    axes = np.atleast_2d(axes)
    for r, w in enumerate(workloads):
        for c, (metric, title) in enumerate((("dr_at_b", "Detection rate @ 10"),
                                             ("precision_at_b", "Precision @ 10"))):
            ax = axes[r, c]
            d = _pick(summ, workload=w, metric=metric, budget=10).set_index("variant").reindex(order)
            y = np.arange(len(order))[::-1]
            colors = [STYLE["isolation_forest"]["color"] if v == "isolation_forest"
                      else STYLE[PROPOSED]["color"] if v.startswith("Full") else "#9a9890" for v in order]
            lo = np.where(np.isfinite(d["ci_lo"]), d["mean"] - d["ci_lo"], 0)
            hi = np.where(np.isfinite(d["ci_hi"]), d["ci_hi"] - d["mean"], 0)
            ax.barh(y, d["mean"], height=0.62, color=colors, zorder=3)
            ax.errorbar(d["mean"], y, xerr=[lo, hi], fmt="none", ecolor=INK, elinewidth=1, capsize=2.5, zorder=4)
            ax.set_yticks(y, ["Isolation Forest" if v == "isolation_forest" else v for v in order], fontsize=8.5)
            ax.set_title(f"{WORKLOAD_LABEL.get(w, w)}: {title}", fontsize=10, loc="left")
            ax.grid(axis="y", visible=False)
            if metric == "dr_at_b":
                ax.set_xlim(0, 1.05)
    fig.suptitle("Ablation: one change at a time from the tuned model (mean over seeds, 95% CI; "
                 "blue = tuned model, orange = Isolation Forest)", fontsize=10, color=INK, x=0.01, ha="left")
    _save(fig, out_dir / "ablation.png", summ[summ["budget"] == 10])


# ---------------------------------------------------------------------------
# Sweeps
# ---------------------------------------------------------------------------
def plot_sweeps(summ: pd.DataFrame, timing_path: Path = Path("results/sweeps/scale_timing.csv"),
                out_dir: Path = Path("figures")) -> None:
    for sweep, xlabel, name in (("suppress", "suppress_days (C4: skip a principal alerted in the last N days)",
                                 "sweep_suppress_days"),
                                ("calfrac", "cal_fraction (share of the fit window used for calibration)",
                                 "sweep_cal_fraction"),
                                ("stealth", "attack magnitude (x the default; lower = stealthier)", "sweep_stealth"),
                                ("principals", "number of principals (identities)", "sweep_principals")):
        d = summ[summ["sweep"] == sweep]
        if d.empty:
            continue
        fig, axes = _fig(9.0, 4.0, ncols=2)
        for ax, (metric, title) in zip(axes, (("dr_at_b", "Detection rate @ 10"), ("precision_at_b", "Precision @ 10"))):
            dm = _pick(d, metric=metric, budget=10)
            for i, det in enumerate(ORDER):
                if det in set(dm["detector"]):
                    _line(ax, dm, "x", det, offset=(i - 2) * (0.02 if sweep == "principals" else 0.004),
                          log=sweep == "principals")
            if sweep == "principals":
                ax.set_xscale("log")
                ax.set_xticks(sorted(dm["x"].unique()), [str(int(v)) for v in sorted(dm["x"].unique())])
                ax.minorticks_off()
            ax.set_xlabel(xlabel, fontsize=8.5)
            ax.set_title(title, fontsize=10, loc="left")
            if metric == "dr_at_b":
                ax.set_ylim(0, 1.05)
        _legend(axes[1], loc="best")
        _save(fig, out_dir / f"{name}.png", d[d["budget"] == 10])

    bud = summ[summ["sweep"] == "budget"]
    if not bud.empty:
        plot_budget_curves(bud.assign(workload="W1_baseline"), out_dir)

    if Path(timing_path).exists():
        t = pd.read_csv(timing_path)
        g = t.groupby(["n_principals", "detector"])["fit_score_seconds"].agg(["mean", "std"]).reset_index()
        fig, ax = _fig(7.0, 4.2)
        for det in ORDER:
            r = g[g["detector"] == det].sort_values("n_principals")
            if r.empty:
                continue
            st = STYLE[det]
            ax.errorbar(r["n_principals"], r["mean"], yerr=r["std"].fillna(0), color=st["color"],
                        marker=st["marker"], ls=st["ls"], lw=2, ms=7, capsize=3, mec=SURFACE, mew=1.2,
                        label=st["label"], zorder=3)
        ax.set_xscale("log")
        ax.set_yscale("log")
        xs = sorted(g["n_principals"].unique())
        ax.set_xticks(xs, [str(int(v)) for v in xs])
        ax.minorticks_off()
        ax.set_xlabel("Number of principals")
        ax.set_ylabel("Fit + score time per window (s, mean +/- std)")
        ax.set_title("Cost vs scale: seconds to fit on train+val and score the test window", fontsize=10, loc="left")
        _legend(ax, loc="upper left")
        _save(fig, out_dir / "runtime_vs_principals.png", g)


if __name__ == "__main__":
    plot_campaign()
