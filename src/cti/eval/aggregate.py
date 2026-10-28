"""Shared aggregation helpers: per-seed means, t-intervals, long-format summaries, and the
insider / day bootstrap used on one fixed dataset (CERT), where seeds are not independent."""
from __future__ import annotations

import numpy as np
import pandas as pd
from scipy import stats


def t_interval(x, conf: float = 0.95) -> tuple[float, float]:
    """Two-sided t confidence interval of the mean; (nan, nan) if fewer than 2 finite values."""
    x = np.asarray(x, dtype=float)
    x = x[np.isfinite(x)]
    if len(x) < 2:
        return np.nan, np.nan
    half = stats.t.ppf(0.5 + conf / 2, len(x) - 1) * x.std(ddof=1) / np.sqrt(len(x))
    return float(x.mean() - half), float(x.mean() + half)


# Metrics bounded to [0, 1]: their t-intervals are clipped to that range (with n = 3-5 seeds a
# symmetric interval can otherwise extend below 0, which is not a possible value).
BOUNDED = {"dr_at_b", "precision_at_b", "precision_oracle_at_b", "precision_day_mean", "auc_roc", "pr_auc"}


def clip_bounded(lo: float, hi: float, metric) -> tuple[float, float]:
    if metric in BOUNDED:
        return (max(0.0, lo) if np.isfinite(lo) else lo, min(1.0, hi) if np.isfinite(hi) else hi)
    return lo, hi


def summarise(df: pd.DataFrame, keys: list[str], value: str = "value",
              replicate: str = "seed", within: str | None = "origin") -> pd.DataFrame:
    """Mean / std / 95% t-CI over independent replicates (seeds).

    Rows that differ only in ``within`` (rolling origins of one seed overlap in time) are
    averaged first, so ``n_seeds`` is the number of independent datasets.
    """
    d = df.groupby(keys + [replicate])[value].mean().reset_index() if within else df
    rows = []
    for key, g in d.groupby(keys):
        x = g[value].to_numpy(dtype=float)
        lo, hi = t_interval(x)
        key = key if isinstance(key, tuple) else (key,)
        if "metric" in keys:
            lo, hi = clip_bounded(lo, hi, key[keys.index("metric")])
        rows.append({**dict(zip(keys, key)), "n_seeds": int(np.isfinite(x).sum()),
                     "mean": float(np.nanmean(x)),
                     "std": float(np.nanstd(x, ddof=1)) if np.isfinite(x).sum() > 1 else np.nan,
                     "ci_lo": lo, "ci_hi": hi})
    return pd.DataFrame(rows)


# ---------------------------------------------------------------------------
# One fixed dataset: pool each insider / day over the runs covering it, bootstrap those units
# ---------------------------------------------------------------------------
N_BOOT = 10_000


def insider_matrix(ins: pd.DataFrame, budget: int, value: str, col: str = "detector") -> pd.DataFrame:
    """principal x ``col``: mean of ``value`` over the runs whose test window contains the insider."""
    d = ins[ins["budget"] == budget]
    return d.pivot_table(index="principal", columns=col, values=value, aggfunc="mean")


def day_matrices(days: pd.DataFrame, budget: int, col: str = "detector") -> tuple[pd.DataFrame, pd.DataFrame]:
    """date x ``col``: true alerts and alerts per test day, averaged over the runs covering it."""
    d = days[days["budget"] == budget]
    tp = d.pivot_table(index="date", columns=col, values="day_tp", aggfunc="mean")
    n = d.pivot_table(index="date", columns=col, values="day_n", aggfunc="mean")
    return tp, n


def boot_idx(k: int, seed: int = 0, n_boot: int = N_BOOT) -> np.ndarray:
    return np.random.default_rng(seed).integers(0, k, size=(n_boot, k))


def percentile_ci(boots: np.ndarray) -> tuple[float, float]:
    boots = np.asarray(boots, dtype=float)
    boots = boots[np.isfinite(boots)]
    if len(boots) == 0:
        return np.nan, np.nan
    return float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))


def ratio_of_sums(tp: np.ndarray, n: np.ndarray) -> float:
    s = n.sum()
    return float(tp.sum() / s) if s > 0 else np.nan


def pooled_rates(ins: pd.DataFrame, days: pd.DataFrame, col: str = "detector") -> pd.DataFrame:
    """Per (``col``, budget): pooled DR (bootstrap over insiders) and precision (over days)."""
    rows = []
    for b in sorted(ins["budget"].unique()):
        det = insider_matrix(ins, b, "detected", col)
        idx = boot_idx(len(det))
        for c in det.columns:
            v = det[c].to_numpy(dtype=float)
            lo, hi = clip_bounded(*percentile_ci(v[idx].mean(axis=1)), "dr_at_b")
            rows.append({col: c, "budget": b, "metric": "dr_at_b", "mean": float(v.mean()),
                         "ci_lo": lo, "ci_hi": hi, "ci_unit": f"insiders (n={len(v)})"})
        tp, n = day_matrices(days, b, col)
        idx = boot_idx(len(tp))
        for c in tp.columns:
            t, k = tp[c].to_numpy(dtype=float), n[c].to_numpy(dtype=float)
            sk = k[idx].sum(axis=1)
            boots = t[idx].sum(axis=1) / np.where(sk > 0, sk, np.nan)
            lo, hi = clip_bounded(*percentile_ci(boots), "precision_at_b")
            rows.append({col: c, "budget": b, "metric": "precision_at_b", "mean": ratio_of_sums(t, k),
                         "ci_lo": lo, "ci_hi": hi, "ci_unit": f"days (n={len(t)})"})
    return pd.DataFrame(rows)
