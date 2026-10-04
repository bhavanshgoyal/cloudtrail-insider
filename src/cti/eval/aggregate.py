"""Shared aggregation helpers: per-seed means, t-intervals, long-format summaries."""
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
