"""
cti.util.splits
---------------
Causal, relative-day temporal splits with rolling origins.

Layout for origin *k* (0 .. n_origins-1), over the *usable* days
(everything after ``warmup_days``)::

    | warmup | ------ train ------ | val | ---- test ---- |
                                                    ^ test_end(k)

The test window length is ``round(test_frac * n_usable)``; origins shift the
whole window back by ``test_len // n_origins`` days, so the last origin ends
at the final day of the data. Train is an expanding window ending where val
begins. Windows never overlap each other within one origin.

Every window is validated: an empty or too-short window raises
``ValueError``. There is deliberately **no fallback** to "use everything".
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class Split:
    origin: int
    train_days: np.ndarray   # datetime64[ns], sorted
    val_days: np.ndarray
    test_days: np.ndarray

    def mask(self, dates: pd.Series | np.ndarray, which: str) -> np.ndarray:
        """Boolean mask over ``dates`` selecting rows inside window ``which``."""
        days = {"train": self.train_days, "val": self.val_days, "test": self.test_days}[which]
        return np.isin(pd.to_datetime(np.asarray(dates)).to_numpy(dtype="datetime64[ns]"), days)

    def select(self, df: pd.DataFrame, which: str, date_col: str = "date") -> pd.DataFrame:
        """Rows of ``df`` inside window ``which`` (index reset)."""
        return df.loc[self.mask(df[date_col], which)].reset_index(drop=True)

    def describe(self) -> str:
        def rng(a: np.ndarray) -> str:
            return f"{str(a[0])[:10]}..{str(a[-1])[:10]} ({len(a)}d)"
        return (f"origin {self.origin}: train {rng(self.train_days)} | "
                f"val {rng(self.val_days)} | test {rng(self.test_days)}")


def n_origins(cfg: dict) -> int:
    return int(cfg["splits"]["n_origins"])


def make_splits(dates, cfg: dict, origin_idx: int | None = None) -> Split:
    """Build the split for one rolling origin.

    Parameters
    ----------
    dates:
        Any iterable of dates covering the dataset (duplicates are fine).
    cfg:
        Project config (``warmup_days`` and the ``splits`` block are used).
    origin_idx:
        ``0 .. n_origins-1``; ``None`` selects the last origin (test window
        ends on the final day of the data).
    """
    sc = cfg["splits"]
    all_days = np.sort(pd.to_datetime(pd.Series(np.asarray(dates)).drop_duplicates()).to_numpy(
        dtype="datetime64[ns]"))
    warmup = int(cfg["warmup_days"])
    usable = all_days[warmup:]
    n = len(usable)
    n_orig = int(sc["n_origins"])
    k = (n_orig - 1) if origin_idx is None else int(origin_idx)
    if not 0 <= k < n_orig:
        raise ValueError(f"origin_idx must be in [0, {n_orig - 1}], got {k}")

    test_len = int(round(float(sc["test_frac"]) * n))
    val_len = int(round(float(sc["val_frac"]) * n))
    shift = max(1, test_len // n_orig)
    test_end = n - (n_orig - 1 - k) * shift
    test_start = test_end - test_len
    val_start = test_start - val_len
    min_train = int(sc["min_train_days"])

    if test_len < 1 or val_len < 1:
        raise ValueError(f"test/val window empty: {n} usable days, test_len={test_len}, val_len={val_len}")
    if val_start < min_train:
        raise ValueError(
            f"train window too short for origin {k}: {val_start} days < min_train_days={min_train} "
            f"({n} usable days after {warmup} warmup days)")

    return Split(
        origin=k,
        train_days=usable[:val_start],
        val_days=usable[val_start:test_start],
        test_days=usable[test_start:test_end],
    )


def all_splits(dates, cfg: dict) -> list[Split]:
    return [make_splits(dates, cfg, k) for k in range(int(cfg["splits"]["n_origins"]))]


def tuning_splits(dates, cfg: dict) -> list[Split]:
    """Rolling splits inside the development period, for model selection only.

    On one fixed dataset the evaluation origins overlap (origin 0's test days
    are origin 1's and 2's validation days), so their validation windows cannot
    be used to choose settings. The development period is every day before the
    earliest test day of any evaluation origin; these splits re-apply the same
    layout inside it. Their ``val`` windows never contain an evaluation test day.
    """
    all_days = pd.to_datetime(pd.Series(np.asarray(dates)).drop_duplicates())
    first_test = min(s.test_days[0] for s in all_splits(all_days, cfg))
    dev = all_days[all_days < first_test]
    splits = all_splits(dev, cfg)
    assert all(s.val_days[-1] < first_test for s in splits)
    return splits


def assert_test_positives(split: Split, ground_truth: list[dict], cfg: dict) -> int:
    """Number of insiders with >=1 malicious day in the test window; raises if too few."""
    test = set(pd.to_datetime(split.test_days).strftime("%Y-%m-%d"))
    n = sum(1 for g in ground_truth if test.intersection(g["malicious_days"]))
    need = int(cfg["splits"]["min_test_insiders"])
    if n < need:
        raise ValueError(f"origin {split.origin}: only {n} insiders in test window, need >= {need}")
    return n
