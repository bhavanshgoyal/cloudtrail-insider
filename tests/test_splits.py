"""Temporal split helper: ordering, non-overlap, no empty windows, no fallback."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from cti.util.config import load_config
from cti.util.splits import all_splits, assert_test_positives, make_splits, tuning_splits


@pytest.fixture()
def cfg():
    return load_config()


def _dates(n=180):
    return pd.date_range("2023-01-01", periods=n, freq="D")


def test_windows_are_ordered_and_disjoint(cfg):
    for sp in all_splits(_dates(), cfg):
        assert sp.train_days.max() < sp.val_days.min()
        assert sp.val_days.max() < sp.test_days.min()
        assert len(set(sp.train_days) & set(sp.val_days) & set(sp.test_days)) == 0
        assert len(sp.train_days) >= cfg["splits"]["min_train_days"]


def test_warmup_days_are_never_used(cfg):
    dates = _dates()
    first_usable = dates[cfg["warmup_days"]]
    for sp in all_splits(dates, cfg):
        assert pd.Timestamp(sp.train_days.min()) == first_usable


def test_last_origin_ends_on_last_day(cfg):
    dates = _dates()
    assert pd.Timestamp(make_splits(dates, cfg).test_days.max()) == dates[-1]


def test_origins_shift_the_test_window(cfg):
    starts = [make_splits(_dates(), cfg, k).test_days.min() for k in range(cfg["splits"]["n_origins"])]
    assert starts == sorted(starts) and len(set(starts)) == len(starts)


def test_too_short_data_raises_instead_of_falling_back(cfg):
    with pytest.raises(ValueError):
        make_splits(_dates(40), cfg)


def test_bad_origin_raises(cfg):
    with pytest.raises(ValueError):
        make_splits(_dates(), cfg, origin_idx=99)


def test_mask_and_select(cfg):
    dates = _dates()
    sp = make_splits(dates, cfg, 0)
    df = pd.DataFrame({"date": np.tile(dates, 2), "x": 1})
    assert len(sp.select(df, "test")) == 2 * len(sp.test_days)
    assert sp.mask(df["date"], "train").sum() == 2 * len(sp.train_days)


def test_assert_test_positives_raises_when_too_few(cfg):
    sp = make_splits(_dates(), cfg)
    gt = [{"malicious_days": [str(pd.Timestamp(sp.test_days[0]).date())]}]
    with pytest.raises(ValueError):
        assert_test_positives(sp, gt, cfg)


def test_tuning_windows_never_touch_any_test_day(cfg):
    dates = _dates(500)                                     # CERT r4.2 spans ~500 days
    test_days = set().union(*(set(s.test_days) for s in all_splits(dates, cfg)))
    tune = tuning_splits(dates, cfg)
    assert len(tune) == cfg["splits"]["n_origins"]
    for sp in tune:
        assert not (set(sp.val_days) | set(sp.train_days)) & test_days
