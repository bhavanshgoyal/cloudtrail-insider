"""Aggregation over seeds and figure smoke tests."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from scipy import stats

from cti.eval.aggregate import summarise, t_interval
from cti.eval.figures import ORDER, STYLE, plot_budget_curves, plot_rank_reversal


def test_t_interval_matches_scipy():
    x = np.array([0.8, 0.9, 1.0, 0.7, 0.85])
    lo, hi = t_interval(x)
    ref = stats.t.interval(0.95, 4, loc=x.mean(), scale=stats.sem(x))
    assert (lo, hi) == pytest.approx(ref)
    assert np.isnan(t_interval([1.0])[0])


def test_summarise_averages_origins_within_a_seed_first():
    df = pd.DataFrame({"det": "a", "seed": [0, 0, 0, 1, 1, 1], "origin": [0, 1, 2] * 2,
                       "value": [0.0, 0.3, 0.6, 1.0, 1.0, 1.0]})
    s = summarise(df, ["det"]).iloc[0]
    assert s["n_seeds"] == 2                          # origins are NOT independent replicates
    assert s["mean"] == pytest.approx((0.3 + 1.0) / 2)


def test_every_detector_has_a_distinct_style():
    assert len({STYLE[d]["color"] for d in ORDER}) == len(ORDER)
    assert len({STYLE[d]["marker"] for d in ORDER}) == len(ORDER)


def _fake_summary():
    rows = []
    rng = np.random.default_rng(0)
    for det in ORDER:
        for b in (10, 50, 100):
            for metric in ("dr_at_b", "precision_at_b", "precision_oracle_at_b", "auc_roc", "mttd_hours_median"):
                m = float(rng.uniform(0.1, 0.9))
                rows.append(dict(workload="W1_baseline", detector=det, budget=0 if metric == "auc_roc" else b,
                                 metric=metric, n_seeds=5, mean=m, std=0.05, ci_lo=m - 0.05, ci_hi=m + 0.05))
    return pd.DataFrame(rows).drop_duplicates(subset=["workload", "detector", "budget", "metric"])


def test_budget_and_rank_figures_are_written(tmp_path):
    summ = _fake_summary()
    plot_budget_curves(summ, tmp_path)
    plot_rank_reversal(summ, tmp_path)
    for name in ("dr_vs_budget", "precision_vs_budget", "auc_vs_budget_rank"):
        assert (tmp_path / f"{name}.png").stat().st_size > 5000
        assert (tmp_path / f"{name}.csv").exists()          # table view alongside every figure
