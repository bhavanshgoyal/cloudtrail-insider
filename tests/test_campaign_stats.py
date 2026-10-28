"""Campaign statistics on one fixed dataset: insider / day bootstrap and verdicts."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import numpy as np
import pandas as pd

SPEC = importlib.util.spec_from_file_location("run_campaign", Path("scripts/run_campaign.py"))
rc = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rc)


def _tables(p_detect_prop: float, p_detect_base: float, n_ins: int = 60, n_days: int = 100):
    rng = np.random.default_rng(1)
    ins, days = [], []
    for det, p, tpd in ((rc.PROPOSED, p_detect_prop, 4), (rc.BASELINE, p_detect_base, 1)):
        hit = rng.random(n_ins) < p
        for origin in (0, 1):                               # same insider in two overlapping origins
            ins.append(pd.DataFrame({"detector": det, "budget": 10, "principal": [f"u{i}" for i in range(n_ins)],
                                     "scenario_id": "S1", "detected": hit,
                                     "ttd_hours": np.where(hit, 10.0 if det == rc.PROPOSED else 40.0, np.nan),
                                     "origin": origin}))
        days.append(pd.DataFrame({"detector": det, "budget": 10, "date": pd.date_range("2010-06-01", periods=n_days),
                                  "day_tp": rng.binomial(10, tpd / 10, n_days), "day_n": 10}))
    return pd.concat(ins, ignore_index=True), pd.concat(days, ignore_index=True)


def test_clear_win_is_supported():
    ins, days = _tables(0.9, 0.3)
    h = rc.hypotheses(ins, days, "CERT_r4.2").set_index("hypothesis")
    assert (h["verdict"] == "SUPPORTED").all(), h
    assert h.loc["H1a", "ci_unit"] == "insiders (n=60)"     # each insider counted once, not per origin


def test_tie_is_not_supported():
    ins, days = _tables(0.5, 0.5)
    ins.loc[ins.detector == rc.PROPOSED, "ttd_hours"] = ins.loc[ins.detector == rc.BASELINE, "ttd_hours"].to_numpy()
    days.loc[days.detector == rc.PROPOSED, "day_tp"] = days.loc[days.detector == rc.BASELINE, "day_tp"].to_numpy()
    h = rc.hypotheses(ins, days, "CERT_r4.2")
    assert (h["verdict"] == "NOT SUPPORTED").all(), h
