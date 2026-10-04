"""Triage study: generation design invariants and scoring on SYNTHETIC test responses.

These responses exist only inside the test (tmp_path); they are never written to docs/.
"""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from cti.triage.generate_study import SCHEDULE, sample_alerts, write_study
from cti.triage.score_study import balanced_accuracy, cohens_kappa, load, score


def _pool(seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(60):                                  # 60 TP alerts over 5 scenarios, 20 identities
        rows.append(dict(identity_key=f"s0:tp{i % 20}", principal=f"usr-{i % 20:05d}", label=1,
                         scenario_id=f"S{i % 5 + 1}", date=pd.Timestamp("2023-06-01") + pd.Timedelta(days=i),
                         score=float(rng.uniform(3, 6)), rank=int(rng.integers(1, 11)), role="analyst",
                         explanation="Resource access deviation (p = 0.001)", primary_family="resource",
                         n_alerts_that_day=10, source_seed=0))
    for i in range(80):
        rows.append(dict(identity_key=f"s0:fp{i % 40}", principal=f"usr-{100 + i % 40:05d}", label=0,
                         scenario_id="", date=pd.Timestamp("2023-06-01") + pd.Timedelta(days=i % 40),
                         score=float(rng.uniform(2, 5)), rank=int(rng.integers(1, 11)), role="ci-runner",
                         explanation="Timing deviation (p = 0.01)", primary_family="temporal",
                         n_alerts_that_day=10, source_seed=0))
    return pd.DataFrame(rows)


@pytest.fixture()
def study(tmp_path):
    s = sample_alerts(_pool())
    write_study(s, {"test": True}, tmp_path)
    return s, tmp_path


def test_design_invariants(study):
    s, path = study
    assert len(s) == 40 and s["label"].sum() == 20
    assert (s.groupby(["half", "label"]).size() == 10).all()
    assert s.groupby("identity_key").size().max() <= 2
    assert set(s.loc[s["label"] == 1, "scenario_id"]) == {"S1", "S2", "S3", "S4", "S5"}
    resp = pd.concat(pd.read_csv(f) for f in path.glob("responses_R*.csv"))
    per = resp.groupby(["alert_id", "arm"])["reviewer"].nunique().unstack()
    assert (per["A"] == 2).all() and (per["B"] == 2).all()
    assert not resp.duplicated(["reviewer", "alert_id"]).any()
    assert set(SCHEDULE) == set(resp["reviewer"])


def test_packets_are_blind(study):
    _, path = study
    for f in path.glob("packet_*.md"):
        text = f.read_text(encoding="utf-8")
        assert "usr-" not in text and "label" not in text.lower()
        assert "Anomaly score" in text and "deviation" in text      # both arms present
    assert (path / "_facilitator_only" / "answer_key.csv").exists()


def _fill(path, rule):
    key = pd.read_csv(path / "_facilitator_only" / "answer_key.csv").set_index("alert_id")["label"]
    for f in path.glob("responses_R*.csv"):
        r = pd.read_csv(f)
        r["verdict"] = [rule(arm, key[a]) for arm, a in zip(r["arm"], r["alert_id"])]
        r["confidence_1to5"], r["seconds_spent"] = 3, 30
        r.to_csv(f, index=False)


def test_scoring_perfect_explanations_vs_coin_flip_score(study):
    _, path = study
    rng = np.random.default_rng(1)
    _fill(path, lambda arm, y: ("TP" if y else "FP") if arm == "B" else rng.choice(["TP", "FP"]))
    res = score(*load(path))
    assert res["arms"]["B"]["balanced_accuracy"] == 1.0
    assert 0.2 < res["arms"]["A"]["balanced_accuracy"] < 0.8
    assert res["h3"]["effect_ba_B_minus_A"] > 0.2
    assert res["n_responses_usable"] == 160 and not res["problems"]


def test_scoring_no_difference_is_not_supported(study):
    _, path = study
    _fill(path, lambda arm, y: "TP" if y else "FP")
    res = score(*load(path))
    assert res["h3"]["effect_ba_B_minus_A"] == 0.0
    assert res["h3"]["verdict"] == "NOT SUPPORTED"
    assert all(k["kappa"] == 1.0 for k in res["kappa"])


def test_blank_sheets_are_reported_not_imputed(study):
    _, path = study
    res = score(*load(path))                              # untouched templates: every verdict missing
    assert res["n_responses_usable"] == 0
    assert len(res["problems"]) == 160


def test_metric_helpers():
    y = np.array([1, 1, 0, 0])
    assert balanced_accuracy(y, np.array([1, 0, 0, 0])) == 0.75
    assert cohens_kappa(np.array([1, 0, 1, 0]), np.array([1, 0, 1, 0])) == 1.0


def test_alert_codes_do_not_depend_on_python_hash_seed():
    """Regression: codes were once drawn via a set, whose order changes between processes."""
    import os
    import subprocess
    import sys
    code = ("import numpy as np; from cti.triage.generate_study import _codes; "
            "print(_codes(40, np.random.default_rng(2026)))")
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           env={**os.environ, "PYTHONHASHSEED": str(h)}).stdout for h in (1, 2, 3)}
    assert len(outs) == 1 and len(next(iter(outs))) > 10
