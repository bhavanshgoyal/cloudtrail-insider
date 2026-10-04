"""Per-day budget evaluator: hand-computed DR, precision and MTTD on a toy fixture."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from cti.eval.evaluate import (build_context, compare, curve_metrics, emit_alerts, evaluate_alerts,
                               evaluate_window)
from cti.util.config import load_config

D1, D2, D3 = pd.Timestamp("2023-03-01"), pd.Timestamp("2023-03-02"), pd.Timestamp("2023-03-03")

# Insider X: malicious on D2 only, first event D2 03:00.
# Insider Y: malicious D1..D3, first event D1 10:00.
GT = [
    {"principal_id": "X", "scenario_id": "S1", "first_event_time": "2023-03-02T03:00:00+00:00",
     "malicious_days": ["2023-03-02"]},
    {"principal_id": "Y", "scenario_id": "S2", "first_event_time": "2023-03-01T10:00:00+00:00",
     "malicious_days": ["2023-03-01", "2023-03-02", "2023-03-03"]},
]
SCORES = pd.DataFrame([
    ("A", D1, 0.9), ("Y", D1, 0.5), ("X", D1, 0.1),
    ("X", D2, 0.8), ("Y", D2, 0.7), ("A", D2, 0.2),
    ("Y", D3, 0.9), ("A", D3, 0.1),
], columns=["principal", "date", "score"])
LABELS = SCORES[["principal", "date"]].assign(
    label=[0, 1, 0, 1, 1, 0, 1, 0])


@pytest.fixture()
def cfg():
    c = load_config()
    c = {**c, "eval": {**c["eval"], "bootstrap_iterations": 500}}
    return c


def _ctx(days=(D1, D2, D3)):
    return build_context(SCORES, LABELS, GT, list(days))


def test_budget_one_hand_computed():
    r = evaluate_alerts(emit_alerts(SCORES, 1), _ctx(), 1)
    # alerts: D1 A (FP), D2 X (TP), D3 Y (TP)
    assert r.point["precision_at_b"] == pytest.approx(2 / 3)
    assert r.point["dr_at_b"] == 1.0
    # X: alert D2 -> available D3 00:00, onset D2 03:00 -> 21h. Y: first TP alert D3 -> D4 00:00 - D1 10:00 = 62h
    assert sorted(r.ttd_hours) == pytest.approx([21.0, 62.0])
    assert r.point["mttd_hours_median"] == pytest.approx(41.5)
    assert r.point["alerts_per_day"] == 1.0


def test_budget_two_hand_computed():
    r = evaluate_alerts(emit_alerts(SCORES, 2), _ctx(), 2)
    # D1: A, Y(TP)   D2: X(TP), Y(TP)   D3: Y(TP), A
    assert r.point["precision_at_b"] == pytest.approx(4 / 6)
    assert r.point["dr_at_b"] == 1.0
    assert sorted(r.ttd_hours) == pytest.approx([14.0, 21.0])   # Y caught on D1 now
    assert r.point["precision_day_mean"] == pytest.approx((0.5 + 1.0 + 0.5) / 3)


def test_onset_clipped_to_window_start():
    # window D2..D3: Y's attack began before the window, so its onset is D2 00:00
    ctx = _ctx((D2, D3))
    y = ctx.insiders.set_index("principal").loc["Y"]
    assert y["onset"] == D2
    r = evaluate_alerts(emit_alerts(SCORES[SCORES["date"] >= D2], 1), ctx, 1)
    assert sorted(r.ttd_hours) == pytest.approx([21.0, 48.0])  # Y alerted D3 -> D4 00:00 - D2 00:00


def test_detection_rate_counts_insiders_not_rows():
    s = SCORES.copy()
    s.loc[s["principal"] == "Y", "score"] = 0.0          # Y never reaches the top
    r = evaluate_alerts(emit_alerts(s, 1), _ctx(), 1)
    assert r.point["dr_at_b"] == 0.5
    assert r.point["n_detected"] == 1 and r.point["n_insiders"] == 2


def test_insider_outside_window_is_not_counted():
    ctx = _ctx((D3,))
    assert list(ctx.insiders["principal"]) == ["Y"]


def test_nan_means_no_alert():
    s = SCORES.copy()
    s["score"] = np.where(s["principal"] == "A", np.nan, s["score"])
    alerts = emit_alerts(s, 2)
    assert "A" not in set(alerts["principal"])
    r = evaluate_alerts(alerts, _ctx(), 2)
    assert r.point["alerts_per_day"] == pytest.approx((2 + 2 + 1) / 3)
    assert r.point["precision_at_b"] == pytest.approx(4 / 5)  # D1: Y(TP), X(FP); D2: X, Y; D3: Y


def test_ties_are_seeded_random_not_row_order():
    s = pd.DataFrame({"principal": list("ABCDEFGH"), "date": D1, "score": 1.0})
    picks = {tuple(emit_alerts(s, 1, seed=k)["principal"]) for k in range(20)}
    assert len(picks) > 1                                 # not always the first row
    assert emit_alerts(s, 3, seed=7).equals(emit_alerts(s, 3, seed=7))


def test_suppression_skips_recently_alerted_principal():
    s = pd.DataFrame([("P", d, 1.0) for d in (D1, D2, D3)] + [("Q", d, 0.5) for d in (D1, D2, D3)],
                     columns=["principal", "date", "score"])
    plain = emit_alerts(s, 1)
    assert list(plain["principal"]) == ["P", "P", "P"]
    sup = emit_alerts(s, 1, suppress_days=1)
    assert list(sup["principal"]) == ["P", "Q", "P"]      # D3 - D1 = 2 days > 1
    sup2 = emit_alerts(s, 1, suppress_days=2)
    # D3: P was alerted 2 days ago and Q 1 day ago, both within 2 days -> no alert that day
    assert list(sup2["principal"]) == ["P", "Q"]


def test_curve_metrics_reference():
    m = curve_metrics(SCORES, _ctx())
    assert 0.0 <= m["auc_roc"] <= 1.0 and 0.0 <= m["pr_auc"] <= 1.0


def test_evaluate_window_tidy_and_cis(cfg):
    tidy, res = evaluate_window({"det": SCORES}, _ctx(), cfg, budgets=[1, 2])
    assert set(tidy.columns) == {"detector", "budget", "metric", "value", "ci_lo", "ci_hi", "ci_method"}
    p1 = tidy[(tidy.budget == 1) & (tidy.metric == "precision_at_b")].iloc[0]
    assert p1["value"] == pytest.approx(2 / 3)
    assert p1["ci_lo"] <= p1["value"] <= p1["ci_hi"]
    assert set(res["det"]) == {1, 2}


def test_compare_identical_is_zero_and_zero_baseline_is_absolute(cfg):
    ctx = _ctx()
    a = evaluate_alerts(emit_alerts(SCORES, 1), ctx, 1)
    rows = {r["metric"]: r for r in compare(a, a, cfg)}
    assert rows["dr_at_b"]["value"] == 0.0 and rows["dr_at_b"]["kind"] == "relative"
    zero = SCORES.assign(score=np.where(SCORES["principal"] == "A", 1.0, 0.0))
    b = evaluate_alerts(emit_alerts(zero, 1), ctx, 1)
    rows = {r["metric"]: r for r in compare(a, b, cfg)}
    assert rows["dr_at_b"]["kind"].startswith("absolute")
    assert rows["dr_at_b"]["value"] == 1.0
