"""Rule baseline: every rule fires on a hand-built positive and stays quiet on a benign twin."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from cti.detectors.rules import PREDICATES, RuleBaselineDetector, RuleEngine, load_rules
from cti.util.config import load_config

DAY0 = pd.Timestamp("2023-02-01", tz="UTC")


def _ev(principal, name, minute=0, day=0, **kw):
    row = dict(principalId=principal, eventName=name, eventTime=DAY0 + pd.Timedelta(days=day, minutes=minute),
               sourceIp="10.0.0.1", errorCode=None, mfaUsed=-1, requestParameters="", roleName="analyst")
    row.update(kw)
    return row


def _build():
    rows = []
    # R001
    rows.append(_ev("root", "GetObject"))
    # R002: no-MFA success fires; MFA login, and failed no-MFA login, do not
    rows.append(_ev("r2_pos", "ConsoleLogin", mfaUsed=0))
    rows.append(_ev("r2_neg", "ConsoleLogin", mfaUsed=1))
    rows.append(_ev("r2_fail", "ConsoleLogin", mfaUsed=0, errorCode="Failure"))
    # R003: 5 failures then success fires; 4 failures then success does not
    for i in range(5):
        rows.append(_ev("r3_pos", "ConsoleLogin", minute=i, errorCode="Failure", mfaUsed=1))
    rows.append(_ev("r3_pos", "ConsoleLogin", minute=6, mfaUsed=1))
    for i in range(4):
        rows.append(_ev("r3_neg", "ConsoleLogin", minute=i, errorCode="Failure", mfaUsed=1))
    rows.append(_ev("r3_neg", "ConsoleLogin", minute=6, mfaUsed=1))
    # R004
    rows.append(_ev("r4_pos", "GetObject", sourceIp="203.0.113.7"))
    rows.append(_ev("r4_neg", "GetObject", sourceIp="10.1.2.3"))
    # R005
    rows.append(_ev("r5_pos", "ModifySnapshotAttribute", requestParameters='{"userGroups":["all"]}'))
    rows.append(_ev("r5_neg", "ModifySnapshotAttribute", requestParameters='{"userIds":["210987654321"]}'))
    # R006
    rows.append(_ev("r6_pos", "CreateAccessKey", requestParameters='{"userName":"other"}'))
    rows.append(_ev("r6_neg", "CreateAccessKey", requestParameters='{"userName":"self"}'))
    # R007
    rows.append(_ev("r7_pos", "AssumeRole", requestParameters='{"roleName":"admin"}', roleName="developer"))
    rows.append(_ev("r7_admin", "AssumeRole", requestParameters='{"roleName":"admin"}', roleName="admin"))
    rows.append(_ev("r7_ro", "AssumeRole", requestParameters='{"roleName":"readonly"}', roleName="developer"))
    # R008: threshold 35, service accounts exempt
    for i in range(35):
        rows.append(_ev("r8_pos", "GetObject", minute=i))
    for i in range(34):
        rows.append(_ev("r8_neg", "GetObject", minute=i))
    for i in range(300):
        rows.append(_ev("r8_svc", "GetObject", minute=i % 600, roleName="backup-service"))
    # R009
    rows.append(_ev("r9_pos", "StopLogging"))
    rows.append(_ev("r9_neg", "DescribeInstances"))
    # R010
    rows.append(_ev("r10_pos", "SendEmail", requestParameters='{"destinations":["external"]}'))
    rows.append(_ev("r10_neg", "SendEmail", requestParameters='{"destinations":["internal"]}'))
    # R011: a login from an IP the principal has used before does not fire; first use does
    rows.append(_ev("r11_pos", "ConsoleLogin", day=0, sourceIp="10.9.9.1", mfaUsed=1))
    rows.append(_ev("r11_pos", "ConsoleLogin", day=1, sourceIp="10.9.9.2", mfaUsed=1))
    rows.append(_ev("r11_neg", "ConsoleLogin", day=0, sourceIp="10.9.9.1", mfaUsed=1))
    rows.append(_ev("r11_neg", "ConsoleLogin", day=1, sourceIp="10.9.9.1", mfaUsed=1))
    # R012: 20 AccessDenied fires, 19 does not
    for i in range(20):
        rows.append(_ev("r12_pos", "GetObject", minute=i, errorCode="AccessDenied"))
    for i in range(19):
        rows.append(_ev("r12_neg", "GetObject", minute=i, errorCode="AccessDenied"))
    return pd.DataFrame(rows)


@pytest.fixture(scope="module")
def fired():
    events = _build()
    res = RuleEngine.from_file("configs/rules.yaml").evaluate(events)
    out: dict[str, dict[str, set[str]]] = {}
    for _, r in res.iterrows():
        out.setdefault(r["principal"], {}).setdefault(str(r["date"].date()), set()).update(r["rules"].split(","))
    return out


def _rules(fired, principal, day="2023-02-01"):
    return fired.get(principal, {}).get(day, set())


@pytest.mark.parametrize("pos,neg,rule", [
    ("root", None, "R001"),
    ("r2_pos", "r2_neg", "R002"),
    ("r3_pos", "r3_neg", "R003"),
    ("r4_pos", "r4_neg", "R004"),
    ("r5_pos", "r5_neg", "R005"),
    ("r6_pos", "r6_neg", "R006"),
    ("r7_pos", "r7_admin", "R007"),
    ("r8_pos", "r8_neg", "R008"),
    ("r9_pos", "r9_neg", "R009"),
    ("r10_pos", "r10_neg", "R010"),
    ("r12_pos", "r12_neg", "R012"),
])
def test_rule_fires_on_positive_not_on_benign(fired, pos, neg, rule):
    assert rule in _rules(fired, pos)
    if neg:
        assert rule not in _rules(fired, neg)


def test_extra_negative_cases(fired):
    assert "R002" not in _rules(fired, "r2_fail")           # failed login is not "without MFA"
    assert "R007" not in _rules(fired, "r7_ro")             # non-admin role
    assert "R008" not in _rules(fired, "r8_svc")            # service accounts exempt


def test_new_ip_rule_is_causal_and_stateful(fired):
    assert "R011" in _rules(fired, "r11_pos", "2023-02-02")        # first use of 10.9.9.2
    assert "R011" not in _rules(fired, "r11_neg", "2023-02-02")    # IP seen on day 0 already


def test_every_rule_has_a_predicate_and_is_covered():
    rules, _ = load_rules("configs/rules.yaml")
    assert {r["predicate"] for r in rules} <= set(PREDICATES)
    assert len(rules) == 12


def test_unknown_predicate_is_rejected(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("rules:\n  - {id: X1, predicate: eval_this, severity: 1}\n")
    with pytest.raises(ValueError):
        load_rules(bad)


def test_detector_scores_by_severity_then_breadth():
    events = _build()
    cfg = load_config()
    det = RuleBaselineDetector(cfg, 0)
    feat = (events.assign(principal=events["principalId"], date=events["eventTime"].dt.tz_localize(None).dt.floor("D"))
            [["principal", "date"]].drop_duplicates().reset_index(drop=True))
    score = pd.Series(det.score(feat, events), index=feat["principal"] + "|" + feat["date"].astype(str))
    assert score["root|2023-02-01"] >= 5.0                     # severity-5 rule
    assert score["r9_pos|2023-02-01"] >= 5.0
    assert score["r9_neg|2023-02-01"] == 0.0 or score["r9_neg|2023-02-01"] < 2
    assert score["r5_pos|2023-02-01"] > score["r10_pos|2023-02-01"]
    assert np.isfinite(score.to_numpy()).all()


def test_rule_detector_requires_events():
    det = RuleBaselineDetector(load_config(), 0)
    with pytest.raises(ValueError):
        det.score(pd.DataFrame({"principal": ["a"], "date": [pd.Timestamp("2023-02-01")]}), None)
