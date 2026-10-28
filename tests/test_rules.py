"""Rule baseline: fixed feature thresholds, severity-then-breadth scoring, abstention."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
import yaml

from cti.detectors.rules import RuleBaselineDetector, load_rules
from cti.explain.explain_proposed import FEATURE_TEXT
from cti.util.config import load_config


def _rows(**cols):
    n = len(next(iter(cols.values())))
    base = {f: np.zeros(n) for f in FEATURE_TEXT}
    base.update({k: np.asarray(v, dtype=float) for k, v in cols.items()})
    return pd.DataFrame({"principal": [f"u{i}" for i in range(n)],
                         "date": pd.Timestamp("2010-06-01"), **base})


def test_every_rule_uses_a_real_feature():
    for r in load_rules("configs/rules.yaml"):
        assert r["feature"] in FEATURE_TEXT, r["id"]


def test_scores_by_severity_then_breadth_and_abstains():
    det = RuleBaselineDetector(load_config(), 0)
    df = _rows(res_leak_site_visits=[1, 0, 0, 0, 0],
               res_usb_after_hours=[0, 1, 1, 0, 0],
               res_usb_first_use=[0, 0, 1, 0, 0],
               res_job_site_visits=[0, 0, 0, 3, 0])
    s = det.fit(df).score(df)
    assert s[4] == 0                                   # nothing fired -> no alert
    assert s[0] > s[2] > s[1] > s[3] > 0               # sev 3 > two sev-2 rules > one sev 2 > sev 1
    fired = det.fired(df)
    assert fired.loc[2, "rules"] == "R2_usb_after_hours,R3_first_usb_use"


def test_missing_feature_or_field_is_rejected(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text(yaml.safe_dump({"rules": [{"id": "X", "feature": "nope", "min": 1, "severity": 1}]}))
    cfg = {**load_config(), "rules_cfg": {"rules_file": str(p)}}
    with pytest.raises(KeyError):
        RuleBaselineDetector(cfg, 0).fit(_rows(vol_events=[1]))
    p.write_text(yaml.safe_dump({"rules": [{"id": "X", "feature": "vol_events"}]}))
    with pytest.raises(ValueError):
        load_rules(p)
