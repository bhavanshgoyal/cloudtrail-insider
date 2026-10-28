"""Proposed detector: conformal p-values, fusion, per-principal behaviour, explanations."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from cti.detectors.proposed import BudgetAwareConformal, conformal_pvalues, fuse
from cti.explain.explain_proposed import FEATURE_TEXT, explain_alerts, render
from cti.features.pipeline import FAMILY_PREFIXES
from cti.util.config import load_config


def test_conformal_pvalues_hand_computed():
    cal = np.sort(np.array([1.0, 2.0, 3.0, 4.0]))
    p = conformal_pvalues(np.array([0.5, 2.0, 2.5, 9.0]), cal)
    # p = (1 + #cal >= s) / 5
    np.testing.assert_allclose(p, [5 / 5, 4 / 5, 3 / 5, 1 / 5])


@pytest.mark.parametrize("method", ["fisher", "min_p", "harmonic", "stouffer"])
def test_fusion_is_monotone_and_unsaturated(method):
    p = np.array([[0.5, 0.5, 0.5], [0.01, 0.5, 0.5], [1e-6, 0.5, 0.5], [1e-12, 1e-12, 0.5]])
    s = fuse(p, method)
    assert np.all(np.diff(s) > 0)                 # smaller p-values -> strictly larger score
    assert np.isfinite(s).all() and s[-1] > 10    # no saturation at tiny p-values


def _toy(n_days=60, seed=0):
    """Two principals: 'quiet' (~5 calls/day) and 'busy' (~500 calls/day)."""
    rng = np.random.default_rng(seed)
    rows = []
    dates = pd.date_range("2023-01-01", periods=n_days)
    for d in dates:
        for name, mu in (("quiet", 5), ("busy", 500)):
            r = {"principal": name, "date": d}
            for fam, prefixes in FAMILY_PREFIXES.items():
                for k in range(2):
                    r[f"{prefixes[0]}f{k}"] = float(rng.poisson(mu if k == 0 else 1))
            rows.append(r)
    return pd.DataFrame(rows)


def test_deviation_is_relative_to_the_principals_own_history():
    cfg = load_config()
    df = _toy()
    det = BudgetAwareConformal(cfg, 0).fit(df)
    day = pd.Timestamp("2023-03-15")
    # quiet principal jumps to 60 calls (12x its normal), busy principal does its normal 500
    test = pd.DataFrame([{**{c: 1.0 for c in df.columns if c not in ("principal", "date")},
                          "principal": p, "date": day} for p in ("quiet", "busy")])
    for fam, prefixes in FAMILY_PREFIXES.items():
        test[f"{prefixes[0]}f0"] = [60.0, 500.0]
    s = det.score(test)
    assert s[0] > s[1]          # a global detector would rank the busy account first


def test_unknown_principal_falls_back_to_population():
    cfg = load_config()
    df = _toy()
    det = BudgetAwareConformal(cfg, 0).fit(df)
    new = df.iloc[[0]].assign(principal="never-seen")
    assert np.isfinite(det.score(new)).all()


def test_ablation_switches_and_unknown_option():
    cfg = load_config()
    df = _toy()
    for over in ({"per_principal": False}, {"calibrate": False}, {"fusion": "min_p"},
                 {"families": ["volume"]}, {"family_agg": "max"}):
        s = BudgetAwareConformal(cfg, 0, **over).fit(df).score(df)
        assert np.isfinite(s).all(), over
    with pytest.raises(ValueError):
        BudgetAwareConformal(cfg, 0, not_an_option=1)


def test_explanations_name_the_deviating_feature():
    cfg = load_config()
    df = _toy()
    det = BudgetAwareConformal(cfg, 0).fit(df)
    row = df[df["principal"] == "quiet"].iloc[[-1]].copy()
    row["res_f0"] = 400.0                                     # resource-family spike
    e = explain_alerts(det, row)[0]
    assert e["primary_family"] == "resource"
    assert e["top_features"][0]["feature"] == "res_f0"
    assert e["top_features"][0]["value"] == 400.0
    assert e["top_features"][0]["usual"] < 20
    assert "Resource access deviation" in e["text"]
    assert "scenario" not in e["text"].lower() and "label" not in e["text"].lower()


def test_every_pipeline_feature_has_a_description(tmp_path):
    from cert_toy import toy_events, write_parquet

    from cti.features.cert import build_cert_features
    from cti.features.pipeline import feature_columns
    frames, _ = toy_events(n_users=5, n_days=30, attack_from=20)
    cols = feature_columns(build_cert_features(write_parquet(frames, tmp_path), load_config()))
    assert set(cols) == set(FEATURE_TEXT)


def test_render_handles_no_positive_features():
    text = render({"primary_family": "volume", "family_pvalues": {"volume": 0.5}, "top_features": [],
                   "secondary_families": []})
    assert "Activity volume deviation" in text
