"""Causality of the feature pipeline: future events must never change earlier rows."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from cti.features.pipeline import FAMILY_PREFIXES, build_features, family_columns, feature_columns, make_labels
from cti.ingest.normalise import normalise_columns
from cti.ingest.synthetic import SCENARIO_IDS, generate_dataset
from cti.util.config import load_config


@pytest.fixture(scope="module")
def setup():
    cfg = load_config()
    raw, gt = generate_dataset(60, 45, SCENARIO_IDS, 0.2, seed=9)
    return cfg, normalise_columns(raw), gt


def test_features_are_causal(setup):
    cfg, events, _ = setup
    full = build_features(events, cfg)
    cutoff = events["eventTime"].min().normalize() + pd.Timedelta(days=30)
    trunc = build_features(events[events["eventTime"] < cutoff].reset_index(drop=True), cfg)

    cols = feature_columns(full)
    a = full[full["date"] < cutoff.tz_localize(None)].sort_values(["principal", "date"]).reset_index(drop=True)
    b = trunc.sort_values(["principal", "date"]).reset_index(drop=True)
    assert a[["principal", "date"]].equals(b[["principal", "date"]])
    np.testing.assert_allclose(a[cols].to_numpy(), b[cols].to_numpy(), rtol=1e-4, atol=1e-4)


def test_all_four_families_present(setup):
    cfg, events, _ = setup
    feats = build_features(events, cfg)
    cols = feature_columns(feats)
    for fam in FAMILY_PREFIXES:
        assert len(family_columns(cols, fam)) >= 3, fam
    assert set(cols) == {c for fam in FAMILY_PREFIXES for c in family_columns(cols, fam)}


def test_no_nans_and_one_row_per_principal_day(setup):
    cfg, events, _ = setup
    feats = build_features(events, cfg)
    assert not feats[feature_columns(feats)].isna().any().any()
    assert not feats.duplicated(["principal", "date"]).any()


def test_new_ip_feature_fires_on_attacker_ip(setup):
    cfg, events, gt = setup
    feats = build_features(events, cfg)
    labels = make_labels(events, feats)
    merged = feats.merge(labels, on=["principal", "date"])
    s1 = [g for g in gt if g["scenario_id"] == "S1"]
    if s1:                                              # S1 logs in from a never-seen IP
        day = pd.Timestamp(s1[0]["malicious_days"][0])
        row = merged[(merged["principal"] == s1[0]["principal_id"]) & (merged["date"] == day)]
        assert row["idn_new_ips"].iloc[0] >= 1


def test_labels_are_principal_day(setup):
    cfg, events, gt = setup
    feats = build_features(events, cfg)
    labels = make_labels(events, feats)
    assert len(labels) == len(feats)
    assert labels["label"].sum() >= len(gt)             # every insider has >= 1 positive day
    pos = labels[labels["label"] == 1]
    assert set(pos["principal"]) == {g["principal_id"] for g in gt}


def _mini_events(rows):
    return pd.DataFrame([dict(
        eventTime=pd.Timestamp("2023-03-01", tz="UTC") + pd.Timedelta(days=d, hours=h),
        eventName=name, eventSource="s3.amazonaws.com", principalId="A", awsRegion="us-east-1",
    ) for d, h, name in rows])


def test_rarity_uses_only_prior_global_counts():
    """'Late' is used once on day 2 and heavily from day 5 on: on day 2 it was still rare
    (0 prior uses), and a look-ahead implementation would call it common."""
    cfg = load_config()
    rows = [(d, 10, "Common") for d in range(10) for _ in range(20)]
    rows += [(2, 11, "Late")] + [(d, 12, "Late") for d in range(5, 10) for _ in range(20)]
    feats = build_features(_mini_events(rows), cfg).set_index("date")
    day2 = feats.loc[pd.Timestamp("2023-03-03"), "rar_fraction_rare_events"]
    assert day2 > 0                                     # the lone 'Late' event was rare at the time
    day8 = feats.loc[pd.Timestamp("2023-03-09"), "rar_fraction_rare_events"]
    assert day8 == 0                                    # by day 8 'Late' has plenty of history


def test_novelty_is_first_time_for_that_principal_only():
    cfg = load_config()
    rows = [(0, 9, "GetObject"), (1, 9, "GetObject"), (2, 9, "GetObject"), (2, 10, "CreateAccessKey"),
            (3, 9, "CreateAccessKey")]
    feats = build_features(_mini_events(rows), cfg).set_index("date")
    new = feats["div_new_event_types"]
    assert new[pd.Timestamp("2023-03-01")] == 1         # GetObject: first ever use
    assert new[pd.Timestamp("2023-03-02")] == 0
    assert new[pd.Timestamp("2023-03-03")] == 1         # CreateAccessKey appears for the first time
    assert new[pd.Timestamp("2023-03-04")] == 0         # ...and is no longer new the next day
