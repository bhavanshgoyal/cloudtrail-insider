"""Detector interface: fit(df_feat, events) / score(df_feat, events); train-window-only fitting."""
from __future__ import annotations

import copy

import numpy as np
import pandas as pd
import pytest

from cti.detectors.train import build_detectors, train_on_split
from cti.features.pipeline import build_features, make_labels
from cti.ingest.normalise import normalise_columns
from cti.ingest.synthetic import SCENARIO_IDS, generate_dataset
from cti.util.config import load_config
from cti.util.splits import make_splits


@pytest.fixture(scope="module")
def world():
    cfg = copy.deepcopy(load_config())
    cfg["detectors"]["proposed"]["n_estimators"] = 10
    cfg["detectors"]["autoencoder"]["epochs"] = 30
    raw, gt = generate_dataset(40, 75, SCENARIO_IDS, 0.2, seed=4)
    events = normalise_columns(raw)
    feats = build_features(events, cfg)
    return cfg, events, feats, make_labels(events, feats), make_splits(feats["date"], cfg)


def test_all_detectors_follow_the_interface(world):
    cfg, events, feats, _, split = world
    dets = train_on_split(feats, cfg, split, events=events)
    assert [d.name for d in dets] == ["isolation_forest", "lof", "autoencoder", "rule_baseline",
                                      "proposed_budget_aware_conformal"]
    test = split.select(feats, "test")
    for d in dets:
        s = d.score(test, events)
        assert s.shape == (len(test),), d.name
        assert np.isfinite(s).all(), d.name
        assert s.std() > 0, f"{d.name} returns a constant score"


def test_rule_baseline_is_deterministic_not_random(world):
    cfg, events, feats, _, split = world
    det = [d for d in build_detectors(cfg, include_proposed=False) if d.name == "rule_baseline"][0]
    test = split.select(feats, "test")
    np.testing.assert_array_equal(det.score(test, events), det.score(test, events))


def test_feature_detectors_use_identical_columns(world):
    cfg, events, feats, _, split = world
    dets = [d for d in train_on_split(feats, cfg, split, events=events, include_proposed=False)
            if not d.needs_events]
    cols = {tuple(d.feat_cols) for d in dets}
    assert len(cols) == 1


def test_training_uses_only_the_train_window(world):
    cfg, events, feats, _, split = world
    seen = {}

    class Spy:
        name = "spy"
        needs_events = False

        def fit(self, df_feat, events=None):
            seen["dates"] = pd.to_datetime(df_feat["date"])
            return self

    import cti.detectors.train as tr
    orig = tr.build_detectors
    tr.build_detectors = lambda cfg, include_proposed=True: [Spy()]
    try:
        train_on_split(feats, cfg, split, events=events)
    finally:
        tr.build_detectors = orig
    assert seen["dates"].max() <= pd.Timestamp(split.train_days.max())
    assert seen["dates"].min() >= pd.Timestamp(split.train_days.min())


def test_empty_train_window_raises(world):
    cfg, events, feats, _, split = world
    empty = feats.iloc[0:0]
    with pytest.raises(ValueError):
        train_on_split(empty, cfg, split, events=events)
