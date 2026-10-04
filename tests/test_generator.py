"""Synthetic generator: determinism, schema, ground-truth consistency, scenario coverage."""
from __future__ import annotations

import pandas as pd
import pytest

from cti.ingest.synthetic import SCENARIO_IDS, generate_dataset


@pytest.fixture(scope="module")
def data():
    return generate_dataset(120, 70, SCENARIO_IDS, 0.25, seed=3)


def test_deterministic_for_a_seed():
    a, ga = generate_dataset(40, 30, SCENARIO_IDS, 0.2, seed=11)
    b, gb = generate_dataset(40, 30, SCENARIO_IDS, 0.2, seed=11)
    pd.testing.assert_frame_equal(a, b)
    assert ga == gb


def test_different_seeds_differ():
    a, _ = generate_dataset(40, 30, SCENARIO_IDS, 0.2, seed=1)
    b, _ = generate_dataset(40, 30, SCENARIO_IDS, 0.2, seed=2)
    assert len(a) != len(b) or not a["event_time"].equals(b["event_time"])


def test_schema_and_sorting(data):
    df, _ = data
    for col in ["event_time", "event_name", "event_source", "principal_id", "role_name", "source_ip",
                "user_agent", "aws_region", "resource_arn", "request_parameters", "error_code",
                "bytes_transferred", "mfa_used", "label", "scenario_id"]:
        assert col in df.columns
    assert df["event_time"].is_monotonic_increasing
    assert df["event_time"].dt.tz is not None


def test_benign_has_logins_and_lookalikes(data):
    df, _ = data
    benign = df[df["label"] == 0]
    assert (benign["event_name"] == "ConsoleLogin").any()
    assert (benign["event_name"] == "CreateAccessKey").any()           # benign admin lookalike
    assert (benign["mfa_used"] == 0).any()                             # benign users without MFA


def test_ground_truth_matches_labels(data):
    df, gt = data
    assert len(gt) == 30
    mal = df[df["label"] == 1]
    assert set(mal["principal_id"].astype(str)) == {g["principal_id"] for g in gt}
    for g in gt:
        first = df.loc[g["first_event_id"]]
        assert first["label"] == 1 and str(first["principal_id"]) == g["principal_id"]
        assert str(first["scenario_id"]) == g["scenario_id"]
        days = set(mal[mal["principal_id"].astype(str) == g["principal_id"]]["event_time"].dt.strftime("%Y-%m-%d"))
        assert days == set(g["malicious_days"])
        assert g["first_event_time"] <= g["last_event_time"]


def test_all_scenarios_appear():
    df, gt = generate_dataset(300, 120, SCENARIO_IDS, 0.1, seed=5)
    assert {g["scenario_id"] for g in gt} == set(SCENARIO_IDS)


def test_insiders_start_after_history_exists(data):
    _, gt = data
    first_ok = pd.Timestamp("2023-01-01") + pd.Timedelta(days=14 + 7)
    for g in gt:
        assert pd.Timestamp(g["malicious_days"][0]) >= first_ok
