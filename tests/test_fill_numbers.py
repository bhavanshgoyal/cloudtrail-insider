"""Number-filling for the paper / PPT summary: every placeholder resolves or is reported."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pandas as pd
import pytest

SPEC = importlib.util.spec_from_file_location("fill_numbers", Path("scripts/fill_numbers.py"))
fn = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fn)


@pytest.fixture()
def fake_results(tmp_path, monkeypatch):
    (tmp_path / "results/campaign").mkdir(parents=True)
    pd.DataFrame([dict(workload="W1", detector="proposed_budget_aware_conformal", metric="dr_at_b", budget=10,
                       mean=0.956, ci_lo=0.9, ci_hi=0.99)]).to_csv(tmp_path / "results/campaign/summary.csv", index=False)
    pd.DataFrame([dict(workload="W1", hypothesis="H1a", diff=0.463, ci_lo=0.306, ci_hi=0.653,
                       verdict="NOT SUPPORTED")]).to_csv(tmp_path / "results/campaign/hypotheses.csv", index=False)
    monkeypatch.chdir(tmp_path)
    fn._csv.cache_clear()
    yield tmp_path
    fn._csv.cache_clear()


def test_resolves_summary_and_hypothesis(fake_results):
    text, errors = fn.fill("DR {{S|W1|P|dr_at_b|10|mean|.3f}} gain {{H|W1|H1a|diff|pct}} {{H|W1|H1a|verdict|s}}")
    assert errors == []
    assert text == "DR 0.956 gain +46% NOT SUPPORTED"


def test_unresolved_is_reported_never_guessed(fake_results):
    text, errors = fn.fill("{{S|W9|P|dr_at_b|10|mean|.3f}}")
    assert len(errors) == 1 and "UNRESOLVED" in text


def test_triage_pending_until_real_results_exist(fake_results):
    text, errors = fn.fill("{{T|h3.verdict|s}}")
    assert errors == [] and "PENDING" in text
