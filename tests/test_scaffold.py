"""
Smoke test — verifies the core infrastructure from P00 is working.
Runs config loading, seed setting, and RunContext on a minimal fixture.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from cti.util.config import load_config, config_hash, reset_cache
from cti.util.seeds import set_all_seeds, make_rng
from cti.util.run import RunContext


@pytest.fixture(autouse=True)
def _clear_config_cache():
    """Reset the module-level config cache between tests."""
    reset_cache()
    yield
    reset_cache()


class TestConfig:
    def test_load_default(self):
        cfg = load_config()
        assert isinstance(cfg, dict)
        assert cfg["random_seed"] == 42
        assert cfg["warmup_days"] == 14
        assert cfg["max_alerts_per_principal_day"] == 1
        assert cfg["budgets"] == [10, 50, 100]

    def test_config_hash_deterministic(self):
        cfg = load_config()
        h1 = config_hash(cfg)
        reset_cache()
        h2 = config_hash(load_config())
        assert h1 == h2

    def test_budgets_present(self):
        cfg = load_config()
        assert 10 in cfg["budgets"]
        assert 50 in cfg["budgets"]
        assert 100 in cfg["budgets"]

    def test_metrics_are_plan_aligned(self):
        cfg = load_config()
        metrics = cfg["eval"]["metrics"]
        assert "detection_rate_at_b" in metrics
        assert "precision_at_b" in metrics
        assert "mttd_at_b" in metrics
        # These should NOT be in the config
        assert "ndcg_at_b" not in metrics
        assert "map_at_b" not in metrics

    def test_no_drop_event_sources(self):
        """Ensure we don't accidentally drop signin events."""
        cfg = load_config()
        features_cfg = cfg.get("features", {})
        assert "drop_event_sources" not in features_cfg


class TestSeeds:
    def test_determinism(self):
        set_all_seeds(123)
        a = np.random.rand(10)
        set_all_seeds(123)
        b = np.random.rand(10)
        np.testing.assert_array_equal(a, b)

    def test_make_rng(self):
        rng1 = make_rng(42)
        rng2 = make_rng(42)
        assert rng1.random() == rng2.random()


class TestRunContext:
    def test_manifest_written(self, tmp_path, monkeypatch):
        """RunContext writes manifest.json with all required fields."""
        # Point results_dir to tmp
        cfg = load_config()
        cfg["paths"]["results_dir"] = str(tmp_path / "results")
        
        # Monkeypatch load_config to return our modified cfg
        import cti.util.run as run_mod
        monkeypatch.setattr(run_mod, "load_config", lambda *a, **kw: cfg)
        
        with RunContext(name="test_run") as ctx:
            ctx.register(test_key="test_value")

        manifest_path = ctx.run_dir / "manifest.json"
        assert manifest_path.exists()

        with manifest_path.open() as fh:
            manifest = json.load(fh)

        assert "run_id" in manifest
        assert "git_sha" in manifest
        assert "config_hash" in manifest
        assert "seed" in manifest
        assert manifest["seed"] == 42
        assert "packages" in manifest
        assert "wall_seconds" in manifest
        assert manifest["test_key"] == "test_value"

    def test_save_artifact(self, tmp_path, monkeypatch):
        """RunContext can save dict artifacts as JSON."""
        cfg = load_config()
        cfg["paths"]["results_dir"] = str(tmp_path / "results")

        import cti.util.run as run_mod
        monkeypatch.setattr(run_mod, "load_config", lambda *a, **kw: cfg)

        with RunContext(name="test_artifact") as ctx:
            path = ctx.save_artifact("test.json", {"key": "value"})

        assert path.exists()
        with path.open() as fh:
            data = json.load(fh)
        assert data["key"] == "value"
