"""
cti.util.config
---------------
Single source of truth for configuration loading.
All modules call load_config() — no literals anywhere in production code.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any

import yaml

_DEFAULT_CONFIG_PATH = Path(__file__).parents[3] / "configs" / "default.yaml"
_LOADED: dict[str, Any] | None = None


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    """Load (and cache) the YAML configuration.

    Parameters
    ----------
    path:
        Override path to a YAML config file.  Defaults to
        ``configs/default.yaml`` relative to the repository root, or the
        ``CTI_CONFIG`` environment variable if set.
    """
    global _LOADED  # noqa: PLW0603
    if _LOADED is not None and path is None:
        return _LOADED

    env_path = os.environ.get("CTI_CONFIG")
    resolved = Path(path or env_path or _DEFAULT_CONFIG_PATH)

    with resolved.open() as fh:
        cfg = yaml.safe_load(fh)

    if path is None:
        _LOADED = cfg
    return cfg


def config_hash(cfg: dict[str, Any]) -> str:
    """Return a short SHA-256 hex digest of the serialised config."""
    serialised = json.dumps(cfg, sort_keys=True, default=str).encode()
    return hashlib.sha256(serialised).hexdigest()[:12]


def reset_cache() -> None:
    """Clear the module-level config cache (useful in tests)."""
    global _LOADED  # noqa: PLW0603
    _LOADED = None
