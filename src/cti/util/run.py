"""
cti.util.run
------------
RunContext: the single gateway through which every experiment writes outputs.

Every experiment must open a RunContext.  The context manager writes a
``manifest.json`` inside ``results/<run_id>/`` capturing:

- git SHA of HEAD
- SHA-256 hash of the config
- random seed
- installed package versions
- wall-clock start / end / duration
- SHA-256 checksum of the input data file(s)
- any extra key-value pairs the caller registers via ``ctx.register(**kw)``

No result file must be produced outside a RunContext.
"""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any

from cti.util.config import config_hash, load_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _git_sha() -> str:
    """Return the current HEAD git SHA (short), or 'unknown'."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def _package_versions(packages: list[str]) -> dict[str, str]:
    """Return installed versions for each package name."""
    versions: dict[str, str] = {}
    for pkg in packages:
        try:
            versions[pkg] = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            versions[pkg] = "not-installed"
    return versions


def _file_sha256(path: str | Path) -> str:
    """Return SHA-256 hex digest of a file, or 'missing' if not found."""
    p = Path(path)
    if not p.exists():
        return "missing"
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# RunContext
# ---------------------------------------------------------------------------

_TRACKED_PACKAGES = [
    "pandas", "numpy", "scikit-learn", "scipy", "shap",
    "pyarrow", "matplotlib", "pyyaml", "tqdm", "streamlit",
    "boto3", "cloudtrail-insider",
]


class RunContext:
    """Context manager that bookends every experiment run.

    Usage::

        with RunContext(name="baseline_isoforest") as ctx:
            ctx.register(budget=50)
            # ... run experiment ...
            ctx.register(precision_at_50=0.72)
            ctx.save_artifact("scores.parquet", df)

    Parameters
    ----------
    name:
        Human-readable experiment name (used in directory naming).
    config_path:
        Path to YAML config.  Defaults to the project default.
    input_paths:
        Iterable of data files whose checksums will be recorded.
    run_id:
        Override the auto-generated UUID4 run ID.
    """

    def __init__(
        self,
        name: str,
        config_path: str | Path | None = None,
        input_paths: list[str | Path] | None = None,
        run_id: str | None = None,
    ) -> None:
        self.name = name
        self._cfg = load_config(config_path)
        self._input_paths: list[str | Path] = input_paths or []
        self.run_id = run_id or str(uuid.uuid4())[:8]
        self._extras: dict[str, Any] = {}
        self._start: float = 0.0

        results_base = Path(self._cfg["paths"]["results_dir"])
        self.run_dir = results_base / f"{name}__{self.run_id}"
        self.run_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ context
    def __enter__(self) -> "RunContext":
        self._start = time.perf_counter()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        elapsed = time.perf_counter() - self._start
        manifest = self._build_manifest(elapsed, error=str(exc_val) if exc_type else None)
        manifest_path = self.run_dir / "manifest.json"
        with manifest_path.open("w") as fh:
            json.dump(manifest, fh, indent=2, default=str)
        return False  # do not suppress exceptions

    # ------------------------------------------------------------------ public
    def register(self, **kwargs: Any) -> None:
        """Attach arbitrary key-value pairs that will appear in manifest.json."""
        self._extras.update(kwargs)

    def save_artifact(self, filename: str, obj: Any) -> Path:
        """Persist *obj* inside the run directory and return its path.

        Supports pandas DataFrames (parquet) and anything else (JSON).
        """
        import pandas as pd  # local import to keep module lightweight

        dest = self.run_dir / filename
        if isinstance(obj, pd.DataFrame):
            obj.to_parquet(dest, index=False)
        elif isinstance(obj, dict):
            with dest.open("w") as fh:
                json.dump(obj, fh, indent=2, default=str)
        else:
            with dest.open("w") as fh:
                fh.write(str(obj))
        return dest

    def artifact_path(self, filename: str) -> Path:
        """Return full path for an artifact filename within this run."""
        return self.run_dir / filename

    # ------------------------------------------------------------------ private
    def _build_manifest(self, elapsed: float, error: str | None) -> dict[str, Any]:
        return {
            "run_id":        self.run_id,
            "name":          self.name,
            "git_sha":       _git_sha(),
            "config_hash":   config_hash(self._cfg),
            "seed":          self._cfg.get("random_seed"),
            "packages":      _package_versions(_TRACKED_PACKAGES),
            "wall_seconds":  round(elapsed, 3),
            "error":         error,
            "input_checksums": {
                str(p): _file_sha256(p) for p in self._input_paths
            },
            **self._extras,
        }
