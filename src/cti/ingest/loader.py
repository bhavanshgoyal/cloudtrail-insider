"""
cti.ingest.loader
-----------------
Load raw CloudTrail JSON-lines records into a normalised Parquet file.

Entrypoint: ``cti-ingest`` (see pyproject.toml).

CloudTrail log format reference:
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
"""
from __future__ import annotations

import argparse
import gzip
import json
import logging
from pathlib import Path
from typing import Any

import pandas as pd

from cti.util.config import load_config
from cti.util.run import RunContext
from cti.util.seeds import set_all_seeds

log = logging.getLogger(__name__)

# ── Columns we keep (everything else is dropped to save I/O) ─────────────────
_KEEP_COLS = [
    "eventTime",
    "eventSource",
    "eventName",
    "awsRegion",
    "sourceIPAddress",
    "userAgent",
    "errorCode",
    "errorMessage",
    "requestID",
    "eventID",
    "userIdentity.type",
    "userIdentity.arn",
    "userIdentity.accountId",
    "userIdentity.principalId",
    "userIdentity.sessionContext.sessionIssuer.arn",
]


def _flatten(record: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Recursively flatten a nested dict using dot-notation keys."""
    out: dict[str, Any] = {}
    for k, v in record.items():
        full_key = f"{prefix}.{k}" if prefix else k
        if isinstance(v, dict):
            out.update(_flatten(v, full_key))
        else:
            out[full_key] = v
    return out


def load_raw(path: str | Path) -> pd.DataFrame:
    """Read a gzip-compressed JSON-lines CloudTrail export.

    Also handles plain ``.jsonl`` files and AWS CloudTrail JSON bundles
    (where the top-level key is ``"Records"``).
    """
    path = Path(path)
    records: list[dict[str, Any]] = []

    opener = gzip.open if path.suffix in {".gz", ".gzip"} else open
    with opener(path, "rt", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            # CloudTrail batch bundles embed records under "Records"
            if "Records" in obj:
                records.extend(obj["Records"])
            else:
                records.append(obj)

    if not records:
        raise ValueError(f"No records found in {path}")

    flat = [_flatten(r) for r in records]
    df = pd.DataFrame(flat)

    # Keep only columns that exist
    keep = [c for c in _KEEP_COLS if c in df.columns]
    df = df[keep].copy()

    # Parse timestamps
    if "eventTime" in df.columns:
        df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True, errors="coerce")

    log.info("Loaded %d raw events from %s", len(df), path)
    return df


def drop_noisy_sources(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Remove event sources that generate too much noise (from config)."""
    sources_to_drop = cfg["features"].get("drop_event_sources", [])
    if sources_to_drop and "eventSource" in df.columns:
        before = len(df)
        df = df[~df["eventSource"].isin(sources_to_drop)].copy()
        log.info("Dropped %d events from noisy sources", before - len(df))
    return df


def save_processed(df: pd.DataFrame, path: str | Path) -> None:
    """Write normalised events to Parquet."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(path, index=False)
    log.info("Saved %d events to %s", len(df), path)


def main() -> None:
    """CLI entrypoint: cti-ingest."""
    parser = argparse.ArgumentParser(description="Ingest raw CloudTrail logs")
    parser.add_argument("--config", default=None, help="Path to YAML config")
    parser.add_argument("--input",  default=None, help="Override raw log path")
    parser.add_argument("--output", default=None, help="Override output path")
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_all_seeds(cfg["random_seed"])

    raw_path = Path(args.input or cfg["paths"]["raw_logs"])
    out_path = Path(args.output or cfg["paths"]["processed_events"])

    with RunContext("ingest", config_path=args.config, input_paths=[raw_path]) as ctx:
        df = load_raw(raw_path)
        df = drop_noisy_sources(df, cfg)
        save_processed(df, out_path)
        ctx.register(n_events=len(df), output=str(out_path))


if __name__ == "__main__":
    main()
