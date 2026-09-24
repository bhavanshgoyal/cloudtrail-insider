"""
cti.features.pipeline
---------------------
Feature engineering pipeline: converts normalised events into a
per-principal-per-day feature matrix ready for anomaly detectors.

Feature groups
~~~~~~~~~~~~~~
1. **Volume**   – event counts per principal per time bucket
2. **Diversity** – unique event types, services, regions
3. **Rarity**   – fraction of rare event types (< threshold occurrences)
4. **Temporal** – after-hours ratio, burst coefficient
5. **Error**    – error rate per principal

All thresholds come from cfg["features"].
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd

from cti.util.config import load_config
from cti.util.run import RunContext
from cti.util.seeds import set_all_seeds

log = logging.getLogger(__name__)

# Business hours window (UTC) used for after-hours computation
_BIZ_START_HOUR = 8
_BIZ_END_HOUR   = 18


# ---------------------------------------------------------------------------
# Volume features
# ---------------------------------------------------------------------------

def _volume_features(df: pd.DataFrame, principal_col: str, time_col: str = "eventTime") -> pd.DataFrame:
    """Count events per principal per calendar day."""
    df = df.copy()
    df["_date"] = df[time_col].dt.date
    grp = df.groupby([principal_col, "_date"])
    vol = grp.size().rename("vol_events_per_day").reset_index()
    return vol


# ---------------------------------------------------------------------------
# Diversity features
# ---------------------------------------------------------------------------

def _diversity_features(df: pd.DataFrame, principal_col: str) -> pd.DataFrame:
    """Count unique event types, services, and regions per principal per day."""
    df = df.copy()
    df["_date"] = df["eventTime"].dt.date

    agg = (
        df.groupby([principal_col, "_date"])
        .agg(
            div_unique_event_names=("eventName", "nunique"),
            div_unique_sources=("eventSource", "nunique"),
            div_unique_regions=("awsRegion", "nunique"),
        )
        .reset_index()
    )
    return agg


# ---------------------------------------------------------------------------
# Rarity features
# ---------------------------------------------------------------------------

def _rarity_features(
    df: pd.DataFrame,
    principal_col: str,
    threshold: int,
) -> pd.DataFrame:
    """Fraction of events with an event type that appears < threshold times globally."""
    event_counts = df["eventName"].value_counts()
    rare_names = set(event_counts[event_counts < threshold].index)

    df = df.copy()
    df["_date"] = df["eventTime"].dt.date
    df["_is_rare"] = df["eventName"].isin(rare_names).astype(float)

    rare_frac = (
        df.groupby([principal_col, "_date"])["_is_rare"]
        .mean()
        .rename("rar_fraction_rare_events")
        .reset_index()
    )
    return rare_frac


# ---------------------------------------------------------------------------
# Temporal features
# ---------------------------------------------------------------------------

def _temporal_features(df: pd.DataFrame, principal_col: str) -> pd.DataFrame:
    """After-hours ratio and burst coefficient."""
    df = df.copy()
    df["_date"] = df["eventTime"].dt.date
    df["_hour"] = df["eventTime"].dt.hour
    df["_after_hours"] = (
        (df["_hour"] < _BIZ_START_HOUR) | (df["_hour"] >= _BIZ_END_HOUR)
    ).astype(float)

    grp = df.groupby([principal_col, "_date"])

    after_hours = (
        grp["_after_hours"].mean().rename("tmp_after_hours_ratio").reset_index()
    )

    # Burst: std of event inter-arrival time in minutes (high = bursty)
    def _burst(g: pd.DataFrame) -> float:
        ts = g["eventTime"].sort_values()
        if len(ts) < 2:
            return 0.0
        diffs = ts.diff().dt.total_seconds().dropna() / 60.0
        return float(diffs.std()) if len(diffs) > 1 else 0.0

    burst = grp.apply(_burst, include_groups=False).rename("tmp_burst_std_minutes").reset_index()

    merged = after_hours.merge(burst, on=[principal_col, "_date"])
    return merged


# ---------------------------------------------------------------------------
# Error features
# ---------------------------------------------------------------------------

def _error_features(df: pd.DataFrame, principal_col: str) -> pd.DataFrame:
    """Error rate per principal per day."""
    df = df.copy()
    df["_date"] = df["eventTime"].dt.date
    df["_has_error"] = df.get("errorCode", pd.Series(dtype=str)).notna().astype(float)

    err_rate = (
        df.groupby([principal_col, "_date"])["_has_error"]
        .mean()
        .rename("err_error_rate")
        .reset_index()
    )
    return err_rate


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def build_features(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Construct the feature matrix from a normalised events DataFrame.

    Parameters
    ----------
    df:
        Normalised events (output of ``cti.ingest.loader``).
        Accepts both camelCase (eventTime, principalId) and snake_case
        (event_time, principal_id) column names.
    cfg:
        Project configuration dict.

    Returns
    -------
    pd.DataFrame
        One row per (principal, date) with all feature columns.
    """
    # Defensive column-name handling: accept both camelCase and snake_case
    _alias = {
        "event_time": "eventTime",
        "event_name": "eventName",
        "event_source": "eventSource",
        "aws_region": "awsRegion",
        "error_code": "errorCode",
        "principal_id": "principalId",
    }
    df = df.rename(columns={k: v for k, v in _alias.items() if k in df.columns})

    # Ensure eventTime is datetime
    if "eventTime" in df.columns:
        df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True)

    feat_cfg = cfg["features"]
    # Support both list and string for entity_columns
    entity_cols = feat_cfg["entity_columns"]
    if isinstance(entity_cols, str):
        entity_cols = [entity_cols]
    principal_col = entity_cols[0]  # first entity col = principal

    if principal_col not in df.columns:
        # Try common alternatives
        for alt in ["principalId", "principal_id", "userId", "user_id"]:
            if alt in df.columns:
                df = df.rename(columns={alt: principal_col})
                log.info("Mapped '%s' → '%s'", alt, principal_col)
                break
        else:
            raise KeyError(f"Principal column '{principal_col}' not found in events DataFrame. "
                           f"Available: {list(df.columns)}")

    rare_threshold = feat_cfg["rare_event_threshold"]

    parts = [
        _volume_features(df, principal_col),
        _diversity_features(df, principal_col),
        _rarity_features(df, principal_col, rare_threshold),
        _temporal_features(df, principal_col),
        _error_features(df, principal_col),
    ]

    # Merge all feature frames on (principal, date)
    result = parts[0]
    for part in parts[1:]:
        result = result.merge(part, on=[principal_col, "_date"], how="outer")

    result = result.rename(columns={principal_col: "principal", "_date": "date"})
    result["date"] = pd.to_datetime(result["date"])

    # Fill missing numerical values with 0
    num_cols = result.select_dtypes(include="number").columns
    result[num_cols] = result[num_cols].fillna(0.0)

    log.info(
        "Feature matrix: %d rows x %d feature columns",
        len(result),
        len(result.columns) - 2,  # exclude principal + date
    )
    return result


def feature_columns(df: pd.DataFrame) -> list[str]:
    """Return the names of feature columns (excluding principal and date)."""
    return [c for c in df.columns if c not in {"principal", "date"}]


def main() -> None:
    """CLI entrypoint: cti-features."""
    parser = argparse.ArgumentParser(description="Build feature matrix from events")
    parser.add_argument("--config", default=None)
    parser.add_argument("--input",  default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_all_seeds(cfg["random_seed"])

    events_path = Path(args.input  or cfg["paths"]["processed_events"])
    feat_path   = Path(args.output or cfg["paths"]["feature_store"])

    with RunContext(
        "features",
        config_path=args.config,
        input_paths=[events_path],
    ) as ctx:
        df_events = pd.read_parquet(events_path)
        df_events["eventTime"] = pd.to_datetime(df_events["eventTime"], utc=True)
        df_feat = build_features(df_events, cfg)

        feat_path.parent.mkdir(parents=True, exist_ok=True)
        df_feat.to_parquet(feat_path, index=False)
        ctx.register(n_rows=len(df_feat), n_features=len(feature_columns(df_feat)))


if __name__ == "__main__":
    main()
