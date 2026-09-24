"""
cti.ingest.normalise
--------------------
Normalise column names from various input formats to the canonical
CloudTrail-style camelCase schema expected by the feature pipeline.

Supported input formats:
  - Synthetic generator output (snake_case: event_time, event_name, ...)
  - CERT loader output (mixed)
  - Raw CloudTrail JSON (already camelCase)

The canonical schema is::

    eventTime, eventName, eventSource, principalId, awsRegion,
    errorCode, resourceArn, resourceType, readOnly, bytesTransferred,
    label, scenarioId
"""
from __future__ import annotations

import logging

import pandas as pd

log = logging.getLogger(__name__)

# Maps every known input column name to the canonical name.
_COLUMN_MAP: dict[str, str] = {
    # Synthetic generator (snake_case)
    "event_id":             "eventId",
    "event_time":           "eventTime",
    "event_name":           "eventName",
    "event_source":         "eventSource",
    "principal_id":         "principalId",
    "principal_type":       "principalType",
    "principal_arn":        "principalArn",
    "role_name":            "roleName",
    "account_id":           "accountId",
    "source_ip":            "sourceIp",
    "user_agent":           "userAgent",
    "aws_region":           "awsRegion",
    "resource_arn":         "resourceArn",
    "resource_type":        "resourceType",
    "request_parameters":   "requestParameters",
    "error_code":           "errorCode",
    "read_only":            "readOnly",
    "bytes_transferred":    "bytesTransferred",
    "label":                "label",
    "scenario_id":          "scenarioId",
}


def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename columns to canonical CloudTrail camelCase schema.

    Columns already in camelCase are left untouched.  Unknown columns
    are preserved as-is with a warning.

    Parameters
    ----------
    df : pd.DataFrame
        Raw events DataFrame from any loader.

    Returns
    -------
    pd.DataFrame
        DataFrame with canonical column names.
    """
    rename_map = {}
    for col in df.columns:
        if col in _COLUMN_MAP:
            rename_map[col] = _COLUMN_MAP[col]
        elif col not in _COLUMN_MAP.values():
            log.debug("Column '%s' not in canonical map — keeping as-is", col)

    if rename_map:
        log.info(
            "Normalised %d column(s): %s",
            len(rename_map),
            ", ".join(f"{k}→{v}" for k, v in rename_map.items()),
        )

    df = df.rename(columns=rename_map)

    # Ensure eventTime is datetime with UTC
    if "eventTime" in df.columns:
        df["eventTime"] = pd.to_datetime(df["eventTime"], utc=True)

    return df


def validate_schema(df: pd.DataFrame) -> list[str]:
    """Check that required columns exist after normalisation.

    Returns a list of missing column names (empty if all present).
    """
    required = {"eventTime", "eventName", "eventSource", "principalId"}
    missing = required - set(df.columns)
    if missing:
        log.warning("Missing required columns after normalisation: %s", missing)
    return sorted(missing)
