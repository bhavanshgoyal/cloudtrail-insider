"""
cti.ingest.toy
--------------
Generate a synthetic 500-event CloudTrail-like toy log for smoke tests and
CI.  No external data needed.

Usage::

    python -m cti.ingest.toy --output data/raw/toy_logs.jsonl.gz --n 500 --seed 42
"""
from __future__ import annotations

import argparse
import gzip
import json
import logging
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cti.util.config import load_config
from cti.util.seeds import set_all_seeds

log = logging.getLogger(__name__)

_EVENT_SOURCES = [
    "s3.amazonaws.com",
    "ec2.amazonaws.com",
    "iam.amazonaws.com",
    "sts.amazonaws.com",
    "kms.amazonaws.com",
]
_EVENT_NAMES = {
    "s3.amazonaws.com":  ["GetObject", "PutObject", "DeleteObject", "ListBuckets"],
    "ec2.amazonaws.com": ["DescribeInstances", "RunInstances", "TerminateInstances"],
    "iam.amazonaws.com": ["CreateUser", "AttachUserPolicy", "ListUsers", "DeleteUser"],
    "sts.amazonaws.com": ["AssumeRole", "GetCallerIdentity"],
    "kms.amazonaws.com": ["Decrypt", "Encrypt", "GenerateDataKey"],
}
_REGIONS   = ["us-east-1", "eu-west-1", "ap-southeast-1"]
_IPS       = [f"192.168.{i}.{j}" for i in range(1, 5) for j in range(1, 20)]
_USERS     = [f"arn:aws:iam::123456789012:user/user{i:02d}" for i in range(1, 11)]
# user05 is the "insider" — inject anomalous events
_INSIDER   = "arn:aws:iam::123456789012:user/user05"
_ERROR_CODES = [None, None, None, None, "AccessDenied", "InvalidParameter"]


def _random_event(rng: random.Random, ts: datetime, insider: bool = False) -> dict:
    source = rng.choice(_EVENT_SOURCES)
    if insider and source not in ("iam.amazonaws.com", "kms.amazonaws.com"):
        source = rng.choice(["iam.amazonaws.com", "kms.amazonaws.com"])
    name   = rng.choice(_EVENT_NAMES[source])
    user   = _INSIDER if insider else rng.choice([u for u in _USERS if u != _INSIDER])
    record = {
        "eventTime":     ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "eventSource":   source,
        "eventName":     name,
        "awsRegion":     rng.choice(_REGIONS),
        "sourceIPAddress": rng.choice(_IPS),
        "userAgent":     "aws-sdk-python/1.34",
        "errorCode":     rng.choice(_ERROR_CODES),
        "requestID":     f"req-{rng.randint(10**8, 10**9)}",
        "eventID":       f"evt-{rng.randint(10**8, 10**9)}",
        "userIdentity":  {
            "type":       "IAMUser",
            "arn":        user,
            "accountId":  "123456789012",
            "principalId": user.split("/")[-1],
        },
    }
    return record


def generate_toy_logs(n: int, seed: int, start: datetime | None = None) -> list[dict]:
    """Return *n* synthetic CloudTrail records."""
    rng = random.Random(seed)
    start = start or datetime(2023, 12, 1, 0, 0, 0, tzinfo=timezone.utc)

    records = []
    insider_count = max(1, n // 10)  # 10 % of events are from the insider

    for i in range(n):
        delta = timedelta(minutes=rng.randint(0, 60 * 24 * 30))  # spread over ~30 days
        ts = start + delta
        insider = i < insider_count
        records.append(_random_event(rng, ts, insider=insider))

    records.sort(key=lambda r: r["eventTime"])
    return records


def save_toy_logs(records: list[dict], path: str | Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(path, "wt", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec) + "\n")
    log.info("Wrote %d toy records to %s", len(records), path)


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate toy CloudTrail logs")
    parser.add_argument("--config", default=None)
    parser.add_argument("--output", default="data/raw/toy_logs.jsonl.gz")
    parser.add_argument("--n",      type=int, default=500)
    parser.add_argument("--seed",   type=int, default=None)
    args = parser.parse_args()

    cfg  = load_config(args.config)
    seed = args.seed if args.seed is not None else cfg["random_seed"]
    set_all_seeds(seed)

    records = generate_toy_logs(args.n, seed)
    save_toy_logs(records, args.output)


if __name__ == "__main__":
    main()
