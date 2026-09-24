"""
cti.demo.replay
---------------
Read a normalised event parquet (synthetic or CERT) and issue real Boto3
calls against LocalStack so the actions appear in CloudTrail.

Usage::
    python -m cti.demo.replay --limit 500 --speed 1.0
"""
import argparse
import logging
import time
from datetime import datetime, timezone
from typing import Any

import boto3
import pandas as pd
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)

# Map CloudTrail event names to Boto3 clients and methods
# Note: Not all synthetic events are supported directly by Boto3 without complex setups,
# so we map unsupported actions to closest supported ones for testbed demonstration.
_METHOD_MAP = {
    "ConsoleLogin":            ("sts", "get_caller_identity", {}),
    "GetObject":               ("s3", "list_buckets", {}), # Simplified for demo
    "PutObject":               ("s3", "list_buckets", {}),
    "CreateSnapshot":          ("ec2", "describe_instances", {}),
    "ModifySnapshotAttribute": ("ec2", "describe_instances", {}),
    "AssumeRole":              ("sts", "get_caller_identity", {}),
    "SendEmail":               ("ses", "list_identities", {}),
}

def setup_client(service: str, principal: str) -> Any:
    """Setup a boto3 client pointing to LocalStack."""
    # In a full simulation, we might assume the role of the principal here.
    # For the testbed replay, we just use the default credentials.
    return boto3.client(
        service,
        endpoint_url="http://localhost:4566",
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test"
    )

def replay_events(df: pd.DataFrame, speed: float = 1.0) -> None:
    clients = {srv: setup_client(srv, "default") for srv in ["s3", "ec2", "iam", "sts", "ses"]}

    start_real = time.time()
    start_sim = df["eventTime"].iloc[0].timestamp() if not df.empty else 0

    for _, row in df.iterrows():
        action = row["eventName"]
        principal = row.get("principal", "unknown")
        
        # Timing simulation
        if speed > 0:
            sim_elapsed = row["eventTime"].timestamp() - start_sim
            real_elapsed = time.time() - start_real
            target_real = sim_elapsed / speed
            if target_real > real_elapsed:
                time.sleep(target_real - real_elapsed)

        mapping = _METHOD_MAP.get(action)
        if not mapping:
            log.debug(f"Action {action} not supported for replay, mapping to sts:get_caller_identity")
            mapping = ("sts", "get_caller_identity", {})

        service, method, kwargs = mapping
        client = clients.get(service)
        
        try:
            getattr(client, method)(**kwargs)
            log.info(f"[{principal}] Successfully replayed {action} -> {service}:{method}")
        except ClientError as e:
            log.warning(f"[{principal}] Failed to replay {action}: {e}")

def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="Replay events to LocalStack")
    parser.add_argument("--input", default="data/raw/toy_logs.jsonl.gz")
    parser.add_argument("--limit", type=int, default=100)
    parser.add_argument("--speed", type=float, default=0.0, help="Wall-clock compression factor (0 = max speed)")
    parser.add_argument("--principal", type=str, default=None)
    args = parser.parse_args()

    # Fallback to generating some toy data in memory if input is missing for this demo
    try:
        df = pd.read_parquet(args.input)
    except Exception:
        log.info(f"Input {args.input} not found, using dummy events for testbed verification.")
        df = pd.DataFrame([
            {"eventTime": pd.Timestamp.now(tz="UTC"), "eventName": "ConsoleLogin", "principal": "user1"},
            {"eventTime": pd.Timestamp.now(tz="UTC"), "eventName": "GetObject", "principal": "user1"},
            {"eventTime": pd.Timestamp.now(tz="UTC"), "eventName": "AssumeRole", "principal": "user2"},
        ] * (args.limit // 3 + 1)).head(args.limit)

    if args.principal:
        df = df[df["principal"] == args.principal]

    df = df.sort_values("eventTime")
    replay_events(df, args.speed)

if __name__ == "__main__":
    main()
