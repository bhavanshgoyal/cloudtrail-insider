"""
cti.ingest.synthetic
--------------------
Generates synthetic CloudTrail data mimicking benign and malicious behaviors.
Outputs the exact same schema as the CERT loader, allowing the pipeline to be
run entirely locally without the CERT archive.

Usage::
    python -m cti.ingest.synthetic --principals 1000 --days 180 --scenarios S1,S2,S3,S4 --seed 42 --out data/processed/synthetic.parquet
"""
import argparse
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

import numpy as np
import pandas as pd
from scipy.stats import vonmises

from cti.util.seeds import set_all_seeds, make_rng

log = logging.getLogger(__name__)

# Constants
ROLES = ["analyst", "developer", "admin", "backup-service", "ci-runner"]
REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-1"]

# Schema matches CERT output
SCHEMA = [
    "event_id", "event_time", "event_name", "event_source", "principal_id",
    "principal_type", "principal_arn", "role_name", "account_id", "source_ip",
    "user_agent", "aws_region", "resource_arn", "resource_type",
    "request_parameters", "error_code", "read_only", "bytes_transferred",
    "label", "scenario_id"
]

def generate_base_event(ts: datetime, principal: dict, rng: np.random.Generator) -> dict:
    """Generate a boilerplate benign event."""
    is_admin = principal["role"] == "admin"
    is_service = principal["role"] in ("backup-service", "ci-runner")
    
    source = rng.choice(["s3.amazonaws.com", "ec2.amazonaws.com", "sts.amazonaws.com", "iam.amazonaws.com"])
    name = "AssumeRole" if source == "sts.amazonaws.com" else "GetObject"
    if source == "ec2.amazonaws.com":
        name = rng.choice(["DescribeInstances", "RunInstances"])
    if source == "iam.amazonaws.com" and is_admin:
        name = rng.choice(["CreateUser", "AttachUserPolicy"])

    err = None
    if rng.random() < principal.get("error_rate", 0.01):
        err = "AccessDenied"
        
    return {
        "event_id": str(uuid.uuid4()),
        "event_time": ts,
        "event_name": name,
        "event_source": source,
        "principal_id": principal["id"],
        "principal_type": "IAMRole" if is_service else "IAMUser",
        "principal_arn": f"arn:aws:iam::123456789012:user/{principal['id']}",
        "role_name": principal["role"],
        "account_id": "123456789012",
        "source_ip": principal.get("ip", f"192.168.1.{rng.integers(1, 255)}"),
        "user_agent": "aws-cli/2.0" if is_service else "Mozilla/5.0",
        "aws_region": rng.choice(REGIONS),
        "resource_arn": f"arn:aws:s3:::bucket-{rng.zipf(1.5)}",
        "resource_type": "AWS::S3::Bucket",
        "request_parameters": "{}",
        "error_code": err,
        "read_only": name.startswith(("Get", "Describe", "List")),
        "bytes_transferred": rng.integers(100, 10000),
        "label": 0,
        "scenario_id": None
    }

def inject_s1_exfil(principal: dict, start_time: datetime, rng: np.random.Generator) -> List[dict]:
    """S1: exfil-after-hours (dormant -> ConsoleLogin -> GetObject -> CreateSnapshot -> Modify to public)"""
    events = []
    ts = start_time.replace(hour=3) # After hours
    
    # 1. Console Login
    events.append(generate_base_event(ts, principal, rng) | {
        "event_name": "ConsoleLogin", "event_source": "signin.amazonaws.com",
        "label": 1, "scenario_id": "S1"
    })
    
    # 2. Mass GetObject
    for _ in range(50):
        ts += timedelta(seconds=int(rng.integers(1, 5)))
        events.append(generate_base_event(ts, principal, rng) | {
            "event_name": "GetObject", "event_source": "s3.amazonaws.com",
            "resource_arn": "arn:aws:s3:::finance-archive",
            "label": 1, "scenario_id": "S1"
        })
        
    # 3. CreateSnapshot & Modify
    ts += timedelta(minutes=5)
    events.append(generate_base_event(ts, principal, rng) | {
        "event_name": "CreateSnapshot", "event_source": "ec2.amazonaws.com",
        "label": 1, "scenario_id": "S1"
    })
    ts += timedelta(seconds=10)
    events.append(generate_base_event(ts, principal, rng) | {
        "event_name": "ModifySnapshotAttribute", "event_source": "ec2.amazonaws.com",
        "request_parameters": '{"attributeType":"CREATE_VOLUME_PERMISSION","operationType":"add","userGroups":["all"]}',
        "label": 1, "scenario_id": "S1"
    })
    return events

def inject_s2_departing(principal: dict, start_time: datetime, rng: np.random.Generator) -> List[dict]:
    """S2: departing-insider (gradual ramp GetObject over 3 weeks -> PutObject external)"""
    events = []
    ts = start_time
    for week in range(3):
        vol = (week + 1) * 20
        for _ in range(vol):
            ts += timedelta(hours=int(rng.integers(1, 4)))
            events.append(generate_base_event(ts, principal, rng) | {
                "event_name": "GetObject", "event_source": "s3.amazonaws.com",
                "label": 1, "scenario_id": "S2"
            })
    
    # PutObject external
    ts += timedelta(hours=1)
    events.append(generate_base_event(ts, principal, rng) | {
        "event_name": "PutObject", "event_source": "s3.amazonaws.com",
        "resource_arn": "arn:aws:s3:::external-untrusted-bucket",
        "label": 1, "scenario_id": "S2"
    })
    return events

def inject_s3_privesc(principal: dict, start_time: datetime, rng: np.random.Generator) -> List[dict]:
    """S3: privilege-escalation (CreateAccessKey -> AssumeRole -> SendEmail)"""
    events = []
    ts = start_time
    
    events.append(generate_base_event(ts, principal, rng) | {
        "event_name": "CreateAccessKey", "event_source": "iam.amazonaws.com",
        "label": 1, "scenario_id": "S3"
    })
    ts += timedelta(minutes=2)
    events.append(generate_base_event(ts, principal, rng) | {
        "event_name": "AssumeRole", "event_source": "sts.amazonaws.com",
        "role_name": "admin",
        "label": 1, "scenario_id": "S3"
    })
    ts += timedelta(minutes=2)
    events.append(generate_base_event(ts, principal, rng) | {
        "event_name": "SendEmail", "event_source": "ses.amazonaws.com",
        "request_parameters": '{"destinations":["external@attacker.com", "other@attacker.com"]}',
        "label": 1, "scenario_id": "S3"
    })
    return events

def inject_s4_stuffing(principal: dict, start_time: datetime, rng: np.random.Generator) -> List[dict]:
    """S4: credential-stuffing (burst AccessDenied new IP -> success)"""
    events = []
    ts = start_time
    attacker_ip = "203.0.113.42"
    
    for _ in range(15):
        ts += timedelta(seconds=int(rng.integers(1, 3)))
        events.append(generate_base_event(ts, principal, rng) | {
            "event_name": "ConsoleLogin", "event_source": "signin.amazonaws.com",
            "source_ip": attacker_ip,
            "error_code": "AccessDenied",
            "label": 1, "scenario_id": "S4"
        })
        
    ts += timedelta(seconds=5)
    events.append(generate_base_event(ts, principal, rng) | {
        "event_name": "ConsoleLogin", "event_source": "signin.amazonaws.com",
        "source_ip": attacker_ip,
        "error_code": None, # Success
        "label": 1, "scenario_id": "S4"
    })
    return events

def generate_dataset(n_principals: int, n_days: int, scenarios: List[str], insider_rate: float, seed: int) -> Tuple[pd.DataFrame, dict]:
    rng = make_rng(seed)
    start_date = datetime(2023, 1, 1, tzinfo=timezone.utc)
    
    principals = []
    for i in range(n_principals):
        role = rng.choice(ROLES)
        mu = 14 if role in ("backup-service", "ci-runner") else 10 # Mean working hour
        kappa = 0.5 if role == "admin" else 5.0 # Concentration
        
        principals.append({
            "id": f"usr-{i:05d}",
            "role": role,
            "mu": mu,
            "kappa": kappa,
            "error_rate": 0.05 if role == "developer" else 0.01,
            "events_per_day": rng.integers(5, 50) if role != "ci-runner" else rng.integers(100, 500)
        })
        
    all_events = []
    ground_truth = []
    
    # 1. Benign generation
    for day in range(n_days):
        current_date = start_date + timedelta(days=day)
        is_weekend = current_date.weekday() >= 5
        
        for p in principals:
            if is_weekend and p["role"] not in ("backup-service", "admin"):
                continue
            
            n_events = p["events_per_day"]
            if p["role"] == "admin" and rng.random() < 0.1:
                n_events *= 3 # Irregular on-call admin burst
                
            # Sample hours from von Mises
            hours = vonmises.rvs(p["kappa"], loc=p["mu"]/24.0 * 2 * np.pi, size=n_events, random_state=rng)
            hours = (hours / (2 * np.pi) * 24) % 24
            
            for h in hours:
                ts = current_date + timedelta(hours=float(h), minutes=int(rng.integers(0, 59)))
                all_events.append(generate_base_event(ts, p, rng))
                
    # 2. Scenario injection
    n_insiders = int(n_principals * insider_rate)
    insider_principals = rng.choice(principals, size=n_insiders, replace=False)
    
    scenario_map = {
        "S1": inject_s1_exfil,
        "S2": inject_s2_departing,
        "S3": inject_s3_privesc,
        "S4": inject_s4_stuffing
    }
    
    for i, p in enumerate(insider_principals):
        scenario = scenarios[i % len(scenarios)]
        inject_fn = scenario_map.get(scenario)
        if not inject_fn:
            continue
            
        low_day = min(14, max(1, n_days - 5))
        high_day = max(low_day + 1, n_days - 21)
        inject_day = int(rng.integers(low_day, high_day)) # Ensure buffer
        start_ts = start_date + timedelta(days=inject_day, hours=10)
        
        malicious_events = inject_fn(p, start_ts, rng)
        all_events.extend(malicious_events)
        
        if malicious_events:
            ground_truth.append({
                "principal_id": p["id"],
                "scenario_id": scenario,
                "first_event_id": malicious_events[0]["event_id"],
                "first_event_time": malicious_events[0]["event_time"].isoformat()
            })
            
    # Compile
    df = pd.DataFrame(all_events)
    df["event_time"] = pd.to_datetime(df["event_time"], utc=True)
    df = df.sort_values("event_time").reset_index(drop=True)
    
    return df, ground_truth

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--principals", type=int, default=1000)
    parser.add_argument("--days", type=int, default=180)
    parser.add_argument("--scenarios", type=str, default="S1,S2,S3,S4")
    parser.add_argument("--insider-rate", type=float, default=0.02)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=str, default="data/processed/synthetic.parquet")
    args = parser.parse_args()
    
    set_all_seeds(args.seed)
    
    scenarios = args.scenarios.split(",")
    df, gt = generate_dataset(args.principals, args.days, scenarios, args.insider_rate, args.seed)
    
    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Rename to match expected pipeline if needed (or stick to exact schema)
    df.to_parquet(out_path, index=False)
    
    gt_path = out_path.parent / "ground_truth.json"
    with open(gt_path, "w") as f:
        json.dump(gt, f, indent=2)
        
    log.info(f"Wrote {len(df)} events to {out_path}")
    log.info(f"Wrote {len(gt)} ground truth records to {gt_path}")

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
