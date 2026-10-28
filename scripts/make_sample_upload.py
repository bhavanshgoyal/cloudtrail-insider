"""
make_sample_upload.py
---------------------
Cut a small, realistic upload for the frontend from the raw CERT r4.2 CSVs.

The scored part of the sample (everything after the first ``--history`` days) lies inside the
TEST window of the last rolling origin, i.e. after everything the saved model was fitted on,
so the frontend demo never scores training data. The window is the ``--days``-long span with
the most insiders active in its scored part; the sample keeps those insiders plus
``--users`` random other users. Labels go to a separate ``labels.csv`` (user, date) that the
frontend only uses if you upload it.

Output (licensed data - stays under the git-ignored data/ tree):
    data/samples/cert_sample/{logon,device,file,email,http}.csv, labels.csv, README.txt

    python scripts/make_sample_upload.py [--days 75 --history 14 --users 150]
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from cti.experiment import load_world
from cti.ingest.cert import SOURCES
from cti.util.config import load_config
from cti.util.splits import make_splits

OUT = Path("data/samples/cert_sample")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--days", type=int, default=75)
    ap.add_argument("--history", type=int, default=14)
    ap.add_argument("--users", type=int, default=150)
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    cfg = load_config()
    world = load_world(cfg, None, 0)
    split = make_splits(world.features["date"], cfg)
    test_start = pd.Timestamp(split.test_days[0])
    last_day = pd.Timestamp(split.test_days[-1])

    best = None
    for s in pd.date_range(test_start - pd.Timedelta(days=args.history), last_day - pd.Timedelta(days=args.days)):
        lo, hi = s + pd.Timedelta(days=args.history), s + pd.Timedelta(days=args.days)
        active = [g for g in world.ground_truth
                  if any(lo <= pd.Timestamp(d) < hi for d in g["malicious_days"])]
        if best is None or len(active) > len(best[1]):
            best = (s, active)
    start, insiders = best
    end = start + pd.Timedelta(days=args.days)
    ins_ids = {g["principal_id"] for g in insiders}
    victims = {u for g in insiders for u, _ in g.get("other_account_days", [])}
    others = np.setdiff1d(world.features["principal"].unique(), sorted(ins_ids | victims))
    keep = ins_ids | victims | set(np.random.default_rng(args.seed).choice(others, args.users, replace=False))
    print(f"window {start.date()} .. {(end - pd.Timedelta(days=1)).date()}, scored from "
          f"{(start + pd.Timedelta(days=args.history)).date()}; {len(ins_ids)} insiders, {len(keep)} users")

    OUT.mkdir(parents=True, exist_ok=True)
    raw = Path(cfg["cert"]["raw_dir"])
    for src in SOURCES:
        dst = OUT / f"{src}.csv"
        first, n = True, 0
        for chunk in pd.read_csv(raw / f"{src}.csv", dtype=str, chunksize=1_000_000, quoting=3):
            t = pd.to_datetime(chunk["date"], format="%m/%d/%Y %H:%M:%S")
            sel = chunk[chunk["user"].isin(keep) & (t >= start) & (t < end)]
            sel.to_csv(dst, mode="w" if first else "a", header=first, index=False, quoting=3)
            first, n = False, n + len(sel)
        print(f"  {src}: {n:,} rows")

    lab = [(g["principal_id"], d) for g in insiders for d in g["malicious_days"]]
    lab += [(u, d) for g in insiders for u, d in g.get("other_account_days", [])]
    lab = pd.DataFrame(lab, columns=["user", "date"])
    lab = lab[(pd.to_datetime(lab["date"]) >= start) & (pd.to_datetime(lab["date"]) < end)]
    lab.sort_values(["date", "user"]).to_csv(OUT / "labels.csv", index=False)
    (OUT / "README.txt").write_text(
        "Sample upload cut from the CMU CERT Insider Threat r4.2 dataset.\n"
        "Copyright (c) 2011 ExactData, LLC, All Rights Reserved. Do not redistribute.\n\n"
        + json.dumps({"start": str(start.date()), "end_exclusive": str(end.date()), "history_days": args.history,
                      "users": len(keep), "insiders": sorted(ins_ids),
                      "scenarios": sorted({g["scenario_id"] for g in insiders})}, indent=1))
    print(f"wrote {OUT}/")


if __name__ == "__main__":
    main()
