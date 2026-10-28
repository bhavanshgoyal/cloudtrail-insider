"""
cti.ingest.toy
--------------
Tiny CERT-shaped synthetic datasets for tests and fast offline checks
(hand-made; contains no licensed CERT data).
"""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from cti.features.cert import SOURCES

COLS = {"logon": ["is_logon"], "device": ["is_connect"], "file": ["ext"],
        "email": ["n_ext", "size", "n_attach"], "http": ["domain"]}
DOMAINS = ["news.com", "intranet.dtaa.com", "weather.com", "search.com", "shop.com"]


def toy_events(n_users: int = 20, n_days: int = 120, seed: int = 0,
               insider: str = "U00", attack_from: int = 100) -> tuple[dict[str, pd.DataFrame], list[dict]]:
    """Benign office workers; ``insider`` copies files to USB after hours and visits a leak site."""
    rng = np.random.default_rng(seed)
    rows = {s: [] for s in SOURCES}
    base = pd.Timestamp("2010-01-04")
    users = [f"U{i:02d}" for i in range(n_users)]
    mal_days = []
    for d in range(n_days):
        day = base + pd.Timedelta(days=d)
        if day.weekday() >= 5 and rng.random() < 0.8:
            continue
        for i, u in enumerate(users):
            pc = f"PC-{i}"
            start = 8 + rng.normal(0.5, 0.3)
            t0 = day + pd.Timedelta(hours=start)
            rows["logon"].append((u, t0, pc, True))
            rows["logon"].append((u, t0 + pd.Timedelta(hours=8.5), pc, False))
            for _ in range(rng.poisson(15)):
                rows["http"].append((u, t0 + pd.Timedelta(minutes=float(rng.uniform(5, 500))), pc,
                                     DOMAINS[rng.integers(len(DOMAINS))]))
            for _ in range(rng.poisson(3)):
                rows["email"].append((u, t0 + pd.Timedelta(minutes=float(rng.uniform(5, 500))), pc,
                                      int(rng.random() < 0.1), int(rng.integers(1000, 30000)), 0))
            if u == insider and d >= attack_from and rng.random() < 0.5:
                night = day + pd.Timedelta(hours=22)
                rows["logon"].append((u, night, pc, True))
                rows["device"].append((u, night + pd.Timedelta(minutes=2), pc, True))
                for k in range(5):
                    rows["file"].append((u, night + pd.Timedelta(minutes=3 + k), pc, "doc"))
                rows["http"].append((u, night + pd.Timedelta(minutes=9), pc, "wikileaks.org"))
                mal_days.append(night)
    frames = {s: pd.DataFrame(rows[s], columns=["user", "t", "pc", *COLS[s]]) for s in SOURCES}
    gt = [{"principal_id": insider, "scenario_id": "S1",
           "malicious_days": sorted({t.strftime("%Y-%m-%d") for t in mal_days}),
           "first_event_time": min(mal_days).tz_localize("UTC").isoformat() if mal_days else None,
           "other_account_days": []}]
    return frames, gt


def write_parquet(frames: dict[str, pd.DataFrame], out: Path) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    for s, df in frames.items():
        df.to_parquet(out / f"{s}.parquet", index=False)
    return out
