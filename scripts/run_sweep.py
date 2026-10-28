"""
run_sweep.py
------------
Parameter sweeps on CERT r4.2: how does the result move with the alert budget, suppression,
calibration share and organisation size? (Review 2: sweep, Review 3: error bars)

  budget      B in {1,2,5,10,20,50,100,200}   all detectors   full data
  suppress    suppress_days in {0,1,3,7}      proposed        full data, B in {10,50}
  calfrac     cal_fraction in {.1,.2,.3,.4}   proposed        full data, B in {10,50}
  principals  250 / 500 / all users           all detectors   3 random user samples each (+ runtime)

All runs use the TEST windows of the 3 rolling origins and the frozen settings. On the full
data the seeds only change detector randomness, so those rows carry no interval (n_seeds is
reported, ci_lo / ci_hi are empty). The principals sweep draws a different random set of
users per seed: those are genuine replicates and keep their t-interval. The synthetic
"attack stealth" sweep has no CERT counterpart (the attacks are fixed) and is not run.

Output: results/sweeps/sweeps_runs.csv, sweeps_summary.csv, scale_timing.csv; figures/sweep_*.png.

    python scripts/run_sweep.py [--only budget suppress calfrac principals]
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd

from cti.detectors.proposed import BudgetAwareConformal
from cti.detectors.train import build_detectors
from cti.eval.aggregate import summarise
from cti.eval.figures import plot_sweeps
from cti.experiment import apply_frozen_configs, load_world, run_window, subsample_users
from cti.util.config import load_config
from cti.util.splits import all_splits

logging.basicConfig(level=logging.WARNING)
OUT = Path("results/sweeps")
METRICS = ["dr_at_b", "precision_at_b", "precision_oracle_at_b", "mttd_hours_median", "auc_roc",
           "n_insiders"]
PROPOSED = "proposed_budget_aware_conformal"


def _run(world, cfg, make_dets, budgets):
    out, timing = [], []
    for sp in all_splits(world.features["date"], cfg):
        r = run_window(world, cfg, sp, "test", make_dets(world.seed), budgets=budgets, with_ci=False)
        out.append(r.tidy)
        for det, sec in r.fit_seconds.items():
            timing.append(dict(workload=world.workload, seed=world.seed, origin=sp.origin, detector=det,
                               fit_score_seconds=sec, n_principals=world.features["principal"].nunique(),
                               n_rows=len(world.features)))
    return pd.concat(out), timing


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", default=None)
    args = ap.parse_args()
    cfg = apply_frozen_configs(load_config())
    OUT.mkdir(parents=True, exist_ok=True)
    wanted = set(args.only) if args.only else {"budget", "suppress", "calfrac", "principals"}
    rows, timing = [], []
    full = load_world(cfg, None, 0)

    def add(df, sweep, label, x):
        df = df[df["metric"].isin(METRICS)].copy()
        df.insert(0, "x", x)
        df.insert(0, "param", label)
        df.insert(0, "sweep", sweep)
        rows.append(df)

    if "budget" in wanted:
        df, _ = _run(full, cfg, lambda s: build_detectors({**cfg, "random_seed": s}), [1, 2, 5, 10, 20, 50, 100, 200])
        add(df, "budget", "alerts per day", 0)
        print("sweep budget done", flush=True)

    for sweep, key, values in (("suppress", "suppress_days", [0, 1, 3, 7]),
                               ("calfrac", "cal_fraction", [0.1, 0.2, 0.3, 0.4])):
        if sweep not in wanted:
            continue
        for v in values:
            df, _ = _run(full, cfg, lambda s, v=v, key=key: [BudgetAwareConformal(cfg, s, **{key: v})],
                         [10, 50])
            add(df, sweep, key, v)
            print(f"sweep {sweep}={v}", flush=True)

    if "principals" in wanted:
        n_all = full.features["principal"].nunique()
        for n in (250, 500, n_all):
            for seed in range(3 if n < n_all else 1):
                world = subsample_users(full, n, seed)
                world.seed = seed
                df, t = _run(world, cfg, lambda s: build_detectors({**cfg, "random_seed": s}), [10, 50])
                add(df.assign(seed=seed), "principals", "principals", n)
                timing += [{**x, "sweep_n": n} for x in t]
            print("sweep principals", n, flush=True)

    raw = pd.concat(rows, ignore_index=True)
    path = OUT / "sweeps_runs.csv"
    if path.exists():                       # merge with earlier partial runs (--only)
        old = pd.read_csv(path)
        raw = pd.concat([old[~old["sweep"].isin(raw["sweep"].unique())], raw], ignore_index=True)
    raw.to_csv(path, index=False)
    if timing:
        pd.DataFrame(timing).to_csv(OUT / "scale_timing.csv", index=False)
    summ = summarise(raw, ["sweep", "param", "x", "detector", "budget", "metric"])
    fixed = summ["sweep"] != "principals"
    summ.loc[fixed, ["ci_lo", "ci_hi"]] = np.nan
    summ.to_csv(OUT / "sweeps_summary.csv", index=False)
    pd.set_option("display.width", 220)
    print(summ[(summ.budget == 10) & (summ.metric == "dr_at_b") & (summ.sweep != "budget")]
          .pivot_table(index=["sweep", "x"], columns="detector", values="mean").round(3).to_string())
    plot_sweeps(summ, OUT / "scale_timing.csv")


if __name__ == "__main__":
    main()
