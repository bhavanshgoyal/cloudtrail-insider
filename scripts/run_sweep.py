"""
run_sweep.py
------------
Parameter sweeps: how does the result move with budget, suppression, calibration share,
scale and attack stealth? (Review 2: sweep, Review 3: multiple workloads / error bars)

  budget      B in {1,2,5,10,20,50,100,200}   all detectors      W1, seeds 0-4
  suppress    suppress_days in {0,1,3,7}      proposed           W1, seeds 0-2, B in {10,50}
  calfrac     cal_fraction in {.1,.2,.3,.4}   proposed           W1, seeds 0-2, B in {10,50}
  principals  250 / 500 / 1000 / 2000 / 3000  all detectors      seeds 0-2 (+ runtime)
  stealth     attack magnitude x{.25,.5,1,1.5} all detectors      1000 principals, seeds 0-2

All runs use the TEST windows, 3 rolling origins, and the frozen settings. The contamination
sweep of the earlier (invalid) version is intentionally gone: contamination only moves
sklearn's decision threshold, not the score, so a ranking metric cannot change with it.

Output: results/sweeps/sweeps_runs.csv, sweeps_summary.csv, scale_timing.csv; figures/sweep_*.png.

    python scripts/run_sweep.py [--only budget suppress calfrac principals stealth]
"""
from __future__ import annotations

import argparse
import copy
import logging
from pathlib import Path

import pandas as pd

from cti.detectors.proposed import BudgetAwareConformal
from cti.detectors.train import build_detectors
from cti.eval.aggregate import summarise
from cti.eval.figures import plot_sweeps
from cti.experiment import apply_frozen_configs, load_world, run_window
from cti.util.config import load_config
from cti.util.splits import all_splits

logging.basicConfig(level=logging.WARNING)
OUT = Path("results/sweeps")
METRICS = ["dr_at_b", "precision_at_b", "precision_oracle_at_b", "mttd_hours_median", "auc_roc",
           "n_insiders"]
PROPOSED = "proposed_budget_aware_conformal"


def _run(cfg, workload, seed, make_dets, budgets):
    world = load_world(cfg, workload, seed)
    out, timing = [], []
    for sp in all_splits(world.features["date"], cfg):
        r = run_window(world, cfg, sp, "test", make_dets(seed), budgets=budgets, with_ci=False)
        out.append(r.tidy)
        for det, sec in r.fit_seconds.items():
            timing.append(dict(workload=workload, seed=seed, origin=sp.origin, detector=det,
                               fit_score_seconds=sec, n_principals=world.features["principal"].nunique(),
                               n_events=len(world.events)))
    return pd.concat(out), timing


def _with_workload(cfg, name, base, **changes):
    c = copy.deepcopy(cfg)
    c["synthetic"]["workloads"][name] = {**c["synthetic"]["workloads"][base], **changes}
    return c


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", nargs="*", default=None)
    args = ap.parse_args()
    base_cfg = apply_frozen_configs(load_config())
    OUT.mkdir(parents=True, exist_ok=True)
    wanted = set(args.only) if args.only else {"budget", "suppress", "calfrac", "principals", "stealth"}
    rows, timing = [], []

    def add(df, sweep, label, x):
        df = df[df["metric"].isin(METRICS)].copy()
        df.insert(0, "x", x)
        df.insert(0, "param", label)
        df.insert(0, "sweep", sweep)
        rows.append(df)

    if "budget" in wanted:
        for seed in range(5):
            df, _ = _run(base_cfg, "W1_baseline", seed, lambda s: build_detectors(base_cfg),
                         [1, 2, 5, 10, 20, 50, 100, 200])
            add(df, "budget", "alerts per day", 0)
            print("sweep budget seed", seed, flush=True)

    for sweep, key, values in (("suppress", "suppress_days", [0, 1, 3, 7]),
                               ("calfrac", "cal_fraction", [0.1, 0.2, 0.3, 0.4])):
        if sweep not in wanted:
            continue
        for v in values:
            for seed in range(3):
                df, _ = _run(base_cfg, "W1_baseline", seed,
                             lambda s, v=v, key=key: [BudgetAwareConformal(base_cfg, s, **{key: v})],
                             [10, 50])
                add(df, sweep, key, v)
            print(f"sweep {sweep}={v}", flush=True)

    if "principals" in wanted:
        for n in (250, 500, 1000, 2000, 3000):
            name = {1000: "W1_baseline", 3000: "W3_scale"}.get(n, f"W1_n{n}")
            cfg = base_cfg if n in (1000, 3000) else _with_workload(base_cfg, name, "W1_baseline", principals=n)
            for seed in range(3):
                df, t = _run(cfg, name, seed, lambda s, cfg=cfg: build_detectors(cfg), [10, 50])
                add(df, "principals", "principals", n)
                timing += [{**x, "sweep_n": n} for x in t]
            print("sweep principals", n, flush=True)

    if "stealth" in wanted:
        for st in (0.25, 0.5, 1.0, 1.5):
            name = f"W1_st{st}"
            cfg = _with_workload(base_cfg, name, "W1_baseline", stealth=st)
            for seed in range(3):
                df, _ = _run(cfg, name, seed, lambda s, cfg=cfg: build_detectors(cfg), [10, 50])
                add(df, "stealth", "attack magnitude x", st)
            print("sweep stealth", st, flush=True)

    raw = pd.concat(rows, ignore_index=True)
    # merge with earlier partial runs so --only can be used incrementally
    path = OUT / "sweeps_runs.csv"
    if path.exists():
        old = pd.read_csv(path)
        raw = pd.concat([old[~old["sweep"].isin(raw["sweep"].unique())], raw], ignore_index=True)
    raw.to_csv(path, index=False)
    if timing:
        tpath = OUT / "scale_timing.csv"
        pd.DataFrame(timing).to_csv(tpath, index=False)
    summ = summarise(raw, ["sweep", "param", "x", "detector", "budget", "metric"])
    summ.to_csv(OUT / "sweeps_summary.csv", index=False)
    pd.set_option("display.width", 220)
    print(summ[(summ.budget == 10) & (summ.metric == "dr_at_b") & (summ.sweep != "budget")]
          .pivot_table(index=["sweep", "x"], columns="detector", values="mean").round(3).to_string())
    plot_sweeps(summ, OUT / "scale_timing.csv")


if __name__ == "__main__":
    main()
