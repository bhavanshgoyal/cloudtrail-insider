"""
run_ablation.py
---------------
Which component actually causes the gain? (Review 2: ablation, Review 3: error bars)

The proposed detector is run with its frozen settings (configs/proposed_final.yaml) and
with one change at a time, on the CERT r4.2 TEST windows of the 3 rolling origins, seeds
0-2. Isolation Forest (frozen baseline settings) is the reference row.

  Full (tuned)               frozen settings
  -C1 population baseline    per_principal=False  - every user judged against the population
  -C2 no calibration         calibrate=False      - raw family scores, no conformal p-values
  -C3 no fusion (pooled)     pool_families=True   - one pooled family, no cross-family fusion
  C4 toggled                 suppression on if the tuned model has it off, else off
  fusion: <other>            each fusion rule other than the tuned one
  -<family> family           leave one feature family out

DR@10 / P@10 intervals: bootstrap over insiders / test days (one fixed dataset; see
scripts/run_campaign.py). Output: results/ablation/ablation_runs.csv, ablation_summary.csv,
figures/ablation.png.

    python scripts/run_ablation.py
"""
from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from cti.detectors.proposed import BudgetAwareConformal
from cti.detectors.train import IsoForestDetector
from cti.eval.aggregate import pooled_rates, summarise
from cti.eval.evaluate import per_insider_table
from cti.eval.figures import plot_ablation
from cti.experiment import apply_frozen_configs, load_world, run_window
from cti.util.config import load_config
from cti.util.splits import all_splits

logging.basicConfig(level=logging.WARNING)
OUT = Path("results/ablation")
SEEDS = [0, 1, 2]
FAMILIES = ["identity", "resource", "temporal", "volume"]
FUSIONS = ["fisher", "min_p", "harmonic", "stouffer"]
METRICS = ["dr_at_b", "precision_at_b", "mttd_hours_median", "auc_roc"]


def variants(cfg: dict) -> dict[str, dict]:
    tuned = {**BudgetAwareConformal(cfg, 0).params}
    c4 = ({"-C4 no suppression": {"suppress_days": 0}} if tuned["suppress_days"] > 0
          else {"+C4 suppress 3 d": {"suppress_days": 3}})
    return {
        "Full (tuned)": {},
        "-C1 population baseline": {"per_principal": False},
        "-C2 no calibration": {"calibrate": False},
        "-C3 no fusion (pooled)": {"pool_families": True},
        **c4,
        **{f"fusion: {f}": {"fusion": f} for f in FUSIONS if f != tuned["fusion"]},
        **{f"-{f} family": {"families": [x for x in FAMILIES if x != f]} for f in FAMILIES},
    }


def main() -> None:
    cfg = apply_frozen_configs(load_config())
    var = variants(cfg)
    OUT.mkdir(parents=True, exist_ok=True)
    tidy, ins, days = [], [], []
    for seed in SEEDS:
        world = load_world(cfg, None, seed)
        for sp in all_splits(world.features["date"], cfg):
            dets = []
            for name, over in var.items():
                d = BudgetAwareConformal(cfg, seed, **over)
                d.name = name
                dets.append(d)
            dets.append(IsoForestDetector(cfg, seed))
            r = run_window(world, cfg, sp, "test", dets, budgets=[10, 50, 100], with_ci=False)
            tidy.append(r.tidy)
            ins.append(per_insider_table(r.results, r.ctx).assign(seed=seed, origin=sp.origin))
            for det, by_b in r.results.items():
                for b, br in by_b.items():
                    days.append(pd.DataFrame({"detector": det, "budget": b, "date": r.ctx.days,
                                              "day_tp": br.day_tp, "day_n": br.day_n}))
        print(f"ablation: seed {seed} done", flush=True)

    raw = pd.concat(tidy, ignore_index=True).rename(columns={"detector": "variant"})
    raw = raw[raw["metric"].isin(METRICS)]
    raw.to_csv(OUT / "ablation_runs.csv", index=False)
    summ = summarise(raw, ["workload", "variant", "budget", "metric"])
    summ["ci_lo"] = summ["ci_hi"] = float("nan")              # seeds are not independent here
    pooled = pooled_rates(pd.concat(ins).rename(columns={"detector": "variant"}),
                          pd.concat(days).rename(columns={"detector": "variant"}), col="variant")
    for r in pooled.itertuples(index=False):
        sel = (summ.variant == r.variant) & (summ.budget == r.budget) & (summ.metric == r.metric)
        summ.loc[sel, ["mean", "ci_lo", "ci_hi"]] = [r.mean, r.ci_lo, r.ci_hi]
    summ.to_csv(OUT / "ablation_summary.csv", index=False)
    pd.set_option("display.width", 200)
    print(summ[(summ.budget == 10) & summ.metric.isin(["dr_at_b", "precision_at_b"])]
          .pivot_table(index="variant", columns="metric", values="mean", sort=False).round(3).to_string())
    plot_ablation(summ, order=list(var) + ["isolation_forest"])


if __name__ == "__main__":
    main()
