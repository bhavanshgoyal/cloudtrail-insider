"""
run_ablation.py
---------------
Which component actually causes the gain? (Review 2: ablation, Review 3: error bars)

The proposed detector is run with its frozen settings (configs/proposed_final.yaml) and
with one change at a time, on the TEST windows of W1_baseline and W2_stealthy,
seeds 0-2, 3 rolling origins. Isolation Forest (frozen baseline settings) is the reference row.

  Full                       frozen settings
  -C1 (population baseline)  per_principal=False  - every identity judged against the population
  -C2 (no calibration)       calibrate=False      - raw family scores, no conformal p-values
  -C3 (no fusion)            pool_families=True   - one pooled family, no cross-family fusion
  +C4 (suppress 3 d)         suppress_days=3      - the tuned model has C4 OFF; this ADDS it
  fusion = fisher / harmonic / stouffer   alternative fusion rules instead of the tuned min-p
  -identity / -resource / -temporal / -volume    leave one feature family out

Output: results/ablation/ablation_runs.csv (raw), ablation_summary.csv (mean/CI over seeds),
figures/ablation.png.

    python scripts/run_ablation.py
"""
from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd

from cti.detectors.proposed import BudgetAwareConformal
from cti.detectors.train import IsoForestDetector
from cti.eval.aggregate import summarise
from cti.eval.figures import plot_ablation
from cti.experiment import apply_frozen_configs, load_world, run_window
from cti.util.config import load_config
from cti.util.splits import all_splits

logging.basicConfig(level=logging.WARNING)
OUT = Path("results/ablation")
WORKLOADS = ["W1_baseline", "W2_stealthy"]
SEEDS = [0, 1, 2]
FAMILIES = ["identity", "resource", "temporal", "volume"]

VARIANTS: dict[str, dict] = {
    "Full (tuned)": {},
    "-C1 population baseline": {"per_principal": False},
    "-C2 no calibration": {"calibrate": False},
    "-C3 no fusion (pooled)": {"pool_families": True},
    "+C4 suppress 3 d": {"suppress_days": 3},
    "fusion: Fisher": {"fusion": "fisher"},
    "fusion: harmonic": {"fusion": "harmonic"},
    "fusion: Stouffer": {"fusion": "stouffer"},
    **{f"-{f} family": {"families": [x for x in FAMILIES if x != f]} for f in FAMILIES},
}
METRICS = ["dr_at_b", "precision_at_b", "mttd_hours_median", "auc_roc"]


def main() -> None:
    cfg = apply_frozen_configs(load_config())
    OUT.mkdir(parents=True, exist_ok=True)
    rows = []
    for w in WORKLOADS:
        for seed in SEEDS:
            world = load_world(cfg, w, seed)
            for sp in all_splits(world.features["date"], cfg):
                dets = []
                for name, over in VARIANTS.items():
                    d = BudgetAwareConformal(cfg, seed, **over)
                    d.name = name
                    dets.append(d)
                dets.append(IsoForestDetector(cfg, seed))
                r = run_window(world, cfg, sp, "test", dets, budgets=[10, 50, 100], with_ci=False)
                rows.append(r.tidy)
            print(f"ablation: {w} seed {seed} done", flush=True)
    raw = pd.concat(rows, ignore_index=True).rename(columns={"detector": "variant"})
    raw = raw[raw["metric"].isin(METRICS)]
    raw.to_csv(OUT / "ablation_runs.csv", index=False)
    summ = summarise(raw, ["workload", "variant", "budget", "metric"])
    summ.to_csv(OUT / "ablation_summary.csv", index=False)
    pd.set_option("display.width", 200)
    print(summ[(summ.budget == 10) & summ.metric.isin(["dr_at_b", "precision_at_b"])]
          .pivot_table(index=["workload", "variant"], columns="metric", values="mean", sort=False)
          .round(3).to_string())
    plot_ablation(summ, order=list(VARIANTS) + ["isolation_forest"])


if __name__ == "__main__":
    main()
