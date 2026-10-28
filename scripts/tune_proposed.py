"""
tune_proposed.py
----------------
Model selection on VALIDATION windows only (never the test window).

Protocol (declared before running)
  * data: CERT r4.2, the 3 rolling *tuning* splits inside the development
    period (every day before the earliest test day of any evaluation origin,
    see cti.util.splits.tuning_splits); detector seeds 100 and 101 (disjoint
    from the campaign seeds 0-4) -> 6 validation windows;
  * phase "val": fit on train, evaluate on val;
  * criterion: mean DR@10 over the 6 windows; ties (within 0.005) broken by
    mean P@10;
  * proposed detector: coordinate descent over the grid below, two passes,
    starting from the defaults in cti.detectors.proposed.DEFAULTS;
  * Isolation Forest baseline: the full small grid below under the same
    protocol, so the comparison is not "tuned method vs untuned baseline".

Every configuration evaluated is appended to results/tuning_log.csv. The
selected settings are written to configs/proposed_final.yaml and
configs/baseline_final.yaml, which the campaign (Phase 6) must use unchanged.

Usage::

    python scripts/tune_proposed.py
"""
from __future__ import annotations

import copy
import datetime as dt
import hashlib
import itertools
import json
import logging
from pathlib import Path

import pandas as pd
import yaml

from cti.detectors.proposed import DEFAULTS, BudgetAwareConformal
from cti.detectors.train import IsoForestDetector
from cti.experiment import load_world, run_window
from cti.util.config import load_config
from cti.util.splits import tuning_splits

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(message)s")
log = logging.getLogger("tune")

TUNING_SEEDS = [100, 101]
LOG_PATH = Path("results/tuning_log.csv")

PROPOSED_GRID = {
    "family_agg": ["l2", "max", "sum"],
    "fusion": ["fisher", "min_p", "harmonic", "stouffer"],
    "suppress_days": [0, 1, 3, 7],
    "scale_alpha": [0.25, 0.5, 1.0],
    "shrink_k": [3.0, 10.0, 30.0],
    "cal_fraction": [0.2, 0.3, 0.4],
    "transform": ["log1p", "none"],
}
IF_GRID = {
    "n_estimators": [100, 200, 400],
    "max_samples": ["auto", 1024, 4096],
    "max_features": [0.5, 1.0],
}


def _hash(d: dict) -> str:
    return hashlib.sha256(json.dumps(d, sort_keys=True, default=str).encode()).hexdigest()[:10]


class Tuner:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.worlds = [load_world(cfg, None, s) for s in TUNING_SEEDS]
        self.splits = {w.seed: tuning_splits(w.features["date"], cfg) for w in self.worlds}
        for sp in self.splits[TUNING_SEEDS[0]]:
            print("tuning", sp.describe(), flush=True)
        self.seen: dict[str, tuple[float, float]] = {}

    def evaluate(self, detector_name: str, make, params: dict) -> tuple[float, float]:
        key = _hash({"d": detector_name, **params})
        if key in self.seen:
            return self.seen[key]
        rows = []
        for w in self.worlds:
            for sp in self.splits[w.seed]:
                r = run_window(w, self.cfg, sp, "val", [make(params, w.seed)], budgets=[10], with_ci=False)
                rows.append(r.tidy)
        df = pd.concat(rows)
        m = df[df["budget"] == 10].groupby("metric")["value"].mean()
        auc = df[df["metric"] == "auc_roc"]["value"].mean()
        dr, p = float(m["dr_at_b"]), float(m["precision_at_b"])
        rec = dict(timestamp=dt.datetime.now().isoformat(timespec="seconds"), detector=detector_name,
                   config_hash=key, params=json.dumps(params, sort_keys=True, default=str),
                   n_windows=len(rows), val_dr_at_10=round(dr, 4), val_p_at_10=round(p, 5),
                   val_auc_roc=round(float(auc), 4))
        pd.DataFrame([rec]).to_csv(LOG_PATH, mode="a", index=False, header=not LOG_PATH.exists())
        print(f"  {detector_name:10s} DR@10={dr:.3f} P@10={p:.4f} AUC={auc:.3f}  {params}", flush=True)
        self.seen[key] = (dr, p)
        return dr, p


def _better(a: tuple[float, float], b: tuple[float, float]) -> bool:
    """Is result a strictly better than b under the declared criterion?"""
    if a[0] > b[0] + 0.005:
        return True
    return abs(a[0] - b[0]) <= 0.005 and a[1] > b[1]


def tune_proposed(t: Tuner) -> dict:
    make = lambda p, seed: BudgetAwareConformal(t.cfg, seed, **p)  # noqa: E731
    best = {k: DEFAULTS[k] for k in PROPOSED_GRID}
    best_res = t.evaluate("proposed", make, best)
    for pass_no in (1, 2):
        print(f"proposed: coordinate-descent pass {pass_no}", flush=True)
        changed = False
        for param, values in PROPOSED_GRID.items():
            for v in values:
                cand = {**best, param: v}
                res = t.evaluate("proposed", make, cand)
                if _better(res, best_res):
                    best, best_res, changed = cand, res, True
        if not changed:
            break
    print(f"proposed selected: {best}  val DR@10={best_res[0]:.3f} P@10={best_res[1]:.4f}")
    return best


def tune_if(t: Tuner) -> dict:
    def make(p, seed):
        c = copy.deepcopy(t.cfg)
        c["detectors"]["isolation_forest"].update(p)
        return IsoForestDetector(c, seed)

    best, best_res = None, (-1.0, -1.0)
    print("isolation_forest: full grid", flush=True)
    for combo in itertools.product(*IF_GRID.values()):
        p = dict(zip(IF_GRID, combo))
        res = t.evaluate("isolation_forest", make, p)
        if _better(res, best_res):
            best, best_res = p, res
    print(f"isolation_forest selected: {best}  val DR@10={best_res[0]:.3f} P@10={best_res[1]:.4f}")
    return best


def main() -> None:
    cfg = load_config()
    t = Tuner(cfg)
    prop = tune_proposed(t)
    iso = tune_if(t)
    header = (f"# Frozen by scripts/tune_proposed.py on {dt.date.today()} (validation windows of the\n"
              f"# CERT development period only, seeds {TUNING_SEEDS}, 3 tuning splits). Do not edit by\n"
              f"# hand; the campaign must use these values unchanged. Log: {LOG_PATH}\n")
    Path("configs/proposed_final.yaml").write_text(
        header + yaml.safe_dump({"detectors": {"proposed": prop}}, sort_keys=False))
    Path("configs/baseline_final.yaml").write_text(
        header + yaml.safe_dump({"detectors": {"isolation_forest": iso}}, sort_keys=False))
    print("wrote configs/proposed_final.yaml and configs/baseline_final.yaml")


if __name__ == "__main__":
    main()
