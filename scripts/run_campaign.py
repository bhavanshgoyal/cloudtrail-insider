"""
run_campaign.py
---------------
Final experimental campaign (Review 3 statistics).

  workloads  W1_baseline, W2_stealthy, W3_scale, W4_noisy   (cfg synthetic.workloads)
  seeds      0 1 2 3 4                                       (disjoint from tuning seeds 100/101)
  origins    3 rolling temporal origins
  detectors  isolation_forest, lof, autoencoder, rule_baseline, proposed
  protocol   fit on train+val, evaluate the TEST window with the settings frozen in
             configs/proposed_final.yaml and configs/baseline_final.yaml

Per (workload, seed) the raw per-origin results are written to
results/campaign/runs/<workload>_s<seed>.{csv,pkl}; finished worlds are skipped on
re-run (use --force to redo). ``--aggregate-only`` rebuilds the summaries.

Aggregation unit: runs of one seed share data across the 3 origins (overlapping test
windows), so origins are averaged *within* a seed first; the 5 seeds are the independent
replicates. Reported: mean, std and 95% t-interval over seeds (n=5).

    python scripts/run_campaign.py                       # everything
    python scripts/run_campaign.py --workloads W1_baseline --seeds 0 1
    python scripts/run_campaign.py --aggregate-only
"""
from __future__ import annotations

import argparse
import gc
import logging
import pickle
import time
from pathlib import Path

import numpy as np
import pandas as pd
from scipy import stats

from cti.detectors.train import build_detectors
from cti.eval.evaluate import per_insider_table
from cti.experiment import apply_frozen_configs, load_world, run_window
from cti.util.config import load_config
from cti.util.seeds import set_all_seeds
from cti.util.splits import all_splits, assert_test_positives

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("cti.experiment").setLevel(logging.INFO)
log = logging.getLogger("campaign")

OUT = Path("results/campaign")
PROPOSED = "proposed_budget_aware_conformal"
BASELINE = "isolation_forest"
POINT_METRICS = ["dr_at_b", "precision_at_b", "precision_oracle_at_b", "mttd_hours_median",
                 "mttd_hours_mean", "alerts_per_day", "auc_roc", "pr_auc", "n_insiders", "n_detected"]


def run_world(cfg: dict, workload: str, seed: int, force: bool) -> None:
    runs = OUT / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    stem = runs / f"{workload}_s{seed}"
    if stem.with_suffix(".csv").exists() and not force:
        log.warning("skip %s seed %d (done)", workload, seed)
        return
    set_all_seeds(seed)
    t0 = time.time()
    world = load_world(cfg, workload, seed)
    tidy, insiders, raw, timing = [], [], {}, []
    for sp in all_splits(world.features["date"], cfg):
        n_ins = assert_test_positives(sp, world.ground_truth, cfg)
        r = run_window(world, cfg, sp, "test", build_detectors(cfg), with_ci=False)
        tidy.append(r.tidy)
        pi = per_insider_table(r.results, r.ctx)
        insiders.append(pi.assign(workload=workload, seed=seed, origin=sp.origin))
        for det, by_b in r.results.items():
            for b, br in by_b.items():
                raw[(sp.origin, det, b)] = dict(detected=br.detected, day_tp=br.day_tp, day_n=br.day_n,
                                                ttd=br.ttd_hours)
        for det, sec in r.fit_seconds.items():
            timing.append(dict(workload=workload, seed=seed, origin=sp.origin, detector=det,
                               fit_score_seconds=sec, n_principals=world.features["principal"].nunique(),
                               n_events=len(world.events), n_rows_test=len(r.scores[det]), n_insiders_test=n_ins))
    pd.concat(tidy).to_csv(stem.with_suffix(".csv"), index=False)
    pd.concat(insiders).to_csv(f"{stem}_insiders.csv", index=False)
    pd.DataFrame(timing).to_csv(f"{stem}_timing.csv", index=False)
    with open(stem.with_suffix(".pkl"), "wb") as fh:
        pickle.dump(raw, fh)
    log.warning("done %s seed %d in %.0fs", workload, seed, time.time() - t0)
    del world
    gc.collect()


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def _t_interval(x: np.ndarray, conf: float = 0.95) -> tuple[float, float]:
    x = x[np.isfinite(x)]
    if len(x) < 2:
        return np.nan, np.nan
    half = stats.t.ppf(0.5 + conf / 2, len(x) - 1) * x.std(ddof=1) / np.sqrt(len(x))
    return float(x.mean() - half), float(x.mean() + half)


def load_runs() -> pd.DataFrame:
    files = sorted((OUT / "runs").glob("*_s[0-9]*.csv"))
    files = [f for f in files if not f.stem.endswith(("_insiders", "_timing"))]
    if not files:
        raise SystemExit("no campaign runs found; run the campaign first")
    return pd.concat([pd.read_csv(f) for f in files], ignore_index=True)


def summarise(df: pd.DataFrame) -> pd.DataFrame:
    """One row per (workload, detector, budget, metric): mean/std/95% CI over seeds."""
    df = df[df["metric"].isin(POINT_METRICS)]
    per_seed = (df.groupby(["workload", "detector", "budget", "metric", "seed"])["value"]
                .mean().reset_index())                      # average origins within a seed
    rows = []
    for (w, d, b, m), g in per_seed.groupby(["workload", "detector", "budget", "metric"]):
        x = g["value"].to_numpy(dtype=float)
        lo, hi = _t_interval(x)
        n_runs = int(df[(df.workload == w) & (df.detector == d) & (df.budget == b) & (df.metric == m)]
                     ["value"].notna().sum())
        rows.append(dict(workload=w, detector=d, budget=b, metric=m, n_seeds=len(x), n_runs=n_runs,
                         mean=float(np.nanmean(x)), std=float(np.nanstd(x, ddof=1)) if len(x) > 1 else np.nan,
                         ci_lo=lo, ci_hi=hi, min=float(np.nanmin(x)), max=float(np.nanmax(x))))
    return pd.DataFrame(rows)


def _cluster_bootstrap(per_seed_a: np.ndarray, per_seed_b: np.ndarray, kind: str, n: int = 10000,
                       seed: int = 0) -> tuple[float, float, float]:
    """Paired bootstrap over seeds of the relative (or absolute) difference of means."""
    rng = np.random.default_rng(seed)
    k = len(per_seed_a)

    def stat(a, b):
        with np.errstate(invalid="ignore", divide="ignore"):
            return (a.mean() - b.mean()) / b.mean() if kind == "relative" else a.mean() - b.mean()

    point = stat(per_seed_a, per_seed_b)
    boots = []
    for _ in range(n):
        idx = rng.integers(0, k, k)
        boots.append(stat(per_seed_a[idx], per_seed_b[idx]))
    boots = np.asarray(boots)
    boots = boots[np.isfinite(boots)]
    if len(boots) == 0:
        return point, np.nan, np.nan
    return float(point), float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))


def hypotheses(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """H1 (DR@10 >= +40%, P@10 >= +30% vs IF) and H2 (median MTTD@10 >= 25% lower), per workload.

    A hypothesis is SUPPORTED only if the whole 95% interval lies beyond the threshold.
    The bootstrap resamples the 5 seeds (origins averaged within a seed): the conservative
    choice, because origins of one seed share data. With n = 5 clusters the interval is coarse;
    that is stated in the paper's limitations.
    """
    per_seed = (df[df["budget"] == 10].groupby(["workload", "detector", "metric", "seed"])["value"]
                .mean().reset_index())
    rows = []
    for w, gw in per_seed.groupby("workload"):
        def vec(det, metric):
            g = gw[(gw.detector == det) & (gw.metric == metric)].sort_values("seed")
            return g["value"].to_numpy(dtype=float)

        for hyp, metric, thr, direction in (("H1a", "dr_at_b", 0.40, "gain"),
                                            ("H1b", "precision_at_b", 0.30, "gain"),
                                            ("H2", "mttd_hours_median", 0.25, "reduction")):
            a, b = vec(PROPOSED, metric), vec(BASELINE, metric)
            if len(a) == 0 or len(a) != len(b):
                continue
            kind = "relative" if np.nanmean(b) > 0 else "absolute"
            point, lo, hi = _cluster_bootstrap(a, b, kind)
            if direction == "gain":
                supported = bool(kind == "relative" and np.isfinite(lo) and lo > thr)
            else:
                supported = bool(kind == "relative" and np.isfinite(hi) and hi < -thr)
            rows.append(dict(workload=w, hypothesis=hyp, metric=metric + "@10", threshold=thr if direction == "gain" else -thr,
                             proposed_mean=float(np.nanmean(a)), baseline_mean=float(np.nanmean(b)),
                             diff_kind=kind, diff=point, ci_lo=lo, ci_hi=hi, n_seeds=len(a),
                             verdict=("INSUFFICIENT SEEDS" if len(a) < 3
                                      else "SUPPORTED" if supported else "NOT SUPPORTED")))
    return pd.DataFrame(rows)


def aggregate(cfg: dict) -> None:
    df = load_runs()
    df.to_csv(OUT / "campaign_metrics.csv", index=False)
    summ = summarise(df)
    summ.to_csv(OUT / "summary.csv", index=False)
    hyp = hypotheses(df, cfg)
    hyp.to_csv(OUT / "hypotheses.csv", index=False)

    ins = pd.concat([pd.read_csv(f) for f in (OUT / "runs").glob("*_insiders.csv")], ignore_index=True)
    ins.to_csv(OUT / "per_insider_all.csv", index=False)
    by_sc = (ins[ins["budget"] == 10].groupby(["workload", "detector", "scenario_id"])["detected"]
             .agg(["mean", "size"]).reset_index().rename(columns={"mean": "dr_at_10", "size": "n"}))
    by_sc.to_csv(OUT / "dr_by_scenario.csv", index=False)

    tim = pd.concat([pd.read_csv(f) for f in (OUT / "runs").glob("*_timing.csv")], ignore_index=True)
    tim.to_csv(OUT / "timing.csv", index=False)

    n_w, n_s = df["workload"].nunique(), df["seed"].nunique()
    print(f"aggregated {n_w} workloads x {n_s} seeds ({len(df):,} metric rows)")
    pd.set_option("display.width", 200)
    sub = summ[(summ["budget"] == 10) & summ["metric"].isin(["dr_at_b", "precision_at_b"])]
    print(sub.pivot_table(index=["workload", "detector"], columns="metric", values="mean").round(3).to_string())
    print("\nHYPOTHESES\n" + hyp.round(3).to_string(index=False))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workloads", nargs="*", default=None)
    ap.add_argument("--seeds", nargs="*", type=int, default=[0, 1, 2, 3, 4])
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--aggregate-only", action="store_true")
    args = ap.parse_args()

    cfg = apply_frozen_configs(load_config())
    OUT.mkdir(parents=True, exist_ok=True)
    if not args.aggregate_only:
        for w in args.workloads or list(cfg["synthetic"]["workloads"]):
            for s in args.seeds:
                run_world(cfg, w, s, args.force)
    aggregate(cfg)


if __name__ == "__main__":
    main()
