"""
run_campaign.py
---------------
Final experimental campaign on CERT r4.2 (Review 3 statistics).

  data       CERT r4.2 (one fixed dataset)
  seeds      0 1 2 3 4   detector randomness only (disjoint from tuning seeds 100/101)
  origins    3 rolling temporal origins
  detectors  isolation_forest, lof, autoencoder, rule_baseline, proposed
  protocol   fit on train+val, evaluate the TEST window with the settings frozen in
             configs/proposed_final.yaml and configs/baseline_final.yaml

Per seed the raw per-origin results are written to results/campaign/runs/<workload>_s<seed>*;
finished seeds are skipped on re-run (use --force to redo). ``--aggregate-only`` rebuilds
the summaries.

Uncertainty. The data is one fixed organisation, so seeds are NOT independent replicates
(the proposed detector is deterministic; a bootstrap over seeds would give falsely narrow
intervals). The sampling units are the insiders and the days:
  * detection rate and MTTD: each insider's outcome is averaged over every (seed, origin)
    run whose test window contains them; the paired bootstrap resamples insiders;
  * precision: each test day's true / total alerts are averaged over the runs covering that
    day; the paired bootstrap resamples days (ratio of sums).
Other metrics are reported as the mean over runs (origins averaged within a seed).

    python scripts/run_campaign.py                       # everything
    python scripts/run_campaign.py --seeds 0 1
    python scripts/run_campaign.py --aggregate-only
"""
from __future__ import annotations

import argparse
import gc
import logging
import time
from pathlib import Path

import numpy as np
import pandas as pd

from cti.detectors.train import build_detectors
from cti.eval.aggregate import (
    boot_idx,
    day_matrices,
    insider_matrix,
    percentile_ci,
    pooled_rates,
    ratio_of_sums,
)
from cti.eval.evaluate import per_insider_table
from cti.experiment import apply_frozen_configs, cert_workload, load_world, run_window
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


def run_world(cfg: dict, seed: int, force: bool) -> None:
    runs = OUT / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    workload = cert_workload(cfg)
    stem = runs / f"{workload}_s{seed}"
    if Path(f"{stem}.csv").exists() and not force:
        log.warning("skip seed %d (done)", seed)
        return
    set_all_seeds(seed)
    cfg = {**cfg, "random_seed": seed}                      # build_detectors seeds from cfg
    t0 = time.time()
    world = load_world(cfg, None, seed)
    tidy, insiders, days, timing = [], [], [], []
    for sp in all_splits(world.features["date"], cfg):
        n_ins = assert_test_positives(sp, world.ground_truth, cfg)
        r = run_window(world, cfg, sp, "test", build_detectors(cfg), with_ci=False)
        tidy.append(r.tidy)
        insiders.append(per_insider_table(r.results, r.ctx).assign(workload=workload, seed=seed,
                                                                    origin=sp.origin))
        for det, by_b in r.results.items():
            for b, br in by_b.items():
                days.append(pd.DataFrame({"detector": det, "budget": b, "date": r.ctx.days,
                                          "day_tp": br.day_tp, "day_n": br.day_n,
                                          "seed": seed, "origin": sp.origin}))
        for det, sec in r.fit_seconds.items():
            timing.append(dict(workload=workload, seed=seed, origin=sp.origin, detector=det,
                               fit_score_seconds=sec, n_principals=world.features["principal"].nunique(),
                               n_rows=len(world.features), n_rows_test=len(r.scores[det]),
                               n_insiders_test=n_ins))
    pd.concat(tidy).to_csv(f"{stem}.csv", index=False)       # (with_suffix would eat the ".2")
    pd.concat(insiders).to_csv(f"{stem}_insiders.csv", index=False)
    pd.concat(days).to_csv(f"{stem}_days.csv", index=False)
    pd.DataFrame(timing).to_csv(f"{stem}_timing.csv", index=False)
    log.warning("done seed %d in %.0fs", seed, time.time() - t0)
    del world
    gc.collect()


def _median_ttd(t: np.ndarray) -> float:
    t = t[np.isfinite(t)]
    return float(np.median(t)) if len(t) else np.nan


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------
def _read(pattern: str) -> pd.DataFrame:
    files = sorted((OUT / "runs").glob(pattern))
    if not files:
        raise SystemExit(f"no campaign files matching {pattern}; run the campaign first")
    return pd.concat([pd.read_csv(f) for f in files], ignore_index=True)


def load_runs() -> pd.DataFrame:
    files = [f for f in sorted((OUT / "runs").glob("*_s[0-9]*.csv"))
             if not f.stem.endswith(("_insiders", "_timing", "_days"))]
    if not files:
        raise SystemExit("no campaign runs found; run the campaign first")
    return pd.concat([pd.read_csv(f) for f in files], ignore_index=True)


def summarise(df: pd.DataFrame, ins: pd.DataFrame, days: pd.DataFrame) -> pd.DataFrame:
    """One row per (workload, detector, budget, metric).

    dr_at_b / precision_at_b: pooled estimate + bootstrap CI over insiders / days.
    Everything else: mean over seeds of origin-averaged runs (no CI).
    """
    df = df[df["metric"].isin(POINT_METRICS)]
    per_seed = (df.groupby(["workload", "detector", "budget", "metric", "seed"])["value"]
                .mean().reset_index())
    rows = []
    for (w, d, b, m), g in per_seed.groupby(["workload", "detector", "budget", "metric"]):
        x = g["value"].to_numpy(dtype=float)
        n_runs = int(df[(df.workload == w) & (df.detector == d) & (df.budget == b) & (df.metric == m)]
                     ["value"].notna().sum())
        rows.append(dict(workload=w, detector=d, budget=b, metric=m, n_seeds=len(x), n_runs=n_runs,
                         mean=float(np.nanmean(x)), std=float(np.nanstd(x, ddof=1)) if len(x) > 1 else np.nan,
                         ci_lo=np.nan, ci_hi=np.nan, min=float(np.nanmin(x)), max=float(np.nanmax(x)),
                         ci_unit=""))
    summ = pd.DataFrame(rows)
    for r in pooled_rates(ins, days).itertuples(index=False):
        sel = (summ.detector == r.detector) & (summ.budget == r.budget) & (summ.metric == r.metric)
        summ.loc[sel, ["mean", "ci_lo", "ci_hi", "ci_unit"]] = [r.mean, r.ci_lo, r.ci_hi, r.ci_unit]
    return summ


def hypotheses(ins: pd.DataFrame, days: pd.DataFrame, workload: str) -> pd.DataFrame:
    """H1a (DR@10 >= +40%), H1b (P@10 >= +30%), H2 (median MTTD@10 >= 25% lower) vs IF.

    Paired bootstrap: resample insiders (H1a, H2) or test days (H1b). SUPPORTED only if
    the whole 95% interval lies beyond the threshold.
    """
    rows = []
    det = insider_matrix(ins, 10, "detected")
    ttd = insider_matrix(ins, 10, "ttd_hours")
    tp, n = day_matrices(days, 10)
    if PROPOSED not in det or BASELINE not in det:
        return pd.DataFrame()

    def rel(a, b):
        with np.errstate(invalid="ignore", divide="ignore"):
            return (a - b) / b

    # H1a: detection rate
    a, b = det[PROPOSED].to_numpy(float), det[BASELINE].to_numpy(float)
    idx = boot_idx(len(a))
    pa, pb = a.mean(), b.mean()
    kind = "relative" if pb > 0 else "absolute"
    f = rel if kind == "relative" else (lambda x, y: x - y)
    rows.append(_verdict("H1a", "dr_at_b@10", 0.40, "gain", pa, pb, kind, f(pa, pb),
                         percentile_ci(f(a[idx].mean(axis=1), b[idx].mean(axis=1))), len(a), "insiders"))

    # H1b: precision (ratio of summed true alerts over summed alerts, per day)
    ta, na, tb, nb = (m[c].to_numpy(float) for m, c in ((tp, PROPOSED), (n, PROPOSED), (tp, BASELINE), (n, BASELINE)))
    idx = boot_idx(len(ta))
    pa, pb = ratio_of_sums(ta, na), ratio_of_sums(tb, nb)
    with np.errstate(invalid="ignore", divide="ignore"):
        ba = ta[idx].sum(axis=1) / na[idx].sum(axis=1)
        bb = tb[idx].sum(axis=1) / nb[idx].sum(axis=1)
    kind = "relative" if pb > 0 else "absolute"
    f = rel if kind == "relative" else (lambda x, y: x - y)
    rows.append(_verdict("H1b", "precision_at_b@10", 0.30, "gain", pa, pb, kind, f(pa, pb),
                         percentile_ci(f(ba, bb)), len(ta), "days"))

    # H2: median time to detection among the insiders each detector caught
    a, b = ttd[PROPOSED].to_numpy(float), ttd[BASELINE].to_numpy(float)
    idx = boot_idx(len(a))
    pa, pb = _median_ttd(a), _median_ttd(b)
    ba = np.array([_median_ttd(a[i]) for i in idx])
    bb = np.array([_median_ttd(b[i]) for i in idx])
    rows.append(_verdict("H2", "mttd_hours_median@10", 0.25, "reduction", pa, pb, "relative",
                         rel(pa, pb), percentile_ci(rel(ba, bb)), len(a), "insiders"))
    out = pd.DataFrame(rows)
    out.insert(0, "workload", workload)
    return out


def _verdict(hyp, metric, thr, direction, pa, pb, kind, point, ci, n, unit) -> dict:
    lo, hi = ci
    if direction == "gain":
        ok = kind == "relative" and np.isfinite(lo) and lo > thr
    else:
        ok = kind == "relative" and np.isfinite(hi) and hi < -thr
    return dict(hypothesis=hyp, metric=metric, threshold=thr if direction == "gain" else -thr,
                proposed_mean=pa, baseline_mean=pb, diff_kind=kind, diff=point, ci_lo=lo, ci_hi=hi,
                n_seeds=n, ci_unit=f"{unit} (n={n})",
                verdict="SUPPORTED" if ok else "NOT SUPPORTED")


def aggregate(cfg: dict) -> None:
    df = load_runs()
    ins, days = _read("*_insiders.csv"), _read("*_days.csv")
    workload = df["workload"].iloc[0]
    df.to_csv(OUT / "campaign_metrics.csv", index=False)
    summ = summarise(df, ins, days)
    summ.to_csv(OUT / "summary.csv", index=False)
    hyp = hypotheses(ins, days, workload)
    hyp.to_csv(OUT / "hypotheses.csv", index=False)

    ins.to_csv(OUT / "per_insider_all.csv", index=False)
    pooled = (ins[ins["budget"] == 10].groupby(["workload", "detector", "scenario_id", "principal"])
              ["detected"].mean().reset_index())
    by_sc = (pooled.groupby(["workload", "detector", "scenario_id"])["detected"]
             .agg(["mean", "size"]).reset_index().rename(columns={"mean": "dr_at_10", "size": "n"}))
    by_sc.to_csv(OUT / "dr_by_scenario.csv", index=False)
    _read("*_timing.csv").to_csv(OUT / "timing.csv", index=False)

    print(f"aggregated {df['seed'].nunique()} seeds x {df['origin'].nunique()} origins "
          f"({len(df):,} metric rows, {ins['principal'].nunique()} insiders in test windows)")
    pd.set_option("display.width", 200)
    sub = summ[(summ["budget"] == 10) & summ["metric"].isin(["dr_at_b", "precision_at_b"])]
    print(sub[["detector", "metric", "mean", "ci_lo", "ci_hi", "ci_unit"]].round(3).to_string(index=False))
    print("\nHYPOTHESES\n" + hyp.round(3).to_string(index=False))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", nargs="*", type=int, default=[0, 1, 2, 3, 4])
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--aggregate-only", action="store_true")
    args = ap.parse_args()

    cfg = apply_frozen_configs(load_config())
    OUT.mkdir(parents=True, exist_ok=True)
    if not args.aggregate_only:
        for s in args.seeds:
            run_world(cfg, s, args.force)
    aggregate(cfg)


if __name__ == "__main__":
    main()
