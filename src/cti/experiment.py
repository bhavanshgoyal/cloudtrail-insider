"""
cti.experiment
--------------
One shared harness for the pipeline, tuning, campaign and ablations.

``load_world``  load (or build and cache) the CERT features, labels and ground truth.
``run_window``  fit detectors on the fit window, score the evaluation window and
                evaluate at fixed per-day budgets.

Protocol (fixed for every detector):

=========  ======================  ===================
phase      fit on                  evaluate on
=========  ======================  ===================
``val``    train                   val   (tuning ONLY)
``test``   train + val (refit)     test  (final numbers)
=========  ======================  ===================
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from cti.eval.evaluate import EvalContext, build_context, evaluate_window
from cti.features.cert import build_cert_features, make_cert_labels
from cti.ingest.cert import load_ground_truth, load_roles
from cti.util.splits import Split

log = logging.getLogger(__name__)

CACHE_DIR = Path("data/cache")


@dataclass
class World:
    workload: str
    seed: int
    events: pd.DataFrame
    features: pd.DataFrame
    labels: pd.DataFrame
    ground_truth: list[dict]
    meta: dict = field(default_factory=dict)


def cert_workload(cfg: dict) -> str:
    return f"CERT_r{cfg['cert']['release']}"


def load_world(cfg: dict, workload: str | None = None, seed: int | None = None,
               fast: bool = False, cache: bool = True) -> World:
    """The CERT dataset: cached features, labels and ground truth.

    ``seed`` only drives detector randomness and tie-breaks; the data is fixed.
    ``events`` holds one row per user (principalId, roleName) from LDAP.
    ``fast`` keeps every insider plus a fixed random sample of other users
    (a quick sanity check only, never for reported numbers).
    """
    c = cfg["cert"]
    name = cert_workload(cfg)
    if workload not in (None, name):
        raise ValueError(f"unknown workload {workload!r}; the only dataset is {name}")
    seed = cfg["random_seed"] if seed is None else seed
    t0 = time.time()

    key = CACHE_DIR / name
    fpath, lpath, gpath = key / "features.parquet", key / "labels.parquet", key / "ground_truth.json"
    if cache and fpath.exists() and lpath.exists() and gpath.exists():
        feats, labels = pd.read_parquet(fpath), pd.read_parquet(lpath)
        gt = json.loads(gpath.read_text())
    else:
        feats = build_cert_features(Path(c["parquet_dir"]), cfg)
        gt = load_ground_truth(Path(c["answers_dir"]), c["release"])
        labels = make_cert_labels(feats, gt)
        if cache:
            key.mkdir(parents=True, exist_ok=True)
            feats.to_parquet(fpath, index=False)
            labels.to_parquet(lpath, index=False)
            gpath.write_text(json.dumps(gt, indent=1))
    events = load_roles(Path(c["raw_dir"]))

    if fast:
        insiders = {g["principal_id"] for g in gt}
        others = np.setdiff1d(feats["principal"].unique(), sorted(insiders))
        keep = insiders | set(np.random.default_rng(0).choice(others, size=min(200, len(others)),
                                                                replace=False))
        feats = feats[feats["principal"].isin(keep)].reset_index(drop=True)
        labels = labels[labels["principal"].isin(keep)].reset_index(drop=True)
        name += "_fast"
    log.info("world %s seed %d: %d user-days, %d users, %d insiders, %d positive user-days (%.1fs)",
             name, seed, len(feats), feats["principal"].nunique(), len(gt),
             int(labels["label"].sum()), time.time() - t0)
    return World(name, seed, events, feats, labels, gt)


def subsample_users(world: World, n: int, seed: int) -> World:
    """A random ``n``-user organisation from ``world`` (insiders kept only if drawn)."""
    users = np.sort(world.features["principal"].unique())
    if n >= len(users):
        return world
    keep = set(np.random.default_rng(seed).choice(users, size=n, replace=False))
    sel = lambda df: df[df["principal"].isin(keep)].reset_index(drop=True)  # noqa: E731
    gt = [g for g in world.ground_truth if g["principal_id"] in keep]
    return World(f"{world.workload}_n{n}", world.seed, world.events, sel(world.features),
                 sel(world.labels), gt, {**world.meta, "subsample_seed": seed})


@dataclass
class WindowRun:
    phase: str
    split: Split
    tidy: pd.DataFrame                       # evaluate_window output (+ context columns)
    results: dict                            # detector -> budget -> BudgetResult
    scores: dict[str, pd.DataFrame]          # detector -> principal, date, score
    ctx: EvalContext
    detectors: dict                          # fitted detectors by name
    fit_seconds: dict[str, float]


def fit_and_score(world: World, split: Split, phase: str, detectors: list) -> tuple[dict, dict, dict]:
    if phase not in ("val", "test"):
        raise ValueError("phase must be 'val' or 'test'")
    feats = world.features
    fit_mask = split.mask(feats["date"], "train")
    if phase == "test":
        fit_mask |= split.mask(feats["date"], "val")
    df_fit = feats.loc[fit_mask].reset_index(drop=True)
    df_eval = split.select(feats, phase)
    if df_fit.empty or df_eval.empty:
        raise ValueError(f"empty fit or {phase} window: {split.describe()}")

    scores, fitted, secs = {}, {}, {}
    for det in detectors:
        t0 = time.time()
        det.fit(df_fit, world.events)
        s = np.asarray(det.score(df_eval, world.events), dtype=float)
        secs[det.name] = time.time() - t0
        if getattr(det, "abstains", False):
            s = np.where(s > 0, s, np.nan)          # no rule fired -> no alert
        scores[det.name] = df_eval[["principal", "date"]].assign(score=s)
        fitted[det.name] = det
        log.info("  %-34s fit+score %.1fs", det.name, secs[det.name])
    return scores, fitted, secs


def run_window(world: World, cfg: dict, split: Split, phase: str, detectors: list,
               budgets=None, with_ci: bool = True) -> WindowRun:
    """Fit on the phase's fit window, score its evaluation window, evaluate."""
    scores, fitted, secs = fit_and_score(world, split, phase, detectors)
    window_days = split.val_days if phase == "val" else split.test_days
    any_scores = next(iter(scores.values()))
    ctx = build_context(any_scores, world.labels, world.ground_truth, window_days)
    suppress = {name: int(getattr(d, "suppress_days", 0)) for name, d in fitted.items()}
    tidy, results = evaluate_window(scores, ctx, cfg, suppress=suppress, budgets=budgets,
                                    with_ci=with_ci, seed=world.seed)
    tidy.insert(0, "phase", phase)
    tidy.insert(0, "origin", split.origin)
    tidy.insert(0, "seed", world.seed)
    tidy.insert(0, "workload", world.workload)
    return WindowRun(phase, split, tidy, results, scores, ctx, fitted, secs)


FROZEN_CONFIGS = (Path("configs/proposed_final.yaml"), Path("configs/baseline_final.yaml"))


def apply_frozen_configs(cfg: dict) -> dict:
    """Overlay the tuned settings written by scripts/tune_proposed.py (if present)."""
    import copy

    import yaml

    out = copy.deepcopy(cfg)
    for path in FROZEN_CONFIGS:
        if path.exists():
            frozen = yaml.safe_load(path.read_text()) or {}
            for det, params in frozen.get("detectors", {}).items():
                out["detectors"].setdefault(det, {}).update(params)
            log.info("applied frozen settings from %s", path)
        else:
            log.warning("%s not found - using untuned defaults", path)
    return out
