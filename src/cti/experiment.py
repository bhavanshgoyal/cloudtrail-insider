"""
cti.experiment
--------------
One shared harness for the pipeline, tuning, campaign and ablations.

``load_world``  generate (or load cached) events, features, labels, ground truth
                for one (workload, seed).
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
from cti.features.pipeline import build_features, make_labels
from cti.ingest.normalise import normalise_columns
from cti.ingest.synthetic import generate_workload
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


def load_world(cfg: dict, workload: str | None = None, seed: int | None = None,
               fast: bool = False, cache: bool = True) -> World:
    """Generate one (workload, seed) dataset; features are cached on disk."""
    workload = workload or cfg["synthetic"]["default_workload"]
    seed = cfg["random_seed"] if seed is None else seed
    t0 = time.time()
    raw, gt = generate_workload(cfg, workload, seed, fast=fast)
    events = normalise_columns(raw)

    key = CACHE_DIR / f"{workload}_s{seed}{'_fast' if fast else ''}"
    fpath, lpath = key / "features.parquet", key / "labels.parquet"
    if cache and fpath.exists() and lpath.exists():
        feats, labels = pd.read_parquet(fpath), pd.read_parquet(lpath)
    else:
        feats = build_features(events, cfg)
        labels = make_labels(events, feats)
        if cache:
            key.mkdir(parents=True, exist_ok=True)
            feats.to_parquet(fpath, index=False)
            labels.to_parquet(lpath, index=False)
            (key / "ground_truth.json").write_text(json.dumps(gt, indent=1))
    log.info("world %s seed %d: %d events, %d feature rows, %d insiders (%.1fs)",
             workload, seed, len(events), len(feats), len(gt), time.time() - t0)
    return World(workload, seed, events, feats, labels, gt)


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
