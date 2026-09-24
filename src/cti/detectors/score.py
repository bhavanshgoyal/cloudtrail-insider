"""
cti.detectors.score
-------------------
Score the test split using all fitted detectors and emit a unified
``scores.parquet`` file: columns (principal, date, detector, score).
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd

from cti.detectors.train import load_detector, prepare_X
from cti.util.config import load_config
from cti.util.run import RunContext
from cti.util.seeds import set_all_seeds

log = logging.getLogger(__name__)


def score_split(
    df_feat: pd.DataFrame,
    detector,
    split_name: str,
    cfg: dict,
) -> pd.DataFrame:
    """Score all rows in a given temporal split with one detector.

    Parameters
    ----------
    df_feat:
        Full feature matrix with ``principal`` and ``date`` columns.
    detector:
        Fitted detector with ``score_samples`` method.
    split_name:
        One of ``"valid"`` or ``"test"``.
    cfg:
        Project config dict.

    Returns
    -------
    pd.DataFrame
        Columns: principal, date, detector, score
    """
    splits = cfg["splits"]
    lo = pd.Timestamp(splits[f"{split_name}_start"])
    hi = pd.Timestamp(splits[f"{split_name}_end"])

    mask = (df_feat["date"] >= lo) & (df_feat["date"] <= hi)
    df_split = df_feat[mask].copy()

    if df_split.empty:
        log.warning("Split '%s' is empty — scoring all rows instead", split_name)
        df_split = df_feat.copy()

    X, _ = prepare_X(df_split)
    scores = detector.score_samples(X)

    result = df_split[["principal", "date"]].copy()
    result["detector"] = detector.name
    result["score"]    = scores
    return result


def main() -> None:
    """CLI entrypoint for scoring."""
    parser = argparse.ArgumentParser(description="Score test split with trained detectors")
    parser.add_argument("--config",     default=None)
    parser.add_argument("--features",   default=None)
    parser.add_argument("--models-dir", default=None)
    parser.add_argument("--split",      default="test", choices=["valid", "test"])
    parser.add_argument("--output",     default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_all_seeds(cfg["random_seed"])

    feat_path   = Path(args.features  or cfg["paths"]["feature_store"])
    models_dir  = Path(args.models_dir or cfg["paths"]["models_dir"])

    df_feat = pd.read_parquet(feat_path)
    df_feat["date"] = pd.to_datetime(df_feat["date"])

    all_scores = []
    for pkl in models_dir.glob("*.pkl"):
        det = load_detector(pkl)
        log.info("Scoring with %s …", det.name)
        df_s = score_split(df_feat, det, args.split, cfg)
        all_scores.append(df_s)

    if not all_scores:
        raise RuntimeError(f"No detector models found in {models_dir}")

    df_all = pd.concat(all_scores, ignore_index=True)

    with RunContext(
        f"score_{args.split}",
        config_path=args.config,
        input_paths=[feat_path],
    ) as ctx:
        out = ctx.save_artifact("scores.parquet", df_all)
        ctx.register(n_rows=len(df_all), split=args.split)
        log.info("Scores saved to %s", out)


if __name__ == "__main__":
    main()
