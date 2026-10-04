"""
cti.detectors.train
-------------------
Baseline anomaly detectors, the common detector interface and training helpers.

Common interface (every detector, including the proposed one)::

    det.name                         # str
    det.needs_events                 # bool - True if score() needs the raw event log
    det.fit(df_feat, events=None)    # df_feat: (principal, date, <features>) rows of the TRAIN window
    det.score(df_feat, events=None)  # one anomaly score per row, higher = more anomalous

All feature-matrix detectors see the identical feature columns
(``feature_columns(df_feat)``), which is what "equal feature cost" in H1 means.
Hyper-parameters come from ``cfg["detectors"]``.

Baselines
~~~~~~~~~
* ``IsoForestDetector``  - global Isolation Forest (the baseline named in H1)
* ``LOFDetector``        - Local Outlier Factor on standardised features
* ``AutoencoderDetector``- MLP reconstruction error
* ``RuleBaselineDetector`` - commercial-style signatures (see ``cti.detectors.rules``)
"""
from __future__ import annotations

import argparse
import logging
import pickle
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPRegressor
from sklearn.preprocessing import StandardScaler

from cti.detectors.proposed import BudgetAwareConformal
from cti.detectors.rules import RuleBaselineDetector
from cti.features.pipeline import feature_columns
from cti.util.config import load_config
from cti.util.run import RunContext
from cti.util.seeds import set_all_seeds
from cti.util.splits import Split, make_splits

log = logging.getLogger(__name__)


# -- helpers ------------------------------------------------------------------
def prepare_X(df_feat: pd.DataFrame, cols: list[str] | None = None) -> tuple[np.ndarray, list[str]]:
    """Feature matrix (float32) and the column names used."""
    cols = cols or feature_columns(df_feat)
    return df_feat[cols].to_numpy(dtype=np.float32), cols


class _FeatureDetector:
    """Shared plumbing for detectors that score from the feature matrix only."""

    name = "feature_detector"
    needs_events = False
    feat_cols: list[str]

    def _fit_cols(self, df_feat: pd.DataFrame) -> np.ndarray:
        X, self.feat_cols = prepare_X(df_feat)
        return X

    def _X(self, df_feat: pd.DataFrame) -> np.ndarray:
        return prepare_X(df_feat, self.feat_cols)[0]

    def score(self, df_feat: pd.DataFrame, events: pd.DataFrame | None = None) -> np.ndarray:  # noqa: ARG002
        return self.score_samples(self._X(df_feat))

    def score_samples(self, X: np.ndarray) -> np.ndarray:  # pragma: no cover - abstract
        raise NotImplementedError


# -- Isolation Forest ---------------------------------------------------------
class IsoForestDetector(_FeatureDetector):
    """Global Isolation Forest. Higher score = more anomalous (sklearn's sign is flipped)."""

    name = "isolation_forest"

    def __init__(self, cfg: dict, seed: int) -> None:
        dc = cfg["detectors"]["isolation_forest"]
        self._model = IsolationForest(
            n_estimators=dc["n_estimators"], contamination=dc["contamination"],
            max_samples=dc.get("max_samples", "auto"),
            max_features=dc["max_features"], bootstrap=dc["bootstrap"],
            random_state=seed, n_jobs=-1)

    def fit(self, df_feat: pd.DataFrame, events: pd.DataFrame | None = None) -> IsoForestDetector:  # noqa: ARG002
        self._model.fit(self._fit_cols(df_feat))
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return -self._model.score_samples(X)


# -- LOF ----------------------------------------------------------------------
class LOFDetector(_FeatureDetector):
    """LocalOutlierFactor (novelty mode) on standardised features."""

    name = "lof"

    def __init__(self, cfg: dict, seed: int) -> None:  # noqa: ARG002
        dc = cfg["detectors"]["lof"]
        self._scaler = StandardScaler()
        self._model = LocalOutlierFactor(
            n_neighbors=dc["n_neighbors"], contamination=dc["contamination"],
            novelty=True, n_jobs=-1)

    def fit(self, df_feat: pd.DataFrame, events: pd.DataFrame | None = None) -> LOFDetector:  # noqa: ARG002
        self._model.fit(self._scaler.fit_transform(self._fit_cols(df_feat)))
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        return -self._model.score_samples(self._scaler.transform(X))


# -- Autoencoder --------------------------------------------------------------
class AutoencoderDetector(_FeatureDetector):
    """MLPRegressor trained as an autoencoder; score = per-row reconstruction MSE."""

    name = "autoencoder"

    def __init__(self, cfg: dict, seed: int) -> None:
        dc = cfg["detectors"]["autoencoder"]
        self._scaler = StandardScaler()
        self._model = MLPRegressor(
            hidden_layer_sizes=tuple(dc["hidden_dims"]), activation="relu",
            max_iter=dc["epochs"], batch_size=dc["batch_size"], learning_rate_init=dc["lr"],
            random_state=seed, verbose=False, early_stopping=True,
            validation_fraction=0.1, n_iter_no_change=5)

    def fit(self, df_feat: pd.DataFrame, events: pd.DataFrame | None = None) -> AutoencoderDetector:  # noqa: ARG002
        Xs = self._scaler.fit_transform(self._fit_cols(df_feat))
        self._model.fit(Xs, Xs)
        return self

    def score_samples(self, X: np.ndarray) -> np.ndarray:
        Xs = self._scaler.transform(X)
        return np.mean((Xs - self._model.predict(Xs)) ** 2, axis=1)


# -- Registry -----------------------------------------------------------------
BASELINE_CLASSES = {
    "isolation_forest": IsoForestDetector,
    "lof": LOFDetector,
    "autoencoder": AutoencoderDetector,
    "rule_baseline": RuleBaselineDetector,
}
_DETECTOR_CLASSES = {**BASELINE_CLASSES, "proposed_budget_aware_conformal": BudgetAwareConformal}


def build_detectors(cfg: dict, include_proposed: bool = True) -> list:
    """Instantiate every configured detector."""
    seed = cfg["random_seed"]
    classes = _DETECTOR_CLASSES if include_proposed else BASELINE_CLASSES
    return [cls(cfg, seed) for cls in classes.values()]


def save_detector(det, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(det, fh, protocol=5)


def load_detector(path: Path):
    with path.open("rb") as fh:
        return pickle.load(fh)  # noqa: S301


def train_on_split(df_feat: pd.DataFrame, cfg: dict, split: Split,
                   events: pd.DataFrame | None = None, include_proposed: bool = True) -> list:
    """Fit every detector on the TRAIN window of ``split`` and return them.

    Raises ``ValueError`` if the train window is empty - there is no fallback
    to "train on everything".
    """
    df_train = split.select(df_feat, "train")
    if df_train.empty:
        raise ValueError(f"empty train window for {split.describe()}")
    log.info("training on %d rows (%s)", len(df_train), split.describe())
    detectors = build_detectors(cfg, include_proposed)
    for det in detectors:
        log.info("fitting %s ...", det.name)
        det.fit(df_train, events)
    return detectors


# -- CLI ----------------------------------------------------------------------
def main() -> None:
    """CLI entrypoint: cti-train (trains on the last rolling origin by default)."""
    parser = argparse.ArgumentParser(description="Train anomaly detectors")
    parser.add_argument("--config", default=None)
    parser.add_argument("--features", default=None)
    parser.add_argument("--models-dir", default=None)
    parser.add_argument("--origin", type=int, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_all_seeds(cfg["random_seed"])
    feat_path = Path(args.features or cfg["paths"]["feature_store"])
    models_dir = Path(args.models_dir or cfg["paths"]["models_dir"])

    with RunContext("train", config_path=args.config, input_paths=[feat_path]) as ctx:
        df_feat = pd.read_parquet(feat_path)
        df_feat["date"] = pd.to_datetime(df_feat["date"])
        split = make_splits(df_feat["date"], cfg, args.origin)
        detectors = train_on_split(df_feat, cfg, split)
        ctx.register(feature_columns=feature_columns(df_feat), n_detectors=len(detectors),
                     split=split.describe())
        for det in detectors:
            save_detector(det, models_dir / f"{det.name}.pkl")
            log.info("saved %s", det.name)


if __name__ == "__main__":
    main()
