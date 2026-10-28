"""
cti.inference
-------------
Score new CERT-format logs with the frozen model (used by the frontend and the CLI).

``train_final_model``  fit every detector on the last origin's train + val window with the
                       frozen settings and save it to ``models/cert_model.pkl``.
``read_csv_upload``    validate + compact one uploaded CERT CSV (same parsing as the ingest).
``analyse``            features -> scores of every detector -> per-day alert queue with
                       explanations for the proposed detector.

Features are computed from the uploaded period only. The first ``history_days`` days of an
upload are therefore history (novelty and "usual hour" need a past) and are not scored.
"""
from __future__ import annotations

import csv
import io
import logging
import pickle
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from cti.detectors.proposed import BudgetAwareConformal
from cti.detectors.rules import RuleBaselineDetector
from cti.eval.evaluate import emit_alerts
from cti.explain.explain_proposed import explain_alerts
from cti.features.cert import SOURCES, build_cert_features
from cti.ingest.cert import _SPEC

log = logging.getLogger(__name__)

MODEL_PATH = Path("models/cert_model.pkl")
PROPOSED = BudgetAwareConformal.name


@dataclass
class Model:
    detectors: dict                      # name -> fitted detector
    trained_on: tuple[str, str]
    n_users: int
    settings: dict = field(default_factory=dict)


def train_final_model(cfg: dict, path: Path = MODEL_PATH) -> Model:
    from cti.detectors.train import build_detectors
    from cti.experiment import load_world
    from cti.util.splits import make_splits

    world = load_world(cfg, None, cfg["random_seed"])
    split = make_splits(world.features["date"], cfg)
    fit = world.features[split.mask(world.features["date"], "train") | split.mask(world.features["date"], "val")]
    dets = {}
    for d in build_detectors(cfg):
        d.fit(fit.reset_index(drop=True))
        dets[d.name] = d
    model = Model(dets, (str(split.train_days[0])[:10], str(split.val_days[-1])[:10]),
                  int(fit["principal"].nunique()),
                  {"proposed": dets[PROPOSED].params, "release": cfg["cert"]["release"]})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(model, fh, protocol=5)
    log.info("saved %s (trained on %s .. %s, %d users)", path, *model.trained_on, model.n_users)
    return model


def load_model(path: Path = MODEL_PATH) -> Model:
    with path.open("rb") as fh:
        return pickle.load(fh)  # noqa: S301  (our own file)


def detect_source(name: str, data: bytes) -> str | None:
    """Which CERT source a CSV is: from its file name, else its columns (logon and device share
    columns, so their first activity value decides)."""
    stem = Path(name).stem.lower()
    for s in SOURCES:
        if stem.startswith(s):
            return s
    lines = data[:4096].decode("utf-8", errors="replace").splitlines()
    cols = set(lines[0].strip().split(",")) if lines else set()
    for s, key in (("http", "url"), ("file", "filename"), ("email", "bcc")):
        if key in cols:
            return s
    if "activity" in cols and len(lines) > 1:
        act = lines[1].rstrip().split(",")[-1]
        return {"Logon": "logon", "Logoff": "logon", "Connect": "device", "Disconnect": "device"}.get(act)
    return None


def read_csv_upload(data: bytes, src: str, cfg: dict) -> pd.DataFrame:
    """Parse one uploaded CERT CSV of source ``src`` into the compact form; raises on bad input."""
    usecols, fn = _SPEC[src]
    df = pd.read_csv(io.BytesIO(data), dtype=str, quoting=csv.QUOTE_NONE, on_bad_lines="error",
                     usecols=lambda c: c in usecols)
    missing = sorted(set(usecols) - set(df.columns))
    if missing:
        raise ValueError(f"{src}: missing column(s) {missing}; expected CERT r4.2 columns {usecols}")
    return fn(df, cfg)


@dataclass
class Analysis:
    features: pd.DataFrame
    scores: dict[str, pd.DataFrame]       # detector -> principal, date, score (scored days only)
    alerts: pd.DataFrame                  # proposed detector queue with explanations
    scored_days: list
    history_days: int


def analyse(frames: dict[str, pd.DataFrame], model: Model, cfg: dict, budget: int = 10,
            history_days: int = 14) -> Analysis:
    feats = build_cert_features(frames, cfg)
    days = sorted(feats["date"].unique())
    if len(days) <= history_days:
        raise ValueError(f"the upload covers {len(days)} days; it needs more than {history_days} "
                         "(the first days are used as history and are not scored)")
    scored_days = days[history_days:]
    rows = feats[feats["date"].isin(scored_days)].reset_index(drop=True)

    scores = {}
    for name, det in model.detectors.items():
        s = np.asarray(det.score(rows), dtype=float)
        if getattr(det, "abstains", False):
            s = np.where(s > 0, s, np.nan)
        scores[name] = rows[["principal", "date"]].assign(score=s)

    prop = model.detectors[PROPOSED]
    alerts = emit_alerts(scores[PROPOSED], budget, prop.suppress_days, cfg["random_seed"])
    alerts["alerts_that_day"] = alerts.groupby("date")["rank"].transform("max")
    detail = alerts.merge(rows, on=["principal", "date"], how="left")
    expl = explain_alerts(prop, detail, cfg["explain"]["top_k_features"])
    alerts["primary_family"] = [e["primary_family"] for e in expl]
    alerts["explanation"] = [e["text"] for e in expl]
    alerts["family_pvalues"] = [e["family_pvalues"] for e in expl]
    rules = model.detectors.get("rule_baseline")
    if isinstance(rules, RuleBaselineDetector):
        alerts["rules_fired"] = rules.fired(detail)["rules"].to_numpy()
    return Analysis(feats, scores, alerts, scored_days, history_days)


def evaluate_upload(an: Analysis, model: Model, labels: pd.DataFrame, budget: int) -> pd.DataFrame:
    """Per detector: alerts, true alerts, precision and share of labelled users caught at ``budget``.

    ``labels``: columns user, date (one row per malicious user-day).
    """
    lab = labels.rename(columns={"user": "principal"})[["principal", "date"]].copy()
    lab["date"] = pd.to_datetime(lab["date"]).dt.normalize()
    lab = lab[lab["date"].isin(an.scored_days)]
    pos = set(zip(lab["principal"], lab["date"]))
    out = []
    for name, s in an.scores.items():
        al = emit_alerts(s, budget, int(getattr(model.detectors[name], "suppress_days", 0)), 0)
        hit = [(p, d) in pos for p, d in zip(al["principal"], al["date"])]
        caught = {p for (p, d), h in zip(zip(al["principal"], al["date"]), hit) if h}
        out.append(dict(detector=name, alerts=len(al), true_alerts=int(sum(hit)),
                        precision=float(np.mean(hit)) if len(al) else np.nan,
                        insiders_in_upload=lab["principal"].nunique(),
                        insiders_caught=len(caught)))
    return pd.DataFrame(out)
