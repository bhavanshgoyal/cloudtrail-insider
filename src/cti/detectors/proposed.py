"""
cti.detectors.proposed
----------------------
BudgetAwareConformal - the proposed insider-threat detector.

Four ablatable components
~~~~~~~~~~~~~~~~~~~~~~~~~
C1  Per-principal surprisal
    Every feature is compared with *that principal's own* history: a robust
    z-score ``(x - median_p) / scale_p`` using median / MAD of the principal's
    fit-window rows, shrunk towards the population for principals with short
    histories (cold start) and floored by a population scale so a feature
    that has never varied does not explode. Only increases count
    (one-sided). Per-feature z-scores are the per-feature attribution used
    by the explanations (O3). Ablation ``per_principal=False`` replaces the
    principal baseline with the population baseline.

C2  Pooled conformal calibration
    Within each feature family (identity / resource / temporal / volume) the
    z-scores are combined into a family score; the family score is turned into
    a conformal p-value against a **pooled** calibration set: the family
    scores of every principal on the last ``cal_fraction`` of the fit window,
    scored with baselines estimated on the earlier part only (so calibration
    rows are held out). Because scores are already normalised per principal,
    pooling makes p-values comparable across principals *and* gives them
    resolution (~1/20000 instead of the 1/31 floor of a 30-row
    per-principal calibration set). Ablation ``calibrate=False`` sums the raw
    family scores instead.

C3  Fusion
    Family p-values are fused (Fisher by default; ``min_p`` / ``harmonic`` /
    ``stouffer`` for ablation) and returned as ``-log10(fused p)`` so the
    score never saturates.

C4  Budget-aware alert selection
    ``suppress_days``: the evaluator drops a principal already alerted in the
    previous N days so the daily budget goes to distinct candidates
    (see ``cti.eval.evaluate.emit_alerts``).

``explain`` returns, per row, the family p-values, the primary deviating
family and its top-k features with today's value and the principal's usual
value - the material for the alert card (O3).
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import pandas as pd
from scipy import stats

from cti.features.pipeline import FAMILY_PREFIXES, family_columns, feature_columns

log = logging.getLogger(__name__)

_MAD_K = 1.4826                       # MAD -> standard deviation for a normal distribution

DEFAULTS = dict(
    cal_fraction=0.3,                 # last share of the fit window used for C2 calibration
    family_agg="l2",                  # l2 | max | sum   (z-scores -> family score)
    fusion="fisher",                  # fisher | min_p | harmonic | stouffer
    per_principal=True,               # C1 on/off
    calibrate=True,                   # C2 on/off
    transform="log1p",                # log1p | none  (features are non-negative counts / rates)
    scale_alpha=0.5,                  # weight of the population scale floor
    shrink_k=10.0,                    # pseudo-days of population prior for short histories
    families=list(FAMILY_PREFIXES),   # which families to use (feature-family ablation)
    suppress_days=3,                  # C4
)


# ---------------------------------------------------------------------------
# Fusion rules (p-value matrix -> -log10 fused p)
# ---------------------------------------------------------------------------
def fuse(pvals: np.ndarray, method: str) -> np.ndarray:
    """Combine per-family p-values (n x k) into one score = -log10(fused p)."""
    p = np.clip(pvals, 1e-300, 1.0)
    k = p.shape[1]
    if method == "fisher":
        stat = -2.0 * np.log(p).sum(axis=1)
        return -stats.chi2.logsf(stat, df=2 * k) / np.log(10)
    if method == "min_p":                                   # Bonferroni-adjusted minimum
        return -np.log10(np.minimum(p.min(axis=1) * k, 1.0))
    if method == "harmonic":                                # harmonic mean p (un-adjusted)
        return -np.log10(np.minimum(k / (1.0 / p).sum(axis=1), 1.0))
    if method == "stouffer":
        z = stats.norm.isf(p).sum(axis=1) / np.sqrt(k)
        return -stats.norm.logsf(z) / np.log(10)
    raise ValueError(f"unknown fusion method {method!r}")


def conformal_pvalues(scores: np.ndarray, cal_sorted: np.ndarray) -> np.ndarray:
    """p = (1 + #{cal >= s}) / (n_cal + 1) against a sorted calibration sample."""
    n = len(cal_sorted)
    ge = n - np.searchsorted(cal_sorted, scores, side="left")
    return (1.0 + ge) / (n + 1.0)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class BudgetAwareConformal:
    """Proposed detector. See module docstring."""

    name = "proposed_budget_aware_conformal"
    needs_events = False

    def __init__(self, cfg: dict, seed: int, **overrides) -> None:
        self.seed = seed
        unknown = set(overrides) - set(DEFAULTS)
        if unknown:
            raise ValueError(f"unknown proposed-detector options: {sorted(unknown)}")
        p = dict(DEFAULTS)
        p.update({k: v for k, v in cfg.get("detectors", {}).get("proposed", {}).items() if k in DEFAULTS})
        p.update(overrides)
        self.params = p
        self.suppress_days = int(p["suppress_days"])
        self._fitted = False

    # -- C1: baselines -------------------------------------------------------
    def _t(self, X: np.ndarray) -> np.ndarray:
        return np.log1p(np.maximum(X, 0.0)) if self.params["transform"] == "log1p" else X

    def _inv_t(self, X: np.ndarray) -> np.ndarray:
        return np.expm1(X) if self.params["transform"] == "log1p" else X

    def _baselines(self, df: pd.DataFrame) -> None:
        """Per-principal median / scale (shrunk to the population) from ``df``."""
        X = self._t(df[self.feat_cols].to_numpy(dtype=np.float64))
        pop_med = np.median(X, axis=0)
        g = df["principal"].to_numpy()
        order = np.argsort(g, kind="stable")
        g_s, X_s = g[order], X[order]
        uniq, start, counts = np.unique(g_s, return_index=True, return_counts=True)

        med = np.empty((len(uniq), X.shape[1]))
        mad = np.empty_like(med)
        for i, (st, c) in enumerate(zip(start, counts)):
            block = X_s[st:st + c]
            m = np.median(block, axis=0)
            med[i] = m
            mad[i] = np.median(np.abs(block - m), axis=0)

        # population scale: robust spread of within-principal residuals
        resid = np.abs(X_s - np.repeat(med, counts, axis=0))
        pop_scale = _MAD_K * np.median(resid, axis=0)
        fallback = resid.mean(axis=0)
        pop_scale = np.where(pop_scale > 0, pop_scale, np.where(fallback > 0, fallback, 1.0))

        if not self.params["per_principal"]:            # ablation: everybody gets the population baseline
            med[:] = pop_med
            mad[:] = pop_scale / _MAD_K

        alpha = self.params["scale_alpha"]
        w = (counts / (counts + self.params["shrink_k"]))[:, None]
        self._med = w * med + (1 - w) * pop_med
        self._scale = np.sqrt((w * _MAD_K * mad + (1 - w) * pop_scale) ** 2 + (alpha * pop_scale) ** 2)
        self._pop_med = pop_med                           # for principals never seen in the fit window
        self._pop_scale = np.sqrt(pop_scale ** 2 + (alpha * pop_scale) ** 2)
        self._index = {p: i for i, p in enumerate(uniq)}

    def _lookup(self, principals: np.ndarray) -> np.ndarray:
        return np.array([self._index.get(p, -1) for p in principals])

    def _z(self, df: pd.DataFrame) -> np.ndarray:
        X = self._t(df[self.feat_cols].to_numpy(dtype=np.float64))
        idx = self._lookup(df["principal"].to_numpy())
        known = (idx >= 0)[:, None]
        med = np.where(known, self._med[np.maximum(idx, 0)], self._pop_med)
        scale = np.where(known, self._scale[np.maximum(idx, 0)], self._pop_scale)
        return np.maximum((X - med) / scale, 0.0)            # one-sided: only increases are suspicious

    def _family_scores(self, z: np.ndarray) -> np.ndarray:
        agg = self.params["family_agg"]
        cols = []
        for fam in self.families:
            zf = z[:, self._fam_idx[fam]]
            if agg == "l2":
                cols.append(np.sqrt((zf ** 2).sum(axis=1)))
            elif agg == "max":
                cols.append(zf.max(axis=1))
            elif agg == "sum":
                cols.append(zf.sum(axis=1))
            else:
                raise ValueError(f"unknown family_agg {agg!r}")
        return np.column_stack(cols)

    # -- fit -----------------------------------------------------------------
    def fit(self, df_feat: pd.DataFrame, events: Optional[pd.DataFrame] = None) -> "BudgetAwareConformal":  # noqa: ARG002
        """Fit on the fit window (train, or train+val for the final test run)."""
        all_cols = feature_columns(df_feat)
        self.families = [f for f in self.params["families"] if family_columns(all_cols, f)]
        if not self.families:
            raise ValueError("no feature family left to score")
        self.feat_cols, self._fam_idx, pos = [], {}, 0
        for f in self.families:
            cols = family_columns(all_cols, f)
            self.feat_cols += cols
            self._fam_idx[f] = np.arange(pos, pos + len(cols))
            pos += len(cols)

        days = np.sort(df_feat["date"].unique())
        cut = days[int(len(days) * (1.0 - self.params["cal_fraction"]))]
        early, late = df_feat[df_feat["date"] < cut], df_feat[df_feat["date"] >= cut]
        if early.empty or late.empty:
            raise ValueError("fit window too short for the calibration split")

        # C2: baselines from the early part, calibration = family scores of the held-out late part.
        # Scoring later uses these SAME baselines, so test scores and calibration scores are
        # produced by the same function (the exchangeability split-conformal relies on).
        self._baselines(early)
        cal = self._family_scores(self._z(late))
        self._cal_sorted = [np.sort(cal[:, j]) for j in range(cal.shape[1])]
        self._fitted = True
        log.info("BudgetAwareConformal: %d principals, %d features / %d families, %d calibration rows",
                 len(self._index), len(self.feat_cols), len(self.families), len(late))
        return self

    # -- score ---------------------------------------------------------------
    def family_pvalues(self, df_feat: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
        """(z-scores, family scores, family p-values) for ``df_feat`` rows."""
        if not self._fitted:
            raise RuntimeError("detector not fitted")
        z = self._z(df_feat)
        fs = self._family_scores(z)
        pv = np.column_stack([conformal_pvalues(fs[:, j], self._cal_sorted[j]) for j in range(fs.shape[1])])
        return z, fs, pv

    def score(self, df_feat: pd.DataFrame, events: Optional[pd.DataFrame] = None) -> np.ndarray:  # noqa: ARG002
        """Per-row anomaly score (higher = more anomalous)."""
        _, fs, pv = self.family_pvalues(df_feat)
        if not self.params["calibrate"]:                   # ablation: no calibration, raw family scores
            return fs.sum(axis=1)
        return fuse(pv, self.params["fusion"])

    # -- O3: explanations ----------------------------------------------------
    def explain(self, df_feat: pd.DataFrame, top_k: int = 3) -> list[dict]:
        """Structured per-row explanation: family p-values, primary family, top features."""
        z, fs, pv = self.family_pvalues(df_feat)
        X = df_feat[self.feat_cols].to_numpy(dtype=np.float64)
        idx = self._lookup(df_feat["principal"].to_numpy())
        usual = self._inv_t(np.where((idx >= 0)[:, None], self._med[np.maximum(idx, 0)], self._pop_med))
        out = []
        for i in range(len(df_feat)):
            order_f = np.argsort(pv[i], kind="stable")
            primary = self.families[order_f[0]]
            fidx = self._fam_idx[primary]
            top = fidx[np.argsort(-z[i, fidx], kind="stable")][:top_k]
            out.append(dict(
                principal=str(df_feat["principal"].iloc[i]),
                date=str(pd.Timestamp(df_feat["date"].iloc[i]).date()),
                primary_family=primary,
                family_pvalues={f: float(pv[i, j]) for j, f in enumerate(self.families)},
                secondary_families=[self.families[j] for j in order_f[1:] if pv[i, j] < 0.01],
                top_features=[dict(feature=self.feat_cols[c], z=float(z[i, c]), value=float(X[i, c]),
                                   usual=float(usual[i, c])) for c in top if z[i, c] > 0],
            ))
        return out
