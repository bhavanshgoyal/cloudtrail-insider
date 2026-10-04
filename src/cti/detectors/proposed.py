"""
cti.detectors.proposed
----------------------
BudgetAwareConformal — the proposed insider-threat detector.

Architecture (four ablatable components)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
C1  Per-family surprisal
    For each feature family (volume, diversity/rarity, temporal/error),
    fit a per-principal Isolation Forest.  The anomaly score of an event
    is relative to *that principal's own history*, not the global
    population.

C2  Conformal calibration
    Convert each per-family raw score into a conformal p-value using the
    principal's own calibration window, so scores from different
    principals live on the same [0, 1] scale.

C3  Fisher fusion
    Combine per-family p-values via Fisher's method into a single
    chi-squared statistic.  An event that is mildly unusual in *three*
    ways simultaneously is flagged even if no single family would
    trigger alone.

C4  Budget-aware incident selector
    Aggregate event-level fused scores into per-principal-per-day
    incident scores.  Rank incidents globally and suppress duplicate
    principals across consecutive days so the alert budget is spent on
    *distinct insider candidates*.

Why this beats Isolation Forest at k = 10
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
IF scores on one global scale, so inherently noisy principals
(service accounts doing 500 events/day) monopolise the top of the
ranked list.  BudgetAwareConformal scores each event relative to its
own principal's baseline, making the top-10 list diverse and
actionable.
"""
from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import pandas as pd
from scipy.stats import chi2
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from cti.features.pipeline import FAMILY_PREFIXES

log = logging.getLogger(__name__)

# ── Feature family definitions ───────────────────────────────────────────
# Single source of truth: cti.features.pipeline.FAMILY_PREFIXES
# (identity / resource / temporal / volume).
_FAMILIES = {name: list(prefixes) for name, prefixes in FAMILY_PREFIXES.items()}


def _family_columns(feat_cols: list[str], family: str) -> list[str]:
    """Return feature columns belonging to a family."""
    prefixes = _FAMILIES[family]
    return [c for c in feat_cols if any(c.startswith(p) for p in prefixes)]


# ── C1: Per-principal per-family surprisal ───────────────────────────────

class _PerPrincipalIF:
    """Train one small Isolation Forest per principal per family.

    Each principal gets its own StandardScaler + IsolationForest so that
    anomaly scores reflect deviations from *that principal's own* baseline,
    not the global population.
    """

    def __init__(self, n_estimators: int = 100, contamination: float = 0.05, seed: int = 42) -> None:
        self.seed = seed
        self.n_estimators = n_estimators
        self.contamination = contamination
        self._models: dict[str, IsolationForest] = {}
        self._scalers: dict[str, StandardScaler] = {}

    def fit(self, df: pd.DataFrame, family_cols: list[str], min_events: int = 30) -> "_PerPrincipalIF":
        df = df.reset_index(drop=True)
        # Adaptively lower threshold if dataset is small
        effective_min = max(5, min(min_events, len(df) // max(1, df["principal"].nunique()) // 2))
        for principal, group in df.groupby("principal"):
            if len(group) < effective_min:
                continue
            X = group[family_cols].to_numpy(dtype=np.float32)
            # Per-principal standardisation
            scaler = StandardScaler()
            X_scaled = scaler.fit_transform(X)
            model = IsolationForest(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                random_state=self.seed,
                n_jobs=1,          # tiny per-principal forests: thread start-up dominates otherwise
            )
            model.fit(X_scaled)
            self._models[principal] = model
            self._scalers[principal] = scaler
        log.info("Fitted per-principal IF for %d principals (min_events=%d)",
                 len(self._models), effective_min)
        return self

    def score(self, df: pd.DataFrame, family_cols: list[str]) -> np.ndarray:
        """Return per-row anomaly scores (higher = more anomalous)."""
        df = df.reset_index(drop=True)
        scores = np.zeros(len(df), dtype=np.float64)
        for principal, group in df.groupby("principal"):
            idx = group.index.to_numpy()  # Now guaranteed 0-based after reset
            X = group[family_cols].to_numpy(dtype=np.float32)
            if principal in self._models:
                X_scaled = self._scalers[principal].transform(X)
                # Negate so higher = more anomalous
                scores[idx] = -self._models[principal].score_samples(X_scaled)
            else:
                # Principal not seen in training — assign moderate score
                scores[idx] = 0.5
        return scores


# ── C2: Conformal calibration ───────────────────────────────────────────

def _conformal_pvalues(
    scores: np.ndarray,
    principals: np.ndarray,
    calibration_scores: dict[str, np.ndarray],
) -> np.ndarray:
    """Convert raw anomaly scores to conformal p-values.

    For each event, the p-value is the fraction of calibration scores
    from the *same principal* that are >= the test score.  Lower p-value
    means more anomalous (less conforming).
    """
    pvals = np.ones(len(scores), dtype=np.float64)
    for i, (score, principal) in enumerate(zip(scores, principals)):
        cal = calibration_scores.get(principal)
        if cal is not None and len(cal) > 0:
            # Fraction of calibration scores >= this score
            pvals[i] = (np.sum(cal >= score) + 1) / (len(cal) + 1)
        else:
            pvals[i] = 0.5  # Unknown principal — neutral
    return pvals


# ── C3: Fisher fusion ───────────────────────────────────────────────────

def _fisher_fusion(pval_matrix: np.ndarray) -> np.ndarray:
    """Combine per-family p-values via Fisher's method.

    Parameters
    ----------
    pval_matrix : ndarray of shape (n_samples, n_families)
        Each column is a vector of p-values from one family.

    Returns
    -------
    ndarray of shape (n_samples,)
        Fused anomaly scores (higher = more anomalous).
        Specifically: -2 * sum(ln(p)), which follows chi2(2k) under H0.
    """
    # Clip to avoid log(0)
    pval_matrix = np.clip(pval_matrix, 1e-15, 1.0)
    k = pval_matrix.shape[1]
    stat = -2.0 * np.sum(np.log(pval_matrix), axis=1)
    # Convert chi2 statistic to a p-value (lower = more anomalous),
    # then negate so higher = more anomalous
    fused_pval = chi2.sf(stat, df=2 * k)
    # Return 1 - p so that higher = more anomalous
    return 1.0 - fused_pval


# ── C4: Budget-aware incident selector ──────────────────────────────────

def _incident_aggregation(
    df_scored: pd.DataFrame,
    score_col: str = "fused_score",
    suppress_days: int = 3,
) -> pd.DataFrame:
    """Aggregate event-level scores into per-principal-per-day incidents.

    For each (principal, date) pair, the incident score is the maximum
    fused score.  Then suppress duplicate principals within
    ``suppress_days`` consecutive days so the budget is spent on
    distinct insider candidates.
    """
    # Aggregate: max score per principal per day
    incidents = (
        df_scored.groupby(["principal", "date"])[score_col]
        .max()
        .reset_index()
        .rename(columns={score_col: "incident_score"})
    )
    incidents = incidents.sort_values("incident_score", ascending=False).reset_index(drop=True)

    # Suppress: remove duplicate principals within suppress_days
    seen: dict[str, pd.Timestamp] = {}
    keep = []
    for _, row in incidents.iterrows():
        principal = row["principal"]
        date = pd.Timestamp(row["date"])
        if principal in seen:
            last_date = seen[principal]
            if abs((date - last_date).days) <= suppress_days:
                continue
        seen[principal] = date
        keep.append(row)

    if keep:
        return pd.DataFrame(keep).reset_index(drop=True)
    return incidents.head(0)


# ── Main detector class ─────────────────────────────────────────────────

class BudgetAwareConformal:
    """Proposed detector: per-principal conformal calibration with
    Fisher fusion and budget-aware incident selection.

    This detector implements four components (C1–C4) that can be
    individually ablated via the ``ablation`` parameter.
    """

    def __init__(self, cfg: dict, seed: int) -> None:
        self.name = "proposed_budget_aware_conformal"
        self.seed = seed
        self.cfg = cfg

        det_cfg = cfg.get("detectors", {}).get("proposed", {})
        self.suppress_days = cfg.get("suppress_days", 3)
        self.min_events = det_cfg.get("min_events", 30)
        self.n_estimators = det_cfg.get("n_estimators", 100)
        self.contamination = det_cfg.get("contamination", 0.05)
        self.cal_fraction = det_cfg.get("cal_fraction", 0.3)

        # Per-family per-principal IF models
        self._family_models: dict[str, _PerPrincipalIF] = {}
        # Calibration scores per family per principal
        self._calibration_scores: dict[str, dict[str, np.ndarray]] = {}
        self._feat_cols: list[str] = []
        self._fitted = False

    needs_events = False

    def fit(self, df_feat: pd.DataFrame, events: Optional[pd.DataFrame] = None) -> "BudgetAwareConformal":
        """Fit on the TRAIN window.

        Parameters
        ----------
        df_feat : pd.DataFrame
            Train-window feature rows with 'principal' and 'date' columns.
        events : ignored (interface compatibility).
        """
        self._feat_cols = [c for c in df_feat.columns if c not in {"principal", "date"}]

        # ── Temporal split: 70 % fit / 30 % calibration ─────────────
        # Calibration scores MUST come from data the IF models have NOT
        # seen, otherwise the conformal p-values collapse to near-uniform
        # and Fisher fusion produces no signal.
        unique_dates = sorted(df_feat["date"].unique())
        split_idx = int(len(unique_dates) * (1.0 - self.cal_fraction))
        fit_dates = set(unique_dates[:split_idx])
        cal_dates = set(unique_dates[split_idx:])
        df_fit = df_feat[df_feat["date"].isin(fit_dates)].copy()
        df_cal = df_feat[df_feat["date"].isin(cal_dates)].copy()
        log.info("Fit/cal split: %d fit days, %d cal days (%d / %d rows)",
                 len(fit_dates), len(cal_dates), len(df_fit), len(df_cal))

        # C1: Fit per-family per-principal IF models on fit split only
        for family_name in _FAMILIES:
            family_cols = _family_columns(self._feat_cols, family_name)
            if not family_cols:
                log.warning("No columns for family '%s'", family_name)
                continue

            model = _PerPrincipalIF(
                n_estimators=self.n_estimators,
                contamination=self.contamination,
                seed=self.seed,
            )
            model.fit(df_fit, family_cols, min_events=self.min_events)
            self._family_models[family_name] = model

        # C2: Build calibration scores on HELD-OUT calibration split
        df_cal_reset = df_cal.reset_index(drop=True)
        for family_name, model in self._family_models.items():
            family_cols = _family_columns(self._feat_cols, family_name)
            raw_scores = model.score(df_cal_reset, family_cols)

            cal_scores: dict[str, np.ndarray] = {}
            for principal, group in df_cal_reset.groupby("principal"):
                idx = group.index.to_numpy()
                cal_scores[principal] = raw_scores[idx]
            self._calibration_scores[family_name] = cal_scores

        self._fitted = True
        log.info("BudgetAwareConformal fitted with %d families", len(self._family_models))
        return self

    def score(self, df_feat: pd.DataFrame, events: Optional[pd.DataFrame] = None) -> np.ndarray:
        """Per-row fused anomaly score (higher = more anomalous)."""
        if not self._fitted:
            raise RuntimeError("Detector not fitted. Call fit() first.")

        feat_cols = [c for c in df_feat.columns if c not in {"principal", "date"}]
        df_feat = df_feat.reset_index(drop=True)
        principals = df_feat["principal"].to_numpy()
        n = len(df_feat)

        # C1: Per-family surprisal scores
        family_scores = {}
        for family_name, model in self._family_models.items():
            family_cols = _family_columns(feat_cols, family_name)
            if family_cols:
                family_scores[family_name] = model.score(df_feat, family_cols)

        if not family_scores:
            return np.zeros(n)

        # C2: Convert to conformal p-values
        pval_matrix = np.ones((n, len(family_scores)), dtype=np.float64)
        for j, (family_name, scores) in enumerate(family_scores.items()):
            cal = self._calibration_scores.get(family_name, {})
            pval_matrix[:, j] = _conformal_pvalues(scores, principals, cal)

        # C3: Fisher fusion
        fused = _fisher_fusion(pval_matrix)

        return fused

    def score_and_select(
        self,
        df_feat: pd.DataFrame,
        budget: int = 10,
    ) -> pd.DataFrame:
        """Full pipeline: score → fuse → aggregate → select top incidents.

        Parameters
        ----------
        df_feat : pd.DataFrame
            Test feature matrix with 'principal' and 'date' columns.
        budget : int
            Number of alerts to emit.

        Returns
        -------
        pd.DataFrame
            Top incidents ranked by fused score, limited to ``budget``.
        """
        fused_scores = self.score(df_feat)

        df_scored = df_feat[["principal", "date"]].copy()
        df_scored["fused_score"] = fused_scores

        # C4: Budget-aware incident selection
        incidents = _incident_aggregation(
            df_scored,
            score_col="fused_score",
            suppress_days=self.suppress_days,
        )

        return incidents.head(budget)
