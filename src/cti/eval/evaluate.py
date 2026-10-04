"""
cti.eval.evaluate
-----------------
Fixed **per-day** alert-budget evaluation (objective O2).

Operating model
~~~~~~~~~~~~~~~
Detectors score (principal, day) rows. At the end of every day the SOC queue
receives that day's **top-B** rows (``emit_alerts``); an analyst can only look
at those. A score of ``NaN`` means "no alert" (e.g. no rule fired). Ties are
broken by a seeded random order, so a detector that outputs many equal scores
gets no unearned advantage from row order. Optional suppression (component C4
of the proposed detector) drops a principal that was already alerted in the
previous ``suppress_days`` days, so the budget goes to distinct candidates.

Metrics at budget B (``evaluate_alerts``)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
``dr_at_b``          detection rate: fraction of insiders active in the window
                     with >= 1 alert on one of their malicious days.
``precision_at_b``   true-positive alerts / alerts emitted (micro).
``precision_day_mean``  mean of per-day precision over days with >= 1 alert.
``precision_oracle_at_b``  best achievable precision at this budget (few malicious
                     rows exist per day, so the ceiling is far below 1).
``alerts_per_day``   mean alerts actually emitted per day (< B if a detector
                     abstains, e.g. rules).
``mttd_hours_median`` / ``mttd_hours_mean``
                     time to detection over *detected* insiders. Onset = first
                     malicious event inside the window (or 00:00 of the first
                     malicious day if the attack began before the window).
                     Alerts are a daily batch available at the end of the day,
                     so detection time = 24:00 of the alerting day.
``n_detected`` / ``n_insiders``
Reference, budget-free: ``auc_roc``, ``pr_auc`` over all window rows.

Uncertainty
~~~~~~~~~~~
Confidence intervals use ``scipy.stats.bootstrap`` with BCa, falling back to
percentile when BCa is degenerate (logged in ``ci_method``). The resampling
unit follows the metric's denominator: **days** for precision, **insiders**
for DR / MTTD. ``compare`` gives paired relative differences (A - B) / B with
the same resampling of days or insiders for both detectors.
"""
from __future__ import annotations

import logging
import warnings
from dataclasses import dataclass

import numpy as np
import pandas as pd
from scipy import stats
from sklearn.metrics import average_precision_score, roc_auc_score

log = logging.getLogger(__name__)

_DAY = pd.Timedelta(days=1)

# Point metrics with the unit their CI is resampled over.
_DAY_METRICS = ("precision_at_b",)
_INSIDER_METRICS = ("dr_at_b", "mttd_hours_median", "mttd_hours_mean")


# ---------------------------------------------------------------------------
# Context: what is in the evaluation window
# ---------------------------------------------------------------------------
@dataclass
class EvalContext:
    days: pd.DatetimeIndex                 # window days, sorted
    labels: pd.DataFrame                   # principal, date, label for every window row
    insiders: pd.DataFrame                 # principal, scenario_id, onset, first_day, mal_days


def build_context(df_rows: pd.DataFrame, df_labels: pd.DataFrame, ground_truth: list[dict],
                  window_days) -> EvalContext:
    """Restrict labels and ground truth to the evaluation window.

    ``df_rows`` are the (principal, date) rows that will be scored (the window
    rows of the feature matrix).
    """
    days = pd.DatetimeIndex(sorted(pd.to_datetime(np.asarray(window_days))))
    rows = df_rows[["principal", "date"]].copy()
    rows["date"] = pd.to_datetime(rows["date"])
    rows = rows[rows["date"].isin(days)]
    lab = rows.merge(df_labels[["principal", "date", "label"]], on=["principal", "date"], how="left")
    lab["label"] = lab["label"].fillna(0).astype(int)

    day_set = {d.strftime("%Y-%m-%d") for d in days}
    recs = []
    for g in ground_truth:
        in_win = sorted(d for d in g["malicious_days"] if d in day_set)
        if not in_win:
            continue
        first_day = pd.Timestamp(in_win[0])
        first_ev = pd.Timestamp(g["first_event_time"]).tz_convert("UTC").tz_localize(None)
        onset = first_ev if first_ev.normalize() == first_day else first_day
        recs.append({"principal": g["principal_id"], "scenario_id": g["scenario_id"],
                     "onset": onset, "first_day": first_day,
                     "mal_days": frozenset(pd.Timestamp(d) for d in in_win)})
    insiders = pd.DataFrame(recs, columns=["principal", "scenario_id", "onset", "first_day", "mal_days"])
    return EvalContext(days=days, labels=lab, insiders=insiders)


# ---------------------------------------------------------------------------
# Alert emission
# ---------------------------------------------------------------------------
def emit_alerts(df_scores: pd.DataFrame, budget: int, suppress_days: int = 0,
                seed: int = 0) -> pd.DataFrame:
    """Per-day top-``budget`` alerts.

    Parameters
    ----------
    df_scores : principal, date, score (one row per principal-day; NaN = no alert)
    budget : alerts per day
    suppress_days : drop a principal alerted within the previous ``suppress_days`` days
    seed : tie-break seed

    Returns principal, date, score, rank (1 = top of that day's queue).
    """
    df = df_scores[["principal", "date", "score"]].copy()
    df["date"] = pd.to_datetime(df["date"])
    df = df[np.isfinite(df["score"].to_numpy(dtype=float))]
    if df.empty:
        return df.assign(rank=pd.Series(dtype=int))
    rng = np.random.default_rng(seed)
    df["_tie"] = rng.random(len(df))
    df = df.sort_values(["date", "score", "_tie"], ascending=[True, False, True], kind="mergesort")

    if suppress_days <= 0:
        df["rank"] = df.groupby("date").cumcount() + 1
        out = df[df["rank"] <= budget]
    else:
        last_alert: dict[str, pd.Timestamp] = {}
        keep = []
        window = pd.Timedelta(days=suppress_days)
        for date, grp in df.groupby("date", sort=True):
            taken = 0
            for idx, principal in zip(grp.index, grp["principal"]):
                prev = last_alert.get(principal)
                if prev is not None and date - prev <= window:
                    continue
                keep.append(idx)
                taken += 1
                if taken == budget:
                    break
            for principal in df.loc[keep[len(keep) - taken:], "principal"]:
                last_alert[principal] = date
        out = df.loc[keep].copy()
        out["rank"] = out.groupby("date").cumcount() + 1
    return out.drop(columns="_tie").reset_index(drop=True)


# ---------------------------------------------------------------------------
# Metrics for one detector at one budget
# ---------------------------------------------------------------------------
@dataclass
class BudgetResult:
    budget: int
    point: dict                      # metric -> value
    day_tp: np.ndarray               # per window day
    day_n: np.ndarray
    detected: np.ndarray             # per insider (bool), aligned with ctx.insiders
    ttd_hours: np.ndarray            # per insider (NaN if undetected)
    alerts: pd.DataFrame             # emitted alerts with label


def evaluate_alerts(alerts: pd.DataFrame, ctx: EvalContext, budget: int) -> BudgetResult:
    al = alerts.merge(ctx.labels, on=["principal", "date"], how="left")
    al["label"] = al["label"].fillna(0).astype(int)

    per_day = al.groupby("date")["label"].agg(["sum", "size"]).reindex(ctx.days, fill_value=0)
    day_tp = per_day["sum"].to_numpy(dtype=float)
    day_n = per_day["size"].to_numpy(dtype=float)

    tp_alerts = al[al["label"] == 1]
    detected = np.zeros(len(ctx.insiders), dtype=bool)
    ttd = np.full(len(ctx.insiders), np.nan)
    for i, row in enumerate(ctx.insiders.itertuples(index=False)):
        hits = tp_alerts.loc[tp_alerts["principal"] == row.principal, "date"]
        hits = hits[hits.isin(row.mal_days)]
        if len(hits):
            detected[i] = True
            ttd[i] = (hits.min() + _DAY - row.onset) / pd.Timedelta(hours=1)

    n_alerts = day_n.sum()
    days_with = day_n > 0
    # Oracle: best achievable precision with this budget given how few malicious rows exist per day.
    pos_d = ctx.labels.groupby("date")["label"].sum().reindex(ctx.days, fill_value=0).to_numpy()
    rows_d = ctx.labels.groupby("date").size().reindex(ctx.days, fill_value=0).to_numpy()
    oracle_n = np.minimum(rows_d, budget).sum()
    point = {
        "dr_at_b": detected.mean() if len(detected) else np.nan,
        "precision_at_b": day_tp.sum() / n_alerts if n_alerts else np.nan,
        "precision_day_mean": float(np.mean(day_tp[days_with] / day_n[days_with])) if days_with.any() else np.nan,
        "precision_oracle_at_b": float(np.minimum(pos_d, budget).sum() / oracle_n) if oracle_n else np.nan,
        "alerts_per_day": float(day_n.mean()),
        "mttd_hours_median": float(np.nanmedian(ttd)) if detected.any() else np.nan,
        "mttd_hours_mean": float(np.nanmean(ttd)) if detected.any() else np.nan,
        "n_detected": float(detected.sum()),
        "n_insiders": float(len(detected)),
    }
    return BudgetResult(budget, point, day_tp, day_n, detected, ttd, al)


def curve_metrics(df_scores: pd.DataFrame, ctx: EvalContext) -> dict:
    """Budget-free reference metrics over every window row (missing score = lowest)."""
    df = ctx.labels.merge(df_scores[["principal", "date", "score"]], on=["principal", "date"], how="left")
    s = df["score"].to_numpy(dtype=float)
    finite = np.isfinite(s)
    s = np.where(finite, s, (s[finite].min() - 1.0) if finite.any() else 0.0)
    y = df["label"].to_numpy()
    if y.min() == y.max():
        return {"auc_roc": np.nan, "pr_auc": np.nan}
    return {"auc_roc": float(roc_auc_score(y, s)), "pr_auc": float(average_precision_score(y, s))}


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------
def _ci(data: tuple, statistic, n_resamples: int, conf: float, seed: int,
        method: str = "BCa") -> tuple[float, float, str]:
    """CI via scipy.stats.bootstrap (paired resampling of the arrays in ``data``)."""
    n = len(data[0])
    if n < 2:
        return np.nan, np.nan, "n<2"
    point = statistic(*data, axis=-1) if callable(statistic) else np.nan
    for m in ([method, "percentile"] if method != "percentile" else ["percentile"]):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            try:
                res = stats.bootstrap(data, statistic, paired=True, vectorized=True,
                                      n_resamples=n_resamples, confidence_level=conf,
                                      method=m, random_state=np.random.default_rng(seed))
            except Exception as exc:  # noqa: BLE001 - degenerate resamples, too few distinct values
                log.debug("bootstrap %s failed: %s", m, exc)
                continue
        lo, hi = float(res.confidence_interval.low), float(res.confidence_interval.high)
        if np.isfinite(lo) and np.isfinite(hi):
            return lo, hi, m.lower()
    if np.isfinite(point):
        return float(point), float(point), "degenerate"
    return np.nan, np.nan, "degenerate"


def _ratio(tp, n, axis=-1):
    with np.errstate(invalid="ignore", divide="ignore"):
        return np.sum(tp, axis=axis) / np.sum(n, axis=axis)


def _mean(x, axis=-1):
    return np.mean(x, axis=axis)


def _nanmedian(x, axis=-1):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return np.nanmedian(x, axis=axis)


def _nanmean(x, axis=-1):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        return np.nanmean(x, axis=axis)


def confidence_intervals(r: BudgetResult, n_resamples: int, conf: float, seed: int,
                         method: str = "BCa") -> dict[str, tuple[float, float, str]]:
    out = {"precision_at_b": _ci((r.day_tp, r.day_n), _ratio, n_resamples, conf, seed, method),
           "dr_at_b": _ci((r.detected.astype(float),), _mean, n_resamples, conf, seed, method)}
    det = r.ttd_hours[np.isfinite(r.ttd_hours)]
    out["mttd_hours_median"] = _ci((det,), _nanmedian, n_resamples, conf, seed, method)
    out["mttd_hours_mean"] = _ci((det,), _nanmean, n_resamples, conf, seed, method)
    return out


# ---------------------------------------------------------------------------
# Evaluate detectors over a window
# ---------------------------------------------------------------------------
def evaluate_window(score_frames: dict[str, pd.DataFrame], ctx: EvalContext, cfg: dict,
                    suppress: dict[str, int] | None = None, budgets=None, with_ci: bool = True,
                    seed: int | None = None) -> tuple[pd.DataFrame, dict[str, dict[int, BudgetResult]]]:
    """Evaluate every detector at every budget.

    Returns ``(tidy, results)``. ``tidy`` has columns
    ``detector, budget, metric, value, ci_lo, ci_hi, ci_method`` (``budget`` is
    0 for budget-free metrics); ``results[detector][budget]`` keeps the raw
    per-day / per-insider arrays for paired comparisons.
    """
    ev = cfg["eval"]
    budgets = budgets or cfg["budgets"]
    seed = cfg["random_seed"] if seed is None else seed
    suppress = suppress or {}
    rows, results = [], {}
    for name, df_s in score_frames.items():
        results[name] = {}
        for k, v in curve_metrics(df_s, ctx).items():
            rows.append(dict(detector=name, budget=0, metric=k, value=v, ci_lo=np.nan, ci_hi=np.nan,
                             ci_method=""))
        for b in budgets:
            alerts = emit_alerts(df_s, b, suppress.get(name, 0), seed)
            r = evaluate_alerts(alerts, ctx, b)
            results[name][b] = r
            cis = confidence_intervals(r, ev["bootstrap_iterations"], ev["confidence_level"], seed,
                                       ev.get("bootstrap_method", "BCa")) if with_ci else {}
            for metric, value in r.point.items():
                lo, hi, m = cis.get(metric, (np.nan, np.nan, ""))
                rows.append(dict(detector=name, budget=b, metric=metric, value=value,
                                 ci_lo=lo, ci_hi=hi, ci_method=m))
    return pd.DataFrame(rows), results


def compare(a: BudgetResult, b: BudgetResult, cfg: dict, seed: int | None = None) -> list[dict]:
    """Paired relative difference (A - B) / B for DR and precision, with CIs.

    If B's point value is 0 the relative difference is undefined; the absolute
    difference (A - B) is reported instead and ``kind`` says so.
    """
    ev = cfg["eval"]
    seed = cfg["random_seed"] if seed is None else seed
    n_res, conf, method = ev["bootstrap_iterations"], ev["confidence_level"], ev.get("bootstrap_method", "BCa")
    out = []

    da, db = a.detected.astype(float), b.detected.astype(float)
    if db.mean() > 0:
        stat = lambda x, y, axis=-1: (np.mean(x, axis) - np.mean(y, axis)) / np.mean(y, axis)  # noqa: E731
        kind = "relative"
    else:
        stat = lambda x, y, axis=-1: np.mean(x, axis) - np.mean(y, axis)  # noqa: E731
        kind = "absolute (baseline is 0)"
    with np.errstate(invalid="ignore", divide="ignore"):
        lo, hi, m = _ci((da, db), stat, n_res, conf, seed, method)
        out.append(dict(metric="dr_at_b", kind=kind, value=float(stat(da, db)), ci_lo=lo, ci_hi=hi, ci_method=m))

    pa, pb = _ratio(a.day_tp, a.day_n), _ratio(b.day_tp, b.day_n)
    if np.isfinite(pb) and pb > 0:
        stat = lambda tpa, na, tpb, nb, axis=-1: (_ratio(tpa, na, axis) - _ratio(tpb, nb, axis)) / _ratio(tpb, nb, axis)  # noqa: E731
        kind = "relative"
    else:
        stat = lambda tpa, na, tpb, nb, axis=-1: _ratio(tpa, na, axis) - _ratio(tpb, nb, axis)  # noqa: E731
        kind = "absolute (baseline is 0)"
    with np.errstate(invalid="ignore", divide="ignore"):
        data = (a.day_tp, a.day_n, b.day_tp, b.day_n)
        lo, hi, m = _ci(data, stat, n_res, conf, seed, method)
        out.append(dict(metric="precision_at_b", kind=kind, value=float(stat(*data)), ci_lo=lo, ci_hi=hi,
                        ci_method=m))
    return out


def per_insider_table(results: dict[str, dict[int, BudgetResult]], ctx: EvalContext) -> pd.DataFrame:
    """Long table: detector, budget, principal, scenario, detected, ttd_hours."""
    rows = []
    for name, by_b in results.items():
        for b, r in by_b.items():
            for i, ins in enumerate(ctx.insiders.itertuples(index=False)):
                rows.append(dict(detector=name, budget=b, principal=ins.principal,
                                 scenario_id=ins.scenario_id, detected=bool(r.detected[i]),
                                 ttd_hours=r.ttd_hours[i]))
    return pd.DataFrame(rows)
