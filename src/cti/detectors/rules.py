"""
cti.detectors.rules
-------------------
Rule-signature baseline in the style of commercial cloud threat-detection
services (GuardDuty / Security Hub findings).

Each rule in ``configs/rules.yaml`` names a predicate below; predicates are
explicit vectorised Python (no ``eval``) and return a boolean mask over events.
Rules are *causal*: stateful ones (first-seen IP) only use earlier events, so
the engine can be evaluated over the full event log and queried for any window.

A (principal, day) is scored::

    score = max_severity + 0.1 * (distinct_rules - 1) + 0.001 * log1p(total_hits)

and 0 when no rule fires.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

log = logging.getLogger(__name__)

_NS_DAY = 86_400 * 10**9


# -- event context ------------------------------------------------------------
def _has(df: pd.DataFrame, col: str) -> bool:
    return col in df.columns


def _flag(series: pd.Series, fn) -> np.ndarray:
    """Boolean mask of ``fn(value)`` per row, evaluating ``fn`` once per unique value."""
    if isinstance(series.dtype, pd.CategoricalDtype):
        cats = series.cat.categories
        table = np.append(np.array([bool(fn(str(c))) for c in cats], dtype=bool), False)
        return table[series.cat.codes.to_numpy()]            # code -1 (missing) -> False
    codes, uniques = pd.factorize(series, use_na_sentinel=True)
    table = np.append(np.array([bool(fn(str(u))) for u in uniques], dtype=bool), False)
    return table[codes]


def _eq(series: pd.Series, *values: str) -> np.ndarray:
    vals = set(values)
    return _flag(series, lambda s: s in vals)


@dataclass
class _Ctx:
    df: pd.DataFrame
    pid: np.ndarray
    pid_names: np.ndarray
    day: np.ndarray
    D: int
    day0: pd.Timestamp
    params: dict

    @classmethod
    def build(cls, df: pd.DataFrame, params: dict) -> _Ctx:
        ts = pd.to_datetime(df["eventTime"], utc=True)
        t_ns = ts.dt.tz_convert("UTC").dt.tz_localize(None).to_numpy().astype("datetime64[ns]").astype(np.int64)
        day0 = (t_ns.min() // _NS_DAY) * _NS_DAY
        day = (t_ns - day0) // _NS_DAY
        codes, uniques = pd.factorize(df["principalId"], use_na_sentinel=True)
        return cls(df=df, pid=codes.astype(np.int64), pid_names=np.asarray(uniques, dtype=object),
                   day=day.astype(np.int64), D=int(day.max()) + 1,
                   day0=pd.Timestamp(day0, unit="ns"), params=params)

    def group_count(self, mask: np.ndarray) -> np.ndarray:
        """For events in ``mask``: how many masked events share its (principal, day)."""
        idx = np.nonzero(mask)[0]
        out = np.zeros(len(self.df), dtype=np.int64)
        if len(idx):
            key = self.pid[idx] * self.D + self.day[idx]
            _, inv, cnt = np.unique(key, return_inverse=True, return_counts=True)
            out[idx] = cnt[inv]
        return out


# -- predicates ---------------------------------------------------------------
def root_credential_usage(c: _Ctx) -> np.ndarray:
    return _eq(c.df["principalId"], "root")


def console_login_without_mfa(c: _Ctx) -> np.ndarray:
    if not _has(c.df, "mfaUsed"):
        return np.zeros(len(c.df), bool)
    ok = c.df["errorCode"].isna().to_numpy() if _has(c.df, "errorCode") else True
    return _eq(c.df["eventName"], "ConsoleLogin") & ok & (c.df["mfaUsed"].to_numpy() == 0)


def brute_force_then_success(c: _Ctx) -> np.ndarray:
    n = len(c.df)
    login = _eq(c.df["eventName"], "ConsoleLogin")
    out = np.zeros(n, bool)
    if not login.any() or not _has(c.df, "sourceIp") or not _has(c.df, "errorCode"):
        return out
    idx = np.nonzero(login)[0]
    ip, _ = pd.factorize(c.df["sourceIp"].iloc[idx], use_na_sentinel=True)
    failed = c.df["errorCode"].iloc[idx].notna().to_numpy()
    key = (c.pid[idx] * c.D + c.day[idx]) * (int(ip.max()) + 2) + ip
    uk, inv = np.unique(key, return_inverse=True)
    n_fail = np.bincount(inv, weights=failed, minlength=len(uk))
    n_succ = np.bincount(inv, weights=~failed, minlength=len(uk))
    fire = (n_fail[inv] >= c.params["brute_force_min_failures"]) & (n_succ[inv] >= 1) & ~failed
    out[idx[fire]] = True
    return out


def api_call_outside_corporate_ip(c: _Ctx) -> np.ndarray:
    if not _has(c.df, "sourceIp"):
        return np.zeros(len(c.df), bool)
    prefixes = tuple(c.params["corporate_ip_prefixes"])
    valid = c.df["sourceIp"].notna().to_numpy()
    return valid & ~_flag(c.df["sourceIp"], lambda s: s.startswith(prefixes))


def _params_contain(c: _Ctx, text: str) -> np.ndarray:
    if not _has(c.df, "requestParameters"):
        return np.zeros(len(c.df), bool)
    return _flag(c.df["requestParameters"], lambda s: text in s)


def public_exposure(c: _Ctx) -> np.ndarray:
    return _eq(c.df["eventName"], "ModifySnapshotAttribute", "PutBucketPolicy") & _params_contain(c, '"all"')


def create_access_key_for_other(c: _Ctx) -> np.ndarray:
    return _eq(c.df["eventName"], "CreateAccessKey") & _params_contain(c, '"other"')


def assume_admin_by_non_admin(c: _Ctx) -> np.ndarray:
    if not _has(c.df, "roleName"):
        return np.zeros(len(c.df), bool)
    return (_eq(c.df["eventName"], "AssumeRole") & _params_contain(c, '"admin"')
            & ~_eq(c.df["roleName"], "admin"))


def mass_get_object(c: _Ctx) -> np.ndarray:
    get = _eq(c.df["eventName"], "GetObject")
    if _has(c.df, "roleName"):
        get &= ~_eq(c.df["roleName"], *c.params["mass_get_exempt_roles"])
    return get & (c.group_count(get) >= c.params["mass_get_object_threshold"])


def logging_disabled(c: _Ctx) -> np.ndarray:
    return _eq(c.df["eventName"], "DeleteTrail", "StopLogging")


def external_mail(c: _Ctx) -> np.ndarray:
    mail = _eq(c.df["eventName"], "SendEmail") & _params_contain(c, "external")
    return mail & (c.group_count(mail) >= c.params["min_external_mails"])


def console_login_new_ip(c: _Ctx) -> np.ndarray:
    if not _has(c.df, "sourceIp"):
        return np.zeros(len(c.df), bool)
    ip, _ = pd.factorize(c.df["sourceIp"], use_na_sentinel=True)
    pair = c.pid * (int(ip.max()) + 2) + ip
    up, inv = np.unique(pair, return_inverse=True)
    first = pd.Series(c.day).groupby(inv).min().to_numpy()
    new_today = c.day == first[inv]                       # first time this principal used this IP
    return _eq(c.df["eventName"], "ConsoleLogin") & new_today & (ip >= 0)


def excessive_access_denied(c: _Ctx) -> np.ndarray:
    if not _has(c.df, "errorCode"):
        return np.zeros(len(c.df), bool)
    denied = _eq(c.df["errorCode"], "AccessDenied")
    return denied & (c.group_count(denied) >= c.params["excessive_denied_threshold"])


PREDICATES = {fn.__name__: fn for fn in (
    root_credential_usage, console_login_without_mfa, brute_force_then_success,
    api_call_outside_corporate_ip, public_exposure, create_access_key_for_other,
    assume_admin_by_non_admin, mass_get_object, logging_disabled, external_mail,
    console_login_new_ip, excessive_access_denied,
)}


# -- engine -------------------------------------------------------------------
def load_rules(path: str | Path) -> tuple[list[dict], dict]:
    """Load and validate the rule file. Returns ``(rules, params)``."""
    p = Path(path)
    if not p.exists():
        p = Path(__file__).parents[3] / path
    with p.open(encoding="utf-8") as fh:
        spec = yaml.safe_load(fh)
    rules = spec["rules"]
    unknown = [r["id"] for r in rules if r["predicate"] not in PREDICATES]
    if unknown:
        raise ValueError(f"rules reference unknown predicates: {unknown}")
    return rules, spec.get("params", {})


class RuleEngine:
    """Evaluates the configured rules over an event log."""

    def __init__(self, rules: list[dict], params: dict) -> None:
        self.rules = rules
        self.params = params

    @classmethod
    def from_file(cls, path: str | Path) -> RuleEngine:
        return cls(*load_rules(path))

    def evaluate(self, events: pd.DataFrame) -> pd.DataFrame:
        """Per (principal, date): ``max_severity, n_rules, hits, rules`` for fired rules."""
        ctx = _Ctx.build(events, self.params)
        parts = []
        for rule in self.rules:
            mask = PREDICATES[rule["predicate"]](ctx)
            idx = np.nonzero(mask)[0]
            log.info("  %s %-34s fired on %d events", rule["id"], rule["predicate"], len(idx))
            if len(idx):
                parts.append(pd.DataFrame({
                    "pid": ctx.pid[idx], "day": ctx.day[idx],
                    "rule": rule["id"], "severity": float(rule["severity"])}))
        if not parts:
            return pd.DataFrame(columns=["principal", "date", "max_severity", "n_rules", "hits", "rules"])
        fired = pd.concat(parts, ignore_index=True)
        agg = fired.groupby(["pid", "day"]).agg(
            max_severity=("severity", "max"), n_rules=("rule", "nunique"), hits=("rule", "size"),
            rules=("rule", lambda s: ",".join(sorted(set(s))))).reset_index()
        agg["principal"] = ctx.pid_names[agg["pid"].to_numpy()].astype(str)
        agg["date"] = ctx.day0 + pd.to_timedelta(agg["day"], unit="D")
        agg["date"] = agg["date"].dt.tz_localize(None) if agg["date"].dt.tz is not None else agg["date"]
        return agg[["principal", "date", "max_severity", "n_rules", "hits", "rules"]]


class RuleBaselineDetector:
    """Detector wrapper: scores (principal, day) rows by their fired rules.

    ``score(df_feat, events)`` needs the **full event log** (rules are causal,
    so earlier events are history, not leakage); only rows of ``df_feat`` are
    scored.
    """

    name = "rule_baseline"
    needs_events = True
    abstains = True          # score 0 (no rule fired) means "no alert", not "lowest-ranked alert"

    def __init__(self, cfg: dict, seed: int) -> None:  # noqa: ARG002
        path = cfg.get("rules_cfg", {}).get("rules_file", "configs/rules.yaml")
        self.engine = RuleEngine.from_file(path)
        self._cache_key: tuple | None = None
        self._cache: pd.DataFrame | None = None

    def fit(self, df_feat: pd.DataFrame, events: pd.DataFrame | None = None) -> RuleBaselineDetector:  # noqa: ARG002
        return self                                           # signatures need no training

    def fired(self, events: pd.DataFrame) -> pd.DataFrame:
        key = (id(events), len(events))
        if self._cache_key != key:
            self._cache, self._cache_key = self.engine.evaluate(events), key
        return self._cache

    def score(self, df_feat: pd.DataFrame, events: pd.DataFrame | None = None) -> np.ndarray:
        if events is None:
            raise ValueError("RuleBaselineDetector.score needs the event log")
        res = self.fired(events)
        merged = df_feat[["principal", "date"]].merge(res, on=["principal", "date"], how="left")
        sev = merged["max_severity"].fillna(0.0).to_numpy()
        n_rules = merged["n_rules"].fillna(0.0).to_numpy()
        hits = merged["hits"].fillna(0.0).to_numpy()
        return np.where(sev > 0, sev + 0.1 * (n_rules - 1) + 0.001 * np.log1p(hits), 0.0)
