"""
cti.features.pipeline
---------------------
Per-(principal, day) feature matrix for the anomaly detectors (objective O1).

Four feature families, each capturing a different aspect of deviation:

=========  ==========================  =======================================
family     prefixes                    what it captures
=========  ==========================  =======================================
identity   ``idn_`` ``err_``           *who*: new IPs / user agents / regions,
                                       login failures, logins without MFA
resource   ``res_`` ``rar_``           *what*: sensitive / new / external
                                       resources, privilege-escalating calls,
                                       public exposure, rare API actions
temporal   ``tmp_``                    *when*: after-hours, deviation from the
                                       principal's own usual hour, weekends,
                                       burstiness
volume     ``vol_`` ``div_``           *how much / how varied*: event and byte
                                       volume, distinct APIs / services,
                                       never-before-used API actions
=========  ==========================  =======================================

Causality
~~~~~~~~~
Every "new" / "usual" statistic for day *d* is computed from events strictly
before day *d* (novelty = first time a principal ever used an IP / user agent /
region / resource / API; usual hour = circular mean of all earlier days; rarity
= global cumulative API counts before day *d*). ``tests/test_features_causal.py``
checks that appending future events never changes earlier rows.

All thresholds come from ``cfg["features"]``. The implementation works on
integer codes with ``numpy.bincount`` so it scales to tens of millions of
events.
"""
from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np
import pandas as pd

from cti.util.config import load_config
from cti.util.run import RunContext
from cti.util.seeds import set_all_seeds

log = logging.getLogger(__name__)

# Single source of truth for detector feature families.
FAMILY_PREFIXES: dict[str, tuple[str, ...]] = {
    "identity": ("idn_", "err_"),
    "resource": ("res_", "rar_"),
    "temporal": ("tmp_",),
    "volume":   ("vol_", "div_"),
}

_BIZ_START_HOUR = 8     # UTC business-hours window used by tmp_after_hours_ratio
_BIZ_END_HOUR = 18
_NS_DAY = 86_400 * 10**9
_NS_HOUR = 3_600 * 10**9
_IAM_WRITES = ("CreateUser", "AttachUserPolicy", "CreateAccessKey", "PutBucketPolicy",
               "CreateRole", "PutUserPolicy", "AttachRolePolicy")

_ALIASES = {
    "event_time": "eventTime", "event_name": "eventName", "event_source": "eventSource",
    "aws_region": "awsRegion", "error_code": "errorCode", "principal_id": "principalId",
    "source_ip": "sourceIp", "user_agent": "userAgent", "resource_arn": "resourceArn",
    "bytes_transferred": "bytesTransferred", "request_parameters": "requestParameters",
    "mfa_used": "mfaUsed",
}


def family_columns(columns, family: str) -> list[str]:
    """Feature columns of ``columns`` that belong to ``family``."""
    prefixes = FAMILY_PREFIXES[family]
    return [c for c in columns if c.startswith(prefixes)]


def feature_columns(df: pd.DataFrame) -> list[str]:
    """Names of feature columns (everything except principal and date)."""
    return [c for c in df.columns if c not in {"principal", "date"}]


# -- helpers ------------------------------------------------------------------
def _codes(s: pd.Series) -> tuple[np.ndarray, np.ndarray]:
    """Integer codes (>=0, missing -> its own code) and the unique values."""
    codes, uniques = pd.factorize(s, use_na_sentinel=True)
    codes = np.where(codes < 0, len(uniques), codes).astype(np.int64)
    return codes, np.asarray(uniques, dtype=object)


def _novelty(pid: np.ndarray, x: np.ndarray, day: np.ndarray, D: int, ukey: np.ndarray,
             g: np.ndarray, G: int) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Causal novelty of attribute ``x`` per principal.

    Returns ``(new_events, new_values, new_mask)``: per group, the number of
    events whose (principal, x) pair was first seen that very day, the number
    of distinct such pairs, and the per-event boolean.
    """
    M = int(x.max()) + 1
    pair = pid * M + x
    up, inv = np.unique(pair, return_inverse=True)
    first = pd.Series(day).groupby(inv).min().to_numpy()
    new_mask = day == first[inv]
    new_events = np.bincount(g, weights=new_mask, minlength=G)
    gi = np.searchsorted(ukey, (up // M) * D + first)
    new_values = np.bincount(gi, minlength=G).astype(float)
    return new_events, new_values, new_mask


def _nunique(g: np.ndarray, x: np.ndarray, G: int) -> np.ndarray:
    M = int(x.max()) + 1
    up = np.unique(g.astype(np.int64) * M + x)
    return np.bincount(up // M, minlength=G).astype(float)


def _flag_from_uniques(uniques: np.ndarray, fn) -> np.ndarray:
    return np.array([bool(fn(str(u))) for u in uniques] + [False])


# -- main ---------------------------------------------------------------------
def build_features(df: pd.DataFrame, cfg: dict) -> pd.DataFrame:
    """Build the (principal, day) feature matrix from a normalised events frame."""
    df = df.rename(columns={k: v for k, v in _ALIASES.items() if k in df.columns})
    feat_cfg = cfg["features"]
    pcol = feat_cfg["entity_columns"][0] if not isinstance(feat_cfg["entity_columns"], str) \
        else feat_cfg["entity_columns"]
    if pcol not in df.columns:
        for alt in ("principalId", "principal_id", "userId", "user_id"):
            if alt in df.columns:
                df = df.rename(columns={alt: pcol})
                break
        else:
            raise KeyError(f"principal column '{pcol}' not found; have {list(df.columns)}")

    ts = pd.to_datetime(df["eventTime"], utc=True)
    t_ns = ts.dt.tz_convert("UTC").dt.tz_localize(None).to_numpy().astype("datetime64[ns]").astype(np.int64)
    day0 = (t_ns.min() // _NS_DAY) * _NS_DAY
    rel = t_ns - day0
    day = (rel // _NS_DAY).astype(np.int64)
    hour = (rel % _NS_DAY) / _NS_HOUR
    D = int(day.max()) + 1
    n = len(df)

    pid, p_unique = _codes(df[pcol])
    key = pid * D + day
    ukey, g = np.unique(key, return_inverse=True)
    G = len(ukey)
    ev_count = np.bincount(g, minlength=G).astype(float)

    name, name_u = _codes(df["eventName"])
    out: dict[str, np.ndarray] = {}

    # ---- volume family ------------------------------------------------------
    out["vol_events_per_day"] = ev_count
    if "bytesTransferred" in df.columns:
        out["vol_log_bytes"] = np.log1p(np.bincount(
            g, weights=df["bytesTransferred"].to_numpy(dtype=float), minlength=G))
    get_obj = _flag_from_uniques(name_u, lambda s: s == "GetObject")[name]
    out["vol_get_object"] = np.bincount(g, weights=get_obj, minlength=G)
    out["div_unique_event_names"] = _nunique(g, name, G)
    src, _ = _codes(df["eventSource"])
    out["div_unique_sources"] = _nunique(g, src, G)
    _, new_names, _ = _novelty(pid, name, day, D, ukey, g, G)
    out["div_new_event_types"] = new_names

    # ---- identity family ----------------------------------------------------
    if "sourceIp" in df.columns:
        ip, _ = _codes(df["sourceIp"])
        new_ip_ev, new_ip_vals, new_ip_mask = _novelty(pid, ip, day, D, ukey, g, G)
        out["idn_new_ip_events"] = new_ip_ev
        out["idn_new_ips"] = new_ip_vals
        out["idn_unique_ips"] = _nunique(g, ip, G)
    else:
        new_ip_mask = np.zeros(n, dtype=bool)
    if "userAgent" in df.columns:
        ua, _ = _codes(df["userAgent"])
        out["idn_new_user_agents"] = _novelty(pid, ua, day, D, ukey, g, G)[1]
    reg, _ = _codes(df["awsRegion"])
    out["idn_new_regions"] = _novelty(pid, reg, day, D, ukey, g, G)[1]
    out["idn_unique_regions"] = _nunique(g, reg, G)

    is_login = _flag_from_uniques(name_u, lambda s: s == "ConsoleLogin")[name]
    has_err = df["errorCode"].notna().to_numpy() if "errorCode" in df.columns else np.zeros(n, bool)
    out["idn_login_failures"] = np.bincount(g, weights=is_login & has_err, minlength=G)
    out["idn_login_new_ip"] = np.bincount(g, weights=is_login & new_ip_mask, minlength=G)
    if "mfaUsed" in df.columns:
        no_mfa = (df["mfaUsed"].to_numpy() == 0) & is_login
        out["idn_logins_no_mfa"] = np.bincount(g, weights=no_mfa, minlength=G)
    out["err_error_rate"] = np.bincount(g, weights=has_err, minlength=G) / ev_count
    out["err_error_count"] = np.bincount(g, weights=has_err, minlength=G)

    # ---- resource family ----------------------------------------------------
    if "resourceArn" in df.columns:
        res, res_u = _codes(df["resourceArn"])
        prefixes = tuple(feat_cfg["sensitive_resource_prefixes"])

        def bucket(s: str) -> str:
            return s.split(":::")[-1] if ":::" in s else ""

        sens = _flag_from_uniques(res_u, lambda s: bucket(s).startswith(prefixes))[res]
        ext = _flag_from_uniques(res_u, lambda s: bucket(s).startswith("external-"))[res]
        new_res_ev, new_res_vals, new_res_mask = _novelty(pid, res, day, D, ukey, g, G)
        out["res_unique_resources"] = _nunique(g, res, G)
        out["res_new_resources"] = new_res_vals
        out["res_sensitive_events"] = np.bincount(g, weights=sens, minlength=G)
        out["res_sensitive_frac"] = out["res_sensitive_events"] / ev_count
        out["res_new_sensitive_events"] = np.bincount(g, weights=sens & new_res_mask, minlength=G)
        write_names = {"PutObject", "DeleteObject"}
        is_write = _flag_from_uniques(name_u, lambda s: s in write_names)[name]
        out["res_external_writes"] = np.bincount(g, weights=ext & is_write, minlength=G)
    priv = set(feat_cfg["privilege_escalating_actions"])
    out["res_priv_esc_events"] = np.bincount(
        g, weights=_flag_from_uniques(name_u, lambda s: s in priv)[name], minlength=G)
    out["res_iam_writes"] = np.bincount(
        g, weights=_flag_from_uniques(name_u, lambda s: s in _IAM_WRITES)[name], minlength=G)
    if "requestParameters" in df.columns:
        rp = df["requestParameters"].astype(str)
        public = rp.str.contains('"all"', regex=False).to_numpy()
        out["res_public_exposure"] = np.bincount(g, weights=public, minlength=G)

    # rarity: share of today's events whose API action had < threshold *prior* global uses
    thr = feat_cfg["rare_event_threshold"]
    per_day = np.bincount(name * D + day, minlength=(len(name_u) + 1) * D).reshape(-1, D).astype(float)
    prior = np.cumsum(per_day, axis=1) - per_day
    rare = prior[name, day] < thr
    out["rar_fraction_rare_events"] = np.bincount(g, weights=rare, minlength=G) / ev_count

    # ---- temporal family ----------------------------------------------------
    after = (hour < _BIZ_START_HOUR) | (hour >= _BIZ_END_HOUR)
    out["tmp_after_hours_ratio"] = np.bincount(g, weights=after, minlength=G) / ev_count

    ang = hour / 24.0 * 2 * np.pi
    P = len(p_unique) + 1
    g_pid = ukey // D
    g_day = ukey % D
    cos_m = np.zeros((P, D)); sin_m = np.zeros((P, D)); cnt_m = np.zeros((P, D))
    cos_m[g_pid, g_day] = np.bincount(g, weights=np.cos(ang), minlength=G)
    sin_m[g_pid, g_day] = np.bincount(g, weights=np.sin(ang), minlength=G)
    cnt_m[g_pid, g_day] = ev_count
    pc = np.cumsum(cos_m, axis=1) - cos_m
    ps = np.cumsum(sin_m, axis=1) - sin_m
    pn = np.cumsum(cnt_m, axis=1) - cnt_m
    mean_ang = np.arctan2(ps, pc)
    mean_hour_g = (mean_ang / (2 * np.pi) * 24.0) % 24.0
    has_hist_g = pn[g_pid, g_day] > 0
    mh = mean_hour_g[g_pid, g_day][g]
    dist = np.abs(((hour - mh + 12.0) % 24.0) - 12.0)
    dev = np.bincount(g, weights=dist, minlength=G) / ev_count
    out["tmp_hour_deviation"] = np.where(has_hist_g, dev, 0.0)

    weekday0 = pd.Timestamp(day0, unit="ns").weekday()
    is_weekend_g = ((weekday0 + g_day) % 7) >= 5
    out["tmp_weekend_events"] = np.where(is_weekend_g, ev_count, 0.0)
    out["tmp_active_hours"] = _nunique(g, hour.astype(np.int64), G)

    order = np.lexsort((t_ns, g))
    gs, tsrt = g[order], t_ns[order]
    same = gs[1:] == gs[:-1]
    diffs = (np.diff(tsrt)[same]) / 6e10
    gg = gs[1:][same]
    m = np.bincount(gg, minlength=G).astype(float)
    s1 = np.bincount(gg, weights=diffs, minlength=G)
    s2 = np.bincount(gg, weights=diffs ** 2, minlength=G)
    var = np.where(m > 1, (s2 - s1 ** 2 / np.maximum(m, 1)) / np.maximum(m - 1, 1), 0.0)
    out["tmp_burst_std_minutes"] = np.sqrt(np.maximum(var, 0.0))

    p_names = np.append(p_unique.astype(str), "NA")
    result = pd.DataFrame({
        "principal": p_names[g_pid],
        "date": pd.to_datetime(day0) + pd.to_timedelta(g_day, unit="D"),
        **out,
    })
    result = result.sort_values(["date", "principal"]).reset_index(drop=True)
    result[feature_columns(result)] = result[feature_columns(result)].fillna(0.0).astype("float32")

    log.info("feature matrix: %d rows x %d features", len(result), len(feature_columns(result)))
    return result


def make_labels(df_events: pd.DataFrame, df_feat: pd.DataFrame) -> pd.DataFrame:
    """Label (principal, date) rows: 1 if the principal had >=1 malicious event that day."""
    pcol = "principalId" if "principalId" in df_events.columns else "principal_id"
    tcol = "eventTime" if "eventTime" in df_events.columns else "event_time"
    mal = df_events.loc[df_events["label"] == 1, [pcol, tcol]].copy()
    mal["principal"] = mal[pcol].astype(str)
    mal["date"] = pd.to_datetime(mal[tcol], utc=True).dt.tz_localize(None).dt.floor("D")
    pos = mal[["principal", "date"]].drop_duplicates().assign(label=1)
    out = df_feat[["principal", "date"]].merge(pos, on=["principal", "date"], how="left")
    out["label"] = out["label"].fillna(0).astype(int)
    return out


def main() -> None:
    """CLI entrypoint: cti-features."""
    parser = argparse.ArgumentParser(description="Build feature matrix from events")
    parser.add_argument("--config", default=None)
    parser.add_argument("--input", default=None)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_all_seeds(cfg["random_seed"])
    events_path = Path(args.input or cfg["paths"]["processed_events"])
    feat_path = Path(args.output or cfg["paths"]["feature_store"])

    with RunContext("features", config_path=args.config, input_paths=[events_path]) as ctx:
        from cti.ingest.normalise import normalise_columns
        df_events = normalise_columns(pd.read_parquet(events_path))
        df_feat = build_features(df_events, cfg)
        feat_path.parent.mkdir(parents=True, exist_ok=True)
        df_feat.to_parquet(feat_path, index=False)
        ctx.register(n_rows=len(df_feat), n_features=len(feature_columns(df_feat)))


if __name__ == "__main__":
    main()
