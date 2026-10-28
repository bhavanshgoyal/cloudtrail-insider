"""
cti.features.cert
-----------------
Per-(user, day) feature matrix from the CERT r4.2 logs (objective O1).

=========  ===========  ==================================================
family     prefixes     CERT features
=========  ===========  ==================================================
identity   ``idn_``     PCs used, first-time PCs, logons on first-time PCs
resource   ``res_``     removable-media use (first ever, after hours),
           ``rar_``     executables copied, job-search / leak-site visits,
                        external email (with attachments), rare domains
temporal   ``tmp_``     after-hours share, after-hours logons, distance from
                        the user's own usual hour, weekend activity
volume     ``vol_``     events per source, email bytes, distinct domains,
           ``div_``     first-time domains
=========  ===========  ==================================================

Causality: every "new", "usual" or "rare" statistic for day *d* uses only
events strictly before day *d* (``tests/test_cert_features.py``).
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd

from cti.features.pipeline import _novelty, _nunique, feature_columns

log = logging.getLogger(__name__)

_NS_DAY = 86_400 * 10**9
_NS_HOUR = 3_600 * 10**9
SOURCES = ("logon", "device", "file", "email", "http")


def _prior_global_count(x: np.ndarray, day: np.ndarray, D: int) -> np.ndarray:
    """Per event: how many events with the same ``x`` occurred on strictly earlier days."""
    if len(x) == 0:
        return np.zeros(0, dtype=np.int64)
    key = x.astype(np.int64) * D + day
    uk, inv, cnt = np.unique(key, return_inverse=True, return_counts=True)
    xs = uk // D
    cum = np.cumsum(cnt)
    start = np.r_[0, np.flatnonzero(np.diff(xs)) + 1]
    base = np.repeat(cum[start] - cnt[start], np.diff(np.r_[start, len(uk)]))
    return (cum - cnt - base)[inv]


def _keyword_flag(uniques: np.ndarray, keywords: list[str]) -> np.ndarray:
    kws = tuple(k.lower() for k in keywords)
    return np.array([any(k in str(u) for k in kws) for u in uniques], dtype=bool)


class _Frame:
    """One source's events as integer arrays on the shared (user, day) grid."""

    def __init__(self, df: pd.DataFrame, users: pd.Index, day0: int, biz: tuple[int, int]) -> None:
        self.uid = users.get_indexer(df["user"].astype(str)).astype(np.int64)
        t_ns = df["t"].to_numpy().astype("datetime64[ns]").astype(np.int64)
        self.t = t_ns
        rel = t_ns - day0
        self.day = (rel // _NS_DAY).astype(np.int64)
        self.hour = (rel % _NS_DAY) / _NS_HOUR
        self.after = (self.hour < biz[0]) | (self.hour >= biz[1])
        self.n = len(df)


COLUMNS = {"logon": ["user", "t", "pc", "is_logon"], "device": ["user", "t", "pc", "is_connect"],
           "file": ["user", "t", "pc", "ext"], "email": ["user", "t", "pc", "n_ext", "size", "n_attach"],
           "http": ["user", "t", "pc", "domain"]}


def build_cert_features(source: Path | dict[str, pd.DataFrame], cfg: dict) -> pd.DataFrame:
    """``source``: a folder of ``<src>.parquet`` files, or the compact frames themselves.

    A source with no events (e.g. nobody used USB in an uploaded slice) gives zero features.
    """
    c = cfg["cert"]
    biz = tuple(c["business_hours"])
    if isinstance(source, dict):
        raw = {s: source[s][COLUMNS[s]] if s in source else pd.DataFrame(columns=COLUMNS[s])
               for s in SOURCES}
    else:
        raw = {s: pd.read_parquet(Path(source) / f"{s}.parquet", columns=COLUMNS[s]) for s in SOURCES}
    present = [s for s in SOURCES if not raw[s].empty]
    if not present:
        raise ValueError("no events in any CERT source")

    users = pd.Index(sorted(set().union(*(set(raw[s]["user"].astype(str).unique()) for s in SOURCES))))
    t_min = min(int(raw[s]["t"].min().value) for s in present)
    day0 = (t_min // _NS_DAY) * _NS_DAY
    fr = {s: _Frame(raw[s], users, day0, biz) for s in SOURCES}
    D = int(max(fr[s].day.max() for s in present)) + 1

    ukey = np.unique(np.concatenate([f.uid * D + f.day for f in fr.values()]))
    G = len(ukey)
    for f in fr.values():
        f.g = np.searchsorted(ukey, f.uid * D + f.day)

    def count(src: str, mask: np.ndarray | None = None) -> np.ndarray:
        f = fr[src]
        return np.bincount(f.g, weights=None if mask is None else mask, minlength=G).astype(float)

    out: dict[str, np.ndarray] = {}

    # ---- all events: identity + temporal ------------------------------------
    g_all = np.concatenate([fr[s].g for s in SOURCES])
    uid_all = np.concatenate([fr[s].uid for s in SOURCES])
    day_all = np.concatenate([fr[s].day for s in SOURCES])
    hour_all = np.concatenate([fr[s].hour for s in SOURCES])
    after_all = np.concatenate([fr[s].after for s in SOURCES])
    pc_codes, _ = pd.factorize(pd.concat([raw[s]["pc"] for s in SOURCES], ignore_index=True))
    pc_all = pc_codes.astype(np.int64)
    ev = np.bincount(g_all, minlength=G).astype(float)

    _, new_pcs, new_pc_mask = _novelty(uid_all, pc_all, day_all, D, ukey, g_all, G)
    out["idn_unique_pcs"] = _nunique(g_all, pc_all, G)
    out["idn_new_pcs"] = new_pcs
    lo = fr["logon"]
    is_logon = raw["logon"]["is_logon"].to_numpy(dtype=bool)
    new_pc_logon = new_pc_mask[:lo.n] & is_logon            # logon rows come first in the concat
    out["idn_logons_new_pc"] = count("logon", new_pc_logon)

    out["tmp_after_hours_ratio"] = np.bincount(g_all, weights=after_all, minlength=G) / ev
    out["tmp_after_hours_logons"] = count("logon", is_logon & lo.after)
    out["tmp_hour_deviation"] = _hour_deviation(g_all, hour_all, ukey, D, len(users), ev)
    weekday0 = pd.Timestamp(day0, unit="ns").weekday()
    is_weekend = ((weekday0 + ukey % D) % 7) >= 5
    out["tmp_weekend_events"] = np.where(is_weekend, ev, 0.0)
    out["tmp_active_hours"] = _nunique(g_all, hour_all.astype(np.int64), G)
    del g_all, uid_all, day_all, hour_all, after_all, pc_all, new_pc_mask

    # ---- volume -------------------------------------------------------------
    out["vol_events"] = ev
    out["vol_logons"] = count("logon", is_logon)
    out["vol_http"] = count("http")
    out["vol_emails"] = count("email")
    out["vol_email_log_bytes"] = np.log1p(count("email", raw["email"]["size"].to_numpy(dtype=float)))
    out["vol_file_copies"] = count("file")

    # ---- resource: removable media + files ----------------------------------
    dv = fr["device"]
    is_conn = raw["device"]["is_connect"].to_numpy(dtype=bool)
    out["res_usb_connects"] = count("device", is_conn)
    out["res_usb_after_hours"] = count("device", is_conn & dv.after)
    ci = np.flatnonzero(is_conn)
    first_use = np.zeros(G)
    if len(ci):
        _, fu, _ = _novelty(dv.uid[ci], np.zeros(len(ci), np.int64), dv.day[ci], D, ukey, dv.g[ci], G)
        first_use = fu
    out["res_usb_first_use"] = first_use
    exe = raw["file"]["ext"].isin(c["executable_extensions"]).to_numpy()
    out["res_exe_files"] = count("file", exe)

    # ---- resource / volume: web ---------------------------------------------
    hp = fr["http"]
    dom, dom_u = pd.factorize(raw["http"]["domain"])
    dom = dom.astype(np.int64)
    out["res_job_site_visits"] = count("http", _keyword_flag(dom_u, c["job_site_keywords"])[dom])
    out["res_leak_site_visits"] = count("http", _keyword_flag(dom_u, c["leak_site_keywords"])[dom])
    out["div_unique_domains"] = _nunique(hp.g, dom, G)
    out["div_new_domains"] = _novelty(hp.uid, dom, hp.day, D, ukey, hp.g, G)[1]
    rare = _prior_global_count(dom, hp.day, D) < cfg["features"]["rare_event_threshold"]
    out["rar_rare_domain_visits"] = count("http", rare)
    n_http = out["vol_http"]
    out["rar_rare_domain_frac"] = np.divide(out["rar_rare_domain_visits"], n_http,
                                            out=np.zeros(G), where=n_http > 0)
    del dom, rare

    # ---- resource: email ----------------------------------------------------
    em = raw["email"]
    ext = em["n_ext"].to_numpy() > 0
    att = em["n_attach"].to_numpy() > 0
    out["res_email_external"] = count("email", ext)
    out["res_email_external_attach"] = count("email", ext & att)
    out["res_email_ext_recipients"] = count("email", em["n_ext"].to_numpy(dtype=float))

    result = pd.DataFrame({
        "principal": users.to_numpy()[ukey // D].astype(str),
        "date": pd.to_datetime(day0, unit="ns") + pd.to_timedelta(ukey % D, unit="D"),
        **out,
    })
    result = result.sort_values(["date", "principal"]).reset_index(drop=True)
    fc = feature_columns(result)
    result[fc] = result[fc].fillna(0.0).astype("float32")
    log.info("CERT feature matrix: %d user-days x %d features, %d users, %d days",
             len(result), len(fc), result["principal"].nunique(), D)
    return result


def _hour_deviation(g: np.ndarray, hour: np.ndarray, ukey: np.ndarray, D: int, P: int,
                    ev: np.ndarray) -> np.ndarray:
    """Mean circular distance (hours) of today's events from the user's usual hour on earlier days."""
    G = len(ukey)
    ang = hour / 24.0 * 2 * np.pi
    g_pid, g_day = ukey // D, ukey % D
    cos_m = np.zeros((P, D)); sin_m = np.zeros((P, D)); cnt_m = np.zeros((P, D))
    cos_m[g_pid, g_day] = np.bincount(g, weights=np.cos(ang), minlength=G)
    sin_m[g_pid, g_day] = np.bincount(g, weights=np.sin(ang), minlength=G)
    cnt_m[g_pid, g_day] = ev
    pc = np.cumsum(cos_m, axis=1) - cos_m
    ps = np.cumsum(sin_m, axis=1) - sin_m
    pn = np.cumsum(cnt_m, axis=1) - cnt_m
    mean_hour = (np.arctan2(ps, pc) / (2 * np.pi) * 24.0) % 24.0
    has_hist = pn[g_pid, g_day] > 0
    mh = mean_hour[g_pid, g_day][g]
    dist = np.abs(((hour - mh + 12.0) % 24.0) - 12.0)
    dev = np.bincount(g, weights=dist, minlength=G) / ev
    return np.where(has_hist, dev, 0.0)


def make_cert_labels(feats: pd.DataFrame, ground_truth: list[dict]) -> pd.DataFrame:
    """label = 1 for every (account, day) with a malicious event, incl. stolen-account days."""
    pos = set()
    for g in ground_truth:
        pos.update((g["principal_id"], d) for d in g["malicious_days"])
        pos.update((u, d) for u, d in g.get("other_account_days", []))
    key = list(zip(feats["principal"], feats["date"].dt.strftime("%Y-%m-%d")))
    labels = feats[["principal", "date"]].copy()
    labels["label"] = np.fromiter((k in pos for k in key), dtype=np.int64, count=len(key))
    missing = pos - set(key)
    if missing:
        raise ValueError(f"{len(missing)} malicious account-days have no feature row, e.g. "
                         f"{sorted(missing)[:3]}")
    return labels
