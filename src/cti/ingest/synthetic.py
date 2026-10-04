"""
cti.ingest.synthetic
--------------------
Vectorised synthetic CloudTrail generator with planted insider scenarios.

Benign behaviour (per principal, so identity/resource/temporal baselines exist):
  * roles with different volume, working hours (EU / US / APAC time zones,
    von Mises hour-of-day), regions, IPs, user agents and a personal
    "working set" of S3 buckets (Zipf-popular), so *per-principal* deviation
    is meaningful;
  * benign **lookalikes** that fool global detectors and naive rules:
    backup-service night-time bulk reads, admin on-call bursts, developer
    error bursts, month-end spike days, travelling users on a new IP,
    users without MFA, admins creating access keys / sharing snapshots,
    analysts writing to an approved partner bucket, occasional break-glass
    admin role assumption.

Planted misuse (label=1 on malicious events, scenario_id set):
  S1 exfil-after-hours   S2 departing insider (3-week ramp, external PutObject)
  S3 privilege escalation S4 credential stuffing   S5 low-and-slow collection

Magnitudes scale with ``stealth``; benign lookalike frequency with ``noise``.
Everything is driven by a seeded ``numpy.random.Generator``.

Usage::

    python -m cti.ingest.synthetic --workload W1_baseline --seed 42 \
        --out data/processed/events.parquet
"""
from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

import numpy as np
import pandas as pd

from cti.util.config import load_config
from cti.util.seeds import make_rng, set_all_seeds

log = logging.getLogger(__name__)

# -- Vocabulary ---------------------------------------------------------------
ROLES = ["analyst", "developer", "admin", "backup-service", "ci-runner"]
R_ANALYST, R_DEV, R_ADMIN, R_BACKUP, R_CI = range(5)
HUMAN_ROLES = (R_ANALYST, R_DEV, R_ADMIN)
REGIONS = ["us-east-1", "eu-west-1", "ap-southeast-1"]
SCENARIO_IDS = ["S1", "S2", "S3", "S4", "S5"]

_S3, _EC2, _STS, _IAM, _SES, _SIGNIN, _CT = (
    "s3.amazonaws.com", "ec2.amazonaws.com", "sts.amazonaws.com", "iam.amazonaws.com",
    "ses.amazonaws.com", "signin.amazonaws.com", "cloudtrail.amazonaws.com")
SOURCES = [_S3, _EC2, _STS, _IAM, _SES, _SIGNIN, _CT]
_RTYPE = {_S3: "AWS::S3::Bucket", _EC2: "AWS::EC2::Instance", _STS: "AWS::IAM::Role",
          _IAM: "AWS::IAM::User", _SES: "AWS::SES::Identity",
          _SIGNIN: "AWS::SignIn::Console", _CT: "AWS::CloudTrail::Trail"}

_NAME_SRC = [
    ("ConsoleLogin", _SIGNIN), ("GetObject", _S3), ("PutObject", _S3), ("ListObjects", _S3),
    ("DeleteObject", _S3), ("DescribeInstances", _EC2), ("RunInstances", _EC2),
    ("StopInstances", _EC2), ("AssumeRole", _STS), ("GetCallerIdentity", _STS),
    ("ListUsers", _IAM), ("CreateUser", _IAM), ("AttachUserPolicy", _IAM),
    ("CreateAccessKey", _IAM), ("PutBucketPolicy", _S3), ("CreateSnapshot", _EC2),
    ("ModifySnapshotAttribute", _EC2), ("SendEmail", _SES), ("DeleteTrail", _CT),
    ("StopLogging", _CT),
]
NAMES = [n for n, _ in _NAME_SRC]
N = {n: i for i, n in enumerate(NAMES)}
_NAME_SRC_IDX = np.array([SOURCES.index(s) for _, s in _NAME_SRC], dtype=np.int16)
_READ_ONLY = np.array([n.startswith(("Get", "List", "Describe")) for n in NAMES])
_S3_DATA = np.array([N["GetObject"], N["PutObject"], N["ListObjects"], N["DeleteObject"]])

# request_parameters vocabulary (JSON-ish strings, as in real CloudTrail).
PARAMS = ["", '{"userGroups":["all"]}', '{"userIds":["210987654321"]}',
          '{"destinations":["external"]}', '{"destinations":["internal"]}',
          '{"userName":"self"}', '{"userName":"other"}',
          '{"roleName":"admin"}', '{"roleName":"readonly"}']
(P_NONE, P_PUBLIC, P_PRIVATE_SHARE, P_EXT_MAIL, P_INT_MAIL, P_KEY_SELF, P_KEY_OTHER,
 P_ADMIN_ROLE, P_RO_ROLE) = range(9)

# error_code: internal 0 = none (-> missing value in the DataFrame)
ERROR_NAMES = ["AccessDenied", "Failure"]
E_NONE, E_DENIED, E_FAIL = 0, 1, 2

USER_AGENTS = ["Mozilla/5.0 (console)", "aws-cli/2.15", "boto3/1.34", "aws-sdk-go/1.50",
               "python-requests/2.31", "curl/8.4"]
UA_CONSOLE, UA_CLI, UA_BOTO, UA_GO, UA_REQ, UA_CURL = range(6)

# Resources: [generic buckets][sensitive][partner][external-untrusted][service placeholders]
N_GENERIC = 200
SENSITIVE = ["finance-archive", "finance-reports", "hr-records", "hr-payroll",
             "pii-customers", "pii-exports", "security-logs", "security-audit"]
SENS_BUSINESS = [0, 1, 2, 3, 4, 5]        # indices usable by analysts
SENS_SECURITY = [6, 7]                     # indices used by admins
PARTNER = ["partner-share-1", "partner-share-2"]
EXTERNAL = "external-untrusted-bucket"
_PLACEHOLDERS = {_EC2: "arn:aws:ec2:::instance/shared", _STS: "arn:aws:sts::123456789012:role/shared",
                 _IAM: "arn:aws:iam::123456789012:user/shared", _SES: "arn:aws:ses:::identity/corp",
                 _SIGNIN: "arn:aws:signin:::console", _CT: "arn:aws:cloudtrail:::trail/main"}

RES_SENS0 = N_GENERIC
RES_PARTNER0 = RES_SENS0 + len(SENSITIVE)
RES_EXTERNAL = RES_PARTNER0 + len(PARTNER)
RES_PLACE0 = RES_EXTERNAL + 1
_RES_STR = (
    [f"arn:aws:s3:::bucket-{i:04d}" for i in range(N_GENERIC)]
    + [f"arn:aws:s3:::{b}" for b in SENSITIVE]
    + [f"arn:aws:s3:::{b}" for b in PARTNER]
    + [f"arn:aws:s3:::{EXTERNAL}"]
    + [_PLACEHOLDERS.get(s, "arn:aws:s3:::placeholder") for s in SOURCES]
)

N_ROAM_IPS = 5000
N_ATTACKER_IPS = 64

# Benign event mix per role (over NAMES; ConsoleLogin is generated separately).
_MIX = {
    R_ANALYST: {"GetObject": .50, "ListObjects": .20, "PutObject": .06, "GetCallerIdentity": .08,
                "AssumeRole": .06, "DescribeInstances": .04, "SendEmail": .03, "ListUsers": .03},
    R_DEV: {"GetObject": .25, "PutObject": .10, "ListObjects": .10, "DescribeInstances": .15,
            "RunInstances": .08, "StopInstances": .05, "AssumeRole": .12, "GetCallerIdentity": .08,
            "CreateSnapshot": .01, "ListUsers": .02},
    R_ADMIN: {"GetObject": .15, "ListObjects": .08, "DescribeInstances": .12, "AssumeRole": .15,
              "GetCallerIdentity": .08, "ListUsers": .10, "CreateUser": .06, "AttachUserPolicy": .08,
              "CreateAccessKey": .015, "PutBucketPolicy": .015, "CreateSnapshot": .04,
              "ModifySnapshotAttribute": .02, "StopInstances": .03, "SendEmail": .02},
    R_BACKUP: {"GetObject": .45, "ListObjects": .15, "PutObject": .15, "CreateSnapshot": .15,
               "DescribeInstances": .05, "AssumeRole": .05},
    R_CI: {"GetObject": .20, "PutObject": .25, "DescribeInstances": .10, "RunInstances": .15,
           "StopInstances": .10, "AssumeRole": .10, "GetCallerIdentity": .10},
}
_MIX_P = np.zeros((5, len(NAMES)))
for _r, _m in _MIX.items():
    for _n, _p in _m.items():
        _MIX_P[_r, N[_n]] = _p
_MIX_P /= _MIX_P.sum(axis=1, keepdims=True)

_NS = 86_400 * 10**9
_HOUR_NS = 3_600 * 10**9


# -- Per-principal attributes -------------------------------------------------
def _build_principals(P: int, role_weights: dict, rng: np.random.Generator, vol_scale: float) -> dict:
    w = np.array([role_weights[r] for r in ROLES], dtype=float)
    role = rng.choice(5, size=P, p=w / w.sum())
    human = np.isin(role, HUMAN_ROLES)

    tz = rng.choice(3, size=P, p=[0.5, 0.3, 0.2])          # 0 EU, 1 US, 2 APAC
    mu = np.array([9.0, 15.0, 3.0])[tz] + rng.normal(0, 0.7, P)
    mu = np.where(role == R_BACKUP, 2.0 + rng.normal(0, 0.5, P), mu)
    mu = np.where(role == R_CI, 12.0, mu)
    kappa = np.full(P, 4.0)
    kappa[role == R_ADMIN] = 0.5
    kappa[role == R_BACKUP] = 6.0
    kappa[role == R_CI] = 0.3

    lo = np.array([8, 10, 10, 30, 50])
    hi = np.array([30, 40, 35, 100, 150])
    mean_ev = rng.uniform(lo[role], hi[role]) * vol_scale

    err_rate = np.where(role == R_DEV, 0.05, 0.01)
    # region index: EU -> eu-west-1 (1), US -> us-east-1 (0), APAC -> ap-southeast-1 (2)
    home_region = np.where(human, np.array([1, 0, 2])[tz], rng.integers(0, 3, P))

    n_ips = np.where(human, 2, 1)
    ua_primary = np.where(role == R_DEV, UA_CLI,
                          np.where(human, UA_CONSOLE, np.where(role == R_BACKUP, UA_BOTO, UA_GO)))
    ua_secondary = np.where(human, np.where(ua_primary == UA_CONSOLE, UA_CLI, UA_CONSOLE), ua_primary)
    has_mfa = ~(human & (rng.random(P) < 0.05))

    # personal working set of S3 buckets (Zipf-popular generic + role-specific sensitive)
    K = 8
    pop = 1.0 / np.arange(1, N_GENERIC + 1) ** 1.2
    pop /= pop.sum()
    ws = np.zeros((P, K), dtype=np.int32)
    has_sens = rng.random(P) < np.array([0.7, 0.1, 0.5, 0.0, 0.0])[role]
    has_partner = (role == R_ANALYST) & (rng.random(P) < 0.08)
    for i in range(P):
        slots = list(rng.choice(N_GENERIC, size=K, replace=False, p=pop))
        if has_sens[i]:
            pool = SENS_SECURITY if role[i] == R_ADMIN else SENS_BUSINESS
            pick = rng.choice(pool, size=min(2, len(pool)), replace=False)
            for j, s in enumerate(pick):
                slots[1 + j] = RES_SENS0 + int(s)
        if has_partner[i]:
            slots[5] = RES_PARTNER0 + int(rng.integers(0, len(PARTNER)))
        ws[i] = slots
    return dict(role=role, human=human, tz=tz, mu=mu, kappa=kappa, mean_ev=mean_ev,
                err_rate=err_rate, home_region=home_region, n_ips=n_ips,
                ua_primary=ua_primary, ua_secondary=ua_secondary, has_mfa=has_mfa, ws=ws,
                P=P, roam_base=P * 3, attacker_base=P * 3 + N_ROAM_IPS)


def _ip_strings(P: int) -> list[str]:
    own = [f"10.{p >> 8}.{p & 255}.{k + 1}" for p in range(P) for k in range(3)]
    roam = [f"198.51.{i >> 8}.{i & 255}" for i in range(N_ROAM_IPS)]
    att = [f"203.0.113.{i + 1}" for i in range(N_ATTACKER_IPS)]
    return own + roam + att


# -- Benign generation --------------------------------------------------------
def _benign(pr: dict, D: int, noise: float, rng: np.random.Generator) -> dict:
    P, role, human = pr["P"], pr["role"], pr["human"]
    weekday = (6 + np.arange(D)) % 7                    # 2023-01-01 is a Sunday
    weekend = weekday >= 5

    # services run every day; humans skip weekends except ~20% of admins (on-call)
    works_weekend = np.where(role == R_ADMIN, rng.random(P) < 0.2, ~human)
    active = ~(weekend[None, :] & ~works_weekend[:, None])
    active &= ~(human[:, None] & (rng.random((P, D)) < 0.03))        # leave / sick days

    mult = rng.lognormal(0.0, 0.25, (P, D))
    spike = human[:, None] & (rng.random((P, D)) < 0.03 * noise)      # month-end style spikes
    mult = np.where(spike, mult * rng.uniform(2.0, 3.5, (P, D)), mult)
    burst = (role == R_ADMIN)[:, None] & (rng.random((P, D)) < 0.10 * noise)   # on-call bursts
    mult = np.where(burst, mult * 3.0, mult)
    errday = (role == R_DEV)[:, None] & (rng.random((P, D)) < 0.05 * noise)    # bursty error days
    mult = np.where(errday, mult * 2.0, mult)
    err_mult = np.where(errday, 8.0, 1.0)
    roam = human[:, None] & (rng.random((P, D)) < 0.01 * noise)       # travelling / VPN day

    counts = rng.poisson(pr["mean_ev"][:, None] * mult * active)
    p_idx, d_idx = np.nonzero(counts)
    c = counts[p_idx, d_idx]
    p_ev = np.repeat(p_idx, c)
    d_ev = np.repeat(d_idx, c)
    n = len(p_ev)
    log.info("benign: %d principals x %d days -> %d events", P, D, n)

    angle = rng.vonmises(0.0, pr["kappa"][p_ev])
    hour = (pr["mu"][p_ev] + angle / (2 * np.pi) * 24.0) % 24.0
    t = d_ev.astype(np.int64) * _NS + (hour * _HOUR_NS).astype(np.int64)

    name = np.empty(n, dtype=np.int16)
    r_ev = role[p_ev]
    for r in range(5):
        idx = np.nonzero(r_ev == r)[0]
        if len(idx):
            name[idx] = rng.choice(len(NAMES), size=len(idx), p=_MIX_P[r])

    params = np.zeros(n, dtype=np.int8)
    m = name == N["ModifySnapshotAttribute"]
    params[m] = P_PRIVATE_SHARE
    m = name == N["PutBucketPolicy"]
    params[m] = P_PRIVATE_SHARE
    m = name == N["CreateAccessKey"]
    params[m] = np.where(rng.random(m.sum()) < 0.8, P_KEY_SELF, P_KEY_OTHER)
    m = name == N["SendEmail"]
    params[m] = np.where(rng.random(m.sum()) < 0.05 * noise, P_EXT_MAIL, P_INT_MAIL)
    m = name == N["AssumeRole"]
    p_admin = np.where(r_ev[m] == R_ADMIN, 0.30, np.where(r_ev[m] == R_DEV, 0.002 * noise, 0.001 * noise))
    params[m] = np.where(rng.random(m.sum()) < p_admin, P_ADMIN_ROLE, P_RO_ROLE)

    res = (RES_PLACE0 + _NAME_SRC_IDX[name]).astype(np.int32)
    s3 = np.isin(name, _S3_DATA) | (name == N["PutBucketPolicy"])
    k_idx = np.nonzero(s3)[0]
    w = np.array([.30, .22, .16, .11, .08, .06, .04, .03])
    w = w / w.sum()
    slot = rng.choice(8, size=len(k_idx), p=w)
    res_s3 = pr["ws"][p_ev[k_idx], slot]
    drift = rng.random(len(k_idx)) < 0.03
    res[k_idx] = np.where(drift, rng.integers(0, N_GENERIC, len(k_idx)), res_s3)

    slot_ip = np.minimum(rng.choice(3, size=n, p=[.80, .15, .05]), pr["n_ips"][p_ev] - 1)
    ip = (p_ev * 3 + slot_ip).astype(np.int32)
    roam_ip = pr["roam_base"] + rng.integers(0, N_ROAM_IPS, (P, D))
    ip = np.where(roam[p_ev, d_ev], roam_ip[p_ev, d_ev], ip).astype(np.int32)
    ua = np.where(rng.random(n) < 0.92, pr["ua_primary"][p_ev], pr["ua_secondary"][p_ev]).astype(np.int8)
    p_other = np.where(np.isin(r_ev, (R_DEV, R_ADMIN)), 0.04, 0.005) * noise
    other = rng.random(n) < p_other
    region = np.where(other, (pr["home_region"][p_ev] + 1 + rng.integers(0, 2, n)) % 3,
                      pr["home_region"][p_ev]).astype(np.int8)
    err = np.where(rng.random(n) < pr["err_rate"][p_ev] * err_mult[p_ev, d_ev], E_DENIED, E_NONE).astype(np.int8)
    byt = np.where(np.isin(name, _S3_DATA), np.exp(rng.normal(8.5, 1.2, n)), np.exp(rng.normal(6.0, 0.5, n)))
    byt = np.clip(byt, 1, 2**31 - 1).astype(np.int32)

    ev = dict(t=t, p=p_ev.astype(np.int32), name=name, res=res, ip=ip, ua=ua, region=region,
              err=err, mfa=np.full(n, -1, dtype=np.int8), params=params, bytes=byt,
              label=np.zeros(n, dtype=np.int8), scen=np.zeros(n, dtype=np.int8),
              mal_seq=np.full(n, -1, dtype=np.int32))

    # console logins: one per human per active day (+3% failed first attempt)
    lp, ld = np.nonzero((counts > 0) & human[:, None])
    nl = len(lp)
    lhour = (pr["mu"][lp] - 0.4 + rng.normal(0, 0.3, nl)) % 24.0
    lt = ld.astype(np.int64) * _NS + (lhour * _HOUR_NS).astype(np.int64)
    lip = np.where(roam[lp, ld], roam_ip[lp, ld], lp * 3).astype(np.int32)
    fail = rng.random(nl) < 0.03
    nf = int(fail.sum())
    lp_all = np.concatenate([lp, lp[fail]])
    lt_all = np.concatenate([lt, lt[fail] - 60 * 10**9 * rng.integers(1, 3, nf)])
    lip_all = np.concatenate([lip, lip[fail]])
    lerr = np.concatenate([np.zeros(nl, np.int8), np.full(nf, E_FAIL, np.int8)])
    k = len(lp_all)
    ev_login = dict(
        t=lt_all, p=lp_all.astype(np.int32), name=np.full(k, N["ConsoleLogin"], np.int16),
        res=np.full(k, RES_PLACE0 + SOURCES.index(_SIGNIN), np.int32), ip=lip_all,
        ua=np.full(k, UA_CONSOLE, np.int8), region=pr["home_region"][lp_all].astype(np.int8),
        err=lerr, mfa=pr["has_mfa"][lp_all].astype(np.int8), params=np.zeros(k, np.int8),
        bytes=np.full(k, 400, np.int32), label=np.zeros(k, np.int8),
        scen=np.zeros(k, np.int8), mal_seq=np.full(k, -1, np.int32))
    return {key: np.concatenate([ev[key], ev_login[key]]) for key in ev}


# -- Planted scenarios --------------------------------------------------------
class _Mal:
    """Accumulates malicious events for all insiders."""

    def __init__(self, pr: dict) -> None:
        self.pr = pr
        self.rows: list[dict] = []

    def add(self, p: int, t, name: str, scen: int, seq: int, *, res=None, ip=None, ua=None,
            region=None, err=E_NONE, mfa=-1, params=P_NONE) -> None:
        t = np.atleast_1d(np.asarray(t, dtype=np.int64))
        n = len(t)
        pr = self.pr
        src_idx = int(_NAME_SRC_IDX[N[name]])
        self.rows.append(dict(
            t=t, p=np.full(n, p, np.int32), name=np.full(n, N[name], np.int16),
            res=np.broadcast_to(RES_PLACE0 + src_idx if res is None else res, (n,)).astype(np.int32),
            ip=np.broadcast_to(p * 3 if ip is None else ip, (n,)).astype(np.int32),
            ua=np.full(n, pr["ua_primary"][p] if ua is None else ua, np.int8),
            region=np.full(n, pr["home_region"][p] if region is None else region, np.int8),
            err=np.broadcast_to(err, (n,)).astype(np.int8), mfa=np.full(n, mfa, np.int8),
            params=np.full(n, params, np.int8),
            bytes=np.full(n, 5000 if name in ("GetObject", "PutObject") else 400, np.int32),
            label=np.ones(n, np.int8), scen=np.full(n, scen, np.int8),
            mal_seq=np.full(n, seq, np.int32)))


def _sens_not_in_ws(pr: dict, p: int, pool: list[int], rng: np.random.Generator, k: int) -> np.ndarray:
    ws = set(pr["ws"][p].tolist())
    cand = [RES_SENS0 + s for s in pool if RES_SENS0 + s not in ws] or [RES_SENS0 + s for s in pool]
    return rng.choice(cand, size=k, replace=len(cand) < k)


def _biz_times(pr: dict, p: int, d: int, n: int, rng: np.random.Generator) -> np.ndarray:
    hour = (pr["mu"][p] + rng.uniform(-3, 3, n)) % 24.0
    return d * _NS + (hour * _HOUR_NS).astype(np.int64)


def _is_weekend(d: int) -> bool:
    return (6 + d) % 7 >= 5


def _inject(m: _Mal, scen_id: str, p: int, d0: int, D: int, stealth: float,
            rng: np.random.Generator, seq: int) -> None:
    pr = m.pr
    sc = SCENARIO_IDS.index(scen_id) + 1
    att_ip = pr["attacker_base"] + int(rng.integers(0, N_ATTACKER_IPS))

    if scen_id == "S1":                                   # exfil after hours, new IP
        t0 = d0 * _NS + 3 * _HOUR_NS
        m.add(p, t0, "ConsoleLogin", sc, seq, ip=att_ip, ua=UA_CONSOLE, mfa=int(pr["has_mfa"][p]))
        n_get = max(5, int(round(50 * stealth)))
        tg = t0 + np.cumsum(rng.integers(1, 5, n_get)) * 10**9
        m.add(p, tg, "GetObject", sc, seq, res=_sens_not_in_ws(pr, p, SENS_BUSINESS, rng, n_get),
              ip=att_ip, ua=UA_CONSOLE)
        t1 = int(tg[-1]) + 300 * 10**9
        m.add(p, t1, "CreateSnapshot", sc, seq, ip=att_ip)
        m.add(p, t1 + 10 * 10**9, "ModifySnapshotAttribute", sc, seq, ip=att_ip, params=P_PUBLIC)

    elif scen_id == "S2":                                 # departing insider ramp
        base = [4, 9, 14]
        res_pool = _sens_not_in_ws(pr, p, SENS_BUSINESS, rng, 2)
        last = d0
        for i in range(21):
            d = d0 + i
            if _is_weekend(d) or d >= D:
                continue
            k = max(1, int(round(base[i // 7] * stealth)))
            m.add(p, _biz_times(pr, p, d, k, rng), "GetObject", sc, seq, res=rng.choice(res_pool, size=k))
            last = d
        m.add(p, _biz_times(pr, p, last, 1, rng) + _HOUR_NS, "PutObject", sc, seq, res=RES_EXTERNAL)

    elif scen_id == "S3":                                 # privilege escalation
        t0 = int(_biz_times(pr, p, d0, 1, rng)[0])
        m.add(p, t0, "CreateAccessKey", sc, seq, params=P_KEY_OTHER)
        m.add(p, t0 + 120 * 10**9, "AssumeRole", sc, seq, params=P_ADMIN_ROLE)
        m.add(p, t0 + 200 * 10**9, "AttachUserPolicy", sc, seq)
        n = max(1, int(round(5 * stealth)))
        m.add(p, t0 + 260 * 10**9 + np.arange(n) * 10**10, "GetObject", sc, seq,
              res=_sens_not_in_ws(pr, p, SENS_SECURITY, rng, n))
        m.add(p, t0 + 600 * 10**9, "SendEmail", sc, seq, params=P_EXT_MAIL)
        if rng.random() < 0.5:                            # defence evasion: stop audit logging
            m.add(p, t0 + 660 * 10**9, "StopLogging", sc, seq)

    elif scen_id == "S4":                                 # credential stuffing then use
        t0 = d0 * _NS + 2 * _HOUR_NS
        n_fail = max(5, int(round(15 * stealth)))
        tf = t0 + np.cumsum(rng.integers(1, 3, n_fail)) * 10**9
        m.add(p, tf, "ConsoleLogin", sc, seq, ip=att_ip, ua=UA_REQ, err=E_FAIL, mfa=0, region=0)
        ts = int(tf[-1]) + 5 * 10**9
        m.add(p, ts, "ConsoleLogin", sc, seq, ip=att_ip, ua=UA_REQ, mfa=0, region=0)
        m.add(p, ts + 20 * 10**9, "ListUsers", sc, seq, ip=att_ip, ua=UA_REQ, region=0)
        n = max(2, int(round(4 * stealth)))
        m.add(p, ts + 60 * 10**9 + np.arange(n) * 5 * 10**9, "GetObject", sc, seq,
              res=_sens_not_in_ws(pr, p, [2, 3], rng, n), ip=att_ip, ua=UA_REQ, region=0)

    elif scen_id == "S5":                                 # low-and-slow collection
        target = int(_sens_not_in_ws(pr, p, SENS_BUSINESS, rng, 1)[0])
        for i in range(30):
            d = d0 + i
            if _is_weekend(d) or d >= D:
                continue
            k = max(1, int(round((2 + 3 * i / 29) * stealth)))
            m.add(p, _biz_times(pr, p, d, k, rng), "GetObject", sc, seq, res=target)
    else:
        raise ValueError(f"unknown scenario {scen_id}")


_SCEN_LEN = {"S1": 1, "S2": 21, "S3": 1, "S4": 1, "S5": 30}
_SCEN_ROLES = {"S1": (R_ANALYST, R_DEV, R_ADMIN), "S2": (R_ANALYST, R_DEV),
               "S3": (R_ANALYST, R_DEV), "S4": (R_ANALYST, R_DEV, R_ADMIN),
               "S5": (R_ANALYST, R_DEV)}


# -- Public API ---------------------------------------------------------------
def generate_dataset(
    n_principals: int,
    n_days: int,
    scenarios: list[str] | None,
    insider_rate: float,
    seed: int,
    *,
    scenario_weights: dict | None = None,
    stealth: float = 1.0,
    noise: float = 1.0,
    role_weights: dict | None = None,
    volume_scale: float = 1.0,
    warmup_days: int = 14,
    start_date: str = "2023-01-01",
) -> tuple[pd.DataFrame, list[dict]]:
    """Generate ``(events, ground_truth)``. See the module docstring."""
    rng = make_rng(seed)
    scenarios = list(scenarios or SCENARIO_IDS)
    weights = np.array([(scenario_weights or {}).get(s, 1.0) for s in scenarios], dtype=float)
    weights = weights / weights.sum()
    role_weights = role_weights or {"analyst": .30, "developer": .30, "admin": .08,
                                    "backup-service": .12, "ci-runner": .20}
    P, D = int(n_principals), int(n_days)

    pr = _build_principals(P, role_weights, rng, volume_scale)
    ben = _benign(pr, D, noise, rng)

    # Insiders are stratified over time so every temporal window holds positives.
    n_ins = max(1, int(round(P * insider_rate)))
    scen_seq = rng.choice(scenarios, size=n_ins, p=weights)
    lo = warmup_days + 7
    base = lo + (np.arange(n_ins) + rng.random(n_ins)) / n_ins * max(1, D - 2 - lo)
    start_days = base.astype(int)[rng.permutation(n_ins)]
    used = np.zeros(P, dtype=bool)
    mal = _Mal(pr)
    insiders: list[tuple[int, str]] = []
    for i in range(n_ins):
        sid = str(scen_seq[i])
        cands = np.nonzero(np.isin(pr["role"], _SCEN_ROLES[sid]) & ~used)[0]
        if len(cands) == 0:
            log.warning("no eligible principal left for %s; skipping insider", sid)
            continue
        p = int(rng.choice(cands))
        used[p] = True
        d0 = int(min(start_days[i], D - _SCEN_LEN[sid] - 1))
        _inject(mal, sid, p, d0, D, stealth, rng, seq=len(insiders))
        insiders.append((p, sid))

    mal_ev = {k: np.concatenate([r[k] for r in mal.rows]) for k in mal.rows[0]}
    ev = {k: np.concatenate([ben[k], mal_ev[k]]) for k in ben}
    order = np.argsort(ev["t"], kind="stable")
    ev = {k: v[order] for k, v in ev.items()}
    n = len(ev["t"])

    start_ns = pd.Timestamp(start_date, tz="UTC").value
    abs_t = ev["t"] + start_ns

    ground_truth = []
    for seq, (p, sid) in enumerate(insiders):
        pos = np.nonzero(ev["mal_seq"] == seq)[0]
        days = np.unique(ev["t"][pos] // _NS)
        ground_truth.append({
            "principal_id": f"usr-{p:05d}", "scenario_id": sid, "role": ROLES[pr["role"][p]],
            "first_event_id": int(pos[0]),
            "first_event_time": pd.Timestamp(int(abs_t[pos[0]]), tz="UTC").isoformat(),
            "last_event_time": pd.Timestamp(int(abs_t[pos[-1]]), tz="UTC").isoformat(),
            "malicious_days": [(pd.Timestamp(start_date) + pd.Timedelta(days=int(d))).strftime("%Y-%m-%d")
                               for d in days],
        })

    cat = pd.Categorical.from_codes
    src_of_name = _NAME_SRC_IDX[ev["name"]]
    df = pd.DataFrame({
        "event_id": np.arange(n, dtype=np.int64),
        "event_time": pd.DatetimeIndex(abs_t.astype("datetime64[ns]"), tz="UTC"),
        "event_name": cat(ev["name"], NAMES),
        "event_source": cat(src_of_name, SOURCES),
        "principal_id": cat(ev["p"], [f"usr-{i:05d}" for i in range(P)]),
        "role_name": cat(pr["role"][ev["p"]], ROLES),
        "source_ip": cat(ev["ip"], _ip_strings(P)),
        "user_agent": cat(ev["ua"], USER_AGENTS),
        "aws_region": cat(ev["region"], REGIONS),
        "resource_arn": cat(ev["res"], _RES_STR),
        "resource_type": cat(src_of_name, [_RTYPE[s] for s in SOURCES]),
        "request_parameters": cat(ev["params"], PARAMS),
        "error_code": cat(ev["err"].astype(np.int64) - 1, ERROR_NAMES),     # -1 -> missing
        "read_only": _READ_ONLY[ev["name"]],
        "bytes_transferred": ev["bytes"],
        "mfa_used": ev["mfa"],                                  # -1 n/a, 0 no, 1 yes
        "label": ev["label"],
        "scenario_id": cat(ev["scen"].astype(np.int64) - 1, SCENARIO_IDS),  # -1 -> missing
    })
    return df, ground_truth


def generate_workload(cfg: dict, workload: str | None = None, seed: int | None = None,
                      fast: bool = False) -> tuple[pd.DataFrame, list[dict]]:
    """Generate a named workload from ``cfg['synthetic']['workloads']``."""
    syn = cfg["synthetic"]
    name = workload or syn["default_workload"]
    w = dict(syn["workloads"][name])
    if fast:
        w.update(syn["fast"])
    seed = cfg["random_seed"] if seed is None else seed
    df, gt = generate_dataset(
        w["principals"], w["days"], syn["scenarios_all"], w["insider_rate"], seed,
        scenario_weights=w.get("scenario_weights"), stealth=w.get("stealth", 1.0),
        noise=w.get("noise", 1.0), role_weights=w.get("role_weights", syn["role_weights"]),
        warmup_days=cfg["warmup_days"], start_date=syn["start_date"])
    log.info("workload %s seed %d: %d events, %d insiders", name, seed, len(df), len(gt))
    return df, gt


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic CloudTrail events")
    parser.add_argument("--workload", default=None)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--fast", action="store_true")
    parser.add_argument("--out", default="data/processed/events.parquet")
    args = parser.parse_args()

    cfg = load_config()
    seed = cfg["random_seed"] if args.seed is None else args.seed
    set_all_seeds(seed)
    df, gt = generate_workload(cfg, args.workload, seed, args.fast)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(out, index=False)
    with open(out.parent / "ground_truth.json", "w") as f:
        json.dump(gt, f, indent=2)
    log.info("wrote %d events to %s and %d insiders", len(df), out, len(gt))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    main()
