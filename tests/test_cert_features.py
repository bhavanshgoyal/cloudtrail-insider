"""CERT feature builder, labels and rule baseline on a tiny hand-made dataset (no licensed data)."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from cti.detectors.rules import RuleBaselineDetector
from cti.features.cert import SOURCES, _prior_global_count, build_cert_features, make_cert_labels
from cti.util.config import load_config


def _events(days: int) -> dict[str, pd.DataFrame]:
    """Two users; U2 starts using a second PC and USB on day 5 and visits a leak site on day 6."""
    rows = {s: [] for s in SOURCES}
    base = pd.Timestamp("2010-01-04")                      # a Monday
    for d in range(days):
        day = base + pd.Timedelta(days=d)
        for u, pc in (("U1", "PC-1"), ("U2", "PC-2")):
            rows["logon"].append((u, day + pd.Timedelta(hours=9), pc, True))
            rows["logon"].append((u, day + pd.Timedelta(hours=17), pc, False))
            rows["http"].append((u, day + pd.Timedelta(hours=10), pc, "news.com"))
            rows["email"].append((u, day + pd.Timedelta(hours=11), pc, 0, 1000, 0))
        if d >= 5:
            rows["logon"].append(("U2", day + pd.Timedelta(hours=22), "PC-9", True))
            rows["device"].append(("U2", day + pd.Timedelta(hours=22, minutes=5), "PC-9", True))
            rows["file"].append(("U2", day + pd.Timedelta(hours=22, minutes=6), "PC-9", "exe"))
        if d == 6:
            rows["http"].append(("U2", day + pd.Timedelta(hours=23), "PC-9", "wikileaks.org"))
            rows["email"].append(("U2", day + pd.Timedelta(hours=23), "PC-9", 2, 50_000, 1))
    rows["device"].append(("U1", base + pd.Timedelta(hours=12), "PC-1", True))
    rows["file"].append(("U1", base + pd.Timedelta(hours=12), "PC-1", "doc"))
    cols = {"logon": ["is_logon"], "device": ["is_connect"], "file": ["ext"],
            "email": ["n_ext", "size", "n_attach"], "http": ["domain"]}
    return {s: pd.DataFrame(rows[s], columns=["user", "t", "pc", *cols[s]]) for s in SOURCES}


def _write(tmp_path, days: int):
    d = tmp_path / f"d{days}"
    d.mkdir()
    for s, df in _events(days).items():
        df.to_parquet(d / f"{s}.parquet", index=False)
    return d


@pytest.fixture(scope="module")
def cfg():
    return load_config()


def test_features_are_causal(tmp_path, cfg):
    short = build_cert_features(_write(tmp_path, 7), cfg)
    long = build_cert_features(_write(tmp_path, 12), cfg)
    long = long[long["date"] <= short["date"].max()].reset_index(drop=True)
    pd.testing.assert_frame_equal(short, long)


def test_novelty_and_removable_media(tmp_path, cfg):
    f = build_cert_features(_write(tmp_path, 9), cfg).set_index(["principal", "date"])
    u2 = f.loc["U2"]
    d0, d5, d6 = (pd.Timestamp("2010-01-04") + pd.Timedelta(days=k) for k in (0, 5, 6))
    assert u2.loc[d0, "idn_new_pcs"] == 1 and u2.loc[d0 + pd.Timedelta(days=1), "idn_new_pcs"] == 0
    assert u2.loc[d5, "idn_new_pcs"] == 1 and u2.loc[d6, "idn_new_pcs"] == 0
    assert u2.loc[d5, "idn_logons_new_pc"] == 1
    assert u2.loc[d5, "res_usb_first_use"] == 1 and u2.loc[d6, "res_usb_first_use"] == 0
    assert u2.loc[d5, "res_usb_after_hours"] == 1 and u2.loc[d5, "res_exe_files"] == 1
    assert u2.loc[d6, "res_leak_site_visits"] == 1 and u2.loc[d5, "res_leak_site_visits"] == 0
    assert u2.loc[d6, "res_email_external_attach"] == 1
    assert u2.loc[d6, "rar_rare_domain_visits"] == 1          # wikileaks never seen before
    assert u2.loc[d5, "tmp_after_hours_logons"] == 1 and u2.loc[d0, "tmp_after_hours_logons"] == 0
    assert u2.loc[d0, "tmp_hour_deviation"] == 0             # no history on the first day
    assert f.loc[("U1", d0), "res_usb_first_use"] == 1 and f.loc[("U1", d0), "res_exe_files"] == 0
    weekend = pd.Timestamp("2010-01-09")
    assert f.loc[("U1", weekend), "tmp_weekend_events"] > 0 and f.loc[("U1", d0), "tmp_weekend_events"] == 0


def test_all_four_families_no_nans_one_row_per_user_day(tmp_path, cfg):
    from cert_toy import toy_events, write_parquet

    from cti.features.pipeline import FAMILY_PREFIXES, family_columns, feature_columns
    frames, _ = toy_events(n_users=6, n_days=40, attack_from=30)
    f = build_cert_features(write_parquet(frames, tmp_path / "t"), cfg)
    for fam in FAMILY_PREFIXES:
        assert family_columns(feature_columns(f), fam), fam
    assert not f[feature_columns(f)].isna().any().any()
    assert not f.duplicated(["principal", "date"]).any()


def test_missing_sources_give_zero_features(cfg):
    frames = {s: df for s, df in _events(7).items() if s in ("logon", "http")}
    f = build_cert_features(frames, cfg)
    assert len(f) == 14 and (f["res_usb_connects"] == 0).all() and (f["vol_emails"] == 0).all()
    assert f["idn_new_pcs"].sum() == 3                   # PC-1, PC-2, then PC-9 on day 5


def test_prior_global_count():
    x = np.array([0, 0, 1, 0, 1, 0])
    day = np.array([0, 0, 0, 1, 2, 2])
    assert _prior_global_count(x, day, 3).tolist() == [0, 0, 0, 2, 1, 3]


def test_labels_include_stolen_account_days(tmp_path, cfg):
    f = build_cert_features(_write(tmp_path, 7), cfg)
    gt = [{"principal_id": "U2", "malicious_days": ["2010-01-10"],
           "other_account_days": [["U1", "2010-01-09"]]}]
    lab = make_cert_labels(f, gt).set_index(["principal", "date"])["label"]
    assert lab.sum() == 2
    assert lab[("U2", pd.Timestamp("2010-01-10"))] == 1 and lab[("U1", pd.Timestamp("2010-01-09"))] == 1
    with pytest.raises(ValueError, match="no feature row"):
        make_cert_labels(f, [{"principal_id": "U2", "malicious_days": ["2011-01-01"]}])


def test_rule_baseline_fires_and_abstains(tmp_path, cfg):
    f = build_cert_features(_write(tmp_path, 7), cfg)
    det = RuleBaselineDetector(cfg, 0).fit(f)
    s = pd.Series(det.score(f), index=pd.MultiIndex.from_frame(f[["principal", "date"]]))
    assert s[("U2", pd.Timestamp("2010-01-10"))] >= 3          # leak-site rule, severity 3
    assert s[("U1", pd.Timestamp("2010-01-05"))] == 0          # ordinary day: no rule, no alert
