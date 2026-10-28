"""Frontend inference path: source detection, upload parsing, scoring an upload with a saved model."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest
from cert_toy import toy_events

from cti.detectors.train import build_detectors
from cti.features.cert import build_cert_features
from cti.inference import Model, analyse, detect_source, evaluate_upload, read_csv_upload
from cti.util.config import load_config


@pytest.fixture(scope="module")
def cfg():
    return load_config()


def test_detect_source_by_name_then_columns():
    assert detect_source("HTTP_2010.csv", b"") == "http"
    assert detect_source("x.csv", b"id,date,user,pc,url,content\n") == "http"
    assert detect_source("x.csv", b"id,date,user,pc,activity\n{A},01/02/2010 07:00:00,U,PC-1,Connect\n") == "device"
    assert detect_source("x.csv", b"id,date,user,pc,activity\n{A},01/02/2010 07:00:00,U,PC-1,Logoff\n") == "logon"
    assert detect_source("x.csv", b"a,b\n1,2\n") is None


def test_upload_parsing_and_missing_columns(cfg):
    ok = b"id,date,user,pc,to,cc,bcc,from,size,attachments,content\n" \
         b"{A},01/04/2010 09:00:00,U1,PC-1,a@dtaa.com;b@gmail.com,,,U1@dtaa.com,2000,2,hello\n"
    df = read_csv_upload(ok, "email", cfg)
    assert df.loc[0, "n_ext"] == 1 and df.loc[0, "n_attach"] == 2 and df.loc[0, "n_rcpt"] == 2
    with pytest.raises(ValueError, match="missing column"):
        read_csv_upload(b"id,date,user,pc\n{A},01/04/2010 09:00:00,U1,PC-1\n", "logon", cfg)


def test_analyse_upload_ranks_the_insider_and_explains(cfg):
    train, _ = toy_events(n_users=20, n_days=120, seed=1, attack_from=500)        # benign history only
    feats = build_cert_features(train, cfg)
    dets = {d.name: d.fit(feats) for d in build_detectors(cfg)}
    model = Model(dets, ("2010-01-04", "2010-05-03"), 20)

    upload, gt = toy_events(n_users=20, n_days=60, seed=2, attack_from=40)
    an = analyse(upload, model, cfg, budget=2, history_days=14)
    assert an.scored_days[0] > an.features["date"].min()
    assert {"explanation", "primary_family", "rank"} <= set(an.alerts.columns)
    assert (an.alerts.groupby("date").size() <= 2).all()
    attack_days = pd.to_datetime(gt[0]["malicious_days"])
    first = an.alerts[an.alerts["date"] == attack_days.min()]
    assert "U00" in set(first["principal"])                    # caught on the first attack day
    s = an.scores["proposed_budget_aware_conformal"]           # (later days may be suppressed by C4)
    bad = s["principal"].eq("U00") & s["date"].isin(attack_days)
    assert s.loc[bad, "score"].min() > s.loc[~bad, "score"].quantile(0.95)

    labels = pd.DataFrame({"user": "U00", "date": gt[0]["malicious_days"]})
    ev = evaluate_upload(an, model, labels, 2).set_index("detector")
    assert ev.loc["proposed_budget_aware_conformal", "insiders_caught"] == 1
    assert np.isfinite(ev["precision"]).all()

    with pytest.raises(ValueError, match="needs more than"):
        analyse(upload, model, cfg, history_days=60)
