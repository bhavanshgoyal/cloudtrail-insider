"""
explanation_stats.py
--------------------
O3 evidence over every alert the frozen proposed detector emits at 10 alerts/day on the CERT test
windows (3 origins, an alert kept once): which behaviour family the explanation names, split by
whether the alert was a true or a false positive.

Output: results/explanations/family_by_label.csv, summary.json

    python scripts/explanation_stats.py
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import pandas as pd

from cti.experiment import apply_frozen_configs
from cti.triage.generate_study import select_alerts
from cti.util.config import load_config

OUT = Path("results/explanations")


def main() -> None:
    logging.basicConfig(level=logging.WARNING)
    cfg = apply_frozen_configs(load_config())
    al = select_alerts(cfg, 0)
    al["outcome"] = al["label"].map({1: "true alert", 0: "false alert"})
    tab = pd.crosstab(al["primary_family"], al["outcome"])
    share = tab / tab.sum()
    OUT.mkdir(parents=True, exist_ok=True)
    out = tab.join(share.add_suffix(" share")).reset_index()
    out.to_csv(OUT / "family_by_label.csv", index=False)
    prec = (al.groupby("primary_family")["label"].mean()).round(4).to_dict()
    summary = {"n_alerts": len(al), "n_true": int(al["label"].sum()),
               "precision_by_primary_family": prec,
               "share_true_explained_by": share["true alert"].round(4).to_dict(),
               "share_false_explained_by": share["false alert"].round(4).to_dict()}
    (OUT / "summary.json").write_text(json.dumps(summary, indent=1))
    print(out.round(3).to_string(index=False))
    print(json.dumps(summary, indent=1))


if __name__ == "__main__":
    main()
