"""
cti.detectors.rules
-------------------
Rule-signature baseline in the style of commercial DLP / UEBA alert rules.

Each rule in ``configs/rules.yaml`` fires on a (user, day) when one named
feature reaches a fixed threshold. Thresholds are set a priori and never
tuned. A (user, day) is scored::

    score = max_severity + 0.1 * (distinct_rules - 1) + 0.001 * log1p(total_hits)

and 0 (= no alert) when no rule fires. Hits = sum of the firing features' values.
"""
from __future__ import annotations

import logging
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

log = logging.getLogger(__name__)


def load_rules(path: str | Path) -> list[dict]:
    rules = (yaml.safe_load(Path(path).read_text()) or {}).get("rules", [])
    if not rules:
        raise ValueError(f"no rules in {path}")
    for r in rules:
        missing = {"id", "feature", "min", "severity"} - set(r)
        if missing:
            raise ValueError(f"rule {r.get('id', '?')} missing {sorted(missing)}")
    return rules


class RuleBaselineDetector:
    name = "rule_baseline"
    needs_events = False
    abstains = True          # score 0 (no rule fired) means "no alert", not "lowest-ranked alert"

    def __init__(self, cfg: dict, seed: int) -> None:  # noqa: ARG002
        self.rules = load_rules(cfg.get("rules_cfg", {}).get("rules_file", "configs/rules.yaml"))

    def fit(self, df_feat: pd.DataFrame, events: pd.DataFrame | None = None) -> RuleBaselineDetector:  # noqa: ARG002
        missing = sorted({r["feature"] for r in self.rules} - set(df_feat.columns))
        if missing:
            raise KeyError(f"rules use features not in the matrix: {missing}")
        return self                                           # signatures need no training

    def fired(self, df_feat: pd.DataFrame) -> pd.DataFrame:
        """Per row: ``max_severity, n_rules, hits, rules`` (comma-joined rule ids)."""
        n = len(df_feat)
        sev, n_rules, hits = np.zeros(n), np.zeros(n), np.zeros(n)
        names = [[] for _ in range(n)]
        for r in self.rules:
            v = df_feat[r["feature"]].to_numpy(dtype=float)
            on = v >= r["min"]
            sev = np.where(on, np.maximum(sev, float(r["severity"])), sev)
            n_rules += on
            hits += np.where(on, v, 0.0)
            for i in np.flatnonzero(on):
                names[i].append(r["id"])
        return pd.DataFrame({"max_severity": sev, "n_rules": n_rules, "hits": hits,
                             "rules": [",".join(x) for x in names]}, index=df_feat.index)

    def score(self, df_feat: pd.DataFrame, events: pd.DataFrame | None = None) -> np.ndarray:  # noqa: ARG002
        f = self.fired(df_feat)
        sev, n_rules, hits = (f[c].to_numpy() for c in ("max_severity", "n_rules", "hits"))
        return np.where(sev > 0, sev + 0.1 * (n_rules - 1) + 0.001 * np.log1p(hits), 0.0)
