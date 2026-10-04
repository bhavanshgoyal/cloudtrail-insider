"""
fill_numbers.py
---------------
Replace number placeholders in a document template with values read from the result files, so
every number in the paper / PPT summary is traceable to a CSV and cannot drift.

Placeholder syntax (pipe-separated, inside double braces)::

    {{S|workload|det|metric|budget|field|fmt}}   results/campaign/summary.csv
    {{H|workload|hypothesis|field|fmt}}          results/campaign/hypotheses.csv
    {{A|workload|variant|metric|budget|field|fmt}}  results/ablation/ablation_summary.csv
    {{W|sweep|x|det|metric|budget|field|fmt}}    results/sweeps/sweeps_summary.csv
    {{C|workload|det|scenario|fmt}}             results/campaign/dr_by_scenario.csv (DR@10 per scenario)
    {{R|det|n_principals|fmt}}                  results/sweeps/scale_timing.csv (mean fit+score seconds)
    {{T|path.to.key|fmt}}                       results/triage_results.json (PENDING if not run)
    {{N|name}}                                  named counts (n_tuning_configs, n_runs, ...)

``det`` accepts P (proposed), IF, LOF, AE, RULE or the full name. ``fmt`` is a Python format
spec ('.3f', '.0%', 'd', 's'); 'pct' formats a ratio as a signed percentage (0.46 -> +46%).

    python scripts/fill_numbers.py docs/paper/paper_template.md docs/paper/paper.md
    python scripts/fill_numbers.py TEMPLATE OUT --check     # exit 1 if anything is unresolved
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from functools import lru_cache
from pathlib import Path

import pandas as pd

DET = {"P": "proposed_budget_aware_conformal", "IF": "isolation_forest", "LOF": "lof",
       "AE": "autoencoder", "RULE": "rule_baseline"}
PAT = re.compile(r"\{\{([A-Z])\|([^}]*)\}\}")


@lru_cache(None)
def _csv(path: str) -> pd.DataFrame:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(path)
    return pd.read_csv(p)


def _fmt(v, fmt: str) -> str:
    if isinstance(v, str):
        return v
    if pd.isna(v):
        return "n/a"
    if fmt == "pct":
        return f"{v:+.0%}"
    if fmt == "d":
        return f"{int(round(v))}"
    return format(v, fmt)


def _one(df: pd.DataFrame, **conds) -> pd.Series:
    m = pd.Series(True, index=df.index)
    for k, v in conds.items():
        col = df[k]
        m &= (col.astype(str) == str(v)) | (pd.to_numeric(col, errors="coerce") == pd.to_numeric(v, errors="coerce"))
    rows = df[m]
    if len(rows) != 1:
        raise KeyError(f"{len(rows)} rows match {conds}")
    return rows.iloc[0]


def resolve(kind: str, args: list[str]) -> str:
    if kind == "S":
        w, d, metric, b, field, fmt = args
        r = _one(_csv("results/campaign/summary.csv"), workload=w, detector=DET.get(d, d), metric=metric, budget=b)
        return _fmt(r[field], fmt)
    if kind == "H":
        w, h, field, fmt = args
        r = _one(_csv("results/campaign/hypotheses.csv"), workload=w, hypothesis=h)
        return _fmt(r[field], fmt)
    if kind == "A":
        w, var, metric, b, field, fmt = args
        r = _one(_csv("results/ablation/ablation_summary.csv"), workload=w, variant=DET.get(var, var),
                 metric=metric, budget=b)
        return _fmt(r[field], fmt)
    if kind == "W":
        sweep, x, d, metric, b, field, fmt = args
        r = _one(_csv("results/sweeps/sweeps_summary.csv"), sweep=sweep, x=x, detector=DET.get(d, d),
                 metric=metric, budget=b)
        return _fmt(r[field], fmt)
    if kind == "C":
        w, d, sc, fmt = args
        r = _one(_csv("results/campaign/dr_by_scenario.csv"), workload=w, detector=DET.get(d, d), scenario_id=sc)
        return _fmt(r["dr_at_10"], fmt)
    if kind == "R":
        d, n, fmt = args
        t = _csv("results/sweeps/scale_timing.csv")
        t = t[(t["detector"] == DET.get(d, d)) & (t["n_principals"] == int(n))]
        if t.empty:
            raise KeyError(f"no timing for {d} at {n}")
        return _fmt(t["fit_score_seconds"].mean(), fmt)
    if kind == "T":
        key, fmt = args
        p = Path("results/triage_results.json")
        if not p.exists():
            return "[PENDING: triage study not yet run]"
        v = json.loads(p.read_text())
        for part in key.split("."):
            v = v[part]
        return _fmt(v, fmt)
    if kind == "N":
        (name,) = args
        return str(named(name))
    raise KeyError(f"unknown placeholder kind {kind}")


def named(name: str):
    if name == "n_tuning_configs":
        return len(_csv("results/tuning_log.csv"))
    if name == "n_campaign_runs":
        c = _csv("results/campaign/campaign_metrics.csv")
        return c[["workload", "seed", "origin"]].drop_duplicates().shape[0]
    if name == "n_test_insiders_total":
        c = _csv("results/campaign/campaign_metrics.csv")
        c = c[(c.metric == "n_insiders") & (c.budget == 10) & (c.detector == DET["P"])]
        return int(c["value"].sum())
    if name == "n_features":
        f = pd.read_parquet("data/cache/W1_baseline_s0/features.parquet")
        return f.shape[1] - 2
    raise KeyError(name)


def fill(text: str) -> tuple[str, list[str]]:
    errors = []

    def sub(m):
        try:
            return resolve(m.group(1), m.group(2).split("|"))
        except Exception as exc:  # noqa: BLE001 - report every unresolved placeholder
            errors.append(f"{m.group(0)} -> {exc}")
            return f"[[UNRESOLVED {m.group(0)}]]"

    return PAT.sub(sub, text), errors


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("template")
    ap.add_argument("out")
    ap.add_argument("--check", action="store_true", help="exit 1 if any placeholder is unresolved")
    args = ap.parse_args()
    text, errors = fill(Path(args.template).read_text(encoding="utf-8"))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(text, encoding="utf-8")
    n = len(PAT.findall(Path(args.template).read_text(encoding="utf-8")))
    print(f"{args.out}: {n} placeholders, {len(errors)} unresolved")
    for e in errors:
        print("  ", e)
    if args.check and errors:
        sys.exit(1)


if __name__ == "__main__":
    main()
