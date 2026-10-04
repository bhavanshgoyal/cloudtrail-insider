"""
cti.triage.score_study
----------------------
Scores the O4 triage study (hypothesis H3) from the reviewers' response sheets.

Inputs
  docs/triage_study/responses_R*.csv           filled in by the reviewers
  docs/triage_study/_facilitator_only/answer_key.csv

Analysis (pre-declared in docs/triage_study/PROTOCOL.md)
  * Per arm, pooled over reviewers: balanced accuracy (primary), accuracy, sensitivity
    (TP recall), specificity, mean confidence, mean seconds per alert.
  * H3 effect: balanced accuracy of arm B minus arm A. 95% CI by bootstrap over alerts,
    resampling TP and FP alerts separately (each alert carries its arm-A and arm-B judgements,
    so the comparison is paired). SUPPORTED only if the whole interval lies above +0.20.
  * Inter-rater agreement: Cohen's kappa for the two reviewers who judged the same alerts in
    the same arm (R1/R2 on H1-A and H2-B, R3/R4 on H1-B and H2-A).
  * Per-family accuracy in arm B (which kinds of explanation work).

Incomplete sheets are reported, never filled in.

    python -m cti.triage.score_study
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

STUDY = Path("docs/triage_study")
THRESHOLD = 0.20


def load(study: Path = STUDY) -> tuple[pd.DataFrame, pd.DataFrame]:
    key = pd.read_csv(study / "_facilitator_only" / "answer_key.csv")
    sheets = sorted(study.glob("responses_R*.csv"))
    if not sheets:
        raise SystemExit(f"no response sheets in {study}")
    resp = pd.concat([pd.read_csv(f, dtype={"verdict": str}) for f in sheets], ignore_index=True)
    return resp, key


def validate(resp: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """Normalise verdicts; return usable rows and a list of problems (never imputed)."""
    problems = []
    v = resp["verdict"].fillna("").astype(str).str.strip().str.upper()
    v = v.replace({"TRUE POSITIVE": "TP", "FALSE POSITIVE": "FP", "T": "TP", "F": "FP"})
    bad = ~v.isin(["TP", "FP"])
    for _, r in resp[bad].iterrows():
        problems.append(f"{r['reviewer']} alert {r['alert_id']} (arm {r['arm']}): missing/invalid verdict "
                        f"{r['verdict']!r}")
    ok = resp.loc[~bad].copy()
    ok["pred"] = (v[~bad] == "TP").astype(int)
    ok["confidence_1to5"] = pd.to_numeric(ok["confidence_1to5"], errors="coerce")
    ok["seconds_spent"] = pd.to_numeric(ok["seconds_spent"], errors="coerce")
    return ok, problems


def balanced_accuracy(y: np.ndarray, pred: np.ndarray) -> float:
    rec = [np.mean(pred[y == c] == c) for c in (0, 1) if (y == c).any()]
    return float(np.mean(rec)) if rec else np.nan


def cohens_kappa(a: np.ndarray, b: np.ndarray) -> float:
    if len(a) == 0:
        return np.nan
    po = np.mean(a == b)
    pa, pb = a.mean(), b.mean()
    pe = pa * pb + (1 - pa) * (1 - pb)
    return float((po - pe) / (1 - pe)) if pe < 1 else 1.0


def arm_stats(df: pd.DataFrame) -> dict:
    y, p = df["label"].to_numpy(), df["pred"].to_numpy()
    return dict(n_judgements=len(df), n_reviewers=df["reviewer"].nunique(),
                balanced_accuracy=balanced_accuracy(y, p), accuracy=float(np.mean(y == p)),
                sensitivity=float(np.mean(p[y == 1] == 1)) if (y == 1).any() else np.nan,
                specificity=float(np.mean(p[y == 0] == 0)) if (y == 0).any() else np.nan,
                mean_confidence=float(df["confidence_1to5"].mean()),
                mean_seconds=float(df["seconds_spent"].mean()))


def effect_ci(df: pd.DataFrame, n_boot: int = 10000, seed: int = 0) -> tuple[float, float, float]:
    """BA(B) - BA(A) with a stratified bootstrap over alerts (paired: each alert keeps both arms)."""
    rng = np.random.default_rng(seed)
    per = df.groupby(["alert_id", "arm"]).agg(correct=("correct", "mean"), label=("label", "first")).reset_index()
    wide = per.pivot(index="alert_id", columns="arm", values="correct").join(
        per.groupby("alert_id")["label"].first()).dropna()

    tp, fp = wide[wide["label"] == 1], wide[wide["label"] == 0]
    tpA, tpB, fpA, fpB = (tp["A"].to_numpy(), tp["B"].to_numpy(), fp["A"].to_numpy(), fp["B"].to_numpy())
    point = 0.5 * (tpB.mean() + fpB.mean()) - 0.5 * (tpA.mean() + fpA.mean())
    it = rng.integers(0, len(tp), (n_boot, len(tp)))          # stratified, paired resampling of alerts
    jf = rng.integers(0, len(fp), (n_boot, len(fp)))
    boots = 0.5 * (tpB[it].mean(1) + fpB[jf].mean(1)) - 0.5 * (tpA[it].mean(1) + fpA[jf].mean(1))
    return float(point), float(np.percentile(boots, 2.5)), float(np.percentile(boots, 97.5))


def score(resp: pd.DataFrame, key: pd.DataFrame) -> dict:
    ok, problems = validate(resp)
    df = ok.merge(key[["alert_id", "label", "primary_family", "scenario_id"]], on="alert_id", how="left")
    if df["label"].isna().any():
        problems.append(f"{int(df['label'].isna().sum())} responses reference unknown alert ids")
        df = df.dropna(subset=["label"])
    df["label"] = df["label"].astype(int)
    df["correct"] = (df["pred"] == df["label"]).astype(int)

    expected = len(key) * 4                       # each alert: 2 reviewers in arm A + 2 in arm B
    res: dict = {"n_alerts": int(len(key)), "n_responses_usable": int(len(df)), "problems": problems}
    res["arms"] = {arm: arm_stats(g) for arm, g in df.groupby("arm")}
    res["per_reviewer"] = {f"{r}-{a}": arm_stats(g) for (r, a), g in df.groupby(["reviewer", "arm"])}

    if {"A", "B"} <= set(df["arm"]):
        pt, lo, hi = effect_ci(df)
        res["h3"] = dict(effect_ba_B_minus_A=pt, ci_lo=lo, ci_hi=hi, threshold=THRESHOLD,
                         verdict="SUPPORTED" if lo > THRESHOLD else "NOT SUPPORTED")
    kappas = []
    for r1, r2 in (("R1", "R2"), ("R3", "R4")):
        for arm in ("A", "B"):
            a = df[(df.reviewer == r1) & (df.arm == arm)].set_index("alert_id")["pred"]
            b = df[(df.reviewer == r2) & (df.arm == arm)].set_index("alert_id")["pred"]
            common = a.index.intersection(b.index)
            if len(common):
                kappas.append(dict(pair=f"{r1}/{r2}", arm=arm, n=len(common),
                                   kappa=cohens_kappa(a[common].to_numpy(), b[common].to_numpy())))
    res["kappa"] = kappas
    b = df[df["arm"] == "B"]
    res["arm_B_accuracy_by_family"] = (b.groupby("primary_family")["correct"].agg(["mean", "size"])
                                       .rename(columns={"mean": "accuracy", "size": "n"}).round(3)
                                       .to_dict(orient="index"))
    res["completeness"] = dict(expected_judgements=expected, usable=int(len(df)))
    return res


def report(res: dict) -> str:
    lines = ["TRIAGE STUDY (O4 / H3)", f"usable judgements: {res['n_responses_usable']} "
             f"(expected {res['completeness']['expected_judgements']})"]
    for p in res["problems"]:
        lines.append(f"  ! {p}")
    for arm, s in sorted(res["arms"].items()):
        lines.append(f"arm {arm}: balanced acc {s['balanced_accuracy']:.3f}  acc {s['accuracy']:.3f}  "
                     f"sens {s['sensitivity']:.3f}  spec {s['specificity']:.3f}  "
                     f"conf {s['mean_confidence']:.2f}  sec {s['mean_seconds']:.0f}  (n={s['n_judgements']})")
    if "h3" in res:
        h = res["h3"]
        lines.append(f"H3: BA(B) - BA(A) = {h['effect_ba_B_minus_A']:+.3f}  95% CI [{h['ci_lo']:+.3f}, "
                     f"{h['ci_hi']:+.3f}]  threshold +{h['threshold']:.2f}  -> {h['verdict']}")
    for k in res["kappa"]:
        lines.append(f"kappa {k['pair']} arm {k['arm']}: {k['kappa']:.3f} (n={k['n']})")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description="Score the triage study")
    ap.add_argument("--study", default=str(STUDY))
    ap.add_argument("--output", default="results/triage_results.json")
    args = ap.parse_args()
    resp, key = load(Path(args.study))
    res = score(resp, key)
    print(report(res))
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    Path(args.output).write_text(json.dumps(res, indent=1, default=float))
    print(f"\nsaved {args.output}")


if __name__ == "__main__":
    main()
