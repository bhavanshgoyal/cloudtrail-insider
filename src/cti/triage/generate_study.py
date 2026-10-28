"""
cti.triage.generate_study
-------------------------
Builds the triage study for objective O4 / hypothesis H3:

    "Can a reviewer triage an alert correctly from the generated explanation alone?"

Design (see docs/triage_study/PROTOCOL.md - written before any response is collected)
  * Source: alerts actually emitted by the proposed detector at B = 10 alerts/day on the
    CERT r4.2 TEST windows of all 3 rolling origins, frozen settings. Origins overlap in
    time, so an alert (user, day) raised in several origins is kept once (first origin).
    All origins are pooled because one window holds too few distinct insiders once each
    identity is capped at 2 alerts.
  * 40 alerts: 20 true positives (user-day with malicious activity per the CERT answers),
    stratified round-robin over scenarios S1-S3 (distinct identities first), + 20 false positives sampled
    uniformly from the emitted false alerts; at most 2 alerts per identity; fixed seed.
  * Two arms:  A = score only (anomaly score + rank in that day's queue)
               B = explanation only (no score)
    Both arms show the same context an analyst always has: pseudonymised identity, role, date.
  * Crossover with 4 reviewers: alerts split into halves H1 / H2 (10 TP + 10 FP each).
        R1: H1-A then H2-B     R2: H2-B then H1-A
        R3: H1-B then H2-A     R4: H2-A then H1-B
    Every alert is judged in both arms (by different reviewers); nobody sees an alert twice;
    arm order is counterbalanced.
  * Blinding: identities are pseudonymised, alert ids are random codes, the TP/FP mix is not
    disclosed, and the answer key is written to a separate facilitator folder.

Usage::

    python -m cti.triage.generate_study            # writes docs/triage_study/
"""
from __future__ import annotations

import argparse
import json
import logging
import string
from pathlib import Path

import numpy as np
import pandas as pd

from cti.detectors.proposed import BudgetAwareConformal
from cti.eval.evaluate import emit_alerts
from cti.experiment import apply_frozen_configs, load_world, run_window
from cti.explain.explain_proposed import explain_alerts
from cti.util.config import load_config
from cti.util.splits import all_splits

log = logging.getLogger(__name__)

OUT = Path("docs/triage_study")
FACILITATOR = OUT / "_facilitator_only"
STUDY_SEED = 2026
N_PER_CLASS = 20
MAX_PER_IDENTITY = 2

# reviewer -> [(half, arm), (half, arm)] in presentation order
SCHEDULE = {
    "R1": [("H1", "A"), ("H2", "B")],
    "R2": [("H2", "B"), ("H1", "A")],
    "R3": [("H1", "B"), ("H2", "A")],
    "R4": [("H2", "A"), ("H1", "B")],
}

ARM_TEXT = {
    "A": "SCORE ONLY - you see the detector's anomaly score and the alert's rank in that day's queue.",
    "B": "EXPLANATION ONLY - you see the generated explanation of what deviated; no score.",
}

INSTRUCTIONS = """\
## Instructions

You are a SOC analyst. Each alert below was raised by an anomaly detector watching a company's
activity logs (logons, USB devices, files copied to removable media, email and web browsing).
For each alert decide:

* **TP** - this looks like genuine misuse of the identity (insider / stolen credentials) and you would
  escalate it, or
* **FP** - this looks like unusual but benign activity and you would close it.

Rules:
1. Use **only** what is shown for each alert. Do not look at code, data, results, other packets or
   the facilitator folder, and do not discuss alerts with other reviewers until everyone is done.
2. Work through the sections in the order given. Do not go back to change earlier answers.
3. For every alert fill in your verdict (`TP` or `FP`), your confidence (1 = guess ... 5 = certain)
   and roughly how many seconds you spent, in your response sheet
   `responses_<you>.csv` (one row per alert, already listed).
4. The proportion of TP and FP alerts is not disclosed - judge each alert on its own.

Glossary (arm B): *p* is how unusual the deviation is compared with this identity's own history
(smaller = more unusual). "usually" is this identity's typical value on a normal day.
"""


def _codes(n: int, rng: np.random.Generator) -> list[str]:
    """n distinct random alert codes, deterministic for a given generator state.

    (A list, not a set: set iteration order of strings changes between Python processes,
    which would make the study differ from run to run.)
    """
    letters = np.array(list(string.ascii_uppercase))
    out: list[str] = []
    while len(out) < n:
        code = "".join(rng.choice(letters, 2)) + str(rng.integers(100, 1000))
        if code not in out:
            out.append(code)
    return out


def _scenario_of(gt: list[dict]) -> dict[tuple[str, str], str]:
    """(account, day) -> scenario, including days on a stolen account (scenario 3)."""
    out = {}
    for g in gt:
        out.update({(g["principal_id"], d): g["scenario_id"] for d in g["malicious_days"]})
        out.update({(u, d): g["scenario_id"] for u, d in g.get("other_account_days", [])})
    return out


def select_alerts(cfg: dict, seed: int = 0, budget: int = 10) -> pd.DataFrame:
    """Alerts emitted by the frozen proposed detector on every origin's test window, with labels
    and explanations; an alert (user, day) seen in several overlapping origins is kept once."""
    world = load_world(cfg, None, seed)
    labels = world.labels.set_index(["principal", "date"])["label"]
    scen = _scenario_of(world.ground_truth)
    role = world.events.set_index("principalId")["roleName"].astype(str)
    parts, splits = [], {}
    for split in all_splits(world.features["date"], cfg):
        det = BudgetAwareConformal(cfg, seed)
        run = run_window(world, cfg, split, "test", [det], budgets=[budget], with_ci=False)
        alerts = emit_alerts(run.scores[det.name], budget, det.suppress_days, seed)
        alerts["n_alerts_that_day"] = alerts.groupby("date")["rank"].transform("max")
        rows = alerts.merge(world.features, on=["principal", "date"], how="left")
        expl = explain_alerts(run.detectors[det.name], rows, cfg["explain"]["top_k_features"])
        alerts["explanation"] = [e["text"] for e in expl]
        alerts["primary_family"] = [e["primary_family"] for e in expl]
        alerts["origin"] = split.origin
        parts.append(alerts)
        splits[split.origin] = split.describe()
    out = pd.concat(parts, ignore_index=True).drop_duplicates(["principal", "date"]).reset_index(drop=True)
    out["label"] = [int(labels.get((p, d), 0)) for p, d in zip(out["principal"], out["date"])]
    out["scenario_id"] = [scen.get((p, pd.Timestamp(d).strftime("%Y-%m-%d")), "") if lab else ""
                          for p, d, lab in zip(out["principal"], out["date"], out["label"])]
    out["role"] = out["principal"].map(role).fillna("unknown")
    out["source_seed"] = seed
    out["identity_key"] = out["principal"].astype(str)
    out.attrs.update(workload=world.workload, seed=seed, budget=budget, splits=splits)
    return out


def _round_robin_tp(pool: pd.DataFrame, n: int, rng: np.random.Generator) -> pd.DataFrame:
    """TP alerts stratified by attack scenario: round-robin over scenarios, distinct identities first.

    Sampling alerts uniformly would let the multi-day scenario (S2, ~29 malicious days each) crowd
    out the short ones (S1, S3: 1-5 days), and the study would then measure one kind of explanation only.
    """
    queues = {}
    for sc, g in pool.groupby("scenario_id"):
        g = g.sample(frac=1.0, random_state=int(rng.integers(1 << 31)))
        g = g.assign(_k=g.groupby("identity_key").cumcount()).query("_k < @MAX_PER_IDENTITY")
        queues[sc] = list(g.sort_values("_k", kind="stable").index)      # first alert of each identity first
    picked = []
    while len(picked) < n and any(queues.values()):
        for sc in sorted(queues):
            if queues[sc] and len(picked) < n:
                picked.append(queues[sc].pop(0))
    if len(picked) < n:
        raise ValueError(f"only {len(picked)} eligible TP alerts, need {n}")
    return pool.loc[picked]


def sample_alerts(alerts: pd.DataFrame, n_per_class: int = N_PER_CLASS, seed: int = STUDY_SEED) -> pd.DataFrame:
    """n TP (scenario-stratified) + n FP alerts, <= MAX_PER_IDENTITY per identity, split into H1/H2.

    Each half gets n/2 TP and n/2 FP; TPs are dealt to halves alternately in scenario order so both
    halves contain every attack type.
    """
    rng = np.random.default_rng(seed)
    tp = _round_robin_tp(alerts[alerts["label"] == 1], n_per_class, rng).copy()
    tp = tp.sort_values("scenario_id", kind="stable")
    fp = alerts[alerts["label"] == 0].sample(frac=1.0, random_state=int(rng.integers(1 << 31)))
    fp = fp.groupby("identity_key", group_keys=False).head(MAX_PER_IDENTITY).head(n_per_class).copy()
    if len(fp) < n_per_class:
        raise ValueError(f"only {len(fp)} eligible FP alerts, need {n_per_class}")
    halves = ["H1", "H2"] * (n_per_class // 2) + ["H1"] * (n_per_class % 2)
    tp["half"], fp["half"] = halves, halves
    study = pd.concat([tp, fp]).sample(frac=1.0, random_state=int(rng.integers(1 << 31))).reset_index(drop=True)
    study["alert_id"] = _codes(len(study), rng)
    ids = {p: f"identity-{i + 1:02d}" for i, p in enumerate(rng.permutation(study["identity_key"].unique()))}
    study["identity"] = study["identity_key"].map(ids)
    return study


def _card(r: pd.Series, arm: str) -> str:
    head = (f"### Alert {r['alert_id']}\n\n"
            f"- Identity: `{r['identity']}` (role: {r['role']})\n"
            f"- Date: {pd.Timestamp(r['date']).date()}\n")
    if arm == "A":
        body = (f"- Anomaly score: **{r['score']:.2f}** (higher = more anomalous)\n"
                f"- Position in that day's queue: {int(r['rank'])} of {int(r['n_alerts_that_day'])}\n")
    else:
        body = "\n```\n" + r["explanation"] + "\n```\n"
    return head + body + "\n**Verdict (TP / FP):** ____  **Confidence (1-5):** ____\n\n---\n"


def write_study(study: pd.DataFrame, meta: dict, out: Path = OUT) -> None:
    out.mkdir(parents=True, exist_ok=True)
    (out / "_facilitator_only").mkdir(exist_ok=True)
    rng = np.random.default_rng(STUDY_SEED + 1)
    for reviewer, blocks in SCHEDULE.items():
        md = [f"# Triage study - packet for reviewer {reviewer}\n\n", INSTRUCTIONS, "\n"]
        resp = []
        for k, (half, arm) in enumerate(blocks, 1):
            part = study[study["half"] == half].sample(frac=1.0, random_state=int(rng.integers(1 << 31)))
            md.append(f"\n## Section {k} of {len(blocks)} - arm {arm}: {ARM_TEXT[arm]}\n\n")
            md += [_card(r, arm) for _, r in part.iterrows()]
            resp += [dict(reviewer=reviewer, section=k, arm=arm, alert_id=a, verdict="", confidence_1to5="",
                          seconds_spent="") for a in part["alert_id"]]
        (out / f"packet_{reviewer}.md").write_text("".join(md), encoding="utf-8")
        pd.DataFrame(resp).to_csv(out / f"responses_{reviewer}.csv", index=False)

    key = study[["alert_id", "half", "identity", "source_seed", "principal", "date", "label", "scenario_id", "role",
                 "primary_family", "score", "rank"]].copy()
    key["date"] = key["date"].astype(str)
    key["true_label"] = np.where(key["label"] == 1, "TP", "FP")
    (out / "_facilitator_only" / "answer_key.csv").write_text(key.to_csv(index=False), encoding="utf-8")
    (out / "_facilitator_only" / "README.md").write_text(
        "# Facilitator only - reviewers must not open this folder\n\n"
        "`answer_key.csv` holds the ground truth for every alert id (label from the CERT r4.2 answers).\n"
        "Score the study with `python -m cti.triage.score_study` after all four response sheets are in.\n",
        encoding="utf-8")
    (out / "study_meta.json").write_text(json.dumps({**meta, "n_alerts": len(study),
                                                     "n_tp": int(study["label"].sum()),
                                                     "schedule": SCHEDULE, "study_seed": STUDY_SEED,
                                                     "max_alerts_per_identity": MAX_PER_IDENTITY}, indent=1))
    log.info("wrote %d alerts, 4 packets and 4 response sheets to %s", len(study), out)


def main() -> None:
    ap = argparse.ArgumentParser(description="Generate the O4 triage study")
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    cfg = apply_frozen_configs(load_config())
    alerts = select_alerts(cfg, args.seed)
    study = sample_alerts(alerts)
    meta = {"workload": alerts.attrs["workload"], "seed": args.seed, "budget": 10,
            "splits": alerts.attrs["splits"],
            "n_emitted_alerts": len(alerts), "emitted_tp": int(alerts["label"].sum()),
            "emitted_tp_identities": int(alerts.loc[alerts["label"] == 1, "identity_key"].nunique())}
    write_study(study, meta)
    print(f"emitted {len(alerts)} alerts ({alerts['label'].sum()} TP); study: {len(study)} alerts -> {OUT}/")


if __name__ == "__main__":
    main()
