"""
live_demo.py - Review 3 live demonstration on CERT r4.2 (well under 2 minutes once the
feature cache exists).

  1. pick an insider storyline (S1/S2/S3); one insider of that type whose attack falls inside
     the watch (test) window is chosen at random (or pass --insider);
  2. the detectors are fitted on the past only (no labels are ever used);
  3. the SOC queue for that insider's first malicious day: the top-B alerts, each with its
     generated explanation;
  4. the reveal: which alerts were malicious, and DR / precision at B for the proposed
     detector vs Isolation Forest over the whole watch window.

    python scripts/live_demo.py                       # S2 departing insider (default)
    python scripts/live_demo.py --scenario S1 --budget 5
    python scripts/live_demo.py --scenario S3 --no-reveal

Scenarios: S1 after-hours USB + leak-site upload | S2 job-hunting, then data theft on USB |
           S3 disgruntled admin: keylogger, logs in as the supervisor, mass email
"""
from __future__ import annotations

import argparse
import logging
import sys
import textwrap
import time

import numpy as np

from cti.detectors.proposed import BudgetAwareConformal
from cti.detectors.train import IsoForestDetector
from cti.eval.evaluate import build_context, emit_alerts, evaluate_alerts
from cti.experiment import apply_frozen_configs, fit_and_score, load_world
from cti.explain.explain_proposed import explain_alerts
from cti.util.config import load_config
from cti.util.splits import make_splits

logging.basicConfig(level=logging.ERROR)
SCENARIOS = {"S1": "after-hours USB use and an upload to a leak site, then quits",
             "S2": "browses job sites, then steals data on USB before leaving",
             "S3": "disgruntled admin: keylogger, logs in as the supervisor, sends a mass email"}
PROPOSED = BudgetAwareConformal.name
W = 78


def say(msg: str = "", pause: float = 0.0) -> None:
    print(msg, flush=True)
    if pause:
        time.sleep(pause)


def rule(title: str) -> None:
    say("\n" + "=" * W)
    say(f"  {title}")
    say("=" * W)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", choices=list(SCENARIOS), default="S2")
    ap.add_argument("--insider", default=None, help="user id (default: random insider of --scenario)")
    ap.add_argument("--origin", type=int, default=None, help="rolling origin (default: last)")
    ap.add_argument("--seed", type=int, default=None, help="picks the insider; default: random")
    ap.add_argument("--any-insider", action="store_true",
                    help="pick among all insiders of the storyline (default: among those the detector caught)")
    ap.add_argument("--budget", type=int, default=10)
    ap.add_argument("--no-reveal", action="store_true", help="hide ground truth (let the audience triage)")
    ap.add_argument("--pause", type=float, default=0.0, help="seconds to pause between steps (presenting)")
    args = ap.parse_args()
    t0 = time.time()
    seed = args.seed if args.seed is not None else int(np.random.default_rng().integers(1_000, 99_999))
    cfg = apply_frozen_configs(load_config())

    rule("1. The company: CMU CERT r4.2 benchmark (simulated organisation)")
    world = load_world(cfg, None, 0)
    feats, labels, gt = world.features, world.labels, world.ground_truth
    split = make_splits(feats["date"], cfg, args.origin)
    say(f"  {feats['principal'].nunique():,} employees, {feats['date'].nunique()} days of logons, USB, file,"
        f" email and web logs -> {len(feats):,} employee-days x {feats.shape[1] - 2} clues.")
    test_days = {str(d)[:10] for d in split.test_days}
    cands = [g for g in gt if g["scenario_id"] == args.scenario and test_days.intersection(g["malicious_days"])]
    if args.insider:
        cands = [g for g in gt if g["principal_id"] == args.insider and test_days.intersection(g["malicious_days"])]
    if not cands:
        sys.exit("  No matching insider is active in this watch window - try another --scenario or --origin.")
    say(f"  Hidden somewhere in the watch window: insider storyline {args.scenario} "
        f"({SCENARIOS[args.scenario]}).", args.pause)

    rule("2. Learn from the past only")
    say(f"  Learn from {str(split.train_days[0])[:10]} .. {str(split.val_days[-1])[:10]}, "
        f"then watch {str(split.test_days[0])[:10]} .. {str(split.test_days[-1])[:10]}.")
    dets = [BudgetAwareConformal(cfg, seed), IsoForestDetector(cfg, seed)]
    scores, fitted, secs = fit_and_score(world, split, "test", dets)
    for name, s in secs.items():
        say(f"  {name:34s} fit + score in {s:.1f} s")
    ctx = build_context(scores[PROPOSED], labels, gt, split.test_days)

    alerts = emit_alerts(scores[PROPOSED], args.budget, fitted[PROPOSED].suppress_days, seed)
    alert_day = alerts["date"].dt.strftime("%Y-%m-%d")

    def hits(g):
        mal = sorted(d for d in g["malicious_days"] if d in test_days)
        return mal, alerts.loc[(alerts["principal"] == g["principal_id"]) & alert_day.isin(mal), "date"].sort_values()

    caught = [g for g in cands if len(hits(g)[1])]
    if not args.no_reveal and not args.insider:
        say(f"  This window: {len(caught)} of {len(cands)} {args.scenario} insider(s) caught at {args.budget}/day.")
    pool = cands if (args.any_insider or args.insider or not caught) else caught
    target = pool[np.random.default_rng(seed).integers(len(pool))]
    mal, hit = hits(target)
    if not args.no_reveal:
        if len(hit):
            lag = (hit.iloc[0] - np.datetime64(mal[0], "ns")).days
            say(f"  The chosen insider was active from {mal[0]} on {len(mal)} day(s) in this window; first "
                f"alerted on {str(hit.iloc[0])[:10]} ({lag} day(s) later). Showing that day.")
        else:
            say(f"  The chosen insider was active on {len(mal)} day(s) in this window and was NOT alerted "
                f"at {args.budget}/day. Showing their first active day.")
    day = hit.iloc[0] if len(hit) else np.datetime64(mal[0], "ns")
    rule(f"3. The analyst's queue on {str(day)[:10]}  (top {args.budget} alerts that day)")
    today = alerts[alerts["date"] == day].merge(feats, on=["principal", "date"], how="left")
    expl = explain_alerts(fitted[PROPOSED], today, cfg["explain"]["top_k_features"])
    truth = labels.set_index(["principal", "date"])["label"]
    for e, (_, a) in zip(expl, today.iterrows()):
        is_bad = bool(truth.get((a["principal"], a["date"]), 0))
        tag = ("   <-- MALICIOUS (per CERT answers)" if is_bad else "   (benign)") if not args.no_reveal else ""
        say(f"\n  #{int(a['rank']):<2d} {a['principal']}   score {a['score']:.2f}{tag}")
        say(textwrap.indent(e["text"], "      "))
        if args.pause:
            time.sleep(args.pause / 2)
    if target["principal_id"] not in set(today["principal"]):
        say(f"\n  (the chosen insider is not in today's top {args.budget})")

    if args.no_reveal:
        say("\n  (ground truth hidden: ask the audience which alerts they would escalate)")
        return

    rule(f"4. Over the whole watch window, at {args.budget} alerts/day")
    for name in (PROPOSED, IsoForestDetector.name):
        r = evaluate_alerts(emit_alerts(scores[name], args.budget, getattr(fitted[name], "suppress_days", 0), seed),
                            ctx, args.budget)
        p = r.point
        mttd = f"{p['mttd_hours_median']:.0f} h" if np.isfinite(p["mttd_hours_median"]) else "-"
        label = "Proposed (BudgetAwareConformal)" if name == PROPOSED else "Isolation Forest"
        say(f"  {label:32s} caught {int(p['n_detected'])}/{int(p['n_insiders'])} insiders   "
            f"precision {p['precision_at_b']:.3f} (ceiling {p['precision_oracle_at_b']:.3f})   "
            f"median time-to-detect {mttd}")
    say(f"\n  Whole demo: {time.time() - t0:.0f} s.")


if __name__ == "__main__":
    main()
