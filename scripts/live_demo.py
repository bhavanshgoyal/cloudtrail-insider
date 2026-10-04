"""
live_demo.py - Review 3 live demonstration (runs in well under 2 minutes).

What it shows, live, on data generated on the spot:
  1. a brand-new synthetic company (random seed unless --seed is given) with one attack type planted;
  2. the detector is trained on the past only (no labels are ever used);
  3. the SOC queue for one day: the top-B alerts, each with its generated explanation;
  4. the reveal: which alerts were the planted attacks, and DR / precision at B for the
     proposed detector vs Isolation Forest over the whole test window.

    python scripts/live_demo.py --scenario S1          # night-time exfiltration
    python scripts/live_demo.py --scenario S5 --budget 5
    python scripts/live_demo.py --scenario S2 --seed 7 --no-reveal

Scenarios: S1 exfil after hours | S2 departing insider | S3 privilege escalation |
           S4 credential stuffing | S5 low-and-slow collection
"""
from __future__ import annotations

import argparse
import logging
import sys
import textwrap
import time

import numpy as np
import pandas as pd

from cti.detectors.proposed import BudgetAwareConformal
from cti.detectors.train import IsoForestDetector
from cti.eval.evaluate import build_context, emit_alerts, evaluate_alerts
from cti.experiment import World, apply_frozen_configs, fit_and_score
from cti.explain.explain_proposed import explain_alerts
from cti.features.pipeline import build_features, make_labels
from cti.ingest.normalise import normalise_columns
from cti.ingest.synthetic import generate_dataset
from cti.util.config import load_config
from cti.util.splits import make_splits

logging.basicConfig(level=logging.ERROR)
SCENARIOS = {"S1": "exfiltration after hours", "S2": "departing insider (3-week ramp)",
             "S3": "privilege escalation", "S4": "credential stuffing", "S5": "low-and-slow collection"}
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
    ap.add_argument("--scenario", choices=list(SCENARIOS), default="S1")
    ap.add_argument("--seed", type=int, default=None, help="default: a fresh random company")
    ap.add_argument("--principals", type=int, default=300)
    ap.add_argument("--days", type=int, default=100)
    ap.add_argument("--budget", type=int, default=10)
    ap.add_argument("--no-reveal", action="store_true", help="hide ground truth (let the audience triage)")
    ap.add_argument("--pause", type=float, default=0.0, help="seconds to pause between steps (presenting)")
    args = ap.parse_args()
    t0 = time.time()
    seed = args.seed if args.seed is not None else int(np.random.default_rng().integers(1_000, 99_999))
    cfg = apply_frozen_configs(load_config())

    rule(f"1. A brand-new company (seed {seed})")
    raw, gt = generate_dataset(args.principals, args.days, [args.scenario], insider_rate=0.03, seed=seed,
                               warmup_days=cfg["warmup_days"], start_date=cfg["synthetic"]["start_date"])
    events = normalise_columns(raw)
    say(f"  {args.principals} identities, {args.days} days, {len(events):,} CloudTrail events generated just now.")
    say(f"  Hidden inside: {len(gt)} insider(s) running scenario {args.scenario} ({SCENARIOS[args.scenario]}).",
        args.pause)

    rule("2. Turn the raw log into per-identity, per-day clues (causal: past only)")
    feats = build_features(events, cfg)
    labels = make_labels(events, feats)
    world = World("live_demo", seed, events, feats, labels, gt)
    split = make_splits(feats["date"], cfg)
    say(f"  {len(feats):,} identity-days x {feats.shape[1] - 2} clues "
        f"(identity, resource, timing, volume).")
    say(f"  Learn from {str(split.train_days[0])[:10]} .. {str(split.val_days[-1])[:10]}, "
        f"then watch {str(split.test_days[0])[:10]} .. {str(split.test_days[-1])[:10]}.", args.pause)

    rule("3. Fit the detectors on the past (no attack labels are used)")
    dets = [BudgetAwareConformal(cfg, seed), IsoForestDetector(cfg, seed)]
    scores, fitted, secs = fit_and_score(world, split, "test", dets)
    for name, s in secs.items():
        say(f"  {name:34s} fit + score in {s:.1f} s")
    ctx = build_context(scores[PROPOSED], labels, gt, split.test_days)
    if ctx.insiders.empty:
        sys.exit("  No planted attack fell inside the watch window for this seed - rerun (or pass --seed).")

    # the day to show: first malicious day of the first insider in the window
    day = min(ctx.insiders["first_day"])
    rule(f"4. The analyst's queue on {day.date()}  (top {args.budget} alerts that day)")
    alerts = emit_alerts(scores[PROPOSED], args.budget, fitted[PROPOSED].suppress_days, seed)
    today = alerts[alerts["date"] == day].merge(feats, on=["principal", "date"], how="left")
    expl = explain_alerts(fitted[PROPOSED], today, cfg["explain"]["top_k_features"])
    truth = labels.set_index(["principal", "date"])["label"]
    for e, (_, a) in zip(expl, today.iterrows()):
        is_bad = bool(truth.get((a["principal"], day), 0))
        tag = ("   <-- PLANTED ATTACK" if is_bad else "   (benign)") if not args.no_reveal else ""
        say(f"\n  #{int(a['rank']):<2d} {a['principal']}   score {a['score']:.2f}{tag}")
        say(textwrap.indent(e["text"], "      "))
        if args.pause:
            time.sleep(args.pause / 2)

    if args.no_reveal:
        say("\n  (ground truth hidden: ask the audience which alerts they would escalate)")
        return

    rule(f"5. Over the whole watch window, at {args.budget} alerts/day")
    for name in (PROPOSED, IsoForestDetector.name):
        r = evaluate_alerts(emit_alerts(scores[name], args.budget, getattr(fitted[name], "suppress_days", 0), seed),
                            ctx, args.budget)
        p = r.point
        mttd = f"{p['mttd_hours_median']:.0f} h" if np.isfinite(p["mttd_hours_median"]) else "-"
        label = "Proposed (BudgetAwareConformal)" if name == PROPOSED else "Isolation Forest"
        say(f"  {label:32s} caught {int(p['n_detected'])}/{int(p['n_insiders'])} insiders   "
            f"precision {p['precision_at_b']:.3f} (ceiling {p['precision_oracle_at_b']:.3f})   "
            f"median time-to-detect {mttd}")
    say(f"\n  Whole demo: {time.time() - t0:.0f} s, on data that did not exist when it started.")


if __name__ == "__main__":
    main()
