# P20: Project summary for building the Review 1, 2 and 3 slide decks

> **For the deck-building agent.** Everything you need is in this file. Numbers are filled
> automatically from `results/` by `scripts/build_docs.py`. **Do not change, round or invent
> numbers.** If a number shows `[PENDING ...]`, put a visible "pending" marker on the slide. Figure
> paths are relative to the repository root (`cloudtrail-insider/`). Each review is marked out of 10.
> The slide plan below maps each slide to the rubric line it earns.

---

## 0. The project in one minute

**Title:** Insider-Threat Detection on Cloud Audit Logs at Operationally Realistic Alert Budgets (P20)

**Problem.** Clouds log every action (AWS CloudTrail: who, what, which resource, outcome). Misuse of
valid credentials, by an insider or by someone who stole them, shows up only in this log. Research
scores detectors by area under the curve. A SOC analyst, though, can look at only about 10 alerts a
day, and an alert that doesn't say *what* deviated gets dismissed.

**What we built.**
1. A synthetic CloudTrail organisation (1,000-3,000 identities, 180 days, five insider scenarios,
   benign look-alikes) plus a LocalStack testbed.
2. {{N|n_features}} causal features in four families: identity, resource, timing, volume.
3. **BudgetAwareConformal**: each identity is judged against its own history, with pooled conformal
   calibration, and each alert is explained.
4. Four baselines: Isolation Forest, LOF, autoencoder, and 12 rule signatures.
5. A per-day alert-budget evaluator with confidence intervals.
6. A campaign: 4 workloads x 5 seeds x 3 temporal origins.
7. Ablation and sweeps.
8. A pre-registered human triage study.

**Headline (W1, 10 alerts/day, test windows, mean of 5 seeds).** The proposed detector catches
**{{S|W1_baseline|P|dr_at_b|10|mean|.0%}}** of insiders against **{{S|W1_baseline|IF|dr_at_b|10|mean|.0%}}**
for Isolation Forest. Precision is **{{S|W1_baseline|P|precision_at_b|10|mean|.3f}}** vs
**{{S|W1_baseline|IF|precision_at_b|10|mean|.3f}}**, where a perfect detector would reach
{{S|W1_baseline|P|precision_oracle_at_b|10|mean|.2f}}.

**Glossary (put on a backup slide).**
- **Alert budget B:** alerts reviewed per day.
- **DR@B (detection rate):** share of insiders caught at least once.
- **P@B:** true alerts / alerts.
- **Oracle precision:** the best precision possible, given that few malicious identity-days exist.
- **MTTD:** hours from attack start to the alert.
- **Conformal p-value:** "how unusual compared with held-out normal data" (smaller = more unusual).
- **Seed:** one randomly generated organisation.
- **Workload:** a type of organisation.
- **Ablation:** removing one part to measure its effect.
- **Leakage:** training on data you later test on.

**Visual identity for charts:** proposed = blue `#2a78d6`, Isolation Forest = orange `#eb6834`,
LOF = green `#1baf7a`, autoencoder = yellow `#eda100`, rules = pink `#e87ba4`. Reuse the PNGs in
`figures/` (they are colour-blind-checked) instead of redrawing them.

---

## REVIEW 1: Problem formulation and baseline (10 marks)

### Slide R1-1: Title
Project title, team names, guide, date. One-line tagline: *"Catching insiders where analysts actually work: 10 alerts a day."*

### Slide R1-2: Background (no marks, needed context)
- CloudTrail records identity, action, resource and outcome for every control-plane call.
- Credential misuse produces no "intrusion": the only evidence is behaviour in this log.
- Speaker note: say that Amazon GuardDuty-style rules exist, but they flag known patterns only.

### Slide R1-3: Literature survey: gap table (3 marks)
- **Source:** `docs/related_work.md`. Use the 14-row table with columns *Paper · Method · Dataset /
  testbed · Metric · Limitation*. Split it over two slides (7 + 7 rows) and keep the column names.
- All papers are 2021-2026 and verified. Note in small text: "every entry verified via Crossref /
  DBLP / arXiv; links in repo".
- **Gap slide (closing):**
  1. Most work reports AUC/F1/accuracy, not detection at a fixed daily queue [1-4, 6, 13].
  2. The closest work [1] uses an investigation budget as a % of all sessions. **Say this
     explicitly: we are not the first budget-aware evaluation; we are per-day and add explanations
     tested with people.**
  3. Only 14% of security-XAI papers run a user study [11].
  4. Cloud audit-log work reports point metrics [6, 7].
- Speaker note: "We rebuilt this table because three entries in our first draft could not be found
  in any index."

### Slide R1-4: Problem statement in our words (part of 2 marks)
"Given CloudTrail-style events, raise at most **B alerts per day** (B = 10, 50, 100) so that as many
insiders as possible are caught, as early as possible, and each alert names the deviating
behaviour."

### Slide R1-5: Falsifiable hypotheses (2 marks with R1-4)
Use the template "*Method X improves metric M by at least N% compared with baseline B under
condition C*":
- **H1a:** BudgetAwareConformal increases **detection rate at 10 alerts/day** by **≥ 40%**
  (relative) compared with **Isolation Forest** on the identical feature matrix, on the test windows
  of synthetic CloudTrail workloads.
- **H1b:** the same for **precision at 10 alerts/day**, by **≥ 30%**.
- **H2:** reduces **median time to detection** at 10 alerts/day by **≥ 25%**.
- **H3:** reviewers using **only the explanation** reach balanced triage accuracy **≥ 20 points**
  above reviewers using only the score.
- **Falsification rule (box):** supported only if the **whole 95% interval** clears the threshold.

### Slide R1-6: Testbed and environment evidence (3 marks; slides alone score 0)
- **Evidence files:** `docs/evidence/testbed_evidence.txt` (LocalStack 3.8.1 healthy; S3 buckets
  `cloudtrail-logs-bucket`, `finance-archive`, `public-assets-bucket`; STS caller identity) and
  **screenshots in `docs/evidence/screenshots/`** (the team must take these: `docker compose up -d`,
  `docker ps`, the health endpoint, `python scripts/capture_evidence.py`).
- Second evidence: a terminal screenshot of `python -m pytest -q` (all green) and of
  `python run_pipeline.py` finishing.
- Architecture diagram to draw: *Synthetic CloudTrail generator → events (7M rows) → causal
  features → detectors → per-day alert queue → explanations → analyst*, with LocalStack (S3, IAM,
  STS) as the AWS-compatible testbed.
- **Honesty note on the slide:** LocalStack Community does not implement CloudTrail
  `LookupEvents`, so events come from our generator with the CloudTrail schema.

### Slide R1-7: Baseline reproduced (2 marks)
- The baselines named in the statement run and produce numbers. W1, 10 alerts/day, 5 seeds:
  - Isolation Forest DR@10 = **{{S|W1_baseline|IF|dr_at_b|10|mean|.3f}}** [{{S|W1_baseline|IF|dr_at_b|10|ci_lo|.3f}}, {{S|W1_baseline|IF|dr_at_b|10|ci_hi|.3f}}],
    P@10 = {{S|W1_baseline|IF|precision_at_b|10|mean|.3f}}, AUC = {{S|W1_baseline|IF|auc_roc|0|mean|.3f}}
  - Rule signatures DR@10 = **{{S|W1_baseline|RULE|dr_at_b|10|mean|.3f}}**, P@10 = {{S|W1_baseline|RULE|precision_at_b|10|mean|.3f}}
- Show the 12 rules in a small table (from `configs/rules.yaml`: root use, login without MFA,
  brute force then success, external IP, public exposure, access key for another user, admin role
  assumed by a non-admin, mass GetObject, logging disabled, external e-mail, login from a new IP,
  excessive AccessDenied).
- Speaker note: "The rule engine abstains when no rule fires, so it raises fewer than 10 alerts on
  quiet days."

---

## REVIEW 2: Implementation and preliminary results (10 marks)

### Slide R2-1: What changed since the first draft (credibility slide, put it early)
Table from `docs/THREATS_TO_VALIDITY.md`, "What changed": train = test leakage fixed; random rule
baseline replaced; per-day budget evaluator; explanations from our own detector; literature
verified. One line: "The earlier numbers were invalid, and these replace them."

### Slide R2-2: Architecture (O1 + O2 code, 4 marks with R2-3)
Draw the four components:
- **C1:** compare each identity with its own history (robust z-score).
- **C2:** pooled conformal calibration. The old per-identity calibration had a p-value floor of 1/31.
- **C3:** keep the 4 families separate and alert on the strongest (min-p).
- **C4:** suppression (off after tuning).

Feature families with examples:
- *identity:* new IP, login without MFA
- *resource:* never-touched sensitive bucket, public exposure
- *timing:* hours from the usual time
- *volume:* calls, distinct actions

### Slide R2-3: Working code in a version-controlled repository (4 marks)
- Screenshot of the GitHub repo with its commit list. There is one commit per phase (Phase 0 → 10);
  `git log --oneline` shows them.
- Screenshot of `python -m pytest -q`: all tests pass, covering metrics against hand-computed values,
  feature causality (with deliberately injected look-ahead bugs that the tests catch), rules,
  splits and triage scoring.
- Repo map table from `README.md`.

### Slide R2-4: Comparative results: baseline vs proposed on the same axes (3 marks)
- **Figure:** `figures/per_workload_dr10.png` (DR@10 and P@10, all 5 detectors, 4 workloads,
  95% CIs). Backup figures: `figures/dr_vs_budget.png`, `figures/precision_vs_budget.png` (with the
  oracle ceiling line).
- Numbers for the slide (W1, 10 alerts/day):

| Detector | DR@10 | P@10 |
|---|---|---|
| **Proposed** | **{{S|W1_baseline|P|dr_at_b|10|mean|.3f}}** | **{{S|W1_baseline|P|precision_at_b|10|mean|.3f}}** |
| Isolation Forest | {{S|W1_baseline|IF|dr_at_b|10|mean|.3f}} | {{S|W1_baseline|IF|precision_at_b|10|mean|.3f}} |
| LOF | {{S|W1_baseline|LOF|dr_at_b|10|mean|.3f}} | {{S|W1_baseline|LOF|precision_at_b|10|mean|.3f}} |
| Autoencoder | {{S|W1_baseline|AE|dr_at_b|10|mean|.3f}} | {{S|W1_baseline|AE|precision_at_b|10|mean|.3f}} |
| Rules | {{S|W1_baseline|RULE|dr_at_b|10|mean|.3f}} | {{S|W1_baseline|RULE|precision_at_b|10|mean|.3f}} |
| *Oracle ceiling* | 1.000 | {{S|W1_baseline|P|precision_oracle_at_b|10|mean|.3f}} |

- Speaker notes:
  - "Precision looks small because only about 2 of ~800 identities per day are malicious. Read it
    against the ceiling."
  - "LOF nearly ties us on detection in W1; we win clearly on precision."

### Slide R2-5: Where the gain comes from: per attack type (supports the 3 marks)
W1, DR@10:

| Scenario | Isolation Forest | Proposed |
|---|---|---|
| S1 exfil after hours | {{C|W1_baseline|IF|S1|.0%}} | {{C|W1_baseline|P|S1|.0%}} |
| S2 departing insider (slow) | {{C|W1_baseline|IF|S2|.0%}} | {{C|W1_baseline|P|S2|.0%}} |
| S3 privilege escalation | {{C|W1_baseline|IF|S3|.0%}} | {{C|W1_baseline|P|S3|.0%}} |
| S4 credential stuffing | {{C|W1_baseline|IF|S4|.0%}} | {{C|W1_baseline|P|S4|.0%}} |
| S5 low-and-slow | {{C|W1_baseline|IF|S5|.0%}} | {{C|W1_baseline|P|S5|.0%}} |

Message: everyone catches the loud attacks; the per-identity view wins on slow, quiet ones.

### Slide R2-6: Ablation: which component causes the gain? (2 marks with R2-7)
- **Figure:** `figures/ablation.png`.
- Key numbers (W1, P@10):
  - full {{A|W1_baseline|Full (tuned)|precision_at_b|10|mean|.3f}}
  - −C1 {{A|W1_baseline|-C1 population baseline|precision_at_b|10|mean|.3f}}
  - −C2 {{A|W1_baseline|-C2 no calibration|precision_at_b|10|mean|.3f}}
  - −C3 {{A|W1_baseline|-C3 no fusion (pooled)|precision_at_b|10|mean|.3f}}
  - +C4 {{A|W1_baseline|+C4 suppress 3 d|precision_at_b|10|mean|.3f}}
- Removing the resource family: DR@10 W1 {{A|W1_baseline|-resource family|dr_at_b|10|mean|.2f}},
  W2 {{A|W2_stealthy|-resource family|dr_at_b|10|mean|.2f}}. Removing identity, temporal or volume
  changes almost nothing.
- Message: C1, C2 and C3 each matter (about 4x precision); C4 hurts (negative result); the signal
  is resource access.

### Slide R2-7: Parameter sweeps: load, scale, cost (2 marks with R2-6)
- **Figures:**
  - `figures/dr_vs_budget.png` (budget 1 → 200)
  - `figures/sweep_principals.png` + `figures/runtime_vs_principals.png` (250 → 3,000 identities)
  - `figures/sweep_stealth.png` (attack magnitude x0.25 → x1.5)
  - `figures/sweep_suppress_days.png`
  - `figures/sweep_cal_fraction.png`
- Numbers:
  - At **1 alert/day**: proposed DR {{W|budget|0|P|dr_at_b|1|mean|.0%}} vs IF {{W|budget|0|IF|dr_at_b|1|mean|.0%}}
    (LOF {{W|budget|0|LOF|dr_at_b|1|mean|.0%}}; **say that LOF matches us on detection at small budgets
    in W1**, and that our edge is precision and scale).
  - **Scale (best sweep message):** from 250 to 3,000 identities, proposed DR@10
    {{W|principals|250|P|dr_at_b|10|mean|.2f}} → {{W|principals|3000|P|dr_at_b|10|mean|.2f}}, while
    Isolation Forest goes {{W|principals|250|IF|dr_at_b|10|mean|.2f}} → {{W|principals|3000|IF|dr_at_b|10|mean|.2f}}
    and LOF {{W|principals|250|LOF|dr_at_b|10|mean|.2f}} → {{W|principals|3000|LOF|dr_at_b|10|mean|.2f}}.
  - **Cost:** fit + score at 3,000 identities is proposed {{R|P|3000|.1f}} s, Isolation Forest
    {{R|IF|3000|.1f}} s, LOF {{R|LOF|3000|.0f}} s (`figures/runtime_vs_principals.png`).
  - **Stealth:** at x0.25 attack strength the proposed detector still gets
    {{W|stealth|0.25|P|dr_at_b|10|mean|.2f}}. Detection relies on *novel* resources, not volume (ties
    to the ablation caveat).
  - `cal_fraction` 0.1-0.4: no change, so the result is robust to that setting.

### Slide R2-8: Threats to validity (1 mark)
From `docs/THREATS_TO_VALIDITY.md`, four bullets:
1. Synthetic data only (CERT not used; LocalStack is not AWS).
2. We designed both attacks and detector; the signal concentrates in resource-access novelty.
3. Only the proposed method and IF were tuned (on separate validation seeds).
4. Five seeds, 12 tests without correction, and a small triage study run by the authors.

---

## REVIEW 3: Evaluation and documentation (10 marks)

### Slide R3-1: All objectives evidenced (3 marks)
- Use the matrix in `docs/OBJECTIVES_EVIDENCE.md` (O1-O4 → code → result → status).
- State the campaign size: **4 workloads x 5 seeds x 3 temporal origins = {{N|n_campaign_runs}}
  test windows**, with every configuration run at least 3 times, reporting mean, std and 95% CI
  (`results/campaign/summary.csv`).
- Workload table:

| Workload | Description |
|---|---|
| W1 baseline | normal organisation |
| W2 stealthy | attacks half as strong, slow attacks twice as likely |
| W3 scale | 3,000 identities |
| W4 noisy | 2.5x more benign look-alikes |

### Slide R3-2: Statistical soundness (2 marks)
- Every chart has 95% CI error bars over 5 seeds; origins are averaged within a seed because their
  windows overlap.
- **Hypothesis verdict table** (paired bootstrap over seeds):

| | W1 | W2 | W3 | W4 |
|---|---|---|---|---|
| H1a DR@10 ≥ +40% | {{H|W1_baseline|H1a|diff|pct}} [{{H|W1_baseline|H1a|ci_lo|pct}}, {{H|W1_baseline|H1a|ci_hi|pct}}] **{{H|W1_baseline|H1a|verdict|s}}** | {{H|W2_stealthy|H1a|diff|pct}} [{{H|W2_stealthy|H1a|ci_lo|pct}}, {{H|W2_stealthy|H1a|ci_hi|pct}}] **{{H|W2_stealthy|H1a|verdict|s}}** | {{H|W3_scale|H1a|diff|pct}} [{{H|W3_scale|H1a|ci_lo|pct}}, {{H|W3_scale|H1a|ci_hi|pct}}] **{{H|W3_scale|H1a|verdict|s}}** | {{H|W4_noisy|H1a|diff|pct}} [{{H|W4_noisy|H1a|ci_lo|pct}}, {{H|W4_noisy|H1a|ci_hi|pct}}] **{{H|W4_noisy|H1a|verdict|s}}** |
| H1b P@10 ≥ +30% | {{H|W1_baseline|H1b|diff|pct}} **{{H|W1_baseline|H1b|verdict|s}}** | {{H|W2_stealthy|H1b|diff|pct}} **{{H|W2_stealthy|H1b|verdict|s}}** | {{H|W3_scale|H1b|diff|pct}} **{{H|W3_scale|H1b|verdict|s}}** | {{H|W4_noisy|H1b|diff|pct}} **{{H|W4_noisy|H1b|verdict|s}}** |
| H2 MTTD ≤ −25% | {{H|W1_baseline|H2|diff|pct}} **{{H|W1_baseline|H2|verdict|s}}** | {{H|W2_stealthy|H2|diff|pct}} **{{H|W2_stealthy|H2|verdict|s}}** | {{H|W3_scale|H2|diff|pct}} **{{H|W3_scale|H2|verdict|s}}** | {{H|W4_noisy|H2|diff|pct}} **{{H|W4_noisy|H2|verdict|s}}** |

- Speaker note: "H1 is supported in 7 of 8 tests. On W1 the average gain is above 40%, but the
  cautious end of the interval is not, so we call it not supported. H2 fails mostly because alerts
  come in a daily batch: everyone who catches an insider catches them within about a day."
- Backup slide: `figures/auc_vs_budget_rank.png` and `figures/auc_vs_dr10.png`. On W4, Isolation
  Forest's AUC ({{S|W4_noisy|IF|auc_roc|0|mean|.3f}}) ≈ LOF's ({{S|W4_noisy|LOF|auc_roc|0|mean|.3f}}),
  yet DR@10 is {{S|W4_noisy|IF|dr_at_b|10|mean|.0%}} vs {{S|W4_noisy|LOF|dr_at_b|10|mean|.0%}}: the
  curve hides the operating-point difference.

### Slide R3-3: Explanations (O3) and the triage study (O4)
- Example alert card (copy as monospace text):

```
Resource access deviation (p = 0.00058)
  - calls on sensitive buckets (finance / hr / pii / security): 9 (usually 0)
  - share of calls on sensitive buckets: 21% (usually 0%)
```

- Triage design diagram: 40 alerts (20 true across all 5 scenarios, 20 false); arm A = score only,
  arm B = explanation only; 4 reviewers in a crossover; every alert judged twice per arm;
  pre-registered in `docs/triage_study/PROTOCOL.md`.
- **Result:** arm A balanced accuracy {{T|arms.A.balanced_accuracy|.2f}}, arm B
  {{T|arms.B.balanced_accuracy|.2f}}, effect {{T|h3.effect_ba_B_minus_A|+.2f}}
  [{{T|h3.ci_lo|+.2f}}, {{T|h3.ci_hi|+.2f}}] → **{{T|h3.verdict|s}}**.
- SHAP cross-check: SHAP's top feature was among the named features in all 20 checked alerts.
  Present this as consistency, not independent proof.

### Slide R3-4: Live demonstration (2 marks; must run live)
Follow `docs/DEMO_RUNBOOK.md`: `pytest`, then `python scripts/live_demo.py --scenario S1` (a
brand-new organisation, trained on the past, today's 10-alert queue with explanations, reveal),
then `--scenario S5 --no-reveal` (the audience triages), then the Streamlit dashboard.

### Slide R3-5: Documentation (3 marks)
- **Paper:** `docs/paper/paper.pdf`, 6-8 pages, with abstract, related work, method, evaluation,
  limitations and references.
- **Demo video link:** recorded by the team.
- Show the paper's first page as an image.

### Slide R3-6: Limitations and future work
Synthetic only; resource-dominated signal; attacks inside normal resources not modelled; small
author-run triage study. Next: real CloudTrail, harder attacks, outside analysts.

### Slide R3-7: Conclusion
Three takeaways:
1. Judge identities against themselves.
2. Evaluate at the analyst's queue, not the curve.
3. Explanations must be tested with people.

---

## Do-not-claim list (important)
- ❌ "First budget-aware evaluation." Le & Zincir-Heywood (2021) evaluate against an investigation budget.
- ❌ "All four components help." C4 (suppression) lowers precision and is switched off.
- ❌ "Works on real AWS data." The data is synthetic, and LocalStack does not provide CloudTrail lookups.
- ❌ "H1 supported on all workloads." W1 H1a is not supported. H2 is supported only on W2.
- ❌ "Explanations proven to help" unless the triage study (real responses) says SUPPORTED.
- ❌ Any number from `results/_invalid_pre_fix/`, `figures/_invalid_pre_fix/` or the earlier README.
- ❌ The mock triage responses used to test the scorer. They are not data.
- ❌ "Beats every baseline at every budget." LOF matches us on detection rate at 1-2 alerts/day on W1.
- ❌ "Robust to stealthy attacks" in general. Only attacks that touch new resources were tested.
- ❌ "Uses SHAP to explain." Explanations come from the detector's own per-feature deviations; SHAP
  is only a cross-check.

## Still to be provided by the team (mark these slides as pending if missing)
- Testbed screenshots (`docs/evidence/screenshots/`)
- GitHub URL and commit-history screenshot
- Real triage-study responses
- Demo video link
- Team names
