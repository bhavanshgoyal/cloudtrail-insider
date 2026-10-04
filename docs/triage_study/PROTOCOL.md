# Triage study protocol (objective O4, hypothesis H3)

This protocol was fixed and committed **before any response was collected**. The analysis below is
the one that will be reported, whatever it shows.

## Question
Can a reviewer triage an alert correctly using **only the generated explanation**, and does the
explanation beat the bare anomaly score?

**H3.** Reviewers shown only the explanation classify alerts as true / false positive with balanced
accuracy at least **20 percentage points** higher than reviewers shown only the anomaly score.

## Material
- Alerts actually raised by the proposed detector (frozen settings, `configs/proposed_final.yaml`)
  at **10 alerts/day** on the **test windows** of workload W1_baseline, seeds 0 and 1 (last rolling
  origin). Neither seed was used for tuning.
- **40 alerts: 20 TP + 20 FP.** TP = the identity had planted misuse that day.
  - TPs are drawn round-robin over the five attack scenarios (distinct identities first), so every
    attack type appears: S1 x2, S2 x6, S3 x2, S4 x5, S5 x5. Sampling alerts uniformly would have
    given only multi-day S2/S5 attacks, which raise ~20 alerts each.
  - FPs are drawn uniformly from the emitted false alerts.
  - At most 2 alerts per identity. Fixed seed (`STUDY_SEED = 2026`).
- Regenerate with `python -m cti.triage.generate_study`. The output is deterministic.

## Arms
| arm | reviewer sees |
|---|---|
| **A - score only** | pseudonymised identity, role, date, anomaly score, position in that day's queue |
| **B - explanation only** | pseudonymised identity, role, date, generated explanation (no score) |

Role is shown in both arms because an analyst always has it. It helps in both arms equally (e.g.
CI-runner service accounts), which makes the A-vs-B difference harder to show, not easier.

## Design: crossover, 4 reviewers
Alerts are split into halves H1 and H2, each with 10 TP and 10 FP.

| reviewer | first section | second section |
|---|---|---|
| R1 | H1, arm A | H2, arm B |
| R2 | H2, arm B | H1, arm A |
| R3 | H1, arm B | H2, arm A |
| R4 | H2, arm A | H1, arm B |

- Every alert is judged twice in arm A and twice in arm B, by different people (160 judgements).
- No reviewer sees any alert twice.
- Arm order is counterbalanced, so learning from explanations cannot favour arm A on average.

## Procedure (facilitator)
1. Give reviewer *Rk* only `packet_Rk.md` and `responses_Rk.csv`. Do **not** share
   `_facilitator_only/`, the repo, results or the ground truth.
2. Reviewers work alone, in section order, without going back. For each alert they fill in
   `verdict` (TP/FP), `confidence_1to5` and `seconds_spent`.
3. Reviewers must not discuss alerts until all four sheets are returned.
4. Put the four filled sheets back in `docs/triage_study/` (same file names) and run
   `python -m cti.triage.score_study`.

Reviewers are team members who built the system. They know the general attack types, which is a
threat to validity (see below). They must not consult the code or data while judging.

## Analysis (pre-declared)
- **Primary:** balanced accuracy per arm, pooled over reviewers.
- **H3 effect:** BA(B) - BA(A), with a 95% CI from 10,000 bootstrap resamples of alerts. TP and FP
  are resampled separately, and each alert keeps its arm-A and arm-B judgements, so the comparison
  is paired.
- **Verdict:** **SUPPORTED** only if the whole interval lies above +0.20. Otherwise NOT SUPPORTED;
  the point estimate and interval are still reported.
- **Secondary:**
  - accuracy, sensitivity and specificity per arm
  - mean confidence and seconds per alert per arm
  - per-reviewer results
  - Cohen's kappa for reviewer pairs who judged the same alerts in the same arm (R1/R2, R3/R4)
  - arm-B accuracy by explanation family
- Missing or invalid answers are reported and excluded, **never imputed**.

## Threats to validity (to be repeated in the paper)
- Small study: 4 reviewers and 40 alerts, so wide intervals.
- Reviewers are the system's authors: possible familiarity bias.
- Synthetic attacks were designed by the same team that wrote the explanations.
- The TP share in the study (50%) is far above the share in the live queue (~10-30% at B=10), so
  absolute accuracy here does not equal accuracy in operation. Balanced accuracy is used for that
  reason.
