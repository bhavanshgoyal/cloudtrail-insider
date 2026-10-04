# Insider-Threat Detection on Cloud Audit Logs at Operationally Realistic Alert Budgets

Project P20. Detect misuse of legitimate cloud credentials in AWS-CloudTrail-style audit logs. Every
detector is judged where a security team actually operates: **a fixed number of alerts an analyst can
review per day**. Every alert says **which behaviour deviated**.

## Problem
Detection research reports area-under-curve figures computed over all operating points. A SOC runs
at one point, set by how many alerts an analyst can examine each day, which is a small number. A
detector with an excellent curve can be useless at ten alerts per day. And an alert that does not
say which aspect of behaviour deviated cannot be triaged, so it gets dismissed.

## Objectives
| ID | Objective |
|---|---|
| O1 | Anomaly detection over cloud audit logs capturing deviation in identity behaviour, resource access and temporal pattern |
| O2 | Evaluate detection at fixed alert budgets (10, 50, 100 alerts/day) that reflect analyst capacity |
| O3 | For each alert, an explanation naming the specific behavioural deviation responsible |
| O4 | Assess whether those explanations let a reviewer triage the alert correctly |

## Hypotheses (falsifiable)
All stated against Isolation Forest on the identical feature matrix, at **B = 10 alerts/day**, on the
**test** windows of 4 synthetic workloads (5 seeds x 3 rolling temporal origins each):
- **H1a** detection rate is at least **40%** higher (relative);
- **H1b** precision is at least **30%** higher (relative);
- **H2** median time to detection is at least **25%** lower;
- **H3** reviewers shown only the explanation triage with balanced accuracy at least **20 percentage
  points** above reviewers shown only the score.

**Falsification rule:** a hypothesis is *supported* only if the **whole** 95% interval (paired
bootstrap over seeds for H1/H2; stratified bootstrap over alerts for H3) lies beyond its threshold.
Otherwise it is reported as *not supported*.

<!-- RESULTS:START -->
(run `python scripts/build_docs.py` to fill this block from results/)
<!-- RESULTS:END -->

## How it works (one paragraph)
CloudTrail events → **32 causal features per identity-day** in four families
(identity, resource, temporal, volume) → **BudgetAwareConformal**:
- **C1** compares every identity with *its own* history (robust z-scores);
- **C2** turns per-family deviations into conformal p-values against a calibration set pooled over
  all identities;
- **C3** keeps the families separate and alerts on the strongest one;
- **C4**, an optional suppression of repeat alerts, was switched off by tuning.

Each alert is explained by its most deviant family and features. Settings were tuned **only** on
validation windows of separate seeds and frozen before the test campaign.

## Reproduce
```bash
pip install -e ".[dev]"
python -m pytest -q                      # all tests: metrics, causality, rules, splits, triage scoring
python run_pipeline.py                   # one run (~40 s): metrics, explanations, SHAP cross-check
python scripts/tune_proposed.py          # model selection on VALIDATION windows only (~10 min)
python scripts/run_campaign.py           # 4 workloads x 5 seeds x 3 origins on TEST windows (~60 min)
python -m cti.eval.figures               # figures from the campaign
python scripts/run_ablation.py           # which component causes the gain
python scripts/run_sweep.py              # budget / scale / stealth / calibration sweeps
python scripts/build_docs.py             # paper (PDF), threats, evidence matrix, this README's results
python scripts/live_demo.py --scenario S1   # live demo on a brand-new company (< 1 min)
streamlit run src/cti/demo/app.py        # analyst dashboard
```
Testbed (LocalStack, AWS-compatible): `docker compose up -d` then `python scripts/capture_evidence.py`
(see `docs/TESTBED.md`).

## Repository map
| Path | What |
|---|---|
| `src/cti/ingest/synthetic.py` | Synthetic CloudTrail generator: roles, habits, benign look-alikes, scenarios S1-S5, workloads W1-W4 |
| `src/cti/features/pipeline.py` | Causal feature families |
| `src/cti/detectors/` | `proposed.py` (BudgetAwareConformal), `train.py` (IF, LOF, autoencoder), `rules.py` (12 signatures) |
| `src/cti/eval/` | `evaluate.py` (per-day budget metrics, CIs), `aggregate.py`, `figures.py` |
| `src/cti/explain/explain_proposed.py` | Alert explanations + SHAP cross-check |
| `src/cti/triage/` | Triage study generator and scorer (O4) |
| `src/cti/experiment.py`, `src/cti/util/splits.py` | Leak-free train / val / test harness |
| `scripts/` | Tuning, campaign, ablation, sweeps, docs build, live demo |
| `configs/` | `default.yaml`, `rules.yaml`, frozen `proposed_final.yaml` / `baseline_final.yaml` |
| `results/`, `figures/` | Outputs (each figure has a CSV table next to it) |
| `docs/` | Paper, related work, threats to validity, evidence matrix, triage study, demo runbook |

## Honest limitations
- The data is **synthetic**; the CERT dataset was not used.
- The gain rests mainly on resource-access deviations, and we wrote both the attacks and the
  detector.
- Duplicate suppression (C4) did not help.

See `docs/THREATS_TO_VALIDITY.md`.

License: MIT
