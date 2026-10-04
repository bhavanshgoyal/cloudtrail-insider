# Results status

## Current (leak-free, per-day budgets)
| file | what it is |
|---|---|
| `metrics.csv` | **one run** (W1_baseline, seed 42, last origin, test window) from `python run_pipeline.py`. Not the paper's statistics - those come from the Phase 6 campaign (workloads x seeds x origins). |
| `per_insider.csv` | per-insider detection / time-to-detection for that run |
| `comparison_vs_if.csv` | paired relative differences proposed vs Isolation Forest for that run |
| `explanations.json` | explanation for every alert the proposed detector raised at B=10 in that run (O3) |
| `shap_crosscheck.json` | Kernel-SHAP agreement with those explanations (n=20) |
| `tuning_log.csv` | every configuration tried during model selection - **validation windows only** (W1, seeds 100/101) |
| `val_baselines_untuned_W1_s100.csv` | untuned baselines on validation windows (reference for tuning) |
| `fast/` | `--fast` sanity-check outputs (gitignored, not results) |

## Invalid - do not quote
`_invalid_pre_fix/` and `figures/_invalid_pre_fix/` and `docs/triage_study/*` (pre-fix SHAP-on-IF study)
and `figures/{comparison_at_10,precision_at_b,recall_at_b,shap_global}.png` were produced by the old
pipeline that trained and tested on the same rows, used a random-number "rule baseline", and ranked a
single global top-B list instead of per-day budgets. They are kept only as history and are replaced in
Phases 6-8.
