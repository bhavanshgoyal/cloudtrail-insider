# Stale results notice

`results/metrics.csv`, `results/shap_alerts.json`, `figures/*.png` (comparison, precision/recall,
shap_global) and `docs/triage_study/*` were generated **before** the leakage fix: the old pipeline
trained and tested on the same rows (the configured test window lay outside the data), used a
random-number "rule baseline", and evaluated one global top-B list instead of per-day budgets.

Do **not** quote them. They are replaced when the corrected evaluation (per-day budgets, real
rule baseline, leak-free rolling splits, >= 3 seeds) is regenerated in Phases 4-6.
`results/_invalid_pre_fix/` and `figures/_invalid_pre_fix/` hold the old ablation / sweep outputs
for reference only.
