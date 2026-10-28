## Results (CERT r4.2 test windows, 3 origins pooled, 10 alerts/day; CIs in `results/campaign/summary.csv`)

| Detector | DR@10 [95% CI over insiders] | P@10 [95% CI over days] | DR@50 | AUC-ROC |
|---|---|---|---|---|
| **Proposed (BudgetAwareConformal)** | **{{S|CERT_r4.2|P|dr_at_b|10|mean|.3f}}** [{{S|CERT_r4.2|P|dr_at_b|10|ci_lo|.2f}}, {{S|CERT_r4.2|P|dr_at_b|10|ci_hi|.2f}}] | **{{S|CERT_r4.2|P|precision_at_b|10|mean|.3f}}** [{{S|CERT_r4.2|P|precision_at_b|10|ci_lo|.3f}}, {{S|CERT_r4.2|P|precision_at_b|10|ci_hi|.3f}}] | {{S|CERT_r4.2|P|dr_at_b|50|mean|.3f}} | {{S|CERT_r4.2|P|auc_roc|0|mean|.3f}} |
| Isolation Forest | {{S|CERT_r4.2|IF|dr_at_b|10|mean|.3f}} [{{S|CERT_r4.2|IF|dr_at_b|10|ci_lo|.2f}}, {{S|CERT_r4.2|IF|dr_at_b|10|ci_hi|.2f}}] | {{S|CERT_r4.2|IF|precision_at_b|10|mean|.3f}} [{{S|CERT_r4.2|IF|precision_at_b|10|ci_lo|.3f}}, {{S|CERT_r4.2|IF|precision_at_b|10|ci_hi|.3f}}] | {{S|CERT_r4.2|IF|dr_at_b|50|mean|.3f}} | {{S|CERT_r4.2|IF|auc_roc|0|mean|.3f}} |
| LOF | {{S|CERT_r4.2|LOF|dr_at_b|10|mean|.3f}} | {{S|CERT_r4.2|LOF|precision_at_b|10|mean|.3f}} | {{S|CERT_r4.2|LOF|dr_at_b|50|mean|.3f}} | {{S|CERT_r4.2|LOF|auc_roc|0|mean|.3f}} |
| Autoencoder | {{S|CERT_r4.2|AE|dr_at_b|10|mean|.3f}} | {{S|CERT_r4.2|AE|precision_at_b|10|mean|.3f}} | {{S|CERT_r4.2|AE|dr_at_b|50|mean|.3f}} | {{S|CERT_r4.2|AE|auc_roc|0|mean|.3f}} |
| Rule signatures | {{S|CERT_r4.2|RULE|dr_at_b|10|mean|.3f}} | {{S|CERT_r4.2|RULE|precision_at_b|10|mean|.3f}} | {{S|CERT_r4.2|RULE|dr_at_b|50|mean|.3f}} | {{S|CERT_r4.2|RULE|auc_roc|0|mean|.3f}} |

Oracle precision ceiling at 10 alerts/day: {{S|CERT_r4.2|P|precision_oracle_at_b|10|mean|.3f}} (few user-days are malicious).

**Hypothesis verdicts vs Isolation Forest** (whole 95% CI beyond the threshold = supported):

| Hypothesis | Relative difference [95% CI] | Verdict |
|---|---|---|
| H1a DR@10 ≥ +40% | {{H|CERT_r4.2|H1a|diff|pct}} [{{H|CERT_r4.2|H1a|ci_lo|pct}}, {{H|CERT_r4.2|H1a|ci_hi|pct}}] | {{H|CERT_r4.2|H1a|verdict|s}} |
| H1b P@10 ≥ +30% | {{H|CERT_r4.2|H1b|diff|pct}} [{{H|CERT_r4.2|H1b|ci_lo|pct}}, {{H|CERT_r4.2|H1b|ci_hi|pct}}] | {{H|CERT_r4.2|H1b|verdict|s}} |
| H2 MTTD ≤ −25% | {{H|CERT_r4.2|H2|diff|pct}} [{{H|CERT_r4.2|H2|ci_lo|pct}}, {{H|CERT_r4.2|H2|ci_hi|pct}}] | {{H|CERT_r4.2|H2|verdict|s}} |
| H3 triage | | {{T|h3.verdict|s}} |

![Detection rate per insider scenario](figures/dr_by_scenario.png)
