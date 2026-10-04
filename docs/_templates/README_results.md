## Results (test windows, 10 alerts/day, mean over 5 seeds; 95% CI in `results/campaign/summary.csv`)

| Workload | Proposed DR@10 | Isolation Forest | LOF | Autoencoder | Rules | Proposed P@10 (oracle) | IF P@10 |
|---|---|---|---|---|---|---|---|
| W1 baseline | **{{S|W1_baseline|P|dr_at_b|10|mean|.3f}}** | {{S|W1_baseline|IF|dr_at_b|10|mean|.3f}} | {{S|W1_baseline|LOF|dr_at_b|10|mean|.3f}} | {{S|W1_baseline|AE|dr_at_b|10|mean|.3f}} | {{S|W1_baseline|RULE|dr_at_b|10|mean|.3f}} | **{{S|W1_baseline|P|precision_at_b|10|mean|.3f}}** ({{S|W1_baseline|P|precision_oracle_at_b|10|mean|.2f}}) | {{S|W1_baseline|IF|precision_at_b|10|mean|.3f}} |
| W2 stealthy | **{{S|W2_stealthy|P|dr_at_b|10|mean|.3f}}** | {{S|W2_stealthy|IF|dr_at_b|10|mean|.3f}} | {{S|W2_stealthy|LOF|dr_at_b|10|mean|.3f}} | {{S|W2_stealthy|AE|dr_at_b|10|mean|.3f}} | {{S|W2_stealthy|RULE|dr_at_b|10|mean|.3f}} | **{{S|W2_stealthy|P|precision_at_b|10|mean|.3f}}** ({{S|W2_stealthy|P|precision_oracle_at_b|10|mean|.2f}}) | {{S|W2_stealthy|IF|precision_at_b|10|mean|.3f}} |
| W3 scale (3,000) | **{{S|W3_scale|P|dr_at_b|10|mean|.3f}}** | {{S|W3_scale|IF|dr_at_b|10|mean|.3f}} | {{S|W3_scale|LOF|dr_at_b|10|mean|.3f}} | {{S|W3_scale|AE|dr_at_b|10|mean|.3f}} | {{S|W3_scale|RULE|dr_at_b|10|mean|.3f}} | **{{S|W3_scale|P|precision_at_b|10|mean|.3f}}** ({{S|W3_scale|P|precision_oracle_at_b|10|mean|.2f}}) | {{S|W3_scale|IF|precision_at_b|10|mean|.3f}} |
| W4 noisy | **{{S|W4_noisy|P|dr_at_b|10|mean|.3f}}** | {{S|W4_noisy|IF|dr_at_b|10|mean|.3f}} | {{S|W4_noisy|LOF|dr_at_b|10|mean|.3f}} | {{S|W4_noisy|AE|dr_at_b|10|mean|.3f}} | {{S|W4_noisy|RULE|dr_at_b|10|mean|.3f}} | **{{S|W4_noisy|P|precision_at_b|10|mean|.3f}}** ({{S|W4_noisy|P|precision_oracle_at_b|10|mean|.2f}}) | {{S|W4_noisy|IF|precision_at_b|10|mean|.3f}} |

**Hypothesis verdicts** (whole 95% CI beyond the threshold = supported):

| | W1 | W2 | W3 | W4 |
|---|---|---|---|---|
| H1a DR@10 ≥ +40% | {{H|W1_baseline|H1a|diff|pct}} {{H|W1_baseline|H1a|verdict|s}} | {{H|W2_stealthy|H1a|diff|pct}} {{H|W2_stealthy|H1a|verdict|s}} | {{H|W3_scale|H1a|diff|pct}} {{H|W3_scale|H1a|verdict|s}} | {{H|W4_noisy|H1a|diff|pct}} {{H|W4_noisy|H1a|verdict|s}} |
| H1b P@10 ≥ +30% | {{H|W1_baseline|H1b|diff|pct}} {{H|W1_baseline|H1b|verdict|s}} | {{H|W2_stealthy|H1b|diff|pct}} {{H|W2_stealthy|H1b|verdict|s}} | {{H|W3_scale|H1b|diff|pct}} {{H|W3_scale|H1b|verdict|s}} | {{H|W4_noisy|H1b|diff|pct}} {{H|W4_noisy|H1b|verdict|s}} |
| H2 MTTD ≤ −25% | {{H|W1_baseline|H2|diff|pct}} {{H|W1_baseline|H2|verdict|s}} | {{H|W2_stealthy|H2|diff|pct}} {{H|W2_stealthy|H2|verdict|s}} | {{H|W3_scale|H2|diff|pct}} {{H|W3_scale|H2|verdict|s}} | {{H|W4_noisy|H2|diff|pct}} {{H|W4_noisy|H2|verdict|s}} |
| H3 triage | {{T|h3.verdict|s}} | | | |

![Detection and precision per workload](figures/per_workload_dr10.png)
