# Threats to validity - what this setup can and cannot prove

> Generated from `docs/_templates/THREATS_TO_VALIDITY.md` by `python scripts/build_docs.py`.
> Every number below comes from a file in `results/`.

## What changed since the earlier (Review 2 draft) numbers, and why
The first version of the pipeline produced numbers that must not be used:

| Defect | Effect | Fix |
|---|---|---|
| The configured test window lay outside the generated data, so train = test = all data | Every model was scored on the rows it was trained on | Relative-day rolling splits; an empty window raises an error ([`cti/util/splits.py`](../src/cti/util/splits.py)) |
| The "rule baseline" returned random numbers | A competitor was a coin flip | A real 12-rule engine ([`cti/detectors/rules.py`](../src/cti/detectors/rules.py)) |
| "10 alerts/day" was evaluated as 10 alerts over two months | The central claim was not tested | Per-day queue evaluator ([`cti/eval/evaluate.py`](../src/cti/eval/evaluate.py)) |
| Explanations came from Isolation Forest, not the proposed detector | O3/O4 did not evaluate our method | Explanations from the proposed detector's own attribution |
| Three cited papers could not be found in any index | Academic-integrity risk | Literature survey rebuilt from verified records ([`related_work.md`](related_work.md)) |
| The contamination sweep was flat by construction | Contamination moves sklearn's threshold, not the score | Removed; replaced by budget, scale, stealth and calibration sweeps |

## 1. Internal validity (are the effects caused by what we think?)
- **We designed both the attacks and the detector.** The five planted scenarios and the features were
  written by the same team. The ablation shows this matters: removing the **resource** feature family
  drops detection rate at 10 alerts/day from {{A|W1_baseline|Full (tuned)|dr_at_b|10|mean|.2f}} to
  {{A|W1_baseline|-resource family|dr_at_b|10|mean|.2f}} on W1 and from
  {{A|W2_stealthy|Full (tuned)|dr_at_b|10|mean|.2f}} to {{A|W2_stealthy|-resource family|dr_at_b|10|mean|.2f}}
  on W2. Removing the identity, temporal or volume family changes almost nothing
  ({{A|W1_baseline|-identity family|dr_at_b|10|mean|.2f}}, {{A|W1_baseline|-temporal family|dr_at_b|10|mean|.2f}},
  {{A|W1_baseline|-volume family|dr_at_b|10|mean|.2f}}). In these synthetic organisations the attacks are
  separable mainly through *access to sensitive resources this identity never touched*. Attacks that
  stay inside an identity's normal resources would be much harder, and they are not modelled.
- **Tuning.** {{N|n_tuning_configs}} configurations were tried, all on validation windows of seeds
  100/101 that never appear in the test campaign (seeds 0-4). Isolation Forest got its own grid under
  the same protocol. LOF, the autoencoder and the rules were **not** tuned, which favours the proposed
  method relative to them.
- **Component C4 (suppression) was switched off by tuning,** and the ablation confirms it lowers
  precision ({{A|W1_baseline|+C4 suppress 3 d|precision_at_b|10|mean|.3f}} vs
  {{A|W1_baseline|Full (tuned)|precision_at_b|10|mean|.3f}} on W1). The "budget-aware" part of the
  contribution is the *evaluation* at a fixed daily queue, not a suppression mechanism.
- **The triage reviewers are the system's authors** and know the attack types. Their accuracy may be
  higher than an outside analyst's in both arms.

## 2. External validity (does it carry over to real organisations?)
- **Synthetic data only.** The CERT r4.2 / r6.2 dataset named in the scope was deliberately not used.
  All numbers come from our generator (1,000-3,000 identities, 180 days, five attack scenarios).
  Real CloudTrail has hundreds of event types (ours: 20), multiple accounts, federated identities
  and much messier benign behaviour.
- **LocalStack is not AWS.** The testbed proves the tooling runs against an AWS-compatible API, but
  LocalStack Community does not implement CloudTrail `LookupEvents`. The detector never consumed a
  live CloudTrail stream.
- **Scale.** At 3,000 identities the proposed detector still runs in seconds, but organisations with
  10^5 identities and terabytes of logs per day were not tested.
- **Attack mix.** Attack starts are spread evenly in time and ~5% of identities are insiders. That is
  far more than a real organisation, where insiders are rarer and the precision ceiling lower.

## 3. Construct validity (do the metrics measure what we claim?)
- **Labels are per identity-day.** A day with one malicious event among a hundred benign ones counts
  as positive.
- **Alerts are a daily batch** (available at the end of the day). Time-to-detection therefore has a
  floor of a few hours to a day, which is why H2 is supported only on W2.
- **A fixed budget per day** is one operating model. Real SOCs also use severity tiers and weekly
  reviews.
- **Precision must be read against its ceiling.** With about 2 malicious identity-days among ~800 per
  day, even a perfect detector reaches only {{S|W1_baseline|P|precision_oracle_at_b|10|mean|.2f}} at
  10 alerts/day on W1.

## 4. Statistical conclusion validity
- **Five independent seeds per workload.** Rolling origins of one seed overlap in data, so they are
  averaged within a seed. Intervals are 95% t-intervals over seeds (n = 5) and are wide, e.g.
  W1 precision@10 [{{S|W1_baseline|P|precision_at_b|10|ci_lo|.3f}}, {{S|W1_baseline|P|precision_at_b|10|ci_hi|.3f}}].
- **Hypothesis tests** use a paired bootstrap over seeds. A hypothesis counts as supported only if the
  whole 95% interval clears the threshold. With 4 workloads x 3 hypotheses there are 12 tests and no
  family-wise correction. Read the verdict table as a pattern, not 12 independent proofs.
- **H1a on W1 is not supported:** the point estimate is {{H|W1_baseline|H1a|diff|pct}}, but the
  interval's lower end ({{H|W1_baseline|H1a|ci_lo|pct}}) is below the +40% threshold.
- **The triage study is small** (4 reviewers x 40 alerts), so its interval will be wide.

## What this work can claim
On synthetic cloud audit logs with planted insider scenarios, judging each identity against its own
history with pooled conformal calibration catches more insiders, with several times higher precision,
than Isolation Forest, LOF, an autoencoder or rule signatures **at a fixed budget of 10 alerts per
day**. The gain comes mainly from resource-access deviations. Whether explanations improve human
triage is answered by the pre-registered study once the four reviewers have completed it.
