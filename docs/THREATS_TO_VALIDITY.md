# Threats to validity - what this setup can and cannot prove

> Generated from `docs/_templates/THREATS_TO_VALIDITY.md` by `python scripts/build_docs.py`.
> Every number below comes from a file in `results/`.

## History: two earlier versions whose numbers must not be used
| Version | Why its numbers are invalid | Where it lives now |
|---|---|---|
| First pipeline | Trained and tested on the same data, a random-number "rule baseline", "10 alerts/day" evaluated over two months, explanations from the wrong detector, three unverifiable citations | `results/_invalid_pre_fix/` |
| Synthetic CloudTrail version | Valid, but on our own simulator: we designed both the attacks and the detector | `results/_synthetic_v1/`, branch `master` |

The current version uses the independent CMU CERT r4.2 benchmark.

## 1. Internal validity (are the effects caused by what we think?)
- **Tuning leakage on a single dataset.** The three rolling origins overlap (origin 0's test days are
  origins 1 and 2's validation days). All tuning was therefore confined to a development period that
  ends before the earliest test day, and a unit test checks that the tuning windows never touch a
  test day. Isolation Forest received its own grid search under the same protocol; LOF, the
  autoencoder and the rules were not tuned.
- **The tuned settings did not transfer fully.** On the test windows several variants beat the tuned
  model, e.g. Fisher fusion (DR@10 0.61 vs
  0.43) or dropping the identity family (DR@10
  0.55, P@10
  0.034 vs
  0.028). We did **not** switch: choosing now would be
  selecting on the test set. Validation DR@10 of the chosen settings was far above the test value,
  which points to drift between the development months and the later months.
- **Where the gain comes from.** Replacing the per-user baseline with a population baseline drops
  precision@10 from 0.028 to
  0.007, the Isolation Forest level
  (0.007).
- **Keyword lists** (job sites, leak sites) were fixed from general knowledge and the *public* CERT
  scenario descriptions, never from the answers files, but those descriptions name the kinds of
  sites involved. Removing the resource family lowers DR@10 to
  0.30.
- **The triage reviewers are the system's authors** and may know the public scenario descriptions.

## 2. External validity (does it carry over to real organisations?)
- **CERT r4.2 is simulated** (ExactData's Dynamic Data Generator for CMU SEI), not real employee data,
  and it contains **no cloud control-plane logs**. The project title says "cloud audit logs"; the
  evidence is on enterprise audit logs (logons, USB, file copies, e-mail, web).
- **One organisation.** 1,000 users over 17 months; no replication on another dataset or release.
- **LocalStack testbed** proves the tooling runs against an AWS-compatible API but is not part of the
  CERT evaluation.

## 3. Construct validity (do the metrics measure what we claim?)
- **Labels are per user-day.** A day with one malicious event counts as positive. Scenario-3 events
  on a stolen supervisor account are labelled malicious, but an insider counts as detected only via
  their own account (the stricter choice).
- **Alerts are a daily batch**, so time to detection has a floor of hours to a day.
- **Precision must be read against its ceiling**: even a perfect detector reaches only
  0.230 at 10 alerts/day, because few user-days are
  malicious.

## 4. Statistical conclusion validity
- **Seeds are not replicates.** On one fixed dataset they only change detector randomness (the
  proposed detector has none). Intervals therefore resample the real sources of uncertainty:
  insiders for detection rate and time to detection, test days for precision.
- **Few insiders.** Only 33 insiders fall in the test windows, so DR@10 has a
  wide interval (0.28-0.60). H1a's
  point estimate (+53%) clears +40%, but its interval
  (-7% to +188%) does not, so it is reported as not
  supported.
- **Three hypotheses, no family-wise correction.** H1b's interval
  (+172% to +723%) is far above +30%, so the
  conclusion does not hinge on a correction.
- **The triage study is small** (4 reviewers x 40 alerts), so its interval will be wide.

## What this work can claim
On the CERT r4.2 benchmark, at a fixed budget of 10 alerts per day, judging each user against their
own history with pooled conformal calibration roughly quadruples the precision of Isolation Forest
(0.028 vs 0.007) and gives the
highest precision of the five detectors. It does **not** reliably catch more insiders than the
baselines at 10 alerts/day. Whether explanations improve human triage is answered by the
pre-registered study once the four reviewers have completed it.
