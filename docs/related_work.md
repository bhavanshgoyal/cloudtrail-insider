# Related Work - verified literature survey (2021 onwards)

> **Rebuilt on 2026-10-04.** The previous version of this table contained papers that could not be
> found in any index (e.g. "CloudTrail-Sec, DSN 2023", "Budget-aware Anomaly Detection for Cloud
> Operations, USENIX Security 2023", "Conformal Prediction for Cybersecurity Alerts, EuroS&P 2023")
> and has been discarded.
>
> Every paper below was checked against at least one authoritative record (DOI via Crossref, DBLP,
> arXiv or the publisher's page); the link in the *Verified via* column is where. Details marked †
> come from the abstract or index record only (the full text was paywalled or blocked); they should
> be re-read from the PDF before being quoted in the paper.

## Gap table

| # | Paper | Method | Dataset / testbed | Metric | Limitation relative to our problem |
|---|---|---|---|---|---|
| 1 | Le, D. C., & Zincir-Heywood, N. (2021). *Anomaly Detection for Insider Threats Using Unsupervised Ensembles.* IEEE TNSM 18(2), 1152-1164. | Ensemble of 4 unsupervised detectors over user-behaviour features with temporal representations | CERT Insider Threat Test Dataset† | Detection rate vs. **investigation budget** (60% of insiders at 0.1% budget, all at < 5%) | Closest prior work: already budget-aware, but the budget is a share of all user-sessions over the whole period, not a fixed number of alerts **per day**; no explanation of *why* an alert fired; not cloud audit logs. |
| 2 | Yuan, S., & Wu, X. (2021). *Deep learning for insider threat detection: Review, challenges and opportunities.* Computers & Security 104, 102221. | Survey of deep-learning insider-threat detectors | 11 datasets reviewed; most synthetic (CERT dominant) | (survey) | Notes the lack of real data and the reliance on synthetic CERT logs; surveyed methods are mostly scored with AUC / accuracy over the whole operating curve. |
| 3 | Li, D., Yang, L., Zhang, H., Wang, X., Ma, L., & Xiao, J. (2021). *Image-based Insider Threat Detection via Geometric Transformation.* arXiv:2108.10567. | Audit logs turned into images; self-supervised geometric-transformation classifier | CERT | Instance- and user-level **AUROC** (+4% / +2% over autoencoder) | Reports AUROC only - says nothing about how many insiders an analyst would catch at a fixed daily budget; no per-alert explanation. |
| 4 | Tian, T., Zhang, C., Jiang, B., Feng, H., & Lu, Z. (2025). *Insider threat detection for specific threat scenarios.* Cybersecurity 8. doi:10.1186/s42400-024-00321-w | Daily behaviour sequences, one-hot encoding, multi-head attention; per-scenario models (privilege abuse, identity theft, data leakage) | CERT | Accuracy (+2-5% per scenario)† | Supervised and scenario-specific (needs labelled attacks); accuracy is uninformative at a ~0.25% base rate; on-premise logs, not cloud control-plane events. |
| 5 | Kantchelian, A., Neo, C., Stevens, R., Kim, H., Fu, Z., et al. (2024). *Facade: High-Precision Insider Threat Detection Using Deep Contextual Anomaly Detection.* arXiv:2412.06700. | Self-supervised contrastive model of each event in the context of the user's role and the resource | Google-internal document, SQL and RPC access logs (not public) | False-positive rate (< 0.01%; 0.0003% for single rogue accesses) | Shows that *context relative to the user* is what makes precision workable - but data and system are proprietary, the evaluation is not reproducible, and there is no analyst-facing explanation study. |
| 6 | Haunschild, D., Patel, D. P., & Gill, S. S. (2026). *AI-Driven DevSecOps for Anomaly Detection of Credential Abuse and Privilege Escalation in Cloud Environment.* Intelligent Systems Reference Library, Springer. doi:10.1007/978-3-032-21753-0_2 | Isolation Forest (lightweight, unsupervised) inside a DevSecOps monitoring pipeline | AWS CloudTrail logs† | F1 (≈ 0.96, ≈ 40% relative over prior work)† | Closest cloud-audit work: uses the same baseline we compare against (Isolation Forest on CloudTrail), but reports F1 at one threshold rather than detection at a fixed analyst budget, with no explanation of alerts. |
| 7 | Zou, X., Jiang, X., Huang, R., et al. (2025). *Towards Generalizable Context-aware Anomaly Detection: A Large-scale Benchmark in Cloud Environments.* arXiv:2508.01844. | LLM agent with symbolic verification over cloud metrics and logs (CloudAnoAgent) + benchmark CloudAnoBench | CloudAnoBench: 28 anomalous + 16 deceptive-normal scenarios, 1,252 labelled cases, ~200k entries; provider not specified | Detection and scenario-identification accuracy† | Operational anomalies (faults) as much as misuse; per-case classification, not a ranked daily queue; LLM cost per event. Useful as evidence that "deceptive normal" behaviour is the hard part. |
| 8 | Bates, S., Candès, E., Lei, L., Romano, Y., & Sesia, M. (2023). *Testing for outliers with conformal p-values.* Annals of Statistics 51(1), 149-178. | Split-conformal p-values for outlier detection; FDR control across many test points | Statistical method (simulations, benchmark data) | Validity / power / FDR | The statistical basis of our C2 calibration step. Its guarantees assume exchangeable calibration data; it does not address per-entity baselines, drifting behaviour or a fixed daily alert budget. |
| 9 | AlAhmadi, B. A., Axon, L., & Martinovic, I. (2022). *99% False Positives: A Qualitative Study of SOC Analysts' Perspectives on Security Alarms.* USENIX Security 2022, 2783-2800. | Survey (n = 20) and interviews (n = 21) of SOC practitioners | Real SOC practice | Qualitative findings | Establishes the operating constraint we model: alarms must be **R**eliable, **E**xplainable, **A**nalytical, **C**ontextual and **T**ransferable, and most "false positives" are benign-but-true triggers. Proposes no detector and no budget-level evaluation. |
| 10 | Arp, D., Quiring, E., Pendlebury, F., Warnecke, A., Pierazzi, F., Wressnegger, C., Cavallaro, L., & Rieck, K. (2022). *Dos and Don'ts of Machine Learning in Computer Security.* USENIX Security 2022. | Systematic study of 10 pitfalls across 30 top-venue papers | Literature (30 papers) + case studies | Prevalence of pitfalls | Names the pitfalls our protocol is built to avoid: data snooping / temporal leakage, inappropriate performance measures and the base-rate fallacy. Gives no specific method for budget-level evaluation of insider detectors. |
| 11 | Nadeem, A., Vos, D., Cao, C., Pajola, L., Dieck, S., Baumgartner, R., & Verwer, S. (2023). *SoK: Explainable Machine Learning for Computer Security Applications.* IEEE EuroS&P 2023, 221-240. | Systematisation of XAI use in security | Literature | - | Finds that explanations are rarely tested with their users: **only 14% of studies run a user study**. This is the gap our triage study (O4) addresses. |
| 12 | Grzeczkowicz, R., Neal, C., Baghalizadeh-Moghadam, N., Boulahia Cuppens, N., & Cuppens, F. (2025). *Classifying Insider Threat Scenarios Through Explainable Artificial Intelligence.* CRiSIS 2024, LNCS, 157-172. doi:10.1007/978-3-031-89350-6_10 | SHAP values of an anomaly detector used to classify the threat scenario after detection† | CERT† | Scenario-classification performance† | Uses explanations to label scenarios automatically - not to help a human decide whether to escalate; no human evaluation; no fixed-budget detection results. |
| 13 | Faqihi, R., Nanda, P., Mohanty, M., Alqahtani, S., & Alrashed, B. (2026). *Towards trustworthy cybersecurity: Reclassifying insider threat detection using SHAP.* Future Generation Computer Systems. doi:10.1016/j.future.2026.108543 | Exact Shapley values + domain-knowledge mapping to re-classify detector outputs† | CMU CERT (316,250 instances)† | Accuracy, false-positive reduction† | SHAP used to correct the classifier, with "analyst oversight" claimed but not measured; accuracy-style metrics, not alerts per day. |
| 14 | Ndichu, S., Ban, T., Ozawa, S., Takahashi, T., & Inoue, D. (2026). *PACT: Reducing Alert Fatigue in Low-Prevalence SOC Streams with Triggered Active Learning.* arXiv:2605.22324 (ACSAC 2026). | Frozen XGBoost screener + drift trigger + active-learning queries to analysts | AIT-ADS alert dataset, BOTSv1 | False-positive burden reduction (43% / 21%), analyst queries, positive-window recall | Works downstream of a detector on IDS alerts, not on raw cloud audit logs; supervised (needs analyst labels); reports that minimising false positives costs recall - the trade-off our budget curves make explicit. |

*Verified via:* 1 Crossref [10.1109/tnsm.2021.3071928](https://doi.org/10.1109/tnsm.2021.3071928) ·
2 ACM DL [10.1016/j.cose.2021.102221](https://doi.org/10.1016/j.cose.2021.102221) ·
3 [arXiv:2108.10567](https://arxiv.org/abs/2108.10567) ·
4 Crossref [10.1186/s42400-024-00321-w](https://doi.org/10.1186/s42400-024-00321-w) ·
5 [arXiv:2412.06700](https://arxiv.org/abs/2412.06700) ·
6 Crossref [10.1007/978-3-032-21753-0_2](https://doi.org/10.1007/978-3-032-21753-0_2) ·
7 [arXiv:2508.01844](https://arxiv.org/abs/2508.01844) ·
8 Project Euclid [10.1214/22-AOS2244](https://doi.org/10.1214/22-AOS2244) ·
9 [DBLP](https://dblp.org/rec/conf/uss/AlAhmadiAM22.html), [USENIX PDF](https://www.usenix.org/system/files/sec22-alahmadi.pdf) ·
10 [USENIX PDF](https://www.usenix.org/system/files/sec22summer_arp.pdf), [arXiv:2010.09470](https://arxiv.org/abs/2010.09470) ·
11 IEEE [10.1109/EuroSP57164.2023.00022](https://doi.org/10.1109/EuroSP57164.2023.00022) ·
12 Crossref [10.1007/978-3-031-89350-6_10](https://doi.org/10.1007/978-3-031-89350-6_10) ·
13 Crossref [10.1016/j.future.2026.108543](https://doi.org/10.1016/j.future.2026.108543) ·
14 [arXiv:2605.22324](https://arxiv.org/abs/2605.22324)

## Gap analysis

1. **Evaluation at the analyst's operating point.** Most detectors are scored with AUC, F1 or
   accuracy over the whole curve or at one threshold [3, 4, 6, 13]. Arp et al. [10] list
   inappropriate performance measures and the base-rate fallacy among the most common pitfalls in
   security ML. The closest prior work, Le & Zincir-Heywood [1], already evaluates against an
   *investigation budget*, expressed as a share of all sessions over the whole period. We evaluate
   at a **fixed number of alerts per day** (10 / 50 / 100), which is how a SOC queue actually works,
   and we report detection rate, precision against its oracle ceiling, and time to detection.
   **We do not claim to be the first budget-aware evaluation.**
2. **Per-identity context, with reproducibility.** Facade [5] shows at Google scale that judging an
   event against the user's own context is what makes precision workable, but its data are private.
   Isolation Forest on CloudTrail [6] is used without per-identity normalisation. We combine
   per-principal robust baselines with pooled conformal calibration [8] and release the whole
   pipeline and synthetic testbed.
3. **Explanations tested with people.** Analysts ask for explainable, contextual alarms [9], yet
   only 14% of security XAI studies test explanations with users [11]. SHAP-based insider-threat
   work uses explanations to re-classify or label alerts automatically [12, 13]. We generate a
   per-alert explanation naming the deviating behaviour and **measure, in a pre-registered crossover
   study, whether reviewers can triage from the explanation alone** (O4).
4. **Cloud control-plane logs.** Insider-threat research relies mostly on synthetic, on-premise CERT
   logs [2]; cloud work [6, 7] targets operational anomalies or reports point metrics. Our features
   come from cloud audit-log fields (identity, resource, time) and are computed strictly causally.

## Search protocol (for the methods section)
Sources: Crossref, DBLP, arXiv, publisher pages, USENIX open-access proceedings. Queries combined
*insider threat*, *CERT*, *CloudTrail / cloud audit log*, *alert fatigue / SOC*, *investigation
budget*, *conformal p-values*, *explainable / SHAP*, limited to 2021-2026. Inclusion: peer-reviewed
or arXiv paper whose existence and bibliographic data could be confirmed in an index. Exclusion:
anything that could not be verified (including three entries of the earlier table), and papers that
are not about detection or triage (e.g. a questionnaire-based maturity study, arXiv:2510.19883).
