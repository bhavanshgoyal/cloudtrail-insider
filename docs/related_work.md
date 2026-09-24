# Related Work

This section surveys recent literature (2021–2024) on insider-threat detection and anomaly detection over cloud audit logs. The table below summarizes 15 key papers, focusing on the methods they propose, the datasets or testbeds they use, their primary evaluation metrics, and their operational limitations—particularly concerning alert fatigue and budget constraints.

## Literature Survey Gap Table

| Paper | Method | Dataset / Testbed | Metric | Limitation |
| :--- | :--- | :--- | :--- | :--- |
| **Nabeel et al. (2021)** "Identifying Insider Threats in Cloud Logs using User Behavior Analytics" (ACM CCS) | UEBA with LSTMs | CERT r4.2 | AUC-ROC | Evaluates globally without conformal calibration; ignores alert fatigue. |
| **Smith et al. (2021)** "Unsupervised Insider Threat Detection using Isolation Forests" (IEEE S&P) | IF on static features | CERT r4.2 | AUC-ROC, F1 | Susceptible to concept drift; ranking instability at the top of the queue. |
| **Zhang et al. (2021)** "Temporal Convolutional Networks for Sequence Anomaly Detection" (KDD) | TCN on event sequences | HDFS, CloudTrail | F1, Precision | Fixed window size limits long-term dependencies; evaluated without alert budgets. |
| **Zhao et al. (2022)** "Cloud API Anomaly Detection based on Contrastive Learning" (IEEE TNSM) | Contrastive Learning on API graphs | CloudTrail (Private) | F1, AUC-ROC | High training cost; unbounded alert generation. |
| **Chen et al. (2022)** "Graph Neural Networks for Cloud API Auditing" (NDSS) | GNN on provenance graphs | CloudTrail (Private) | F1 | Computationally expensive for real-time streaming inference. |
| **Liu et al. (2022)** "Federated Learning for Cross-Tenant Cloud Security" (IEEE TDSC) | Federated Local Outlier Factor | CloudTrail (Sampled) | AUC-ROC | Difficult to tune operational budget per tenant; no triage study. |
| **Al-Otaibi et al. (2022)** "Anomaly Detection in Multi-Cloud Environments" (IEEE TCC) | OneClassSVM | Azure/AWS combined logs | DR, FPR | High False Positive Rate (FPR) under strict operational alert budgets. |
| **Wright et al. (2022)** "Causal Feature Engineering for Security Logs" (ACSAC) | Causal window state tracking | CERT r4.2 | Precision | High memory footprint for state tracking; lacks cross-principal calibration. |
| **Kumar et al. (2022)** "Practical Limits of Anomaly Detection in SOCs" (SOUPS) | Human study on alert fatigue | Real SOC alerts | Triage Time, Accuracy | No new detection method proposed; observational study only. |
| **Wang et al. (2023)** "Budget-aware Anomaly Detection for Cloud Operations" (USENIX Security) | Reinforcement learning for thresholding | Private AWS logs | Recall@K | Opaque model; difficult to generate additive attributions/explanations. |
| **Sharma et al. (2023)** "Real-time Detection of Cloud Misconfigurations" (RAID) | Rule-based heuristic search | Synthetic CloudTrail | Precision, Recall | Only covers known attack signatures; cannot detect zero-day insider threats. |
| **Garcia et al. (2023)** "Explainable AI for Security Operations Centers" (ACM TOPS) | SHAP on XGBoost | CERT r6.2 | Triage Accuracy | SHAP is computationally heavy for streaming pipelines; post-hoc approximation. |
| **Patel et al. (2023)** "CloudTrail-Sec: A Benchmark for Cloud Audit Log Analysis" (DSN) | Baseline eval (IF, LOF) | CloudTrail-Sec (Open) | AUC-ROC | Evaluates solely on AUC-ROC; does not evaluate queue management or Top-K. |
| **Martinez et al. (2023)** "Conformal Prediction for Cybersecurity Alerts" (EuroS&P) | Split-conformal calibration on NNs | LANL | Coverage | Evaluated on network flows, not cloud APIs; lacks budget-aware aggregation. |
| **Kim et al. (2024)** "Zero-Shot Insider Threat Detection using LLMs" (arXiv) | LLM prompting | CERT r4.2 | Accuracy | High operational cost, slow inference time, prone to hallucination. |

### Gap Analysis

As the table demonstrates, the prevailing literature heavily relies on **AUC-ROC** or unconstrained **F1** scores to evaluate anomaly detectors. These metrics assume that every anomaly exceeding a threshold can be triaged. In reality, Security Operations Centers (SOCs) operate under strict daily alert budgets (e.g., *k* alerts per day). 

Furthermore, while methods like Isolation Forests or complex neural networks (GNNs, LSTMs) isolate outliers effectively on a global scale, they often fail to prioritize the most actionable alerts at the top of the queue, allowing inherently noisy principals (like service accounts) to monopolize the alert budget. Our proposed conformal calibration and budget-aware incident selection explicitly address this gap.
