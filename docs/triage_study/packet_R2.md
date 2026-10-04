# Triage study - packet for reviewer R2

## Instructions

You are a SOC analyst. Each alert below was raised by an anomaly detector watching AWS CloudTrail
logs. For each alert decide:

* **TP** - this looks like genuine misuse of the identity (insider / stolen credentials) and you would
  escalate it, or
* **FP** - this looks like unusual but benign activity and you would close it.

Rules:
1. Use **only** what is shown for each alert. Do not look at code, data, results, other packets or
   the facilitator folder, and do not discuss alerts with other reviewers until everyone is done.
2. Work through the sections in the order given. Do not go back to change earlier answers.
3. For every alert fill in your verdict (`TP` or `FP`), your confidence (1 = guess ... 5 = certain)
   and roughly how many seconds you spent, in your response sheet
   `responses_<you>.csv` (one row per alert, already listed).
4. The proportion of TP and FP alerts is not disclosed - judge each alert on its own.

Glossary (arm B): *p* is how unusual the deviation is compared with this identity's own history
(smaller = more unusual). "usually" is this identity's typical value on a normal day.


## Section 1 of 2 - arm B: EXPLANATION ONLY - you see the generated explanation of what deviated; no score.

### Alert TM870

- Identity: `identity-39` (role: developer)
- Date: 2023-06-28

```
Resource access deviation (p = 3.2e-05)
  - writes to an external bucket: 1 (usually 0)
  - share of calls on sensitive buckets: 48% (usually 15%)
  - calls on sensitive buckets (finance / hr / pii / security): 20 (usually 4)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert SM373

- Identity: `identity-34` (role: ci-runner)
- Date: 2023-06-03

```
Timing deviation (p = 0.0023)
  - API calls at the weekend: 193 (usually 0)
  - hours away from this identity's usual working time: 5.5 h (usually 5.0 h)
  - share of activity outside 08:00-18:00 UTC: 51% (usually 49%)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert TZ593

- Identity: `identity-31` (role: analyst)
- Date: 2023-05-29

```
Resource access deviation (p = 0.0024)
  - resources this identity never accessed before: 4 (usually 0)
  - distinct resources touched: 16 (usually 11)
  - privilege-sensitive actions (CreateAccessKey, AssumeRole, PutBucketPolicy, ...): 4 (usually 2)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert JQ419

- Identity: `identity-23` (role: analyst)
- Date: 2023-05-31

```
Identity / access-origin deviation (p = 6.5e-05)
  - client user agents never seen for this identity: 1 (usually 0)
  - console logins without MFA: 16 (usually 0)
  - console logins from a never-seen IP: 16 (usually 0)
Also unusual: resource access
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert WQ188

- Identity: `identity-22` (role: analyst)
- Date: 2023-06-06

```
Resource access deviation (p = 0.00077)
  - calls on sensitive buckets (finance / hr / pii / security): 9 (usually 0)
  - share of calls on sensitive buckets: 28% (usually 0%)
  - distinct resources touched: 11 (usually 11)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert YU575

- Identity: `identity-11` (role: developer)
- Date: 2023-06-23

```
Activity volume deviation (p = 0.0014)
  - API calls: 182 (usually 34)
  - S3 object reads (GetObject): 54 (usually 9)
  - data transferred: 863 KB (usually 177 KB)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert LZ428

- Identity: `identity-02` (role: analyst)
- Date: 2023-06-24

```
Identity / access-origin deviation (p = 3.2e-05)
  - client user agents never seen for this identity: 1 (usually 0)
  - console logins without MFA: 16 (usually 1)
  - console logins from a never-seen IP: 16 (usually 0)
Also unusual: resource access
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert VA519

- Identity: `identity-19` (role: developer)
- Date: 2023-06-06

```
Identity / access-origin deviation (p = 0.00081)
  - console logins without MFA: 2 (usually 1)
  - failed console logins: 1 (usually 0)
  - share of calls that failed: 9% (usually 5%)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert OP489

- Identity: `identity-20` (role: ci-runner)
- Date: 2023-06-04

```
Timing deviation (p = 0.00039)
  - API calls at the weekend: 245 (usually 0)
  - hours away from this identity's usual working time: 5.2 h (usually 5.0 h)
  - distinct hours with activity: 24 (usually 23)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert PF410

- Identity: `identity-18` (role: developer)
- Date: 2023-06-10

```
Resource access deviation (p = 3.2e-05)
  - share of calls using rarely-seen API actions: 10% (usually 0%)
  - calls on sensitive buckets this identity never accessed before: 5 (usually 0)
  - IAM write actions: 2 (usually 0)
Also unusual: activity volume
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert BU886

- Identity: `identity-12` (role: ci-runner)
- Date: 2023-05-20

```
Timing deviation (p = 0.0009)
  - API calls at the weekend: 217 (usually 0)
  - share of activity outside 08:00-18:00 UTC: 59% (usually 48%)
  - hours away from this identity's usual working time: 5.9 h (usually 5.1 h)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert UP943

- Identity: `identity-24` (role: analyst)
- Date: 2023-06-01

```
Activity volume deviation (p = 0.0011)
  - API calls: 110 (usually 23)
  - S3 object reads (GetObject): 57 (usually 11)
  - data transferred: 604 KB (usually 158 KB)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert DN680

- Identity: `identity-14` (role: developer)
- Date: 2023-06-21

```
Resource access deviation (p = 0.00016)
  - resources made public: 1 (usually 0)
  - calls on sensitive buckets this identity never accessed before: 50 (usually 0)
  - calls on sensitive buckets (finance / hr / pii / security): 50 (usually 0)
Also unusual: activity volume, identity / access-origin
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert LH696

- Identity: `identity-13` (role: developer)
- Date: 2023-06-19

```
Resource access deviation (p = 0.001)
  - calls on sensitive buckets (finance / hr / pii / security): 4 (usually 0)
  - share of calls on sensitive buckets: 11% (usually 0%)
  - resources this identity never accessed before: 1 (usually 0)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert GC730

- Identity: `identity-27` (role: analyst)
- Date: 2023-05-30

```
Identity / access-origin deviation (p = 0.0022)
  - calls from source IPs never seen for this identity: 37 (usually 0)
  - source IPs never seen for this identity: 1 (usually 0)
  - console logins from a never-seen IP: 1 (usually 0)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert LI241

- Identity: `identity-07` (role: admin)
- Date: 2023-05-22

```
Activity volume deviation (p = 0.0013)
  - API calls: 148 (usually 14)
  - distinct API actions: 15 (usually 8)
  - S3 object reads (GetObject): 22 (usually 2)
Also unusual: resource access
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert JJ478

- Identity: `identity-30` (role: developer)
- Date: 2023-06-01

```
Resource access deviation (p = 0.00094)
  - calls on sensitive buckets (finance / hr / pii / security): 4 (usually 0)
  - share of calls on sensitive buckets: 19% (usually 0%)
  - resources this identity never accessed before: 1 (usually 0)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert QP777

- Identity: `identity-05` (role: analyst)
- Date: 2023-06-29

```
Identity / access-origin deviation (p = 0.0011)
  - console logins without MFA: 2 (usually 1)
  - failed console logins: 1 (usually 0)
  - share of calls that failed: 7% (usually 0%)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert KI170

- Identity: `identity-32` (role: developer)
- Date: 2023-06-12

```
Resource access deviation (p = 0.0012)
  - calls on sensitive buckets (finance / hr / pii / security): 3 (usually 0)
  - share of calls on sensitive buckets: 16% (usually 0%)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert VU733

- Identity: `identity-37` (role: developer)
- Date: 2023-06-27

```
Resource access deviation (p = 0.00077)
  - share of calls on sensitive buckets: 36% (usually 0%)
  - calls on sensitive buckets (finance / hr / pii / security): 5 (usually 0)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---

## Section 2 of 2 - arm A: SCORE ONLY - you see the detector's anomaly score and the alert's rank in that day's queue.

### Alert MM622

- Identity: `identity-20` (role: ci-runner)
- Date: 2023-06-10
- Anomaly score: **2.28** (higher = more anomalous)
- Position in that day's queue: 8 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert VR503

- Identity: `identity-35` (role: developer)
- Date: 2023-06-19
- Anomaly score: **2.74** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert QE239

- Identity: `identity-28` (role: developer)
- Date: 2023-06-08
- Anomaly score: **3.89** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert NT393

- Identity: `identity-38` (role: ci-runner)
- Date: 2023-06-04
- Anomaly score: **2.48** (higher = more anomalous)
- Position in that day's queue: 4 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert LF586

- Identity: `identity-25` (role: admin)
- Date: 2023-05-31
- Anomaly score: **2.33** (higher = more anomalous)
- Position in that day's queue: 6 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert RH968

- Identity: `identity-09` (role: developer)
- Date: 2023-05-31
- Anomaly score: **2.28** (higher = more anomalous)
- Position in that day's queue: 8 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert HE970

- Identity: `identity-04` (role: analyst)
- Date: 2023-06-09
- Anomaly score: **3.89** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert MY815

- Identity: `identity-17` (role: ci-runner)
- Date: 2023-05-28
- Anomaly score: **3.04** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert HD303

- Identity: `identity-33` (role: ci-runner)
- Date: 2023-06-11
- Anomaly score: **3.11** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert KX103

- Identity: `identity-01` (role: developer)
- Date: 2023-06-09
- Anomaly score: **2.30** (higher = more anomalous)
- Position in that day's queue: 8 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert FY887

- Identity: `identity-36` (role: developer)
- Date: 2023-06-12
- Anomaly score: **2.61** (higher = more anomalous)
- Position in that day's queue: 3 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert XS259

- Identity: `identity-21` (role: developer)
- Date: 2023-06-08
- Anomaly score: **2.15** (higher = more anomalous)
- Position in that day's queue: 10 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert LQ131

- Identity: `identity-26` (role: ci-runner)
- Date: 2023-05-28
- Anomaly score: **2.12** (higher = more anomalous)
- Position in that day's queue: 8 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert EF529

- Identity: `identity-03` (role: developer)
- Date: 2023-06-02
- Anomaly score: **2.59** (higher = more anomalous)
- Position in that day's queue: 2 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert KU101

- Identity: `identity-08` (role: developer)
- Date: 2023-06-15
- Anomaly score: **3.89** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert MA708

- Identity: `identity-29` (role: analyst)
- Date: 2023-05-27
- Anomaly score: **3.89** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert IK726

- Identity: `identity-06` (role: analyst)
- Date: 2023-06-07
- Anomaly score: **3.89** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert PI491

- Identity: `identity-15` (role: ci-runner)
- Date: 2023-06-17
- Anomaly score: **1.92** (higher = more anomalous)
- Position in that day's queue: 6 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert WN182

- Identity: `identity-10` (role: analyst)
- Date: 2023-06-12
- Anomaly score: **2.43** (higher = more anomalous)
- Position in that day's queue: 4 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert SX354

- Identity: `identity-16` (role: analyst)
- Date: 2023-06-02
- Anomaly score: **2.28** (higher = more anomalous)
- Position in that day's queue: 8 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
