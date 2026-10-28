# Triage study - packet for reviewer R4

## Instructions

You are a SOC analyst. Each alert below was raised by an anomaly detector watching a company's
activity logs (logons, USB devices, files copied to removable media, email and web browsing).
For each alert decide:

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


## Section 1 of 2 - arm A: SCORE ONLY - you see the detector's anomaly score and the alert's rank in that day's queue.

### Alert KS470

- Identity: `identity-23` (role: ElectricalEngineer)
- Date: 2011-02-10
- Anomaly score: **2.09** (higher = more anomalous)
- Position in that day's queue: 4 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert MW522

- Identity: `identity-05` (role: ProductionLineWorker)
- Date: 2010-11-04
- Anomaly score: **2.46** (higher = more anomalous)
- Position in that day's queue: 3 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert IL696

- Identity: `identity-25` (role: ProductionLineWorker)
- Date: 2010-11-08
- Anomaly score: **3.06** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert DF868

- Identity: `identity-33` (role: Salesman)
- Date: 2010-11-25
- Anomaly score: **1.39** (higher = more anomalous)
- Position in that day's queue: 7 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert PT206

- Identity: `identity-25` (role: ProductionLineWorker)
- Date: 2010-11-01
- Anomaly score: **2.44** (higher = more anomalous)
- Position in that day's queue: 2 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert US914

- Identity: `identity-28` (role: SoftwareEngineer)
- Date: 2011-01-29
- Anomaly score: **3.59** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert UN646

- Identity: `identity-06` (role: Salesman)
- Date: 2010-12-11
- Anomaly score: **2.47** (higher = more anomalous)
- Position in that day's queue: 4 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert NQ843

- Identity: `identity-30` (role: SystemsEngineer)
- Date: 2010-11-25
- Anomaly score: **1.36** (higher = more anomalous)
- Position in that day's queue: 8 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert RL514

- Identity: `identity-08` (role: Technician)
- Date: 2010-12-03
- Anomaly score: **2.14** (higher = more anomalous)
- Position in that day's queue: 7 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert HZ288

- Identity: `identity-16` (role: AdministrativeAssistant)
- Date: 2010-11-29
- Anomaly score: **2.45** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert SE872

- Identity: `identity-31` (role: SecurityGuard)
- Date: 2011-01-16
- Anomaly score: **1.76** (higher = more anomalous)
- Position in that day's queue: 10 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert AM502

- Identity: `identity-32` (role: ProductionLineWorker)
- Date: 2011-03-25
- Anomaly score: **2.01** (higher = more anomalous)
- Position in that day's queue: 5 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert YW961

- Identity: `identity-11` (role: Director)
- Date: 2011-01-09
- Anomaly score: **3.01** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert HR847

- Identity: `identity-02` (role: ComputerProgrammer)
- Date: 2010-12-24
- Anomaly score: **1.66** (higher = more anomalous)
- Position in that day's queue: 2 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert TI754

- Identity: `identity-34` (role: Manager)
- Date: 2011-01-09
- Anomaly score: **1.84** (higher = more anomalous)
- Position in that day's queue: 8 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert QA434

- Identity: `identity-24` (role: MechanicalEngineer)
- Date: 2011-05-09
- Anomaly score: **2.14** (higher = more anomalous)
- Position in that day's queue: 4 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert XH672

- Identity: `identity-09` (role: Technician)
- Date: 2010-12-20
- Anomaly score: **2.18** (higher = more anomalous)
- Position in that day's queue: 4 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert QC368

- Identity: `identity-07` (role: ITAdmin)
- Date: 2011-04-28
- Anomaly score: **4.37** (higher = more anomalous)
- Position in that day's queue: 1 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert MC433

- Identity: `identity-27` (role: ProductionLineWorker)
- Date: 2010-11-09
- Anomaly score: **1.73** (higher = more anomalous)
- Position in that day's queue: 8 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert IE350

- Identity: `identity-12` (role: ITAdmin)
- Date: 2010-11-04
- Anomaly score: **2.93** (higher = more anomalous)
- Position in that day's queue: 2 of 10

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---

## Section 2 of 2 - arm B: EXPLANATION ONLY - you see the generated explanation of what deviated; no score.

### Alert YU607

- Identity: `identity-03` (role: Salesman)
- Date: 2010-12-19

```
Timing deviation (p = 0.0032)
  - activity at the weekend: 172 (usually 0)
  - hours away from this user's usual working time: 3.1 h (usually 2.7 h)
  - share of activity outside 08:00-18:00: 7% (usually 4%)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert EE758

- Identity: `identity-35` (role: ITAdmin)
- Date: 2010-12-09

```
Resource access deviation (p = 5.1e-05)
  - first USB device use ever by this user: 1 (usually 0)
  - visits to websites almost nobody in the company has visited: 2 (usually 0)
  - share of web visits to rarely-visited websites: 2% (usually 0%)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert PY474

- Identity: `identity-17` (role: Scientist)
- Date: 2011-01-03

```
Resource access deviation (p = 0.0031)
  - executable files copied to removable media: 1 (usually 0)
  - emails with attachments sent outside the company: 1 (usually 0)
  - USB device connections: 9 (usually 8.4)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert ZJ248

- Identity: `identity-10` (role: Scientist)
- Date: 2011-05-03

```
Activity volume deviation (p = 0.0039)
  - files copied to removable media: 25 (usually 0)
  - logged actions: 134 (usually 107)
  - email data sent: 307 KB (usually 287 KB)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert FM635

- Identity: `identity-04` (role: Technician)
- Date: 2011-03-03

```
Activity volume deviation (p = 0.0023)
  - web page visits: 39 (usually 29.8)
  - emails sent: 5 (usually 3.1)
  - logged actions: 56 (usually 40.9)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert MP663

- Identity: `identity-01` (role: Salesman)
- Date: 2011-03-06

```
Timing deviation (p = 0.0017)
  - activity at the weekend: 182 (usually 0)
  - logons outside 08:00-18:00: 1 (usually 1)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert JK769

- Identity: `identity-26` (role: Salesman)
- Date: 2011-03-05

```
Timing deviation (p = 0.0018)
  - activity at the weekend: 181 (usually 0)
  - hours away from this user's usual working time: 2.8 h (usually 2.3 h)
  - logons outside 08:00-18:00: 1 (usually 1)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert IC335

- Identity: `identity-29` (role: Salesman)
- Date: 2011-02-19

```
Timing deviation (p = 0.0024)
  - activity at the weekend: 179 (usually 0)
  - hours away from this user's usual working time: 3.0 h (usually 2.7 h)
  - logons outside 08:00-18:00: 1 (usually 1)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert FO543

- Identity: `identity-14` (role: SoftwareEngineer)
- Date: 2011-03-05

```
Timing deviation (p = 0.0052)
  - activity at the weekend: 151 (usually 0)
  - share of activity outside 08:00-18:00: 28% (usually 11%)
  - hours away from this user's usual working time: 3.3 h (usually 2.5 h)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert CS485

- Identity: `identity-22` (role: ProductionLineWorker)
- Date: 2011-02-11

```
Activity volume deviation (p = 0.006)
  - logged actions: 19 (usually 13.6)
  - web page visits: 12 (usually 10.5)
  - logons: 2 (usually 1)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert UW567

- Identity: `identity-04` (role: Technician)
- Date: 2011-03-02

```
Activity volume deviation (p = 0.0051)
  - web page visits: 37 (usually 29.7)
  - logged actions: 45 (usually 40.8)
  - email data sent: 110 KB (usually 88 KB)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert AR818

- Identity: `identity-13` (role: ComputerScientist)
- Date: 2011-02-21

```
Resource access deviation (p = 0.00093)
  - executable files copied to removable media: 1 (usually 0)
  - USB device connections outside 08:00-18:00: 1 (usually 0)
  - USB device connections: 6 (usually 1.9)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert UA135

- Identity: `identity-19` (role: ProductionLineWorker)
- Date: 2011-01-28

```
Identity / access-origin deviation (p = 0.0046)
  - distinct PCs used: 2 (usually 1)
Also unusual: activity volume
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert EZ755

- Identity: `identity-18` (role: ProductionLineWorker)
- Date: 2011-01-28

```
Activity volume deviation (p = 0.0018)
  - web page visits: 15 (usually 10.6)
  - logged actions: 26 (usually 19.8)
  - distinct websites visited: 11 (usually 9.3)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert ZO505

- Identity: `identity-21` (role: SecurityGuard)
- Date: 2011-01-20

```
Resource access deviation (p = 0.0012)
  - USB device connections outside 08:00-18:00: 7 (usually 0)
  - USB device connections: 7 (usually 0)
  - emails sent outside the company: 5 (usually 4)
Also unusual: activity volume
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert XA387

- Identity: `identity-18` (role: ProductionLineWorker)
- Date: 2011-02-08

```
Resource access deviation (p = 0.0043)
  - executable files copied to removable media: 1 (usually 0)
  - USB device connections: 6 (usually 1.9)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert PL477

- Identity: `identity-15` (role: PurchasingClerk)
- Date: 2011-03-04

```
Resource access deviation (p = 0.0022)
  - executable files copied to removable media: 1 (usually 0)
  - visits to job-search sites: 8 (usually 0)
  - emails sent outside the company: 8 (usually 4)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert NC487

- Identity: `identity-05` (role: ProductionLineWorker)
- Date: 2010-11-08

```
Activity volume deviation (p = 0.00032)
  - web page visits: 19 (usually 10.6)
  - logged actions: 35 (usually 20.9)
  - distinct websites visited: 13 (usually 8.3)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert QJ847

- Identity: `identity-26` (role: Salesman)
- Date: 2011-05-01

```
Timing deviation (p = 0.0011)
  - activity at the weekend: 191 (usually 0)
  - logons outside 08:00-18:00: 1 (usually 1)
  - hours away from this user's usual working time: 2.3 h (usually 2.3 h)
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
### Alert FI516

- Identity: `identity-20` (role: ProductionLineWorker)
- Date: 2011-02-04

```
Activity volume deviation (p = 0.0064)
  - logged actions: 19 (usually 13.7)
  - web page visits: 12 (usually 10.6)
  - logons: 2 (usually 1)
Also unusual: resource access
```

**Verdict (TP / FP):** ____  **Confidence (1-5):** ____

---
