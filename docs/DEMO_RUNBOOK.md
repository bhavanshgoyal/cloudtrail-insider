# Live demo runbook (Review 3: "system runs during the review, not a recorded video")

Total time on stage: about 7 minutes. Rehearse it twice. Everything runs locally, no internet.

## Before the review (the day before)
```powershell
cd "D:\Cloude project\cloudtrail-insider"
py -3.13 -m pytest -q                                   # all tests green
py -3.13 scripts/live_demo.py --scenario S1 --seed 4242 # check it runs (~15 s)
py -3.13 -m streamlit run src/cti/frontend/app.py       # opens http://localhost:8501
```
Needs (already built once): `data/cache/CERT_r4.2/` (features), `models/cert_model.pkl`
(`python scripts/train_final_model.py`) and `data/samples/cert_sample/`
(`python scripts/make_sample_upload.py`). Keep the sample folder open in Explorer for the upload.

## On stage
| Step | Command / action | What to say |
|---|---|---|
| 1 | `py -3.13 -m pytest -q` | "Every metric is checked against hand-computed answers, and a test fails if any feature looks at the future or if tuning ever touches a test day." |
| 2 | `py -3.13 scripts/live_demo.py --scenario S1 --seed 4242 --pause 2` | "CMU's CERT benchmark: 1,000 simulated employees, 17 months, 33 million log events. We train only on the past, with no labels, and watch the last four months. This storyline: an employee starts using USB after hours and uploads to a leak site." |
| 3 | (output section 3) | "This is the analyst's queue for one day: 10 alerts. Each says *what* deviated compared with *this person's own* normal. The demo also says how many of this storyline we caught, including the ones we missed." |
| 4 | (output section 4) | "Over the whole watch window at 10 alerts a day: insiders caught and precision, against the best precision possible." |
| 5 | `py -3.13 scripts/live_demo.py --scenario S2 --any-insider` | "Job-hunters are the hard case: a month of mostly normal days. Here is one we may miss." |
| 6 | Browser: **Upload & detect**, drop the 5 CSVs + `labels.csv` from `data/samples/cert_sample/`, click **Run detection** | "Logs from months the model never trained on. The console builds the same behaviour clues, scores every person-day and shows the queue. Note: this sample is insider-rich, so its precision is much higher than on a whole company." |
| 7 | Browser: **Benchmark results** tab | "The real numbers, with 95% intervals: precision roughly four times Isolation Forest's (supported); detection rate not significantly better (not supported). We report both." |

## If something goes wrong
- *"No matching insider is active in this watch window"*: use `--scenario S1` or `--origin 0`.
- The console says "No trained model found": run `py -3.13 scripts/train_final_model.py` (~2 min).
- The http.csv upload is large (~350 MB): give it ~30 s; or upload only logon, device, file, email.

## What not to claim on stage
- CERT r4.2 is a **simulated** benchmark (not real employees) and contains **no cloud logs**. Say so first.
- One demo run is an illustration; the statistics are the campaign (5 seeds x 3 origins, CIs over
  insiders and days).
- Do not show raw rows (URLs, email text) on slides: the data licence forbids redistribution.
