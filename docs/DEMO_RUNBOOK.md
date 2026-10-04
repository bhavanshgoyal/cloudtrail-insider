# Live demo runbook (Review 3: "system runs during the review, not a recorded video")

Total time on stage: about 6 minutes. Rehearse it twice.

## Before the review (the day before)
```powershell
cd "D:\Cloude project\cloudtrail-insider"
pip install -e ".[dev]"
python -m pytest -q                 # all tests green
python run_pipeline.py              # ~40 s: produces results/ for the dashboard
python scripts/live_demo.py --scenario S1 --seed 4242   # check it runs
```
Optional testbed proof (Review 1 evidence):
```powershell
docker compose up -d
docker ps
python scripts/capture_evidence.py
```

## On stage
| Step | Command | What to say |
|---|---|---|
| 1 | `python -m pytest -q` | "Every metric is checked against hand-computed answers, and there is a test that fails if any feature looks at the future." |
| 2 | `python scripts/live_demo.py --scenario S1 --pause 2` | "This company did not exist a second ago: a random seed, 300 identities, 100 days. We plant one attack type and train only on the past, with no labels." |
| 3 | (output section 4) | "This is the analyst's queue for one day: 10 alerts. Each one says *what* deviated, compared with *this identity's own* normal behaviour." |
| 4 | (output section 5) | "Over the whole watch window: how many insiders each detector catches at 10 alerts a day, and its precision against the best possible precision." |
| 5 | `python scripts/live_demo.py --scenario S5 --no-reveal` | "Low-and-slow attack. Without the answers: which alert would you escalate?" (audience participation) |
| 6 | `streamlit run src/cti/demo/app.py` | Pick a day, switch detector, compare queues; open the Campaign tab for the 5-seed results with confidence intervals. |

## If something goes wrong
- *"No planted attack fell inside the watch window"*: rerun, or pass a fixed `--seed` that you
  checked beforehand.
- The dashboard says "No results yet": run `python run_pipeline.py` first.
- No internet is needed; everything runs locally.

## What not to claim on stage
- The data is synthetic. Say so first, not when asked.
- One live run is an illustration. The statistics are the campaign's 4 workloads x 5 seeds x 3
  origins.
