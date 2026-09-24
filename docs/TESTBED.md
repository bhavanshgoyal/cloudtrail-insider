# CloudSim Testbed — LocalStack on Docker

This document describes the cloud simulation (CloudSim) testbed for the Insider-Threat Detection project. The testbed uses **LocalStack**, a fully functional cloud service emulator that runs AWS services (CloudTrail, S3, IAM, STS) locally via Docker.

## What is LocalStack?

LocalStack is a cloud simulation environment that emulates core AWS services on your local machine. It provides:

- **CloudTrail** — audit log service that records API calls
- **S3** — object storage for log data
- **IAM** — identity and access management
- **STS** — security token service for credential verification
- **EC2, SES, CloudWatch Logs** — additional services

This gives us a **fully controllable cloud testbed** where we can generate, replay, and detect insider threats without needing a live AWS/Azure account.

## Prerequisites

- **Docker Desktop** installed and running on Windows
- **Python 3.11+** with project dependencies installed (`pip install -e ".[dev]"`)

## Bring-Up Instructions

### Step 1: Start LocalStack

```powershell
docker compose up -d
```

**Expected output**: Docker pulls the `localstack/localstack` image and starts the container. Wait ~30 seconds for services to initialise.

### Step 2: Verify the testbed is running

```powershell
python scripts/capture_evidence.py
```

**Expected output**: A summary table showing PASS for:
- Docker container running
- LocalStack health check
- STS get-caller-identity
- CloudTrail events
- S3 service

### Step 3: Capture evidence for submission

The `capture_evidence.py` script automatically saves all proof to `docs/evidence/`:

- `testbed_evidence.txt` — human-readable evidence log
- `testbed_evidence.json` — machine-readable evidence

**📸 Take a screenshot of the terminal output showing the PASS/FAIL summary table.** This screenshot is your testbed evidence for the course submission (3 marks).

### Step 4: (Optional) Bootstrap cloud resources

```powershell
# On Windows PowerShell:
.\scripts\bootstrap_env.ps1

# Or on WSL/Linux:
./scripts/bootstrap_env.sh
```

This creates S3 buckets, a CloudTrail trail, and IAM roles on LocalStack.

### Step 5: (Optional) Replay synthetic events

```powershell
python -m cti.demo.replay --limit 100
```

This issues real boto3 API calls against LocalStack, simulating CloudTrail event generation.

### Step 6: Shut down (when finished)

```powershell
docker compose down -v
```

## Evidence Artifacts

After running `capture_evidence.py`, the following files are saved:

| File | Content |
|------|---------|
| `docs/evidence/testbed_evidence.txt` | Full evidence log with timestamps |
| `docs/evidence/testbed_evidence.json` | Machine-readable evidence data |

## Architecture

```
┌─────────────────────────────────────────────┐
│  Your Windows Machine (Docker Desktop)      │
│                                             │
│  ┌─────────────────────────────────────┐    │
│  │  LocalStack Container               │    │
│  │  ┌──────┐ ┌───┐ ┌─────┐ ┌───────┐  │    │
│  │  │Cloud │ │S3 │ │ IAM │ │  STS  │  │    │
│  │  │Trail │ │   │ │     │ │       │  │    │
│  │  └──────┘ └───┘ └─────┘ └───────┘  │    │
│  │        localhost:4566               │    │
│  └─────────────────────────────────────┘    │
│                    ▲                        │
│                    │ boto3 / AWS CLI         │
│  ┌─────────────────┴───────────────────┐    │
│  │  CTI Pipeline (Python)              │    │
│  │  - Synthetic data generator         │    │
│  │  - Feature engineering              │    │
│  │  - Anomaly detectors (IF, Proposed) │    │
│  │  - Budget-fixed evaluation          │    │
│  │  - SHAP explanations                │    │
│  └─────────────────────────────────────┘    │
└─────────────────────────────────────────────┘
```
