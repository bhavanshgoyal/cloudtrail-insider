# cloudtrail-insider Makefile
# One-command reproduction: `make all`

.PHONY: setup testbed evidence pipeline figures test all clean demo dashboard campaign ablation sweep tune

PYTHON  = python
PYTEST  = pytest

# ── Setup ────────────────────────────────────────────────────────────────
setup:
	pip install -e ".[dev]"

# ── Testbed (LocalStack via Docker) ──────────────────────────────────────
testbed:
	docker compose up -d
	@echo "Waiting for LocalStack to be healthy..."
	@$(PYTHON) -c "import time, urllib.request; [time.sleep(2) for _ in range(15) if not (lambda: (urllib.request.urlopen('http://localhost:4566/_localstack/health', timeout=3), True)[-1])()]" 2>/dev/null || true
	@echo "LocalStack is ready."

# ── Evidence capture ────────────────────────────────────────────────────
evidence: testbed
	$(PYTHON) scripts/capture_evidence.py

# ── Full pipeline (data → features → train → evaluate → explain) ────────
pipeline: setup
	$(PYTHON) run_pipeline.py

# ── Figures only (requires pipeline to have run) ────────────────────────
figures:
	$(PYTHON) -m cti.eval.figures

# ── Tests ────────────────────────────────────────────────────────────────
test:
	$(PYTEST) tests/ -v --tb=short

# ── Full run: testbed + evidence + pipeline ──────────────────────────────
all: setup testbed evidence pipeline test
	@echo "=== Full pipeline complete ==="

# ── Clean ────────────────────────────────────────────────────────────────
clean:
	rm -rf results/* figures/* models/* data/processed/* data/features/*

# ── Shut down testbed ────────────────────────────────────────────────────
down:
	docker compose down -v

# ── Experiments (Phases 5-7) ─────────────────────────────────────────────
tune:
	$(PYTHON) scripts/tune_proposed.py

campaign:
	$(PYTHON) scripts/run_campaign.py
	$(PYTHON) -m cti.eval.figures

ablation:
	$(PYTHON) scripts/run_ablation.py

sweep:
	$(PYTHON) scripts/run_sweep.py

# ── Live demo (Review 3) ─────────────────────────────────────────────────
demo:
	$(PYTHON) scripts/live_demo.py --scenario S2

dashboard:
	streamlit run src/cti/demo/app.py
