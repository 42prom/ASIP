# ASIP development commands. Canonical list: docs/COMMANDS.md.
#
# Targets that are not implemented yet fail loudly and name the phase that
# lands them. They do not print a reassuring message and exit 0 — a green
# gate that checks nothing is worse than a missing one (CLAUDE.md §6).

# One toolchain path for local runs and for CI. CI creates the same .venv a
# developer has, so "the gate passed on my machine" and "the gate passed in CI"
# mean the same thing.
VENV := .venv
ifeq ($(OS),Windows_NT)
  BIN := $(VENV)/Scripts
  EXE := .exe
else
  BIN := $(VENV)/bin
  EXE :=
endif

PY     := $(BIN)/python$(EXE)
PYTEST := $(PY) -m pytest

# import-linter is only reachable through its console script. `python -m
# importlinter.cli` exits 0 and prints nothing — a gate that always passes.
# Do not "simplify" this back into a -m invocation.
LINT_IMPORTS := $(BIN)/lint-imports$(EXE)

.PHONY: help install \
        lint layers test test-contracts test-independence test-isolation check \
        migrate migrate-status seed-dev run run-fetcher pipeline test-fixtures validate-stix \
        verify-chain check-schemas evidence-roundtrip chain-verify-full \
        test-integration \
        shadow-run measure-precision spike0-fetch spike0-report corpus eval

help:
	@echo "Implemented:  lint layers test test-contracts test-independence check"
	@echo "Stubs (exit 1 until their phase):  see docs/COMMANDS.md"

install:
	python -m venv $(VENV)
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

# ─── Quality gates — the five D-114 runs on every push ──────────────────────

lint:
	$(PY) -m ruff check src tests
	$(PY) -m ruff format --check src tests
	$(PY) -m mypy

layers:
	$(LINT_IMPORTS) --config .importlinter

test:
	$(PYTEST)

test-contracts:                 ## D-97 producer output vs every consumer fixture
	$(PYTEST) tests/contracts

test-independence:              ## D-99 remove each module in turn, assert others import
	$(PYTEST) tests/independence

# `check` is what you run before declaring done (CLAUDE.md §5). It grows as
# the stubs below are implemented; it deliberately does not invoke them now,
# because a target that always fails trains everyone to ignore the gate.
check: lint layers test
	@echo PASSED - lint, layers, test. test-contracts and test-independence run inside test.
	@echo NOT RUN HERE - test-isolation needs a database: make test-isolation ASIP_TEST_DB_URL=...
	@echo NOT YET WIRED - test-fixtures, validate-stix, verify-chain, check-schemas.
	@echo These are required by CLAUDE.md section 5 and land with the code they gate.

# ─── Environment — Phase 1 ──────────────────────────────────────────────────

migrate:
ifndef ASIP_DB_URL
	@echo NOT RUN: migrate needs ASIP_DB_URL. >&2
	@echo   Example: make migrate ASIP_DB_URL=postgresql://asip:...@127.0.0.1:5432/asip >&2
	@echo   Start the database first: docker compose up -d postgres >&2
	@exit 1
else
	$(PY) -m asip.entrypoints.migrate --dsn "$(ASIP_DB_URL)"
endif

migrate-status:
ifndef ASIP_DB_URL
	@echo NOT RUN: migrate-status needs ASIP_DB_URL. >&2
	@exit 1
else
	$(PY) -m asip.entrypoints.migrate --dsn "$(ASIP_DB_URL)" --status
endif

seed-dev:
	$(PY) -m asip.entrypoints.seed

# The whole point of this phase: open the application and watch it work.
#   docker compose up -d postgres minio
#   make migrate ASIP_DB_URL=...
#   make seed-dev
#   make run          then open http://127.0.0.1:8000 and press "Run pipeline"
run:
	$(PY) -m uvicorn asip.entrypoints.api:app --host 127.0.0.1 --port 8000 --reload

# The fetch zone, run locally. Useful for debugging the worker itself; it does
# NOT give you the isolation D-11 describes, because a local process shares the
# host's network and can reach postgres. `docker compose up -d fetcher` is the
# arrangement that actually enforces V-3.
run-fetcher:
	$(PY) -m asip.entrypoints.fetch_worker

# One pass of the pipeline from the command line, for when the console is not
# the point. Same code path the console's button calls.
pipeline:
	$(PY) -c "import urllib.request as u; print(u.urlopen(u.Request('http://127.0.0.1:8000/api/pipeline/run', method='POST')).read().decode())"

# ─── Test suites — land with the code they gate ─────────────────────────────

test-fixtures:
	@echo NOT IMPLEMENTED: test-fixtures — no extractors and no golden files. >&2
	@echo   Lands in Phase 1 (docs/WALKING_SKELETON.md): one extractor, one fixture. >&2
	@echo   D-88.1 — run the full set, never filtered. Fixtures are added, never deleted. >&2
	@exit 1

# D-88.4 / V-7. Requires a real database: RLS cannot be tested against a fake,
# because the claim is about what the database refuses, not what the
# application remembers to filter. Fails rather than skips when unconfigured —
# a security suite that silently passes is worse than no suite.
test-isolation:
ifndef ASIP_TEST_DB_URL
	@echo NOT RUN: test-isolation needs ASIP_TEST_DB_URL and a live database. >&2
	@echo   docker compose up -d postgres >&2
	@echo   make test-isolation ASIP_TEST_DB_URL=postgresql://asip:...@127.0.0.1:5432/asip >&2
	@echo   Skipping this suite silently would defeat its purpose (V-7). >&2
	@exit 1
else
	$(PYTEST) tests/isolation
endif

validate-stix:
	@echo NOT IMPLEMENTED: validate-stix — nothing is exported yet. >&2
	@echo   Lands in Phase 1 with the first grouping + sighting bundle (W-01). >&2
	@exit 1

check-schemas:
	@echo NOT IMPLEMENTED: check-schemas — no schemas exist. >&2
	@echo   Asserts no cross-schema writes and that cross-schema reads use v_* views >&2
	@echo   (D-92, D-93). The .claude/hooks/check_cross_schema.py hook covers edits >&2
	@echo   in the meantime; this is the CI-side equivalent. >&2
	@exit 1

# ─── Evidence — Phase 1, built fully rather than minimally (W-02) ───────────

verify-chain:
	@echo NOT IMPLEMENTED: verify-chain — no hash chain exists. >&2
	@echo   Lands in Phase 1. A broken chain is a P1 incident (D-90). >&2
	@exit 1

# D-88.2. Write a bundle, verify its manifest and chain, and read it back with
# an independent WARC reader — against real PostgreSQL and a real object store.
# The TSA leg runs offline: what is asserted is the unreachable-authority path
# (pending, never verified), which is the case that actually occurs. Verifying
# a live token is a separate, network-dependent check.
evidence-roundtrip:
ifndef ASIP_TEST_DB_URL
	@echo NOT RUN: evidence-roundtrip needs ASIP_TEST_DB_URL and ASIP_TEST_S3_URL. >&2
	@echo   docker compose up -d postgres minio >&2
	@echo   make evidence-roundtrip ASIP_TEST_DB_URL=postgresql://... ASIP_TEST_S3_URL=http://127.0.0.1:9000 >&2
	@exit 1
else
	$(PYTEST) tests/integration
endif

chain-verify-full:
	@echo NOT IMPLEMENTED: chain-verify-full — no chain history exists. >&2
	@echo   Nightly full-history verification (D-90). Lands in Phase 1. >&2
	@exit 1

# ─── Detection — Phase 3, and blocked on labels before then ─────────────────

shadow-run:
	@echo NOT IMPLEMENTED: shadow-run — no rules exist. >&2
	@echo   A rule enters shadow mode with at least 3 independent conditions, none >&2
	@echo   stance-based (V-2), and cannot be enabled while measured_precision >&2
	@echo   IS NULL (V-4). Lands in Phase 3. >&2
	@exit 1

measure-precision:
	@echo NOT IMPLEMENTED: measure-precision — no rules and no labelled sample. >&2
	@echo   Requires real analyst labels. Synthetic precision is a filter, never a >&2
	@echo   gate (D-109). Lands in Phase 3. >&2
	@exit 1

corpus:
	@echo NOT IMPLEMENTED: corpus — synthetic corpus generator not built. >&2
	@echo   docs/TEST_DATA.md. Unblocks rule development before real data exists >&2
	@echo   (D-106...D-109). >&2
	@exit 1

eval:
	@echo NOT IMPLEMENTED: eval — no rules and no corpus. >&2
	@echo   Precision/recall against synthetic ground truth. A filter, not a gate (D-109). >&2
	@exit 1

# ─── Spike 0 — throwaway by design (C-02) ───────────────────────────────────

spike0-fetch:
	@echo NOT IMPLEMENTED: spike0-fetch — measurement scripts not written. >&2
	@echo   phases/PHASE_0_SPIKE.md. Produces N1 page weight, N2 success rate, >&2
	@echo   N3 peak RSS, N4 cost per successful extraction. V-6 applies: reliability >&2
	@echo   work stops at retries, backoff and honest rate limiting. >&2
	@exit 1

spike0-report:
	@echo NOT IMPLEMENTED: spike0-report — no measurements to aggregate. >&2
	@echo   Writes spikes/0/RESULTS.md, which is T3 and never committed (R-02). >&2
	@exit 1
