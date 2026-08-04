# ASIP

Social intelligence platform for monitoring public social media activity, detecting coordinated behaviour, and preserving forensic-grade evidence.

## Status

Early development — a walking skeleton. One vertical slice runs end to end:
schedule → fetch → evidence bundle → extract → store → detect → finding →
console → STIX export. Every stage is deliberately minimal except evidence,
which is built fully.

## Running it

Needs Docker, Python 3.12 and GNU Make.

```bash
docker compose up -d postgres minio          # backing services
make install                                 # creates .venv, installs the package

make migrate ASIP_DB_URL=postgresql://asip:asip_dev_only@127.0.0.1:5432/asip
make seed-dev                                # registers the local canary source
make run                                     # serves on 127.0.0.1:8000
```

Then open **<http://127.0.0.1:8000>** and press **Run pipeline**.

The first run fetches the canary page this application serves to itself, seals
it into a WARC evidence bundle, timestamps it against FreeTSA, extracts six
synthetic items, fires one deliberately naive detection rule, and exports the
result as STIX 2.1 — with each stage reporting what it did.

| Where | What |
|---|---|
| <http://127.0.0.1:8000> | Analyst console — eleven screens |
| <http://127.0.0.1:8000/api/docs> | OpenAPI browser for the JSON API |
| <http://127.0.0.1:8000/canary/> | The canary source, as the fetcher sees it |

Keyboard: `g` then a screen number, `j`/`k` to move, `r` to run the pipeline.

The scheduler honours the source's interval, so a second run within 60 seconds
correctly reports `schedule: idle` rather than collecting again.

### Running the fetch zone isolated

By default fetching happens in the API process. That satisfies the credential
boundary — the fetcher is constructed with no database access — but not the
process and network boundary. To run it the way the architecture intends:

```bash
docker compose up -d fetcher                 # separate container, `fetch` network
export ASIP_FETCH_QUEUE_URL=redis://127.0.0.1:6379/0
make seed-dev                                # canary URL as the *fetcher* resolves it
make run
```

The fetch zone now has no route to PostgreSQL, holds no database credential,
and refuses to start if it finds one. System Health reports which arrangement
is in force and whether any worker is alive — a queue with no workers is
reported as a failure, not as an idle pipeline.

You can check the isolation yourself:

```bash
docker compose exec fetcher python -c   "import socket; socket.create_connection(('postgres', 5432), 5)"
# socket.gaierror — the name does not even resolve on that network
```

### Verifying a bundle without this software

Evidence is meant to outlive the tool that produced it. Every bundle is a WARC
carrying its own manifest, hash-chain entry and RFC 3161 token:

```bash
python tools/verify_asip_bundle.py bundle.warc.gz --tsa-cert config/tsa/freetsa-cacert.pem
```

That script imports nothing from ASIP and uses only the standard library.

### Quality gates

```bash
make check                                   # lint, types, layer contracts, tests
make test-isolation  ASIP_TEST_DB_URL=...    # cross-tenant reads, against real RLS
make evidence-roundtrip ASIP_TEST_DB_URL=... ASIP_TEST_S3_URL=http://127.0.0.1:9000
```

## What it does

Answers one question, with evidence: **is this activity organic or coordinated?**

- Captures monitored sources as verifiable evidence bundles — hashed, chained, independently timestamped, stored as WARC
- Preserves content after deletion
- Detects coordination through behavioural signals only, never through opinion or stance
- Requires human review for every finding
- Exports to STIX 2.1

## What it does not do

- Produce verdicts about named individuals
- Infer intent, funding, or sincerity
- Allow content or stance to influence authenticity scoring
- Issue any verdict without human review

These are architectural constraints, not settings.

## Stack

Python 3.12 · FastAPI · PostgreSQL + pgvector · Temporal · Playwright · WARC · React

## License

TBD
