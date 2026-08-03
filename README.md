# ASIP

Social intelligence platform for monitoring public social media activity, detecting coordinated behaviour, and preserving forensic-grade evidence.

## Status

Early development. Not yet usable.

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
