"""L4 — drop every module schema and rebuild. Development only.

Exists because a half-migrated or half-tested database produces findings that
reference evidence which no longer exists, and hand-editing rows to fix that is
the habit this project should not build.

REFUSES TO RUN OUTSIDE A DEVELOPMENT PROFILE. This destroys evidence, which in
any other context is the one thing the system exists to prevent. The guard is
not politeness — a reset script that can be pointed at production by a mistyped
environment variable is a liability, and the confirmation is deliberately
awkward to type.
"""

from __future__ import annotations

import argparse
import os
import sys

import psycopg

#: Every schema this system owns, in an order that respects nothing — the
#: CASCADE handles dependencies, and listing them explicitly means a new module
#: is a visible omission rather than a silent survivor.
SCHEMAS = (
    "sch_collection",
    "sch_extraction",
    "sch_detection",
    "sch_review",
    "sch_export",
    "sch_evidence",
    "sch_migrations",
)

CONFIRMATION = "destroy-all-evidence"


def reset(dsn: str) -> None:
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            for schema in SCHEMAS:
                cur.execute(f"DROP SCHEMA IF EXISTS {schema} CASCADE")
        conn.commit()
    print(f"dropped: {', '.join(SCHEMAS)}")
    print("now run: make migrate ASIP_DB_URL=... && make seed-dev")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Destroy and rebuild the dev database.")
    parser.add_argument(
        "--dsn",
        default=os.environ.get(
            "ASIP_DB_URL", "postgresql://asip:asip_dev_only@127.0.0.1:5432/asip"
        ),
    )
    parser.add_argument(
        "--confirm",
        default="",
        help=f"must be exactly {CONFIRMATION!r}",
    )
    args = parser.parse_args(argv)

    profile = os.environ.get("ASIP_PROFILE", "dev")
    if profile not in ("dev", "sandbox"):
        print(
            f"REFUSING: ASIP_PROFILE is {profile!r}. This command destroys evidence and "
            "runs only under a development profile.",
            file=sys.stderr,
        )
        return 2

    if args.confirm != CONFIRMATION:
        print(
            "REFUSING: this drops every schema, including all evidence bundles and the\n"
            f"hash chain. Re-run with --confirm {CONFIRMATION}",
            file=sys.stderr,
        )
        return 2

    try:
        reset(args.dsn)
    except Exception as exc:
        print(f"reset failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
