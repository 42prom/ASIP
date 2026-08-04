"""L4 — register the development tenant and the canary source.

Idempotent: running it twice changes nothing. That matters because it is the
first thing anyone runs, and a seed that fails the second time teaches people
to be afraid of it.
"""

from __future__ import annotations

import argparse
import os
import sys
from uuid import UUID

import psycopg

from asip.modules.collection.adapters.postgres_repository import PostgresCollectionRepository

DEV_TENANT = UUID("aaaaaaaa-0000-4000-8000-0000000000d1")
CANARY_SOURCE_ID = UUID("c0a17a19-0000-4000-8000-a51900000004")


def seed(dsn: str, canary_url: str) -> None:
    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SET ROLE asip_app")
            cur.execute("SELECT set_config('asip.tenant_id', %s, false)", (str(DEV_TENANT),))

        PostgresCollectionRepository(conn).add_source(
            source_id=CANARY_SOURCE_ID,
            tenant_id=DEV_TENANT,
            name="Canary (local)",
            url=canary_url,
            platform="canary",
            priority=1,
            is_canary=True,
            # 60s so the pipeline can be re-run during a demo without waiting.
            interval_seconds=60,
        )
        conn.commit()
    print(f"seeded tenant {DEV_TENANT} with canary source at {canary_url}")


def _default_canary_url() -> str:
    """The canary URL as the *fetcher* will resolve it, not as the developer does.

    With an isolated fetch zone the fetcher is in another container, where
    127.0.0.1 is its own loopback. Seeding the developer's URL there produces a
    connection refused that looks like a broken canary and is really a routing
    mistake — so the default follows whichever zone will actually do the work.
    """
    if os.environ.get("ASIP_FETCH_QUEUE_URL"):
        return "http://host.docker.internal:8000/canary/"
    return "http://127.0.0.1:8000/canary/"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seed the development tenant.")
    parser.add_argument(
        "--dsn",
        default=os.environ.get(
            "ASIP_DB_URL", "postgresql://asip:asip_dev_only@127.0.0.1:5432/asip"
        ),
    )
    parser.add_argument(
        "--canary-url",
        default=os.environ.get("ASIP_CANARY_URL", _default_canary_url()),
        help="the canary page this instance serves, as the FETCHER will see it",
    )
    args = parser.parse_args(argv)
    try:
        seed(args.dsn, args.canary_url)
    except Exception as exc:
        print(f"seed failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
