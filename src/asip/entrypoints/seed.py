"""L4 — register the development tenant, its first user, and the canary source.

Idempotent: running it twice changes nothing. That matters because it is the
first thing anyone runs, and a seed that fails the second time teaches people
to be afraid of it.

THE DEVELOPMENT PASSWORD IS PRINTED, NOT HIDDEN
It is a known constant in a development seed and pretending otherwise would be
theatre. What matters is that it cannot reach anything else: the seed refuses to
run outside a development profile, exactly like reset_dev, so this account
cannot be created against a production database by a mistyped DSN.
"""

from __future__ import annotations

import argparse
import os
import sys
from uuid import UUID, uuid5

import psycopg

from asip.modules.collection.adapters.postgres_repository import PostgresCollectionRepository
from asip.modules.identity.adapters.postgres_repository import PostgresIdentityRepository
from asip.modules.identity.domain.ids import IDENTITY_NAMESPACE, default_project_id
from asip.modules.identity.domain.passwords import hash_password
from asip.modules.identity.domain.roles import Role

DEV_TENANT = UUID("aaaaaaaa-0000-4000-8000-0000000000d1")
CANARY_SOURCE_ID = UUID("c0a17a19-0000-4000-8000-a51900000004")

DEV_EMAIL = "analyst@asip.local"
DEV_PASSWORD = "asip_dev_only"

AUDITOR_EMAIL = "auditor@asip.local"

#: Deterministic so re-seeding updates the same user rather than making another.
DEV_USER_ID = uuid5(IDENTITY_NAMESPACE, f"user|{DEV_TENANT}|{DEV_EMAIL}")
AUDITOR_USER_ID = uuid5(IDENTITY_NAMESPACE, f"user|{DEV_TENANT}|{AUDITOR_EMAIL}")


def seed(dsn: str, canary_url: str) -> None:
    project_id = default_project_id(DEV_TENANT)

    with psycopg.connect(dsn) as conn:
        with conn.cursor() as cur:
            cur.execute("SET ROLE asip_app")
            cur.execute("SELECT set_config('asip.tenant_id', %s, false)", (str(DEV_TENANT),))

        identity = PostgresIdentityRepository(conn)
        identity.create_tenant(DEV_TENANT, "ASIP development")
        identity.create_project(project_id, DEV_TENANT, "Default")
        identity.create_user(
            DEV_USER_ID,
            DEV_TENANT,
            DEV_EMAIL,
            hash_password(DEV_PASSWORD),
            display_name="Development analyst",
        )

        # Two roles, because D-49 separates administering a tenant from reading
        # its data and the development user needs to do both. That the seed
        # needs two rather than one "admin" is the compartmentalisation working,
        # not a gap in it.
        identity.assign_role(DEV_TENANT, DEV_USER_ID, Role.TENANT_ADMIN)
        identity.assign_role(DEV_TENANT, DEV_USER_ID, Role.ANALYST)
        identity.assign_project(DEV_TENANT, DEV_USER_ID, project_id)

        # A SECOND account, because the analyst above cannot be given the
        # auditor role: no role may both read tenant data and read the record of
        # who read it (T-009), and a test enforces that. Wanting to see the
        # audit screen in development is exactly the pressure that would
        # otherwise erode the separation, so the seed answers it with another
        # account instead of a wider one.
        #
        # Deliberately assigned NO project: an auditor reads the log and never
        # the data, and giving them a project would make that a matter of
        # policy rather than of what they can reach.
        identity.create_user(
            AUDITOR_USER_ID,
            DEV_TENANT,
            AUDITOR_EMAIL,
            hash_password(DEV_PASSWORD),
            display_name="Development auditor",
        )
        identity.assign_role(DEV_TENANT, AUDITOR_USER_ID, Role.AUDITOR)

        PostgresCollectionRepository(conn).add_source(
            source_id=CANARY_SOURCE_ID,
            tenant_id=DEV_TENANT,
            project_id=project_id,
            name="Canary (local)",
            url=canary_url,
            platform="canary",
            priority=1,
            is_canary=True,
            # 60s so the pipeline can be re-run during a demo without waiting.
            interval_seconds=60,
        )
        conn.commit()

    print(f"tenant  {DEV_TENANT}")
    print(f"project {project_id} (Default)")
    print(f"source  canary at {canary_url}")
    print(f"login   {DEV_EMAIL} / {DEV_PASSWORD}   [tenant_admin + analyst]")
    print(f"login   {AUDITOR_EMAIL} / {DEV_PASSWORD}   [auditor — audit log only, no data]")


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

    # This creates an account with a published password. Same guard as
    # reset_dev, and for a sharper reason: a destructive script pointed at
    # production is noticed immediately, whereas a seeded account with a known
    # password is noticed by whoever finds it first.
    profile = os.environ.get("ASIP_PROFILE", "dev")
    if profile not in ("dev", "sandbox"):
        print(
            f"REFUSING: ASIP_PROFILE is {profile!r}. This creates a user whose password "
            "is printed to the terminal and committed to the repository, and it runs "
            "only under a development profile.",
            file=sys.stderr,
        )
        return 2

    try:
        seed(args.dsn, args.canary_url)
    except Exception as exc:
        print(f"seed failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
