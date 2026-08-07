"""Configuration must be repairable; evidence must not be.

Both properties are enforced by grants, and they point in opposite directions.
Getting one confused for the other is how a source seeded with a wrong URL
became unfixable through the application — which is exactly what happened, and
is why these assertions exist.
"""

from __future__ import annotations

import psycopg
import pytest

from asip.modules.collection.adapters.postgres_repository import PostgresCollectionRepository
from asip.modules.identity.domain.ids import default_project_id

from .conftest import TENANT_A, as_tenant

SOURCE = "11111111-2222-3333-4444-555555555555"


def seed(conn: psycopg.Connection, url: str, interval: int = 3600) -> None:
    PostgresCollectionRepository(conn).add_source(
        source_id=SOURCE,  # type: ignore[arg-type]
        tenant_id=TENANT_A,
        project_id=default_project_id(TENANT_A),
        name="Canary",
        url=url,
        platform="canary",
        is_canary=True,
        interval_seconds=interval,
    )


@pytest.mark.isolation
def test_re_seeding_repairs_a_wrong_url(conn: psycopg.Connection) -> None:
    """The regression this test exists for.

    The canary was once pointed at a hostname only resolvable inside a
    container. `add_source` used ON CONFLICT DO NOTHING, so every attempt to
    put it back silently did nothing and the only remedy was hand-editing the
    database. A seed that cannot repair is not idempotent, it is inert.
    """
    as_tenant(conn, TENANT_A)
    seed(conn, "http://unreachable.invalid/canary/")
    seed(conn, "http://127.0.0.1:8000/canary/", interval=60)

    sources = PostgresCollectionRepository(conn).list_sources(TENANT_A)
    canary = next(s for s in sources if str(s["source_id"]) == SOURCE)
    assert canary["url"] == "http://127.0.0.1:8000/canary/"
    assert canary["interval_seconds"] == 60


@pytest.mark.isolation
def test_a_source_cannot_be_deleted_by_the_application(conn: psycopg.Connection) -> None:
    """Retiring a source is what `enabled` is for.

    Deleting one would orphan the captures and findings that reference it, so
    removal stays with retention (D-54) and its separate audited role.
    """
    as_tenant(conn, TENANT_A)
    seed(conn, "http://127.0.0.1:8000/canary/")

    with conn.cursor() as cur, pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute("DELETE FROM sch_collection.sources")


@pytest.mark.isolation
def test_evidence_is_still_not_editable(conn: psycopg.Connection) -> None:
    """The opposite direction, asserted next to the one that changed.

    Loosening sources must not have loosened evidence. These two live in one
    file so the asymmetry is visible: configuration is corrected, evidence is
    appended.
    """
    as_tenant(conn, TENANT_A)

    with conn.cursor() as cur, pytest.raises(psycopg.errors.InsufficientPrivilege):
        cur.execute("UPDATE sch_evidence.evidence_bundles SET source_url = 'x'")
