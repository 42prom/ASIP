"""Fixtures for the evidence round-trip.

Needs both a database and an S3-compatible object store:

    docker compose up -d postgres minio
    make evidence-roundtrip \\
        ASIP_TEST_DB_URL=postgresql://asip:...@127.0.0.1:5432/asip \\
        ASIP_TEST_S3_URL=http://127.0.0.1:9000
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from uuid import UUID, uuid4

import psycopg
import pytest

from asip.entrypoints.migrate import migrate_up
from asip.modules.evidence.adapters.postgres_repository import PostgresEvidenceRepository
from asip.modules.evidence.adapters.s3_object_store import S3ObjectStore
from asip.modules.evidence.adapters.warc_archive import WarcBundleArchive

TENANT = UUID("cccccccc-0000-0000-0000-00000000000c")


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        pytest.skip(f"{name} not set — the round-trip needs real infrastructure")
    return value


@pytest.fixture(scope="session")
def db_url() -> str:
    dsn = _require("ASIP_TEST_DB_URL")
    with psycopg.connect(dsn) as conn:
        migrate_up(conn)
        conn.commit()
    return dsn


@pytest.fixture(scope="session")
def object_store() -> S3ObjectStore:
    store = S3ObjectStore(
        bucket=os.environ.get("ASIP_TEST_S3_BUCKET", "asip-evidence-test"),
        endpoint_url=_require("ASIP_TEST_S3_URL"),
        access_key=os.environ.get("ASIP_TEST_S3_KEY", "asip"),
        secret_key=os.environ.get("ASIP_TEST_S3_SECRET", "asip_dev_only"),
    )
    store.ensure_bucket()
    return store


@pytest.fixture
def archive(object_store: S3ObjectStore) -> WarcBundleArchive:
    return WarcBundleArchive(object_store)


@pytest.fixture
def conn(db_url: str) -> Iterator[psycopg.Connection]:
    """A connection acting as the application role for one tenant.

    Runs as asip_app, not the schema owner — the same role production uses, so
    the round-trip exercises the real grants rather than a privileged shortcut
    that would hide a missing permission until deploy.
    """
    with psycopg.connect(db_url) as connection:
        with connection.cursor() as cur:
            cur.execute("SET ROLE asip_app")
            cur.execute("SELECT set_config('asip.tenant_id', %s, false)", (str(TENANT),))
        yield connection
        connection.rollback()


@pytest.fixture
def repository(conn: psycopg.Connection) -> PostgresEvidenceRepository:
    return PostgresEvidenceRepository(conn)


@pytest.fixture
def capture_id(conn: psycopg.Connection) -> UUID:
    """A capture row for the bundle to reference."""
    new_id = uuid4()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO sch_evidence.captures "
            "(capture_id, tenant_id, source_id, trace_id, url, requested_at, status) "
            "VALUES (%s, %s, %s, 'trace-roundtrip', 'https://example.org/post/1', "
            "        '2026-08-15T10:00:00+00:00', 'succeeded')",
            (new_id, TENANT, uuid4()),
        )
    return new_id
