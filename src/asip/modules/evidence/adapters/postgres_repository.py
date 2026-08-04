"""L3 — the evidence repository over PostgreSQL.

Writes only to sch_evidence (D-91). No statement here touches another module's
schema, and there is no UPDATE and no DELETE in this file — the grants would
refuse them, but the absence is also the point: if a method here ever needs to
rewrite a sealed bundle, the requirement is wrong.

Every query filters on tenant_id explicitly even though RLS already does. Not
redundancy for its own sake: RLS is the guarantee, and the explicit predicate
is what makes a query that forgot to set the tenant GUC return nothing rather
than accidentally rely on a session state set by whoever used the connection
before (V-7).
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any
from uuid import UUID

import psycopg
from psycopg.types.json import Jsonb

from asip.contracts.evidence import (
    BundleRecord,
    ChainEntry,
    ManifestDocument,
    RenderParams,
    StoredBundle,
    TimestampRecord,
)


class PostgresEvidenceRepository:
    """Append-only evidence storage."""

    def __init__(self, connection: psycopg.Connection) -> None:
        self._conn = connection

    # ── writes ──────────────────────────────────────────────────────────────

    def commit_bundle(self, record: BundleRecord, entry: ChainEntry) -> None:
        """Both rows or neither.

        The transaction is the whole reason this method takes two arguments.
        A chain entry attesting to a bundle that does not exist would make the
        chain a record of fiction; a bundle absent from the chain is
        unattested. psycopg's transaction block rolls both back on any failure,
        including the unique violation raised when two workers race for the
        same chain_index — which is the correct outcome, since the loser must
        re-read the head and link again rather than overwrite.
        """
        with self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sch_evidence.evidence_bundles
                    (bundle_id, captured_at, capture_id, tenant_id, trace_id,
                     source_url, manifest, manifest_sha256, object_prefix, render_params)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    record.bundle_id,
                    record.captured_at,
                    record.capture_id,
                    record.tenant_id,
                    record.trace_id,
                    record.source_url,
                    record.manifest_document.raw.decode("utf-8"),
                    record.manifest_sha256,
                    record.object_prefix,
                    None if record.render_params is None else Jsonb(asdict(record.render_params)),
                ),
            )
            cur.execute(
                """
                INSERT INTO sch_evidence.hash_chain
                    (tenant_id, chain_index, prev_hash, manifest_sha256,
                     bundle_id, bundle_captured_at, entry_hash, algorithm)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    entry.tenant_id,
                    entry.chain_index,
                    entry.prev_hash,
                    entry.manifest_sha256,
                    entry.bundle_id,
                    record.captured_at,
                    entry.entry_hash,
                    entry.algorithm,
                ),
            )

    def append_timestamp(self, stamp: TimestampRecord) -> None:
        with self._conn.transaction(), self._conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO sch_evidence.tsa_tokens
                    (tenant_id, bundle_id, bundle_captured_at, manifest_sha256,
                     authority_url, token, obtained_at)
                SELECT %s, %s, b.captured_at, %s, %s, %s, %s
                  FROM sch_evidence.evidence_bundles b
                 WHERE b.tenant_id = %s AND b.bundle_id = %s
                """,
                (
                    stamp.tenant_id,
                    stamp.bundle_id,
                    stamp.manifest_sha256,
                    stamp.authority_url,
                    stamp.token,
                    stamp.obtained_at,
                    stamp.tenant_id,
                    stamp.bundle_id,
                ),
            )

    # ── reads ───────────────────────────────────────────────────────────────

    def head(self, tenant_id: UUID) -> ChainEntry | None:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT tenant_id, chain_index, prev_hash, manifest_sha256,
                       bundle_id, entry_hash, algorithm
                  FROM sch_evidence.hash_chain
                 WHERE tenant_id = %s
                 ORDER BY chain_index DESC
                 LIMIT 1
                """,
                (tenant_id,),
            )
            row = cur.fetchone()
        return None if row is None else _row_to_chain_entry(row)

    def segment(self, tenant_id: UUID, start: int, end: int) -> tuple[ChainEntry, ...]:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT tenant_id, chain_index, prev_hash, manifest_sha256,
                       bundle_id, entry_hash, algorithm
                  FROM sch_evidence.hash_chain
                 WHERE tenant_id = %s AND chain_index BETWEEN %s AND %s
                 ORDER BY chain_index
                """,
                (tenant_id, start, end),
            )
            return tuple(_row_to_chain_entry(row) for row in cur.fetchall())

    def load_bundle(self, tenant_id: UUID, bundle_id: UUID) -> StoredBundle | None:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT bundle_id, captured_at, capture_id, tenant_id, trace_id,
                       source_url, manifest, manifest_sha256, object_prefix, render_params
                  FROM sch_evidence.evidence_bundles
                 WHERE tenant_id = %s AND bundle_id = %s
                """,
                (tenant_id, bundle_id),
            )
            bundle_row = cur.fetchone()
            if bundle_row is None:
                return None

            cur.execute(
                """
                SELECT tenant_id, chain_index, prev_hash, manifest_sha256,
                       bundle_id, entry_hash, algorithm
                  FROM sch_evidence.hash_chain
                 WHERE tenant_id = %s AND bundle_id = %s
                """,
                (tenant_id, bundle_id),
            )
            chain_row = cur.fetchone()
            if chain_row is None:
                # The FK makes this unreachable through any supported path.
                # Reported rather than silently treated as "no bundle", because
                # if it ever happens the chain has been tampered with directly.
                raise RuntimeError(
                    f"bundle {bundle_id} exists with no chain entry — "
                    "the hash chain has been altered outside the application"
                )

            cur.execute(
                """
                SELECT tenant_id, bundle_id, manifest_sha256, authority_url,
                       token, obtained_at
                  FROM sch_evidence.tsa_tokens
                 WHERE tenant_id = %s AND bundle_id = %s
                 ORDER BY obtained_at
                """,
                (tenant_id, bundle_id),
            )
            stamps = tuple(_row_to_timestamp(row) for row in cur.fetchall())

        return StoredBundle(
            record=_row_to_bundle(bundle_row),
            chain_entry=_row_to_chain_entry(chain_row),
            timestamps=stamps,
        )


# ── row mapping ─────────────────────────────────────────────────────────────


def _row_to_bundle(row: tuple[Any, ...]) -> BundleRecord:
    return BundleRecord(
        bundle_id=row[0],
        captured_at=row[1],
        capture_id=row[2],
        tenant_id=row[3],
        trace_id=row[4],
        source_url=row[5],
        manifest_document=ManifestDocument(raw=row[6].encode("utf-8"), sha256=row[7]),
        object_prefix=row[8],
        render_params=None if row[9] is None else _render_from_json(row[9]),
    )


def _render_from_json(payload: dict[str, Any]) -> RenderParams:
    """Rebuild render params from JSONB.

    scroll_sequence is restored to a tuple: JSON has no tuples, so it comes
    back as a list, and a RenderParams holding a list would compare unequal to
    the one that was stored. D-23 turns on those values matching exactly.
    """
    return RenderParams(**{**payload, "scroll_sequence": tuple(payload["scroll_sequence"])})


def _row_to_chain_entry(row: tuple[Any, ...]) -> ChainEntry:
    return ChainEntry(
        tenant_id=row[0],
        chain_index=row[1],
        prev_hash=row[2],
        manifest_sha256=row[3],
        bundle_id=row[4],
        entry_hash=row[5],
        algorithm=row[6],
    )


def _row_to_timestamp(row: tuple[Any, ...]) -> TimestampRecord:
    return TimestampRecord(
        tenant_id=row[0],
        bundle_id=row[1],
        manifest_sha256=row[2],
        authority_url=row[3],
        token=bytes(row[4]),
        obtained_at=row[5],
    )
