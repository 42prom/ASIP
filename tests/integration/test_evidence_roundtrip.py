"""D-88.2 — the evidence integrity round-trip, against real infrastructure.

Write a bundle, verify the manifest, verify the chain, and read it back with an
independent WARC reader. Every fake is gone: real PostgreSQL with real RLS and
real grants, a real S3-compatible store, real WARC bytes.

This is the suite the walking skeleton exists to produce (W-02). If the
transaction reasoning in write_bundle.py is wrong, it is wrong here first.
"""

from __future__ import annotations

from datetime import UTC, datetime
from io import BytesIO
from uuid import UUID, uuid4

import psycopg
import pytest
from warcio.archiveiterator import ArchiveIterator

from asip.contracts.evidence import (
    Artifact,
    ArtifactKind,
    BundleDraft,
    BundleRecord,
    ChainEntry,
    RenderParams,
    TsaStatus,
    VerificationOutcome,
)
from asip.modules.evidence.adapters.postgres_repository import PostgresEvidenceRepository
from asip.modules.evidence.adapters.s3_object_store import S3ObjectStore
from asip.modules.evidence.adapters.warc_archive import WarcBundleArchive
from asip.modules.evidence.application.verify_bundle import VerifyBundle
from asip.modules.evidence.application.write_bundle import ARCHIVE_OBJECT_NAME, WriteBundle
from asip.modules.evidence.domain.hashing import sha256_hex
from asip.modules.evidence.domain.manifest import build_manifest, manifest_digest

from .conftest import TENANT

DOM = "<html><body>დღეს ამინდი კარგია</body></html>".encode()
SHOT = b"\x89PNG\r\n\x1a\n" + b"pixel" * 200
AUTHORITY = "https://tsa.example.org"

RENDER = RenderParams(
    viewport_width=1280,
    viewport_height=2000,
    device_pixel_ratio=1.0,
    locale="ka-GE",
    timezone="Asia/Tbilisi",
    animations_disabled=True,
    network_idle_ms=500,
    settle_delay_ms=250,
    scroll_sequence=(0, 1000, 2000),
)


class OfflineTsa:
    """A TSA that is down.

    The round-trip deliberately does not call a live timestamping authority:
    the suite must pass in CI with no network, and D-22 is about the *authority*
    being external, not about this test reaching it. What is asserted here is
    the behaviour when it cannot be reached — pending, never verified — which
    is the failure mode that actually occurs in production.
    """

    def stamp(self, digest_hex: str) -> bytes:
        raise ConnectionError("TSA unreachable")

    def verify(self, digest_hex: str, token: bytes) -> bool:
        return False


@pytest.fixture
def writer(archive: WarcBundleArchive, repository: PostgresEvidenceRepository) -> WriteBundle:
    return WriteBundle(archive, repository, OfflineTsa(), _FixedClock(), AUTHORITY)


@pytest.fixture
def verifier(archive: WarcBundleArchive, repository: PostgresEvidenceRepository) -> VerifyBundle:
    return VerifyBundle(archive, repository, OfflineTsa())


class _FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 8, 15, 10, 5, tzinfo=UTC)


def make_draft(capture_id: UUID) -> tuple[BundleDraft, dict[str, bytes]]:
    artifacts = {"dom.html.gz": DOM, "screenshot.png": SHOT}
    draft = BundleDraft(
        bundle_id=uuid4(),
        capture_id=capture_id,
        tenant_id=TENANT,
        trace_id="trace-roundtrip",
        source_url="https://example.org/post/1",
        captured_at=datetime(2026, 8, 15, 10, 0, tzinfo=UTC),
        artifacts=(
            Artifact("dom.html.gz", ArtifactKind.DOM, "text/html", len(DOM), sha256_hex(DOM)),
            Artifact(
                "screenshot.png",
                ArtifactKind.SCREENSHOT_FULLPAGE,
                "image/png",
                len(SHOT),
                sha256_hex(SHOT),
            ),
        ),
        render_params=RENDER,
    )
    return draft, artifacts


def test_a_bundle_is_sealed_and_verifies_end_to_end(
    writer: WriteBundle, verifier: VerifyBundle, capture_id: UUID
) -> None:
    draft, artifacts = make_draft(capture_id)

    ref = writer.execute(draft, artifacts)
    result = verifier.execute(ref)

    assert ref.chain_index >= 0
    # No TSA, so the honest answer is INCOMPLETE — not VERIFIED.
    assert result.outcome is VerificationOutcome.INCOMPLETE
    assert result.manifest_ok, result.problems
    assert result.chain_ok, result.problems
    assert not result.tsa_ok


def test_an_unreachable_tsa_leaves_the_bundle_pending(
    writer: WriteBundle, capture_id: UUID
) -> None:
    draft, artifacts = make_draft(capture_id)
    ref = writer.execute(draft, artifacts)
    assert ref.tsa_status is TsaStatus.PENDING


def test_the_stored_object_opens_with_an_independent_warc_reader(
    writer: WriteBundle, object_store: S3ObjectStore, capture_id: UUID
) -> None:
    """The claim of D-20, against bytes that made a full round trip through S3."""
    draft, artifacts = make_draft(capture_id)
    ref = writer.execute(draft, artifacts)

    raw = object_store.get(f"{ref.tenant_id}/{ref.bundle_id}/{ARCHIVE_OBJECT_NAME}")

    recovered: dict[str, bytes] = {}
    for record in ArchiveIterator(BytesIO(raw)):
        if record.rec_type != "resource":
            continue
        uri = record.rec_headers.get_header("WARC-Target-URI")
        recovered[uri.rsplit(":", 1)[-1]] = record.content_stream().read()

    assert recovered == artifacts
    assert recovered["dom.html.gz"].decode().endswith("</html>")


def test_render_params_survive_the_database(
    writer: WriteBundle, repository: PostgresEvidenceRepository, capture_id: UUID
) -> None:
    """D-23 — an unrecorded render is not reproducible even if it was deterministic."""
    draft, artifacts = make_draft(capture_id)
    ref = writer.execute(draft, artifacts)

    stored = repository.load_bundle(TENANT, ref.bundle_id)
    assert stored is not None
    assert stored.record.render_params == RENDER


def test_successive_bundles_extend_the_chain_in_postgres(
    writer: WriteBundle, repository: PostgresEvidenceRepository, capture_id: UUID
) -> None:
    first_draft, first_artifacts = make_draft(capture_id)
    first = writer.execute(first_draft, first_artifacts)

    second_draft, second_artifacts = make_draft(capture_id)
    second = writer.execute(second_draft, second_artifacts)

    assert second.chain_index == first.chain_index + 1

    head = repository.head(TENANT)
    assert head is not None
    assert head.chain_index == second.chain_index
    assert head.prev_hash != "0" * 64


def test_tampering_with_a_stored_artifact_is_detected_after_a_real_round_trip(
    writer: WriteBundle,
    verifier: VerifyBundle,
    object_store: S3ObjectStore,
    capture_id: UUID,
) -> None:
    """The product's central claim, end to end: rewrite the stored bytes, get caught."""
    draft, artifacts = make_draft(capture_id)
    ref = writer.execute(draft, artifacts)

    # Rewrite the stored archive in place, exactly as someone with storage
    # credentials but no database access would.
    key = f"{ref.tenant_id}/{ref.bundle_id}/{ARCHIVE_OBJECT_NAME}"
    WarcBundleArchive(object_store).write(
        key,
        build_manifest(draft.artifacts),
        {"dom.html.gz": b"<html>rewritten history</html>", "screenshot.png": SHOT},
        {"bundle_id": str(draft.bundle_id)},
    )

    result = verifier.execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.manifest_ok
    assert any("hash mismatch" in p for p in result.problems)


def test_the_bundle_and_chain_commit_atomically(
    archive: WarcBundleArchive,
    repository: PostgresEvidenceRepository,
    conn: psycopg.Connection,
    capture_id: UUID,
) -> None:
    """A failing chain insert must take the bundle row with it.

    Forced by writing a bundle whose chain entry violates the genesis CHECK.
    Postgres raises, the transaction rolls back, and neither row survives —
    which is the property the port's two-argument shape exists to guarantee.
    """
    draft, _ = make_draft(capture_id)
    manifest = build_manifest(draft.artifacts)
    digest = manifest_digest(manifest)

    record = BundleRecord(
        bundle_id=draft.bundle_id,
        capture_id=capture_id,
        tenant_id=TENANT,
        trace_id=draft.trace_id,
        source_url=draft.source_url,
        captured_at=draft.captured_at,
        manifest=manifest,
        manifest_sha256=digest,
        object_prefix=f"{TENANT}/{draft.bundle_id}",
    )
    # chain_index 5 with the genesis prev_hash violates chain_genesis_is_index_zero.
    bad_entry = ChainEntry(
        tenant_id=TENANT,
        chain_index=5,
        prev_hash="0" * 64,
        manifest_sha256=digest,
        bundle_id=draft.bundle_id,
        entry_hash=sha256_hex(b"whatever"),
    )

    with pytest.raises(psycopg.errors.CheckViolation):
        repository.commit_bundle(record, bad_entry)

    assert repository.load_bundle(TENANT, draft.bundle_id) is None
