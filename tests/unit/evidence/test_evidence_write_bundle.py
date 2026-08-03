"""L2 — sealing a capture into a bundle.

The tests that matter here are the failure ones. Writing a bundle when
everything works is easy; the design questions are what happens when the TSA is
down, when the transaction rolls back, and when the artifacts do not match the
draft that describes them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from asip.contracts.evidence import Artifact, ArtifactKind, BundleDraft, TsaStatus
from asip.modules.evidence.application.write_bundle import BundleIntegrityError, WriteBundle
from asip.modules.evidence.domain.hashing import sha256_hex

from .fakes import FakeObjectStore, FakeRepository, FakeTimestampAuthority, FixedClock

TENANT = UUID("11111111-1111-1111-1111-111111111111")
AUTHORITY = "https://tsa.example.org"

DOM = b"<html>a captured page</html>"
SHOT = b"\x89PNG fake bytes"


def make_draft(bundle_id: UUID | None = None) -> tuple[BundleDraft, dict[str, bytes]]:
    artifacts = {"dom.html.gz": DOM, "screenshot.png": SHOT}
    draft = BundleDraft(
        bundle_id=bundle_id or uuid4(),
        capture_id=uuid4(),
        tenant_id=TENANT,
        trace_id="trace-abc",
        source_url="https://example.org/post/1",
        captured_at=datetime(2026, 8, 4, 8, 40, tzinfo=UTC),
        artifacts=(
            Artifact(
                "dom.html.gz", ArtifactKind.DOM, "application/gzip", len(DOM), sha256_hex(DOM)
            ),
            Artifact(
                "screenshot.png",
                ArtifactKind.SCREENSHOT_FULLPAGE,
                "image/png",
                len(SHOT),
                sha256_hex(SHOT),
            ),
        ),
    )
    return draft, artifacts


def build(
    objects: FakeObjectStore, repo: FakeRepository, tsa: FakeTimestampAuthority
) -> WriteBundle:
    return WriteBundle(objects, repo, tsa, FixedClock(), AUTHORITY)


def test_a_bundle_is_written_and_lands_at_chain_index_zero() -> None:
    objects, repo, tsa = FakeObjectStore(), FakeRepository(), FakeTimestampAuthority()
    draft, artifacts = make_draft()

    ref = build(objects, repo, tsa).execute(draft, artifacts)

    assert ref.chain_index == 0
    assert ref.tsa_status is TsaStatus.VERIFIED
    assert repo.bundles[(TENANT, draft.bundle_id)].manifest_sha256 == ref.manifest_sha256


def test_artifacts_are_written_before_the_transaction_commits() -> None:
    """The chosen ordering. An orphan blob is cheap; an unattested bundle is not."""
    objects, repo, tsa = FakeObjectStore(), FakeRepository(), FakeTimestampAuthority()
    draft, artifacts = make_draft()

    build(objects, repo, tsa).execute(draft, artifacts)

    assert len(objects.put_order) == 2
    assert repo.commit_calls == 1


def test_a_rolled_back_transaction_leaves_no_bundle_and_no_chain_entry() -> None:
    """Atomicity of the pair — the expensive failure direction, closed."""
    objects, tsa = FakeObjectStore(), FakeTimestampAuthority()
    repo = FakeRepository(fail_commit=True)
    draft, artifacts = make_draft()

    with pytest.raises(RuntimeError, match="rolled back"):
        build(objects, repo, tsa).execute(draft, artifacts)

    assert repo.bundles == {}
    assert repo.chains == {}
    # Blobs survive. That is the deliberate, harmless direction of the window.
    assert len(objects.blobs) == 2


def test_an_unreachable_tsa_leaves_the_bundle_pending_never_verified() -> None:
    """Invariant 3. There is no path from a failed stamp to VERIFIED."""
    objects, repo = FakeObjectStore(), FakeRepository()
    tsa = FakeTimestampAuthority()
    tsa.unreachable = True
    draft, artifacts = make_draft()

    ref = build(objects, repo, tsa).execute(draft, artifacts)

    assert ref.tsa_status is TsaStatus.PENDING
    assert repo.stamps == {}
    # The bundle itself is still sealed and chained — the capture is not lost
    # because a third party was down.
    assert (TENANT, draft.bundle_id) in repo.bundles


def test_a_token_that_does_not_validate_is_recorded_as_failed_not_verified() -> None:
    objects, repo = FakeObjectStore(), FakeRepository()
    tsa = FakeTimestampAuthority()
    tsa.issue_invalid = True
    draft, artifacts = make_draft()

    ref = build(objects, repo, tsa).execute(draft, artifacts)

    assert ref.tsa_status is TsaStatus.FAILED
    assert repo.stamps == {}


def test_artifacts_not_matching_the_draft_hash_are_refused() -> None:
    """Sealing a manifest that misdescribes its own contents is worse than failing."""
    objects, repo, tsa = FakeObjectStore(), FakeRepository(), FakeTimestampAuthority()
    draft, artifacts = make_draft()
    artifacts["dom.html.gz"] = b"different bytes entirely"

    with pytest.raises(BundleIntegrityError, match="does not match its declared hash"):
        build(objects, repo, tsa).execute(draft, artifacts)

    assert repo.commit_calls == 0
    assert objects.blobs == {}


def test_an_artifact_missing_from_the_supplied_bytes_is_refused() -> None:
    objects, repo, tsa = FakeObjectStore(), FakeRepository(), FakeTimestampAuthority()
    draft, artifacts = make_draft()
    del artifacts["screenshot.png"]

    with pytest.raises(BundleIntegrityError, match="missing="):
        build(objects, repo, tsa).execute(draft, artifacts)


def test_an_unexpected_extra_artifact_is_refused() -> None:
    objects, repo, tsa = FakeObjectStore(), FakeRepository(), FakeTimestampAuthority()
    draft, artifacts = make_draft()
    artifacts["planted.js"] = b"payload"

    with pytest.raises(BundleIntegrityError, match="unexpected="):
        build(objects, repo, tsa).execute(draft, artifacts)


def test_successive_bundles_extend_the_same_tenant_chain() -> None:
    objects, repo, tsa = FakeObjectStore(), FakeRepository(), FakeTimestampAuthority()
    writer = build(objects, repo, tsa)

    indices = []
    for _ in range(3):
        draft, artifacts = make_draft()
        indices.append(writer.execute(draft, artifacts).chain_index)

    assert indices == [0, 1, 2]


def test_objects_are_namespaced_by_tenant() -> None:
    """V-7 — tenant separation is visible in the storage layout, not implied."""
    objects, repo, tsa = FakeObjectStore(), FakeRepository(), FakeTimestampAuthority()
    draft, artifacts = make_draft()

    build(objects, repo, tsa).execute(draft, artifacts)

    assert all(key.startswith(f"{TENANT}/{draft.bundle_id}/") for key in objects.blobs)
