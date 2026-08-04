"""Invariant 1 — the manifest covers everything.

The case that matters most is an *extra* file: a missing or altered artifact is
an obvious failure, but an unlisted file is where tampered content would go,
and only the manifest's completeness catches it.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from asip.contracts.evidence import Artifact, ArtifactKind, CaptureBinding, Manifest
from asip.modules.evidence.domain.hashing import sha256_hex
from asip.modules.evidence.domain.manifest import (
    ManifestError,
    build_manifest,
    build_manifest_document,
    parse_manifest_document,
    verify_manifest,
)

CAPTURE = CaptureBinding(
    bundle_id=UUID("11111111-1111-1111-1111-111111111111"),
    tenant_id=UUID("22222222-2222-2222-2222-222222222222"),
    capture_id=UUID("33333333-3333-3333-3333-333333333333"),
    source_url="https://example.org/post/1",
    captured_at=datetime(2026, 8, 4, 8, 40, tzinfo=UTC),
    trace_id="trace-abc",
)


def artifact(name: str, payload: bytes = b"x", kind: ArtifactKind = ArtifactKind.DOM) -> Artifact:
    return Artifact(
        name=name,
        kind=kind,
        media_type="application/octet-stream",
        size_bytes=len(payload),
        sha256=sha256_hex(payload),
    )


def test_artifacts_are_sorted_so_the_digest_ignores_collection_order() -> None:
    a, b, c = artifact("c.har"), artifact("a.html.gz"), artifact("b.png")
    assert [x.name for x in build_manifest([a, b, c], CAPTURE).artifacts] == [
        "a.html.gz",
        "b.png",
        "c.har",
    ]


def test_digest_is_identical_regardless_of_input_order() -> None:
    a, b = artifact("a.html.gz", b"one"), artifact("b.png", b"two")
    assert (
        build_manifest_document(build_manifest([a, b], CAPTURE)).sha256
        == build_manifest_document(build_manifest([b, a], CAPTURE)).sha256
    )


def test_digest_changes_when_an_artifact_hash_changes() -> None:
    before = build_manifest([artifact("dom.html.gz", b"original")], CAPTURE)
    after = build_manifest([artifact("dom.html.gz", b"tampered")], CAPTURE)
    assert build_manifest_document(before) != build_manifest_document(after)


def test_digest_covers_the_algorithm_field() -> None:
    """A manifest recomputed under another algorithm must not collide."""
    real = build_manifest([artifact("dom.html.gz")], CAPTURE)
    forged = Manifest(algorithm="md5", capture=CAPTURE, artifacts=real.artifacts)
    assert build_manifest_document(real) != build_manifest_document(forged)


def test_empty_bundle_is_rejected() -> None:
    with pytest.raises(ManifestError, match="nothing to attest"):
        build_manifest([], CAPTURE)


def test_duplicate_names_are_rejected() -> None:
    with pytest.raises(ManifestError, match="duplicate artifact name"):
        build_manifest([artifact("dom.html.gz", b"a"), artifact("dom.html.gz", b"b")], CAPTURE)


def test_malformed_hash_is_rejected() -> None:
    bad = Artifact("dom.html.gz", ArtifactKind.DOM, "text/html", 1, "not-a-hash")
    with pytest.raises(ManifestError, match="malformed sha256"):
        build_manifest([bad], CAPTURE)


def test_intact_bundle_reports_no_problems() -> None:
    manifest = build_manifest(
        [artifact("dom.html.gz", b"one"), artifact("shot.png", b"two")], CAPTURE
    )
    observed = {a.name: a.sha256 for a in manifest.artifacts}
    assert verify_manifest(manifest, observed) == ()


def test_altered_artifact_is_detected() -> None:
    manifest = build_manifest([artifact("dom.html.gz", b"original")], CAPTURE)
    observed = {"dom.html.gz": sha256_hex(b"tampered")}
    problems = verify_manifest(manifest, observed)
    assert len(problems) == 1
    assert "hash mismatch" in problems[0]


def test_missing_artifact_is_detected() -> None:
    manifest = build_manifest([artifact("dom.html.gz"), artifact("shot.png")], CAPTURE)
    observed = {"dom.html.gz": manifest.artifacts[0].sha256}
    problems = verify_manifest(manifest, observed)
    assert any("missing from bundle: shot.png" in p for p in problems)


def test_unlisted_artifact_invalidates_the_bundle() -> None:
    """The whole point of invariant 1. An extra file is not a warning."""
    manifest = build_manifest([artifact("dom.html.gz", b"one")], CAPTURE)
    observed = {
        "dom.html.gz": manifest.artifacts[0].sha256,
        "planted.js": sha256_hex(b"payload"),
    }
    problems = verify_manifest(manifest, observed)
    assert any("absent from manifest: planted.js" in p for p in problems)


def test_wrong_algorithm_is_reported() -> None:
    manifest = Manifest(algorithm="md5", capture=CAPTURE, artifacts=(artifact("dom.html.gz"),))
    observed = {a.name: a.sha256 for a in manifest.artifacts}
    problems = verify_manifest(manifest, observed)
    assert any("manifest algorithm" in p for p in problems)


def test_the_manifest_binds_the_capture_it_describes() -> None:
    """Relabelling a sealed bundle must change its digest.

    Capture metadata used to live only in the WARC's warcinfo record, covered
    by no hash: the source URL and capture time of a sealed bundle could be
    rewritten without breaking a single check.
    """
    manifest = build_manifest([artifact("dom.html.gz")], CAPTURE)
    relabelled = build_manifest(
        [artifact("dom.html.gz")],
        CaptureBinding(
            bundle_id=CAPTURE.bundle_id,
            tenant_id=CAPTURE.tenant_id,
            capture_id=CAPTURE.capture_id,
            source_url="https://example.org/some-other-page",
            captured_at=CAPTURE.captured_at,
            trace_id=CAPTURE.trace_id,
        ),
    )
    assert build_manifest_document(manifest).sha256 != build_manifest_document(relabelled).sha256


def test_the_digest_is_of_the_stored_bytes() -> None:
    """The property the whole redesign turns on.

    A verifier hashes the bytes it reads. It never re-serialises anything, so
    it never has to reproduce our JSON conventions.
    """
    document = build_manifest_document(build_manifest([artifact("dom.html.gz")], CAPTURE))
    assert document.sha256 == sha256_hex(document.raw)


def test_a_document_round_trips_through_parsing() -> None:
    manifest = build_manifest([artifact("dom.html.gz"), artifact("shot.png")], CAPTURE)
    document = build_manifest_document(manifest)
    assert parse_manifest_document(document.raw) == manifest


def test_re_serialising_a_parsed_document_reproduces_the_same_bytes() -> None:
    """Not relied upon by verification, but a stability check worth having.

    If this ever fails, the serialiser has drifted — which would not break
    stored evidence (the bytes are what count) but would mean two bundles with
    identical content no longer share a digest.
    """
    document = build_manifest_document(build_manifest([artifact("dom.html.gz")], CAPTURE))
    assert build_manifest_document(parse_manifest_document(document.raw)).raw == document.raw
