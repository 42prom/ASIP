"""Invariant 1 — the manifest covers everything.

The case that matters most is an *extra* file: a missing or altered artifact is
an obvious failure, but an unlisted file is where tampered content would go,
and only the manifest's completeness catches it.
"""

from __future__ import annotations

import pytest

from asip.contracts.evidence import Artifact, ArtifactKind, Manifest
from asip.modules.evidence.domain.hashing import sha256_hex
from asip.modules.evidence.domain.manifest import (
    ManifestError,
    build_manifest,
    manifest_digest,
    verify_manifest,
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
    assert [x.name for x in build_manifest([a, b, c]).artifacts] == [
        "a.html.gz",
        "b.png",
        "c.har",
    ]


def test_digest_is_identical_regardless_of_input_order() -> None:
    a, b = artifact("a.html.gz", b"one"), artifact("b.png", b"two")
    assert manifest_digest(build_manifest([a, b])) == manifest_digest(build_manifest([b, a]))


def test_digest_changes_when_an_artifact_hash_changes() -> None:
    before = build_manifest([artifact("dom.html.gz", b"original")])
    after = build_manifest([artifact("dom.html.gz", b"tampered")])
    assert manifest_digest(before) != manifest_digest(after)


def test_digest_covers_the_algorithm_field() -> None:
    """A manifest recomputed under another algorithm must not collide."""
    real = build_manifest([artifact("dom.html.gz")])
    forged = Manifest(algorithm="md5", artifacts=real.artifacts)
    assert manifest_digest(real) != manifest_digest(forged)


def test_empty_bundle_is_rejected() -> None:
    with pytest.raises(ManifestError, match="nothing to attest"):
        build_manifest([])


def test_duplicate_names_are_rejected() -> None:
    with pytest.raises(ManifestError, match="duplicate artifact name"):
        build_manifest([artifact("dom.html.gz", b"a"), artifact("dom.html.gz", b"b")])


def test_malformed_hash_is_rejected() -> None:
    bad = Artifact("dom.html.gz", ArtifactKind.DOM, "text/html", 1, "not-a-hash")
    with pytest.raises(ManifestError, match="malformed sha256"):
        build_manifest([bad])


def test_intact_bundle_reports_no_problems() -> None:
    manifest = build_manifest([artifact("dom.html.gz", b"one"), artifact("shot.png", b"two")])
    observed = {a.name: a.sha256 for a in manifest.artifacts}
    assert verify_manifest(manifest, observed) == ()


def test_altered_artifact_is_detected() -> None:
    manifest = build_manifest([artifact("dom.html.gz", b"original")])
    observed = {"dom.html.gz": sha256_hex(b"tampered")}
    problems = verify_manifest(manifest, observed)
    assert len(problems) == 1
    assert "hash mismatch" in problems[0]


def test_missing_artifact_is_detected() -> None:
    manifest = build_manifest([artifact("dom.html.gz"), artifact("shot.png")])
    observed = {"dom.html.gz": manifest.artifacts[0].sha256}
    problems = verify_manifest(manifest, observed)
    assert any("missing from bundle: shot.png" in p for p in problems)


def test_unlisted_artifact_invalidates_the_bundle() -> None:
    """The whole point of invariant 1. An extra file is not a warning."""
    manifest = build_manifest([artifact("dom.html.gz", b"one")])
    observed = {
        "dom.html.gz": manifest.artifacts[0].sha256,
        "planted.js": sha256_hex(b"payload"),
    }
    problems = verify_manifest(manifest, observed)
    assert any("absent from manifest: planted.js" in p for p in problems)


def test_wrong_algorithm_is_reported() -> None:
    manifest = Manifest(algorithm="md5", artifacts=(artifact("dom.html.gz"),))
    observed = {a.name: a.sha256 for a in manifest.artifacts}
    problems = verify_manifest(manifest, observed)
    assert any("manifest algorithm" in p for p in problems)
