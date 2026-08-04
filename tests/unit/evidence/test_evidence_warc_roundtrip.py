"""D-20 / D-88.2 — a bundle is a WARC that standard tooling can open.

The assertions that matter here do not use the adapter to read what the adapter
wrote. They open the bytes with a plain warcio reader and, in one case, inspect
the gzip and WARC framing directly — because "our writer and our reader agree"
is not the claim D-20 makes. The claim is that software which has never seen
this code can read the evidence.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime
from io import BytesIO
from uuid import UUID

import pytest
from warcio.archiveiterator import ArchiveIterator

from asip.contracts.evidence import (
    Artifact,
    ArtifactKind,
    CaptureBinding,
    Manifest,
)
from asip.modules.evidence.adapters.warc_archive import WarcBundleArchive
from asip.modules.evidence.domain.hashing import sha256_hex
from asip.modules.evidence.domain.manifest import (
    build_manifest,
    build_manifest_document,
    verify_manifest,
)

from .fakes import FakeObjectStore

KEY = "tenant/bundle/bundle.warc.gz"

DOM = "<html><body>გამარჯობა</body></html>".encode()
SHOT = b"\x89PNG\r\n\x1a\n" + b"pixels" * 100
HAR = b'{"log":{"version":"1.2","entries":[]}}'

CAPTURE = CaptureBinding(
    bundle_id=UUID("3f1a0b1e-0000-0000-0000-00000000abcd"),
    tenant_id=UUID("22222222-2222-2222-2222-222222222222"),
    capture_id=UUID("33333333-3333-3333-3333-333333333333"),
    source_url="https://example.org/post/1",
    captured_at=datetime(2026, 8, 4, 8, 40, tzinfo=UTC),
    trace_id="trace-abc",
)


def artifact(name: str, payload: bytes, kind: ArtifactKind, media_type: str) -> Artifact:
    return Artifact(name, kind, media_type, len(payload), sha256_hex(payload))


#: object store holding the archive, its manifest, and the original payloads
Written = tuple[FakeObjectStore, Manifest, dict[str, bytes]]


@pytest.fixture
def written() -> Written:
    payloads = {"dom.html.gz": DOM, "screenshot.png": SHOT, "network.har": HAR}
    manifest = build_manifest(
        [
            artifact("dom.html.gz", DOM, ArtifactKind.DOM, "text/html"),
            artifact("screenshot.png", SHOT, ArtifactKind.SCREENSHOT_FULLPAGE, "image/png"),
            artifact("network.har", HAR, ArtifactKind.HAR, "application/json"),
        ],
        CAPTURE,
    )
    store = FakeObjectStore()
    WarcBundleArchive(store).write(KEY, build_manifest_document(manifest), manifest, payloads)
    return store, manifest, payloads


def test_the_object_is_a_gzipped_warc(written: Written) -> None:
    """Checked at the byte level, without warcio or our adapter."""
    store, _, _ = written
    raw = store.get(KEY)

    assert raw[:2] == b"\x1f\x8b", "not gzip"
    assert gzip.decompress(raw).startswith(b"WARC/1."), "not a WARC record stream"


def test_an_independent_reader_recovers_every_artifact_byte_for_byte(written: Written) -> None:
    """warcio's own iterator, driven directly — not through our read()."""
    store, _, payloads = written

    recovered: dict[str, bytes] = {}
    for record in ArchiveIterator(BytesIO(store.get(KEY))):
        if record.rec_type != "resource":
            continue
        uri = record.rec_headers.get_header("WARC-Target-URI")
        recovered[uri.rsplit(":", 1)[-1]] = record.content_stream().read()

    assert recovered == payloads


def test_media_types_survive_the_round_trip(written: Written) -> None:
    """A reader has to know a PNG is a PNG without consulting our database."""
    store, _, _ = written

    types = {}
    for record in ArchiveIterator(BytesIO(store.get(KEY))):
        if record.rec_type != "resource":
            continue
        uri = record.rec_headers.get_header("WARC-Target-URI")
        types[uri.rsplit(":", 1)[-1]] = record.rec_headers.get_header("Content-Type")

    assert types["screenshot.png"] == "image/png"
    assert types["dom.html.gz"] == "text/html"


def test_capture_metadata_travels_with_the_bundle(written: Written) -> None:
    """D-19 — the bundle carries what a reader needs to interpret it."""
    store, _, _ = written

    warcinfo = next(r for r in ArchiveIterator(BytesIO(store.get(KEY))) if r.rec_type == "warcinfo")
    body = warcinfo.content_stream().read().decode()
    assert "https://example.org/post/1" in body
    assert "2026-08-04T08:40:00+00:00" in body


def test_the_manifest_is_not_itself_an_artifact(written: Written) -> None:
    """It describes the artifacts; counting it as one would fail verification."""
    store, manifest, _ = written

    read_back = WarcBundleArchive(store).read(KEY)
    assert set(read_back) == {a.name for a in manifest.artifacts}
    assert "manifest.json" not in read_back

    # Payloads must be read *during* iteration: ArchiveIterator invalidates a
    # record's content stream as soon as it advances to the next one, so
    # collecting records first and reading them afterwards yields empty bytes.
    manifests = [
        record.content_stream().read()
        for record in ArchiveIterator(BytesIO(store.get(KEY)))
        if record.rec_type == "metadata"
    ]
    assert len(manifests) == 1
    assert json.loads(manifests[0])["hash_algorithm"] == "sha256"


def test_a_bundle_read_back_verifies_against_its_manifest(written: Written) -> None:
    """The full loop: write, read, re-hash, compare."""
    store, manifest, _ = written

    read_back = WarcBundleArchive(store).read(KEY)
    observed = {name: sha256_hex(data) for name, data in read_back.items()}

    assert verify_manifest(manifest, observed) == ()


def test_non_ascii_content_survives_unchanged(written: Written) -> None:
    """Georgian is first-class and the original is always preserved."""
    store, _, _ = written
    read_back = WarcBundleArchive(store).read(KEY)
    assert read_back["dom.html.gz"].decode() == "<html><body>გამარჯობა</body></html>"


def test_a_record_planted_in_the_archive_fails_verification() -> None:
    """Invariant 1 against the real container, not the fake.

    An extra resource record is what tampering would look like inside a WARC,
    and enumerating the archive's own records is the only way to see it.
    """
    payload = b"<html>original</html>"
    manifest = build_manifest(
        [artifact("dom.html.gz", payload, ArtifactKind.DOM, "text/html")], CAPTURE
    )
    store = FakeObjectStore()
    archive = WarcBundleArchive(store)
    archive.write(KEY, build_manifest_document(manifest), manifest, {"dom.html.gz": payload})

    # Re-write the archive with an extra artifact the manifest does not list.
    planted = b"malicious payload"
    tampered_manifest = build_manifest(
        [
            artifact("dom.html.gz", payload, ArtifactKind.DOM, "text/html"),
            artifact("planted.js", planted, ArtifactKind.MEDIA, "text/javascript"),
        ],
        CAPTURE,
    )
    archive.write(
        KEY,
        build_manifest_document(tampered_manifest),
        tampered_manifest,
        {"dom.html.gz": payload, "planted.js": planted},
    )

    observed = {name: sha256_hex(data) for name, data in archive.read(KEY).items()}
    problems = verify_manifest(manifest, observed)

    assert any("absent from manifest: planted.js" in p for p in problems)


def test_records_carry_a_standard_warc_block_digest(written: Written) -> None:
    """Interoperability that costs nothing.

    WARC-Block-Digest is part of the format, so a generic archiving tool can
    confirm a payload is undamaged without knowing anything about ASIP's
    manifest. Two independent integrity mechanisms over the same bytes.
    """
    import base64
    import hashlib

    store, _, payloads = written

    for record in ArchiveIterator(BytesIO(store.get(KEY))):
        if record.rec_type != "resource":
            continue
        uri = record.rec_headers.get_header("WARC-Target-URI")
        name = uri.rsplit(":", 1)[-1]
        declared = record.rec_headers.get_header("WARC-Block-Digest")
        expected = base64.b32encode(hashlib.sha256(payloads[name]).digest()).decode()
        assert declared == f"sha256:{expected}", name


def test_appending_a_seal_leaves_a_readable_warc(written: Written) -> None:
    """WARC files concatenate, so sealing extends rather than rewrites.

    This is what keeps the archive append-only at the byte level: the artifact
    records written at capture time are never touched again.
    """
    store, _manifest, payloads = written
    archive = WarcBundleArchive(store)
    before = store.get(KEY)

    archive.append_seal(KEY, b'{"spec":"asip-seal-v1","chain":{}}')
    after = store.get(KEY)

    assert after.startswith(before), "sealing rewrote existing bytes"
    assert archive.read(KEY) == payloads, "artifacts changed after sealing"
    assert archive.read_seal(KEY) == b'{"spec":"asip-seal-v1","chain":{}}'

    # Still one valid WARC to a reader that knows nothing about seals.
    types = [r.rec_type for r in ArchiveIterator(BytesIO(after))]
    assert types.count("resource") == len(payloads)


def test_the_manifest_bytes_are_stored_verbatim(written: Written) -> None:
    """The digest is over these bytes, so they must survive untouched."""
    store, manifest, _ = written
    document = build_manifest_document(manifest)
    assert WarcBundleArchive(store).read_manifest(KEY) == document.raw
    assert sha256_hex(WarcBundleArchive(store).read_manifest(KEY)) == document.sha256
