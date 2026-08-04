"""tools/verify_asip_bundle.py must verify a real bundle with no ASIP code.

This is the executable form of the claim that evidence outlives the software
that produced it. The verifier is run as a subprocess against a bundle this
suite seals, with the repository's ``src`` deliberately kept off its import
path — so if it ever grows an ``import asip``, these tests fail rather than
quietly passing because the package happened to be installed.

A bundle that only ASIP can verify is not evidence anyone else can rely on.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from asip.contracts.evidence import Artifact, ArtifactKind
from asip.modules.evidence.adapters.warc_archive import WarcBundleArchive
from asip.modules.evidence.application.write_bundle import ARCHIVE_OBJECT_NAME, WriteBundle
from asip.modules.evidence.domain.hashing import sha256_hex

from .fakes import FakeObjectStore, FakeRepository, FakeTimestampAuthority, FixedClock

VERIFIER = Path(__file__).resolve().parents[3] / "tools" / "verify_asip_bundle.py"
TENANT = UUID("aaaaaaaa-1111-1111-1111-111111111111")
DOM = "<html><body>დღეს ამინდი კარგია</body></html>".encode()
SHOT = b"\x89PNG\r\n\x1a\n" + b"pixel" * 50


def seal_a_bundle(tmp_path: Path, tsa: FakeTimestampAuthority | None = None) -> Path:
    """Write a real bundle through the real pipeline, onto disk."""
    store = FakeObjectStore()
    archive = WarcBundleArchive(store)
    repo = FakeRepository()
    authority = tsa or FakeTimestampAuthority()

    from asip.contracts.evidence import BundleDraft

    bundle_id = uuid4()
    artifacts = {"dom.html.gz": DOM, "screenshot.png": SHOT}
    draft = BundleDraft(
        bundle_id=bundle_id,
        capture_id=uuid4(),
        tenant_id=TENANT,
        trace_id="trace-standalone",
        source_url="https://example.org/post/1",
        captured_at=datetime(2026, 8, 4, 8, 40, tzinfo=UTC),
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
    )
    ref = WriteBundle(archive, repo, authority, FixedClock(), "https://tsa.example.org").execute(
        draft, artifacts
    )

    path = tmp_path / "bundle.warc.gz"
    path.write_bytes(store.get(f"{ref.tenant_id}/{ref.bundle_id}/{ARCHIVE_OBJECT_NAME}"))
    return path


def run_verifier(bundle: Path) -> subprocess.CompletedProcess[str]:
    """Run the verifier with the project's source kept off sys.path.

    ``-I`` isolates the interpreter: no site-packages additions from the
    environment, no PYTHONPATH, no current directory on the path. If the
    verifier imports anything from ASIP, it fails here.
    """
    return subprocess.run(
        [sys.executable, "-I", str(VERIFIER), str(bundle)],
        capture_output=True,
        text=True,
        cwd=bundle.parent,
    )


def test_the_verifier_imports_nothing_from_asip() -> None:
    """Checked by reading the file, before any behaviour is exercised."""
    source = VERIFIER.read_text(encoding="utf-8")
    assert "import asip" not in source
    assert "from asip" not in source


def test_a_sealed_bundle_verifies_standalone(tmp_path: Path) -> None:
    bundle = seal_a_bundle(tmp_path)
    result = run_verifier(bundle)

    assert result.returncode == 0, result.stdout + result.stderr
    assert "every check that could run passed" in result.stdout
    assert "chain entry 0 recomputes correctly" in result.stdout


def test_the_standalone_verifier_recomputes_the_same_chain_hash(tmp_path: Path) -> None:
    """The two implementations of the preimage must agree.

    The verifier reimplements the chain preimage from the recipe carried inside
    the seal, independently of ``domain/chain.py``. If the two ever diverge,
    the specification and the implementation have drifted apart — and the
    specification is the one strangers will use.
    """
    bundle = seal_a_bundle(tmp_path)
    result = run_verifier(bundle)
    assert result.returncode == 0, result.stdout + result.stderr

    from asip.modules.evidence.domain.chain import compute_entry_hash

    archive = WarcBundleArchive(_DiskStore(bundle))
    seal = json.loads(archive.read_seal("ignored") or b"{}")
    chain = seal["chain"]

    ours = compute_entry_hash(
        UUID(chain["tenant_id"]),
        chain["chain_index"],
        chain["prev_hash"],
        seal["manifest_sha256"],
        UUID(chain["bundle_id"]),
        chain["algorithm"],
    )
    assert ours == chain["entry_hash"]


def test_tampering_with_an_artifact_is_caught_standalone(tmp_path: Path) -> None:
    """The whole claim, checked by software that has never seen ASIP."""
    bundle = seal_a_bundle(tmp_path)
    raw = bundle.read_bytes()

    # Rewrite the archive with altered content but the original manifest.
    store = _DiskStore(bundle)
    archive = WarcBundleArchive(store)
    manifest_bytes = archive.read_manifest("k")
    from asip.modules.evidence.domain.manifest import parse_manifest_document

    manifest = parse_manifest_document(manifest_bytes)
    from asip.contracts.evidence import ManifestDocument

    archive.write(
        "k",
        ManifestDocument(raw=manifest_bytes, sha256=sha256_hex(manifest_bytes)),
        manifest,
        {"dom.html.gz": b"<html>rewritten history</html>", "screenshot.png": SHOT},
    )
    bundle.write_bytes(store.blobs["k"])
    assert bundle.read_bytes() != raw

    result = run_verifier(bundle)
    assert result.returncode == 1
    assert "archive contains" in result.stderr


def test_an_unsealed_bundle_is_reported_as_lacking_attestation(tmp_path: Path) -> None:
    """A bundle with no seal has intact content and no provable date.

    The verifier says so rather than passing, because "the bytes are unchanged"
    and "this existed on that date" are different claims and only the second
    needs a third party.
    """
    store = FakeObjectStore()
    archive = WarcBundleArchive(store)

    from asip.contracts.evidence import CaptureBinding
    from asip.modules.evidence.domain.manifest import build_manifest, build_manifest_document

    capture = CaptureBinding(
        bundle_id=uuid4(),
        tenant_id=TENANT,
        capture_id=uuid4(),
        source_url="https://example.org/post/1",
        captured_at=datetime(2026, 8, 4, 8, 40, tzinfo=UTC),
        trace_id="t",
    )
    manifest = build_manifest(
        [Artifact("dom.html.gz", ArtifactKind.DOM, "text/html", len(DOM), sha256_hex(DOM))],
        capture,
    )
    archive.write("k", build_manifest_document(manifest), manifest, {"dom.html.gz": DOM})

    bundle = tmp_path / "unsealed.warc.gz"
    bundle.write_bytes(store.blobs["k"])

    result = run_verifier(bundle)
    assert result.returncode == 1
    assert "no seal record" in result.stderr


def test_the_seal_carries_the_recipe_for_recomputing_the_chain(tmp_path: Path) -> None:
    """Principle 8: the instructions travel with the evidence.

    A verifier in 2045 should not have to find this repository.
    """
    bundle = seal_a_bundle(tmp_path)
    seal = json.loads(WarcBundleArchive(_DiskStore(bundle)).read_seal("k") or b"{}")

    assert "SHA256" in seal["chain_preimage_recipe"]
    assert "uint64" in seal["chain_preimage_recipe"]
    assert "Do not re-serialise" in seal["manifest_digest_recipe"]
    assert "No ASIP software is required" in seal["verification"]


class _DiskStore:
    """Minimal ObjectStore over one file, for reading a bundle back."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.blobs: dict[str, bytes] = {}

    def put(self, key: str, data: bytes, media_type: str) -> None:
        self.blobs[key] = data

    def get(self, key: str) -> bytes:
        return self.blobs.get(key, self.path.read_bytes())

    def exists(self, key: str) -> bool:
        return True

    def list_prefix(self, prefix: str) -> tuple[str, ...]:
        return ()


@pytest.mark.parametrize("record_type", ["manifest", "seal"])
def test_both_control_records_survive_a_disk_round_trip(tmp_path: Path, record_type: str) -> None:
    bundle = seal_a_bundle(tmp_path)
    archive = WarcBundleArchive(_DiskStore(bundle))
    payload = archive.read_manifest("k") if record_type == "manifest" else archive.read_seal("k")
    assert payload
    assert json.loads(payload)
