"""L2 — re-verifying a stored bundle.

This is the code behind "here is proof this is unaltered". Each test below is a
way that claim could be false.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from asip.contracts.evidence import BundleRef, VerificationOutcome
from asip.modules.evidence.application.verify_bundle import VerifyBundle
from asip.modules.evidence.application.write_bundle import ARCHIVE_OBJECT_NAME, WriteBundle
from asip.modules.evidence.domain.hashing import sha256_hex

from .fakes import FakeArchive, FakeRepository, FakeTimestampAuthority, FixedClock
from .test_evidence_write_bundle import AUTHORITY, TENANT, make_draft

#: archive, repository, TSA, and the reference to the sealed bundle
Sealed = tuple[FakeArchive, FakeRepository, FakeTimestampAuthority, BundleRef]


@pytest.fixture
def sealed() -> Sealed:
    archive, repo, tsa = FakeArchive(), FakeRepository(), FakeTimestampAuthority()
    draft, artifacts = make_draft()
    ref = WriteBundle(archive, repo, tsa, FixedClock(), AUTHORITY).execute(draft, artifacts)
    return archive, repo, tsa, ref


def verifier(
    archive: FakeArchive, repo: FakeRepository, tsa: FakeTimestampAuthority
) -> VerifyBundle:
    return VerifyBundle(archive, repo, tsa)


def test_an_untouched_bundle_verifies(sealed: Sealed) -> None:
    archive, repo, tsa, ref = sealed
    result = verifier(archive, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.VERIFIED
    assert result.manifest_ok and result.chain_ok and result.tsa_ok
    assert result.problems == ()


def archive_key(ref: BundleRef) -> str:
    return f"{ref.tenant_id}/{ref.bundle_id}/{ARCHIVE_OBJECT_NAME}"


def test_altering_a_stored_artifact_is_detected(sealed: Sealed) -> None:
    """The scenario the product exists for: the bytes changed after capture."""
    archive, repo, tsa, ref = sealed
    archive.corrupt(archive_key(ref), "dom.html.gz", b"<html>rewritten history</html>")

    result = verifier(archive, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.manifest_ok
    assert any("hash mismatch" in p for p in result.problems)


def test_planting_a_record_inside_the_archive_is_detected(sealed: Sealed) -> None:
    """Invariant 1 — an unlisted record is where tampered content would go."""
    archive, repo, tsa, ref = sealed
    archive.plant(archive_key(ref), "planted.js", b"payload")

    result = verifier(archive, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.manifest_ok
    assert any("absent from manifest: planted.js" in p for p in result.problems)


def test_a_missing_archive_is_reported_rather_than_raising(sealed: Sealed) -> None:
    """Storage losing the bundle is a verification failure, not a crash."""
    archive, repo, tsa, ref = sealed
    archive.archives.clear()

    result = verifier(archive, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.manifest_ok
    assert any("archive could not be read" in p for p in result.problems)


def test_a_tampered_chain_entry_is_detected(sealed: Sealed) -> None:
    archive, repo, tsa, ref = sealed
    entry = repo.chains[TENANT][0]
    repo.replace_chain_entry(TENANT, 0, replace(entry, manifest_sha256=sha256_hex(b"substituted")))

    result = verifier(archive, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.chain_ok


def test_a_bundle_without_a_token_is_incomplete_not_verified() -> None:
    """Manifest and chain hold; the TSA has not answered yet.

    Neither verified nor broken. Collapsing this into either would make the
    other two states mean less.
    """
    archive, repo = FakeArchive(), FakeRepository()
    tsa = FakeTimestampAuthority()
    tsa.unreachable = True
    draft, artifacts = make_draft()
    ref = WriteBundle(archive, repo, tsa, FixedClock(), AUTHORITY).execute(draft, artifacts)

    tsa.unreachable = False
    result = verifier(archive, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.INCOMPLETE
    assert result.manifest_ok and result.chain_ok
    assert not result.tsa_ok
    assert any("no RFC 3161 token yet" in p for p in result.problems)


def test_a_token_that_stops_validating_is_a_failure(sealed: Sealed) -> None:
    """Distinct from having no token at all."""
    archive, repo, tsa, ref = sealed
    key = (TENANT, ref.bundle_id)
    stamp = repo.stamps[key][0]
    repo.stamps[key] = [replace(stamp, token=b"tsa:" + b"f" * 64)]

    result = verifier(archive, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.tsa_ok
    assert any("does not validate" in p for p in result.problems)


def test_a_missing_bundle_reports_rather_than_raising(sealed: Sealed) -> None:
    archive, repo, tsa, ref = sealed
    repo.bundles.clear()

    result = verifier(archive, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert any("no bundle" in p for p in result.problems)


def test_every_check_runs_even_when_an_earlier_one_fails(sealed: Sealed) -> None:
    """An analyst needs the whole list, not the first thing that broke."""
    archive, repo, tsa, ref = sealed
    archive.corrupt(archive_key(ref), "dom.html.gz", b"tampered")
    stamp_key = (TENANT, ref.bundle_id)
    repo.stamps[stamp_key] = [replace(repo.stamps[stamp_key][0], token=b"tsa:broken")]

    result = verifier(archive, repo, tsa).execute(ref)

    assert not result.manifest_ok
    assert not result.tsa_ok
    assert any("hash mismatch" in p for p in result.problems)
    assert any("does not validate" in p for p in result.problems)
