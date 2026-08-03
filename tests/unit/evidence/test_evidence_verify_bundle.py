"""L2 — re-verifying a stored bundle.

This is the code behind "here is proof this is unaltered". Each test below is a
way that claim could be false.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from asip.contracts.evidence import BundleRef, VerificationOutcome
from asip.modules.evidence.application.verify_bundle import VerifyBundle
from asip.modules.evidence.application.write_bundle import WriteBundle
from asip.modules.evidence.domain.hashing import sha256_hex

from .fakes import FakeObjectStore, FakeRepository, FakeTimestampAuthority, FixedClock
from .test_evidence_write_bundle import AUTHORITY, TENANT, make_draft

#: object store, repository, TSA, and the reference to the sealed bundle
Sealed = tuple[FakeObjectStore, FakeRepository, FakeTimestampAuthority, BundleRef]


@pytest.fixture
def sealed() -> Sealed:
    objects, repo, tsa = FakeObjectStore(), FakeRepository(), FakeTimestampAuthority()
    draft, artifacts = make_draft()
    ref = WriteBundle(objects, repo, tsa, FixedClock(), AUTHORITY).execute(draft, artifacts)
    return objects, repo, tsa, ref


def verifier(
    objects: FakeObjectStore, repo: FakeRepository, tsa: FakeTimestampAuthority
) -> VerifyBundle:
    return VerifyBundle(objects, repo, tsa)


def test_an_untouched_bundle_verifies(sealed: Sealed) -> None:
    objects, repo, tsa, ref = sealed
    result = verifier(objects, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.VERIFIED
    assert result.manifest_ok and result.chain_ok and result.tsa_ok
    assert result.problems == ()


def test_altering_a_stored_artifact_is_detected(sealed: Sealed) -> None:
    """The scenario the product exists for: the bytes changed after capture."""
    objects, repo, tsa, ref = sealed
    key = next(k for k in objects.blobs if k.endswith("dom.html.gz"))
    objects.corrupt(key, b"<html>rewritten history</html>")

    result = verifier(objects, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.manifest_ok
    assert any("hash mismatch" in p for p in result.problems)


def test_planting_an_unlisted_object_is_detected(sealed: Sealed) -> None:
    objects, repo, tsa, ref = sealed
    prefix = next(k for k in objects.blobs).rsplit("/", 1)[0]
    objects.put(f"{prefix}/planted.js", b"payload", "text/javascript")

    result = verifier(objects, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.manifest_ok
    assert any("absent from manifest: planted.js" in p for p in result.problems)


def test_a_tampered_chain_entry_is_detected(sealed: Sealed) -> None:
    objects, repo, tsa, ref = sealed
    entry = repo.chains[TENANT][0]
    repo.replace_chain_entry(TENANT, 0, replace(entry, manifest_sha256=sha256_hex(b"substituted")))

    result = verifier(objects, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.chain_ok


def test_a_bundle_without_a_token_is_incomplete_not_verified() -> None:
    """Manifest and chain hold; the TSA has not answered yet.

    Neither verified nor broken. Collapsing this into either would make the
    other two states mean less.
    """
    objects, repo = FakeObjectStore(), FakeRepository()
    tsa = FakeTimestampAuthority()
    tsa.unreachable = True
    draft, artifacts = make_draft()
    ref = WriteBundle(objects, repo, tsa, FixedClock(), AUTHORITY).execute(draft, artifacts)

    tsa.unreachable = False
    result = verifier(objects, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.INCOMPLETE
    assert result.manifest_ok and result.chain_ok
    assert not result.tsa_ok
    assert any("no RFC 3161 token yet" in p for p in result.problems)


def test_a_token_that_stops_validating_is_a_failure(sealed: Sealed) -> None:
    """Distinct from having no token at all."""
    objects, repo, tsa, ref = sealed
    key = (TENANT, ref.bundle_id)
    stamp = repo.stamps[key][0]
    repo.stamps[key] = [replace(stamp, token=b"tsa:" + b"f" * 64)]

    result = verifier(objects, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert not result.tsa_ok
    assert any("does not validate" in p for p in result.problems)


def test_a_missing_bundle_reports_rather_than_raising(sealed: Sealed) -> None:
    objects, repo, tsa, ref = sealed
    repo.bundles.clear()

    result = verifier(objects, repo, tsa).execute(ref)

    assert result.outcome is VerificationOutcome.FAILED
    assert any("no bundle" in p for p in result.problems)


def test_every_check_runs_even_when_an_earlier_one_fails(sealed: Sealed) -> None:
    """An analyst needs the whole list, not the first thing that broke."""
    objects, repo, tsa, ref = sealed
    key = next(k for k in objects.blobs if k.endswith("dom.html.gz"))
    objects.corrupt(key, b"tampered")
    stamp_key = (TENANT, ref.bundle_id)
    repo.stamps[stamp_key] = [replace(repo.stamps[stamp_key][0], token=b"tsa:broken")]

    result = verifier(objects, repo, tsa).execute(ref)

    assert not result.manifest_ok
    assert not result.tsa_ok
    assert any("hash mismatch" in p for p in result.problems)
    assert any("does not validate" in p for p in result.problems)
