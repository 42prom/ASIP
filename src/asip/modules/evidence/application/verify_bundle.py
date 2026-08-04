"""L2 — re-verify a stored bundle.

One-click re-verification is the product's central claim: a journalist has to
be able to say *"here is the post, here is proof of what it said, here is proof
of when we captured it"* after the post is gone. This is the code behind that
sentence.

Three independent checks, all of them run even when an earlier one fails,
because an analyst needs to know everything that is wrong rather than the first
thing that went wrong:

1. **Manifest** — do the bytes in the object store still hash to what the
   manifest says, and is every stored object listed?
2. **Chain** — does the bundle's entry still hash to its contents, and does it
   link to its neighbours?
3. **TSA** — does a third party's token still validate the manifest digest?

The outcome is never reduced to a score. ``problems`` names the failing check,
because a number is not something anyone can defend in print.
"""

from __future__ import annotations

from asip.contracts.evidence import (
    BundleRef,
    StoredBundle,
    VerificationOutcome,
    VerificationResult,
)
from asip.contracts.ports.evidence import BundleArchive, EvidenceRepository, TimestampAuthority

from ..domain.chain import verify_chain
from ..domain.hashing import sha256_hex
from ..domain.manifest import parse_manifest_document, verify_manifest
from .write_bundle import ARCHIVE_OBJECT_NAME


class VerifyBundle:
    """Re-verify a bundle from storage."""

    def __init__(
        self,
        archive: BundleArchive,
        repository: EvidenceRepository,
        timestamp_authority: TimestampAuthority,
    ) -> None:
        self._archive = archive
        self._repository = repository
        self._tsa = timestamp_authority

    def execute(self, ref: BundleRef) -> VerificationResult:
        stored = self._repository.load_bundle(ref.tenant_id, ref.bundle_id)
        if stored is None:
            return VerificationResult(
                outcome=VerificationOutcome.FAILED,
                manifest_ok=False,
                chain_ok=False,
                tsa_ok=False,
                problems=(f"no bundle {ref.bundle_id} for tenant {ref.tenant_id}",),
            )

        manifest_problems = self._check_manifest(stored)
        chain_problems = self._check_chain(stored)
        tsa_problems, has_token = self._check_timestamp(stored)

        manifest_ok = not manifest_problems
        chain_ok = not chain_problems
        tsa_ok = has_token and not tsa_problems

        return VerificationResult(
            outcome=self._outcome(manifest_ok, chain_ok, tsa_ok, has_token),
            manifest_ok=manifest_ok,
            chain_ok=chain_ok,
            tsa_ok=tsa_ok,
            problems=tuple(manifest_problems + chain_problems + tsa_problems),
        )

    def _check_manifest(self, stored: StoredBundle) -> list[str]:
        """Re-hash what is actually in the object store."""
        problems: list[str] = []
        record = stored.record
        key = f"{record.object_prefix}/{ARCHIVE_OBJECT_NAME}"

        try:
            archived_manifest = self._archive.read_manifest(key)
            stored_artifacts = self._archive.read(key)
        except Exception as exc:
            problems.append(f"bundle archive could not be read: {exc}")
            return problems

        # The digest is over the bytes in the archive. Hashing what is actually
        # there — rather than re-serialising the parsed manifest and hashing
        # that — is what makes this check reproducible by any tool, in any
        # language, without reproducing our serialiser.
        archived_digest = sha256_hex(archived_manifest)
        if archived_digest != record.manifest_sha256:
            problems.append(
                f"manifest in the archive hashes to {archived_digest}, "
                f"database records {record.manifest_sha256}"
            )

        try:
            manifest = parse_manifest_document(archived_manifest)
        except Exception as exc:
            problems.append(f"manifest document could not be parsed: {exc}")
            return problems

        # The manifest binds the capture it describes, so a bundle relabelled
        # as a capture of some other page fails here rather than nowhere.
        if manifest.capture.bundle_id != record.bundle_id:
            problems.append(
                f"manifest attests to bundle {manifest.capture.bundle_id}, "
                f"stored as {record.bundle_id}"
            )
        if manifest.capture.source_url != record.source_url:
            problems.append(
                f"manifest attests to {manifest.capture.source_url}, "
                f"database records {record.source_url}"
            )

        observed = {name: sha256_hex(data) for name, data in stored_artifacts.items()}
        problems.extend(verify_manifest(manifest, observed))
        return problems

    def _check_chain(self, stored: StoredBundle) -> list[str]:
        """Verify the entry against its neighbours, not in isolation.

        An entry checked alone only proves it is internally consistent, which
        an attacker who rewrites one record achieves trivially. The link to the
        preceding entry is what makes it evidence.
        """
        entry = stored.chain_entry
        problems: list[str] = []

        if entry.manifest_sha256 != stored.record.manifest_sha256:
            problems.append(
                f"chain entry {entry.chain_index} attests to a different manifest "
                f"(entry {entry.manifest_sha256}, bundle {stored.record.manifest_sha256})"
            )

        start = max(entry.chain_index - 1, 0)
        segment = self._repository.segment(entry.tenant_id, start, entry.chain_index + 1)
        problems.extend(verify_chain(segment))
        return problems

    def _check_timestamp(self, stored: StoredBundle) -> tuple[list[str], bool]:
        """Validate every token against the authority.

        Returns the problems found and whether a token exists at all. The two
        are different answers and the caller must not conflate them:

        - **No token** — INCOMPLETE. The bundle may be minutes old with the TSA
          still retrying. Calling that verified would be a lie; calling it
          broken would train analysts to ignore the check.
        - **A token that does not validate** — FAILED. Something attested to
          this digest and no longer agrees, which is exactly the condition the
          timestamp exists to detect.
        """
        if not stored.timestamps:
            return ([f"bundle {stored.record.bundle_id} has no RFC 3161 token yet"], False)

        # A token nobody here can check is not a token that failed. If the
        # authority's certificate is not configured, or the installed library
        # cannot handle its signature algorithm, the honest answer is
        # "unconfirmed" — reporting FAILED would tell an analyst their evidence
        # had been tampered with when the only thing wrong is our configuration.
        if not self._tsa.can_verify():
            return (
                [
                    f"bundle {stored.record.bundle_id} carries "
                    f"{len(stored.timestamps)} RFC 3161 token(s) that could not be "
                    "checked here: no authority certificate is configured for "
                    "verification. The tokens are stored and remain checkable."
                ],
                False,
            )

        problems: list[str] = []
        for stamp in stored.timestamps:
            if stamp.manifest_sha256 != stored.record.manifest_sha256:
                problems.append(
                    f"timestamp attests to {stamp.manifest_sha256}, "
                    f"bundle manifest is {stored.record.manifest_sha256}"
                )
                continue
            if not self._tsa.verify(stamp.manifest_sha256, stamp.token):
                problems.append(f"RFC 3161 token from {stamp.authority_url} does not validate")

        return (problems, True)

    @staticmethod
    def _outcome(
        manifest_ok: bool, chain_ok: bool, tsa_ok: bool, has_token: bool
    ) -> VerificationOutcome:
        if not manifest_ok or not chain_ok:
            return VerificationOutcome.FAILED
        if tsa_ok:
            return VerificationOutcome.VERIFIED
        if has_token:
            # A token exists and does not validate. That is a failure, not an
            # absence — something attested to this digest and no longer agrees.
            return VerificationOutcome.FAILED
        # Manifest and chain hold; the timestamp has not arrived yet. Neither
        # verified nor broken, which is why there are three states and not two.
        return VerificationOutcome.INCOMPLETE
