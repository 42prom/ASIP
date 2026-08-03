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
from asip.contracts.ports.evidence import EvidenceRepository, ObjectStore, TimestampAuthority

from ..domain.chain import verify_chain
from ..domain.hashing import sha256_hex
from ..domain.manifest import manifest_digest, verify_manifest


class VerifyBundle:
    """Re-verify a bundle from storage."""

    def __init__(
        self,
        object_store: ObjectStore,
        repository: EvidenceRepository,
        timestamp_authority: TimestampAuthority,
    ) -> None:
        self._objects = object_store
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

        recomputed = manifest_digest(record.manifest)
        if recomputed != record.manifest_sha256:
            problems.append(
                f"manifest digest does not match the stored value "
                f"(stored {record.manifest_sha256}, recomputed {recomputed})"
            )

        # Discover what is actually stored rather than re-hashing only what the
        # manifest admits to. Listing the prefix is what lets verify_manifest
        # report a planted file; walking the manifest's own entries never can.
        prefix = f"{record.object_prefix}/"
        observed: dict[str, str] = {}
        for key in self._objects.list_prefix(prefix):
            name = key[len(prefix) :]
            observed[name] = sha256_hex(self._objects.get(key))

        problems.extend(verify_manifest(record.manifest, observed))
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
