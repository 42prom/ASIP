"""L2 — write an evidence bundle.

Orchestration only. Every decision about what a correct manifest or a correct
chain link looks like lives in L1; this module sequences the steps, owns the
transaction boundary, and decides what happens when a step fails.

THE TRANSACTION BOUNDARY (docs/WALKING_SKELETON.md question 2)
--------------------------------------------------------------
Three writes, in this order, chosen deliberately:

1. **Artifacts to the object store.** Keyed by bundle id, so re-running with
   the same bytes overwrites with identical content. A crash here leaves
   orphaned blobs, which cost storage and prove nothing — harmless.

2. **Bundle record and chain entry, in one transaction.** Both or neither.
   This is the pair that must not diverge: a chain entry attesting to a bundle
   that does not exist would make the chain a record of fiction, and a bundle
   missing from the chain is unattested. The port takes them together so no
   implementation can offer a way to write one alone.

3. **The RFC 3161 token, appended afterwards.** The TSA is a third party and
   may be slow or down. It is therefore outside the transaction, and a bundle
   whose token has not arrived is ``tsa_pending`` — retried later, never
   promoted to verified by any path in this module.

The failure window this leaves is deliberate and is the cheap direction: an
orphaned blob or a pending timestamp. The expensive direction — a chain that
disagrees with the bundles it describes — is closed by step 2 being atomic.

This ordering is a design decision made before an adapter exists. The skeleton
exists to test it against real transaction semantics; if Postgres and the
object store disagree with the reasoning above, the finding goes in LEARNINGS
and this docstring changes.
"""

from __future__ import annotations

from collections.abc import Mapping

from asip.contracts.evidence import (
    BundleDraft,
    BundleRecord,
    BundleRef,
    ChainEntry,
    TimestampRecord,
    TsaStatus,
)
from asip.contracts.ports.clock import Clock
from asip.contracts.ports.evidence import EvidenceRepository, ObjectStore, TimestampAuthority

from ..domain.chain import link
from ..domain.hashing import sha256_hex
from ..domain.manifest import build_manifest, manifest_digest

MANIFEST_OBJECT_NAME = "manifest.json"


class BundleIntegrityError(ValueError):
    """The artifacts handed in do not match the draft that describes them."""


class WriteBundle:
    """Seal a capture into a verifiable bundle."""

    def __init__(
        self,
        object_store: ObjectStore,
        repository: EvidenceRepository,
        timestamp_authority: TimestampAuthority,
        clock: Clock,
        authority_url: str,
    ) -> None:
        self._objects = object_store
        self._repository = repository
        self._tsa = timestamp_authority
        self._clock = clock
        self._authority_url = authority_url

    def execute(self, draft: BundleDraft, artifacts: Mapping[str, bytes]) -> BundleRef:
        self._reject_mismatched_artifacts(draft, artifacts)

        manifest = build_manifest(draft.artifacts)
        digest = manifest_digest(manifest)
        prefix = f"{draft.tenant_id}/{draft.bundle_id}"

        # Step 1 — blobs first. Idempotent; an orphan here is harmless.
        for artifact in manifest.artifacts:
            self._objects.put(
                f"{prefix}/{artifact.name}",
                artifacts[artifact.name],
                artifact.media_type,
            )

        # Step 2 — the atomic pair.
        entry = self._next_chain_entry(draft, digest)
        record = BundleRecord(
            bundle_id=draft.bundle_id,
            capture_id=draft.capture_id,
            tenant_id=draft.tenant_id,
            trace_id=draft.trace_id,
            source_url=draft.source_url,
            captured_at=draft.captured_at,
            manifest=manifest,
            manifest_sha256=digest,
            object_prefix=prefix,
            render_params=draft.render_params,
        )
        self._repository.commit_bundle(record, entry)

        # Step 3 — external timestamp, outside the transaction.
        tsa_status = self._timestamp(draft, digest)

        return BundleRef(
            bundle_id=draft.bundle_id,
            tenant_id=draft.tenant_id,
            chain_index=entry.chain_index,
            manifest_sha256=digest,
            tsa_status=tsa_status,
        )

    def _reject_mismatched_artifacts(
        self, draft: BundleDraft, artifacts: Mapping[str, bytes]
    ) -> None:
        """The draft's hashes must describe the bytes actually supplied.

        Checked here rather than trusted, because everything downstream — the
        manifest, the chain, the timestamp — attests to these hashes. Sealing a
        bundle whose manifest does not describe its own contents would produce
        evidence that fails verification the first time anyone checks it.
        """
        declared = {a.name for a in draft.artifacts}
        supplied = set(artifacts)

        if declared != supplied:
            missing = sorted(declared - supplied)
            extra = sorted(supplied - declared)
            raise BundleIntegrityError(
                f"draft and artifacts disagree: missing={missing}, unexpected={extra}"
            )

        for artifact in draft.artifacts:
            actual = sha256_hex(artifacts[artifact.name])
            if actual != artifact.sha256:
                raise BundleIntegrityError(
                    f"artifact {artifact.name!r} does not match its declared hash "
                    f"(declared {artifact.sha256}, actual {actual})"
                )

    def _next_chain_entry(self, draft: BundleDraft, digest: str) -> ChainEntry:
        head = self._repository.head(draft.tenant_id)
        return link(head, draft.tenant_id, draft.bundle_id, digest)

    def _timestamp(self, draft: BundleDraft, digest: str) -> TsaStatus:
        """Obtain and record an external timestamp.

        Returns PENDING on any failure. There is deliberately no branch that
        returns VERIFIED without a token that the authority itself validates:
        a timestamp this system generates proves nothing, and a status field
        that can be set without a token is exactly how that would creep in.
        """
        try:
            token = self._tsa.stamp(digest)
        except Exception:
            # Any TSA failure means pending, not failed. Broad on purpose: a
            # network error, a malformed response and an unexpected library
            # exception all mean the same thing here — no external token yet.
            return TsaStatus.PENDING

        if not self._tsa.verify(digest, token):
            return TsaStatus.FAILED

        self._repository.append_timestamp(
            TimestampRecord(
                tenant_id=draft.tenant_id,
                bundle_id=draft.bundle_id,
                manifest_sha256=digest,
                authority_url=self._authority_url,
                token=token,
                obtained_at=self._clock.now(),
            )
        )
        return TsaStatus.VERIFIED
