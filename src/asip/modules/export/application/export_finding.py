"""L2 — the only path from a finding to a stored STIX bundle.

Both the pipeline and the review console reach Tier 2 through here, so the
question "may this leave Tier 1" has exactly one answer rather than one per
caller. M-06 draws that boundary at `LIKELY_COORDINATION`; the domain refuses
below it and this use case reports the refusal instead of swallowing it.

Serialisation is deterministic and the stored bytes are the bytes that were
hashed. A recipient may hash the copy we handed them, and a stored version that
differs by key order would not match.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Protocol
from uuid import UUID

from asip.modules.export.domain.stix import (
    EXPORTABLE_VERDICTS,
    ExportRefused,
    FindingExport,
    build_bundle,
)


class ExportRepository(Protocol):
    """What storage must offer. Narrow on purpose (D-99)."""

    def record_export(
        self,
        export_id: UUID,
        tenant_id: UUID,
        finding_id: UUID,
        trace_id: str,
        bundle_json: str,
        bundle_sha256: str,
        object_count: int,
    ) -> None: ...


@dataclass(frozen=True, slots=True)
class ExportOutcome:
    """What happened, including when nothing did.

    A caller that cannot tell "exported nothing because there was nothing" from
    "exported nothing because the boundary held" will eventually report the
    wrong one to an operator.
    """

    finding_id: UUID
    exported: bool
    reason: str
    export_id: UUID | None = None
    bundle_sha256: str | None = None
    object_count: int = 0


class ExportFinding:
    def __init__(self, repository: ExportRepository) -> None:
        self._repository = repository

    def execute(self, finding: FindingExport, trace_id: str) -> ExportOutcome:
        try:
            bundle = build_bundle(finding)
        except ExportRefused as refusal:
            return ExportOutcome(finding.finding_id, exported=False, reason=str(refusal))

        # sort_keys so two workers exporting the same finding produce identical
        # bytes, and therefore identical digests (M-10).
        payload = json.dumps(bundle, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode()).hexdigest()
        export_id = uuid.uuid4()

        self._repository.record_export(
            export_id,
            finding.tenant_id,
            finding.finding_id,
            trace_id,
            payload,
            digest,
            len(bundle["objects"]),
        )

        return ExportOutcome(
            finding.finding_id,
            exported=True,
            reason=f"verdict {finding.verdict} crosses the M-06 boundary",
            export_id=export_id,
            bundle_sha256=digest,
            object_count=len(bundle["objects"]),
        )


def crosses_the_boundary(verdict: str | None) -> bool:
    """M-06, for callers deciding whether to bother assembling a finding.

    The authoritative refusal still lives in the domain — this is a cheap
    pre-check, never the enforcement.
    """
    return verdict in EXPORTABLE_VERDICTS
