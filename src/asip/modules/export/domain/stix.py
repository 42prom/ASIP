"""L1 — STIX 2.1 serialisation.

Pure: values in, a bundle out. No I/O, no clock — timestamps are passed in, so
the same finding always exports to the same bytes (principle: reproducibility
over convenience).

Why STIX at all: findings have to be exchangeable with organisations that have
never heard of ASIP. A proprietary report format makes every recipient a
dependency on us, which is the same failure the WARC choice avoids for
evidence.

M-10 — deterministic UUIDv5 identifiers. Two independent workers exporting the
same finding produce the same STIX id, which gives deduplication without any
central coordination. Getting this wrong is expensive to fix later, because
identifiers leak into other organisations' systems and cannot be recalled.

V-5 — a `grouping` without an evidence reference is not exported. The bundle
builder refuses rather than emitting a claim nobody can check.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid5

#: The STIX namespace for deterministic SCO identifiers, from the 2.1 spec.
STIX_NAMESPACE = UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

#: ASIP's own extension namespace. Custom properties live under an extension
#: definition rather than as bare `x_` fields, which is what keeps the bundle
#: valid against a stock validator.
ASIP_EXTENSION_ID = "extension-definition--8f4a2b1e-0000-4000-8000-a51900000001"

SPEC_VERSION = "2.1"


class ExportRefused(ValueError):
    """The finding cannot be represented as a defensible STIX bundle."""


@dataclass(frozen=True, slots=True)
class FindingExport:
    """Everything needed to serialise one finding."""

    finding_id: UUID
    tenant_id: UUID
    rule_name: str
    source_url: str
    window_start: datetime
    window_end: datetime
    item_count: int
    account_count: int
    signals: Sequence[dict[str, Any]]
    evidence_refs: Sequence[UUID]
    manifest_digests: Sequence[str]
    shadow: bool
    detected_at: datetime


def deterministic_id(object_type: str, *parts: str) -> str:
    """A STIX id that two independent workers agree on (M-10).

    UUIDv5 over the ID-contributing properties, so the identifier is a function
    of the content rather than of when or where it was generated.
    """
    return f"{object_type}--{uuid5(STIX_NAMESPACE, '|'.join(parts))}"


def build_bundle(finding: FindingExport) -> dict[str, Any]:
    """Serialise one finding as a STIX 2.1 bundle.

    Produces an `observed-data` object for the measured activity, a `grouping`
    that ties it to the evidence, and a `note` carrying the signal breakdown.

    The verdict language is deliberately careful. A finding from a shadow rule
    is labelled as an unvalidated observation, because exporting a shadow
    finding as though it were a confirmed campaign would put an unmeasured
    claim into someone else's threat intelligence — where it would be indexed,
    forwarded, and impossible to retract.
    """
    if not finding.evidence_refs:
        raise ExportRefused(
            f"finding {finding.finding_id} has no evidence references; V-5 forbids "
            "exporting a grouping that rests on nothing"
        )
    if len(finding.signals) < 3:
        raise ExportRefused(
            f"finding {finding.finding_id} carries {len(finding.signals)} signals; "
            "D-29 requires at least three"
        )

    observed_id = deterministic_id("observed-data", str(finding.finding_id), "observed")
    note_id = deterministic_id("note", str(finding.finding_id), "signals")
    grouping_id = deterministic_id("grouping", str(finding.finding_id), "grouping")

    created = _stix_time(finding.detected_at)

    observed_data: dict[str, Any] = {
        "type": "observed-data",
        "spec_version": SPEC_VERSION,
        "id": observed_id,
        "created": created,
        "modified": created,
        "first_observed": _stix_time(finding.window_start),
        "last_observed": _stix_time(finding.window_end),
        "number_observed": finding.item_count,
        "object_refs": [],
        "extensions": {
            ASIP_EXTENSION_ID: {
                "extension_type": "property-extension",
                "account_count": finding.account_count,
                "source_url": finding.source_url,
                "rule_name": finding.rule_name,
                # Named plainly so a recipient cannot mistake an unvalidated
                # observation for a measured one.
                "detection_status": "shadow_unvalidated" if finding.shadow else "measured",
            }
        },
    }

    note: dict[str, Any] = {
        "type": "note",
        "spec_version": SPEC_VERSION,
        "id": note_id,
        "created": created,
        "modified": created,
        "abstract": f"Signal breakdown for {finding.rule_name}",
        "content": _render_signals(finding),
        "object_refs": [observed_id],
    }

    grouping: dict[str, Any] = {
        "type": "grouping",
        "spec_version": SPEC_VERSION,
        "id": grouping_id,
        "created": created,
        "modified": created,
        "name": f"Coordinated posting window — {finding.rule_name}",
        "context": "suspicious-activity",
        "object_refs": [observed_id, note_id],
        "extensions": {
            ASIP_EXTENSION_ID: {
                "extension_type": "property-extension",
                # V-5 travels with the export: the evidence bundles are named
                # in the object itself, so a recipient can ask for them.
                "evidence_bundle_ids": [str(ref) for ref in finding.evidence_refs],
                "evidence_manifest_sha256": list(finding.manifest_digests),
                "verification": (
                    "Each evidence bundle is a WARC carrying its own manifest, hash-chain "
                    "entry and RFC 3161 token, verifiable without ASIP software."
                ),
            }
        },
    }

    return {
        "type": "bundle",
        "id": deterministic_id("bundle", str(finding.finding_id)),
        "objects": [_extension_definition(created), observed_data, note, grouping],
    }


def _extension_definition(created: str) -> dict[str, Any]:
    """Declares ASIP's custom properties (M-16).

    Without this a validator rejects the extension as unknown. Declaring it
    inside the bundle means the bundle is self-describing — the recipient does
    not have to fetch a schema from us to make sense of it.
    """
    return {
        "type": "extension-definition",
        "spec_version": SPEC_VERSION,
        "id": ASIP_EXTENSION_ID,
        "created": created,
        "modified": created,
        "name": "ASIP coordination observation",
        "description": (
            "Behavioural coordination measurements and evidence bundle references. "
            "Carries no assertion about any named individual."
        ),
        "schema": "https://github.com/42prom/ASIP",
        "version": "1.0.0",
        "extension_types": ["property-extension"],
    }


def _render_signals(finding: FindingExport) -> str:
    """The signal breakdown as readable text.

    Every measurement, its threshold, and whether it fired — the same thing the
    analyst saw. A recipient who disagrees with the conclusion can see exactly
    which measurement they disagree with.
    """
    lines = [f"Rule: {finding.rule_name}"]
    if finding.shadow:
        lines.append(
            "STATUS: shadow mode — this rule has no measured precision and this "
            "observation is not a verdict."
        )
    lines.append(f"Window: {_stix_time(finding.window_start)} to {_stix_time(finding.window_end)}")
    lines.append(f"Items: {finding.item_count} from {finding.account_count} distinct accounts")
    lines.append("")
    lines.append("Signals:")
    for signal in finding.signals:
        mark = "PASS" if signal.get("passed") else "----"
        lines.append(
            f"  [{mark}] {signal.get('name')}: observed {signal.get('observed')}, "
            f"threshold {signal.get('threshold')} — {signal.get('description', '')}"
        )
    return "\n".join(lines)


def _stix_time(value: datetime) -> str:
    """STIX timestamps: UTC, millisecond precision, trailing Z.

    A naive datetime is treated as UTC rather than guessed at. Guessing a local
    zone would silently shift an exported observation by hours, and the
    recipient would have no way to know.
    """
    moment = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
