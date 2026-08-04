"""L1 — STIX 2.1 serialisation.

Pure: values in, a bundle out. No I/O, no clock — timestamps are passed in, so
the same finding always exports to the same bytes (reproducibility over
convenience).

Why STIX: findings must be exchangeable with organisations that have never
heard of ASIP. A proprietary report format makes every recipient dependent on
us, which is the failure the WARC choice avoids for evidence.

THE MODELLING DIRECTIVES THIS FILE IMPLEMENTS
---------------------------------------------
M-01  Social objects get their own SCO types via an extension. They are never
      stretched into `identity` or a bare `observed-data` — forcing a Facebook
      page into `identity` is the modelling error the mapping opens with.
M-03  A cluster is a `grouping` over SCOs. An `identity` SDO is NEVER created
      for a natural person. The only `identity` in a bundle is the producing
      organisation.
M-10  SCO ids are deterministic UUIDv5, so two independent workers exporting
      the same observation produce the same identifier.
M-15  Every grouping references at least one evidence bundle.
M-17  `object_refs` contains only SCOs. This is the technical enforcement of
      M-03: if the array cannot hold an `identity`, it cannot hold a person.
M-18  At least three independent signals.

WHAT WAS WRONG BEFORE
---------------------
The first version was written from memory of the spec and never validated. The
OASIS reference implementation rejected it on two counts: `extension-definition`
requires `created_by_ref`, and `observed-data` may not carry an empty
`object_refs`. Both are now fixed, and `make validate-stix` parses every object
with that implementation so the next mistake fails a gate instead of a
recipient.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid5

#: The STIX namespace for deterministic identifiers, from the 2.1 specification.
STIX_NAMESPACE = UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

ASIP_EXTENSION_ID = "extension-definition--8f4a2b1e-0000-4000-8000-a51900000001"

#: The producing organisation. An `identity` of class `organization` is what
#: `created_by_ref` must point at, and it is the ONLY identity a bundle
#: contains. M-03 forbids an identity for a natural person; it does not forbid
#: naming who produced the assessment, which a recipient needs in order to
#: weigh it.
ASIP_IDENTITY_ID = "identity--3d4a1c62-0000-4000-8000-a51900000010"

#: Custom SCO types, declared by the extension definition below (M-01).
ACCOUNT_SCO = "asip-account"
EVIDENCE_SCO = "asip-evidence-bundle"

SPEC_VERSION = "2.1"

#: M-06 — the Tier 1/Tier 2 boundary. Only these cross it. A finding with no
#: verdict, or one an analyst marked as insufficient, stays in Tier 1.
EXPORTABLE_VERDICTS = ("confirmed_coordination", "likely_coordination")


class ExportRefused(ValueError):
    """The finding must not become a STIX bundle."""


@dataclass(frozen=True, slots=True)
class ClusterMember:
    """One account in the cluster, as an observable.

    Carries no judgement. M-03's whole point is that the assessment attaches to
    the group; a member is a thing that was observed, not a thing that was
    accused.
    """

    account_id: UUID
    platform: str
    handle: str
    item_count: int


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
    members: Sequence[ClusterMember] = ()
    verdict: str | None = None


def deterministic_id(object_type: str, *parts: str) -> str:
    """A STIX id two independent workers agree on (M-10).

    UUIDv5 over the ID-contributing properties, so the identifier is a function
    of the content rather than of when or where it was generated. Getting this
    wrong is expensive later: identifiers leak into other organisations'
    systems and cannot be recalled.
    """
    return f"{object_type}--{uuid5(STIX_NAMESPACE, '|'.join(parts))}"


def build_bundle(finding: FindingExport) -> dict[str, Any]:
    """Serialise one finding as a STIX 2.1 bundle."""
    _refuse_if_unexportable(finding)

    created = _stix_time(finding.detected_at)
    objects: list[dict[str, Any]] = [
        _extension_definition(created),
        _identity(created),
    ]

    # SCOs first — everything else references them (M-17).
    account_scos = [_account_sco(member) for member in finding.members]
    evidence_scos = [
        _evidence_sco(str(ref), digest)
        for ref, digest in zip(
            finding.evidence_refs,
            list(finding.manifest_digests) + [""] * len(finding.evidence_refs),
            strict=False,
        )
    ]
    objects.extend(account_scos)
    objects.extend(evidence_scos)

    sco_refs = [sco["id"] for sco in account_scos]
    evidence_ref_ids = [sco["id"] for sco in evidence_scos]

    observed = _observed_data(finding, created, sco_refs or evidence_ref_ids)
    grouping = _grouping(finding, created, sco_refs + evidence_ref_ids)
    note = _note(finding, created, grouping["id"])

    objects.extend([observed, note, grouping])

    return {
        "type": "bundle",
        "id": deterministic_id("bundle", str(finding.finding_id)),
        "objects": objects,
    }


def _refuse_if_unexportable(finding: FindingExport) -> None:
    """M-06 and M-15 and M-18, checked before anything is built.

    Refusing is the correct behaviour, not an inconvenience. An unvalidated
    observation exported as though it were an assessment enters someone else's
    threat intelligence, where it is indexed, forwarded, and impossible to
    retract.
    """
    if not finding.evidence_refs:
        raise ExportRefused(
            f"finding {finding.finding_id} has no evidence references; M-15 and V-5 "
            "forbid exporting a grouping that rests on nothing"
        )
    if len(finding.signals) < 3:
        raise ExportRefused(
            f"finding {finding.finding_id} carries {len(finding.signals)} signals; "
            "M-18 requires at least three"
        )
    if finding.verdict not in EXPORTABLE_VERDICTS:
        raise ExportRefused(
            f"finding {finding.finding_id} has verdict {finding.verdict!r}. M-06: the "
            "boundary into the knowledge layer is crossed only at "
            f"{' or '.join(EXPORTABLE_VERDICTS)}. A finding awaiting review, or one an "
            "analyst judged insufficient, stays in Tier 1."
        )


def _extension_definition(created: str) -> dict[str, Any]:
    """Declares ASIP's custom SCO types (M-01).

    Inside the bundle so it is self-describing: a recipient does not fetch a
    schema from us to make sense of what they were sent. `created_by_ref` is
    required by the specification — the reference implementation rejects the
    object without it, which is how this omission was found.
    """
    return {
        "type": "extension-definition",
        "spec_version": SPEC_VERSION,
        "id": ASIP_EXTENSION_ID,
        "created_by_ref": ASIP_IDENTITY_ID,
        "created": created,
        "modified": created,
        "name": "ASIP social observation types",
        "description": (
            "Custom SCO types for monitored accounts and evidence bundles, plus "
            "coordination measurements. Carries no assertion about any named "
            "individual: assessments attach to clusters, never to members."
        ),
        "schema": "https://github.com/42prom/ASIP",
        "version": "1.0.0",
        "extension_types": ["new-sco", "property-extension"],
    }


def _identity(created: str) -> dict[str, Any]:
    """The producing organisation, and the only identity in the bundle (M-03)."""
    return {
        "type": "identity",
        "spec_version": SPEC_VERSION,
        "id": ASIP_IDENTITY_ID,
        "created": created,
        "modified": created,
        "name": "ASIP",
        "identity_class": "organization",
        "description": "Automated social coordination analysis with forensic evidence.",
    }


def _account_sco(member: ClusterMember) -> dict[str, Any]:
    """A monitored account as a custom SCO (M-01, M-10).

    Not an `identity`. That distinction is the whole of M-03: an identity SDO
    asserts who someone is, while an SCO records that an account was observed.
    Only the second is defensible from behavioural data.
    """
    return {
        "type": ACCOUNT_SCO,
        "spec_version": SPEC_VERSION,
        "id": deterministic_id(ACCOUNT_SCO, member.platform, str(member.account_id)),
        "platform": member.platform,
        "account_handle": member.handle,
        "items_in_window": member.item_count,
        "extensions": {ASIP_EXTENSION_ID: {"extension_type": "new-sco"}},
    }


def _evidence_sco(bundle_id: str, manifest_digest: str) -> dict[str, Any]:
    """An evidence bundle as a first-class object (M-04).

    Standard CTI models have nowhere to put this, which is why it is a custom
    SCO rather than a note or a property. A recipient can ask for the bundle by
    id and verify it without ASIP software.
    """
    return {
        "type": EVIDENCE_SCO,
        "spec_version": SPEC_VERSION,
        "id": deterministic_id(EVIDENCE_SCO, bundle_id),
        "bundle_id": bundle_id,
        "manifest_sha256": manifest_digest,
        "container_format": "WARC",
        "verification": (
            "A WARC carrying its own manifest, hash-chain entry and RFC 3161 token. "
            "Verifiable without ASIP software."
        ),
        "extensions": {ASIP_EXTENSION_ID: {"extension_type": "new-sco"}},
    }


def _observed_data(finding: FindingExport, created: str, object_refs: list[str]) -> dict[str, Any]:
    """The measured activity.

    `object_refs` must be non-empty and must not coexist with `objects` — the
    reference implementation rejects both mistakes, and the first version made
    one of them by passing an empty list.
    """
    return {
        "type": "observed-data",
        "spec_version": SPEC_VERSION,
        "id": deterministic_id("observed-data", str(finding.finding_id), "observed"),
        "created_by_ref": ASIP_IDENTITY_ID,
        "created": created,
        "modified": created,
        "first_observed": _stix_time(finding.window_start),
        "last_observed": _stix_time(finding.window_end),
        "number_observed": finding.item_count,
        "object_refs": object_refs,
        "extensions": {
            ASIP_EXTENSION_ID: {
                "extension_type": "property-extension",
                "account_count": finding.account_count,
                "source_url": finding.source_url,
                "rule_name": finding.rule_name,
                "detection_status": "shadow_unvalidated" if finding.shadow else "measured",
            }
        },
    }


def _grouping(finding: FindingExport, created: str, object_refs: list[str]) -> dict[str, Any]:
    """The cluster (M-03).

    `object_refs` holds SCOs only — accounts and evidence (M-17). An array that
    cannot contain an `identity` cannot contain a person, which is what makes
    the constraint structural rather than editorial.
    """
    return {
        "type": "grouping",
        "spec_version": SPEC_VERSION,
        "id": deterministic_id("grouping", str(finding.finding_id), "grouping"),
        "created_by_ref": ASIP_IDENTITY_ID,
        "created": created,
        "modified": created,
        "name": f"Coordinated posting window — {finding.rule_name}",
        "context": "suspicious-activity",
        "object_refs": object_refs,
        "extensions": {
            ASIP_EXTENSION_ID: {
                "extension_type": "property-extension",
                "verdict": finding.verdict,
                "evidence_bundle_ids": [str(ref) for ref in finding.evidence_refs],
                "evidence_manifest_sha256": list(finding.manifest_digests),
                "signals": list(finding.signals),
                "window_start": _stix_time(finding.window_start),
                "window_end": _stix_time(finding.window_end),
            }
        },
    }


def _note(finding: FindingExport, created: str, grouping_id: str) -> dict[str, Any]:
    """The signal breakdown, in words.

    Every measurement, its threshold, and whether it fired — the same thing the
    analyst saw. A recipient who disagrees can see exactly which measurement
    they disagree with, which a confidence score never allows.
    """
    lines = [f"Rule: {finding.rule_name}", f"Analyst verdict: {finding.verdict}"]
    if finding.shadow:
        lines.append(
            "NOTE: produced by a rule with no measured precision. The analyst verdict "
            "above is a human judgement, not a validated rule output."
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

    return {
        "type": "note",
        "spec_version": SPEC_VERSION,
        "id": deterministic_id("note", str(finding.finding_id), "signals"),
        "created_by_ref": ASIP_IDENTITY_ID,
        "created": created,
        "modified": created,
        "abstract": f"Signal breakdown for {finding.rule_name}",
        "content": "\n".join(lines),
        "object_refs": [grouping_id],
    }


def _stix_time(value: datetime) -> str:
    """STIX timestamps: UTC, millisecond precision, trailing Z.

    A naive datetime is treated as UTC rather than guessed at. Guessing a local
    zone would silently shift an exported observation by hours, and the
    recipient would have no way to know.
    """
    moment = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return moment.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
