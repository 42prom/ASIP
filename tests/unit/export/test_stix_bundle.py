"""The exported bundle must satisfy the standard, not our memory of it.

Every object is parsed with the OASIS reference implementation. That is the
point: the first version of this exporter was written from the spec by hand and
looked right, and the reference implementation rejected it on two counts —
`extension-definition` requires `created_by_ref`, and `observed-data` may not
carry an empty `object_refs`. Neither would have surfaced until a recipient
refused the bundle.

The modelling directives are asserted separately, because a bundle can be
perfectly valid STIX and still say something the product must never say.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

import pytest
import stix2

from asip.modules.export.domain.stix import (
    ACCOUNT_SCO,
    ASIP_IDENTITY_ID,
    EVIDENCE_SCO,
    ClusterMember,
    ExportRefused,
    FindingExport,
    build_bundle,
)

FINDING = UUID("11111111-0000-4000-8000-000000000001")
TENANT = UUID("22222222-0000-4000-8000-000000000002")
BUNDLE = UUID("33333333-0000-4000-8000-000000000003")

SIGNALS = [
    {
        "name": "item_count",
        "observed": 5.0,
        "threshold": 4.0,
        "passed": True,
        "description": "items published inside the window",
    },
    {
        "name": "distinct_accounts",
        "observed": 5.0,
        "threshold": 3.0,
        "passed": True,
        "description": "distinct accounts contributing",
    },
    {
        "name": "window_span_seconds",
        "observed": 58.0,
        "threshold": 120.0,
        "passed": True,
        "description": "elapsed time between first and last item",
    },
]

MEMBERS = [
    ClusterMember(account_id=uuid4(), platform="canary", handle=f"synthetic_{n}", item_count=1)
    for n in ("alpha", "beta", "gamma")
]


def make(verdict: str | None = "likely_coordination", **overrides: Any) -> FindingExport:
    base: dict[str, Any] = {
        "finding_id": FINDING,
        "tenant_id": TENANT,
        "rule_name": "naive-burst-v1",
        "source_url": "https://example.org/post/1",
        "window_start": datetime(2026, 8, 4, 9, 12, 4, tzinfo=UTC),
        "window_end": datetime(2026, 8, 4, 9, 13, 2, tzinfo=UTC),
        "item_count": 5,
        "account_count": 3,
        "signals": SIGNALS,
        "evidence_refs": [BUNDLE],
        "manifest_digests": ["a" * 64],
        "shadow": True,
        "detected_at": datetime(2026, 8, 4, 9, 15, 0, tzinfo=UTC),
        "members": MEMBERS,
        "verdict": verdict,
    }
    base.update(overrides)
    return FindingExport(**base)


# ── the standard ────────────────────────────────────────────────────────────


#: Objects that reference nothing of ours, so the reference implementation can
#: judge them with no allowances at all. `extension-definition` is here because
#: it is where the first defect lived.
STRICTLY_VALIDATED = ("extension-definition", "identity", "note")

#: Objects whose `object_refs` point at SCO types this bundle *declares*.
#: Parsed in isolation, the reference implementation cannot see the declaration
#: and rejects the reference as an unknown type — so these are validated in
#: bundle context instead. Relaxed for a stated reason, not by default.
CUSTOM_REFERENCING = ("observed-data", "grouping")


def test_standard_objects_parse_with_no_allowances() -> None:
    """The gate that would have caught the missing created_by_ref."""
    bundle = build_bundle(make())

    checked = 0
    for obj in bundle["objects"]:
        if obj["type"] not in STRICTLY_VALIDATED:
            continue
        checked += 1
        try:
            stix2.parse(obj, allow_custom=False)
        except Exception as exc:
            pytest.fail(f"{obj['type']} rejected by stix2: {exc}")

    assert checked == len(STRICTLY_VALIDATED), "every strict object should have been checked"


def test_objects_referencing_declared_scos_parse_in_bundle_context() -> None:
    """Valid, but only because the bundle declares the types they reference.

    Asserted separately so the allowance is visible. If one of these ever needs
    `allow_custom` for a reason *other* than our declared SCOs, the strict test
    above is where it should have been caught.
    """
    bundle = build_bundle(make())

    for obj in bundle["objects"]:
        if obj["type"] not in CUSTOM_REFERENCING:
            continue
        try:
            stix2.parse(obj, allow_custom=True)
        except Exception as exc:
            pytest.fail(f"{obj['type']} rejected by stix2: {exc}")


def test_the_whole_bundle_parses() -> None:
    """Custom SCOs are permitted here because the bundle declares them (M-01)."""
    bundle = build_bundle(make())
    parsed = stix2.parse(bundle, allow_custom=True)
    assert parsed["type"] == "bundle"


def test_extension_definition_names_its_creator() -> None:
    """Required by the spec, and the omission the reference implementation caught."""
    bundle = build_bundle(make())
    ext = next(o for o in bundle["objects"] if o["type"] == "extension-definition")
    assert ext["created_by_ref"] == ASIP_IDENTITY_ID


def test_observed_data_references_objects_and_never_an_empty_list() -> None:
    bundle = build_bundle(make())
    observed = next(o for o in bundle["objects"] if o["type"] == "observed-data")
    assert observed["object_refs"], "an empty object_refs is invalid STIX"
    assert "objects" not in observed, "object_refs and objects are mutually exclusive"


def test_identifiers_are_deterministic() -> None:
    """M-10. Two workers exporting the same finding must agree."""
    first = build_bundle(make())
    second = build_bundle(make())
    assert [o["id"] for o in first["objects"]] == [o["id"] for o in second["objects"]]


# ── the modelling directives ────────────────────────────────────────────────


def test_the_only_identity_is_the_producing_organisation() -> None:
    """M-03. An identity SDO is never created for a natural person."""
    bundle = build_bundle(make())
    identities = [o for o in bundle["objects"] if o["type"] == "identity"]

    assert len(identities) == 1
    assert identities[0]["id"] == ASIP_IDENTITY_ID
    assert identities[0]["identity_class"] == "organization"


def test_object_refs_contain_only_scos() -> None:
    """M-17 — the technical enforcement of M-03.

    An array that cannot hold an identity cannot hold a person.
    """
    bundle = build_bundle(make())
    sco_ids = {o["id"] for o in bundle["objects"] if o["type"] in {ACCOUNT_SCO, EVIDENCE_SCO}}
    grouping = next(o for o in bundle["objects"] if o["type"] == "grouping")

    assert grouping["object_refs"], "a grouping over nothing asserts nothing"
    assert set(grouping["object_refs"]) <= sco_ids
    assert ASIP_IDENTITY_ID not in grouping["object_refs"]


def test_accounts_are_scos_not_identities() -> None:
    """M-01. Forcing a monitored account into `identity` is the modelling error
    the mapping document opens with."""
    bundle = build_bundle(make())
    accounts = [o for o in bundle["objects"] if o["type"] == ACCOUNT_SCO]

    assert len(accounts) == len(MEMBERS)
    assert all("identity" not in a["type"] for a in accounts)


def test_no_object_carries_a_verdict_about_a_member() -> None:
    """V-1 and M-03, checked over the serialised bundle.

    The assessment belongs to the grouping. A member SCO records that an
    account was observed and nothing about whether it did anything wrong.
    """
    bundle = build_bundle(make())
    for account in (o for o in bundle["objects"] if o["type"] == ACCOUNT_SCO):
        for field in account:
            assert field not in {"verdict", "score", "confidence", "risk", "labels"}


def test_the_grouping_carries_its_evidence() -> None:
    """M-15 — no grouping without evidence."""
    bundle = build_bundle(make())
    grouping = next(o for o in bundle["objects"] if o["type"] == "grouping")
    evidence = [o for o in bundle["objects"] if o["type"] == EVIDENCE_SCO]

    assert evidence
    assert any(e["id"] in grouping["object_refs"] for e in evidence)


# ── the boundary (M-06) ─────────────────────────────────────────────────────


@pytest.mark.parametrize("verdict", [None, "insufficient_evidence", "no_coordination"])
def test_a_finding_below_the_threshold_never_exports(verdict: str | None) -> None:
    """M-06. The Tier 1/Tier 2 boundary is crossed only at LIKELY or above.

    This is the check that stops an unvalidated observation entering someone
    else's threat intelligence, where it would be indexed, forwarded, and
    impossible to retract.
    """
    with pytest.raises(ExportRefused, match="M-06"):
        build_bundle(make(verdict=verdict))


@pytest.mark.parametrize("verdict", ["likely_coordination", "confirmed_coordination"])
def test_a_reviewed_finding_exports(verdict: str) -> None:
    bundle = build_bundle(make(verdict=verdict))
    grouping = next(o for o in bundle["objects"] if o["type"] == "grouping")
    assert grouping["extensions"][next(iter(grouping["extensions"]))]["verdict"] == verdict


def test_a_finding_without_evidence_is_refused() -> None:
    with pytest.raises(ExportRefused, match="M-15"):
        build_bundle(make(evidence_refs=[]))


def test_a_finding_with_too_few_signals_is_refused() -> None:
    with pytest.raises(ExportRefused, match="M-18"):
        build_bundle(make(signals=SIGNALS[:2]))


def test_a_shadow_finding_says_so_in_the_export() -> None:
    """A recipient must not mistake an unvalidated rule for a measured one."""
    bundle = build_bundle(make())
    observed = next(o for o in bundle["objects"] if o["type"] == "observed-data")
    extension = observed["extensions"][next(iter(observed["extensions"]))]
    assert extension["detection_status"] == "shadow_unvalidated"

    note = next(o for o in bundle["objects"] if o["type"] == "note")
    assert "no measured precision" in note["content"]
