"""M-06 at the use-case level: what reaches storage, and what is said when nothing does.

The domain refuses; this checks the refusal is *reported* rather than swallowed.
A caller that cannot tell "nothing to export" from "the boundary held" will
eventually tell an operator the wrong one, and the operator will conclude the
export stage is broken and go looking for a bug that does not exist.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from asip.modules.export.application.export_finding import (
    ExportFinding,
    crosses_the_boundary,
)
from asip.modules.export.domain.stix import ClusterMember, FindingExport

FINDING = UUID("11111111-0000-4000-8000-000000000001")
TENANT = UUID("22222222-0000-4000-8000-000000000002")
BUNDLE = UUID("33333333-0000-4000-8000-000000000003")

#: Fixed, because in production it is: account ids are UUIDv5 over
#: (platform, handle), so the same account is the same id on every run (M-10).
#: A uuid4() here would make the byte-equality test below fail for a reason that
#: does not exist in the system under test.
ACCOUNT = UUID("44444444-0000-4000-8000-000000000004")

SIGNALS = [
    {"name": "item_count", "observed": 5.0, "threshold": 4.0, "passed": True},
    {"name": "distinct_accounts", "observed": 5.0, "threshold": 3.0, "passed": True},
    {"name": "window_span_seconds", "observed": 58.0, "threshold": 120.0, "passed": True},
]


class FakeRepository:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def record_export(
        self,
        export_id: UUID,
        tenant_id: UUID,
        finding_id: UUID,
        trace_id: str,
        bundle_json: str,
        bundle_sha256: str,
        object_count: int,
    ) -> None:
        self.rows.append(
            {
                "export_id": export_id,
                "tenant_id": tenant_id,
                "finding_id": finding_id,
                "trace_id": trace_id,
                "bundle_json": bundle_json,
                "bundle_sha256": bundle_sha256,
                "object_count": object_count,
            }
        )


def make(verdict: str | None) -> FindingExport:
    return FindingExport(
        finding_id=FINDING,
        tenant_id=TENANT,
        rule_name="naive-burst-v1",
        source_url="https://example.org/post/1",
        window_start=datetime(2026, 8, 4, 9, 12, 4, tzinfo=UTC),
        window_end=datetime(2026, 8, 4, 9, 13, 2, tzinfo=UTC),
        item_count=5,
        account_count=3,
        signals=SIGNALS,
        evidence_refs=[BUNDLE],
        manifest_digests=["a" * 64],
        shadow=True,
        detected_at=datetime(2026, 8, 4, 9, 15, 0, tzinfo=UTC),
        members=[ClusterMember(ACCOUNT, "canary", "synthetic_alpha", 2)],
        verdict=verdict,
    )


@pytest.mark.parametrize("verdict", [None, "insufficient_evidence", "no_coordination"])
def test_an_unreviewed_finding_writes_nothing_and_says_why(verdict: str | None) -> None:
    repository = FakeRepository()

    outcome = ExportFinding(repository).execute(make(verdict), "trace-1")

    assert repository.rows == [], "nothing may reach storage below the M-06 boundary"
    assert outcome.exported is False
    assert "M-06" in outcome.reason
    assert outcome.export_id is None


@pytest.mark.parametrize("verdict", ["likely_coordination", "confirmed_coordination"])
def test_a_reviewed_finding_is_stored_once(verdict: str) -> None:
    repository = FakeRepository()

    outcome = ExportFinding(repository).execute(make(verdict), "trace-1")

    assert len(repository.rows) == 1
    assert outcome.exported is True
    assert outcome.export_id == repository.rows[0]["export_id"]
    assert outcome.object_count == repository.rows[0]["object_count"]


def test_the_stored_bytes_are_the_bytes_that_were_hashed() -> None:
    """A recipient hashes the copy they were handed.

    Storing a re-serialised bundle whose keys sort differently would produce a
    digest that does not match the artifact, and the mismatch would look like
    tampering rather than like a serialisation detail.
    """
    import hashlib

    repository = FakeRepository()
    ExportFinding(repository).execute(make("likely_coordination"), "trace-1")

    row = repository.rows[0]
    assert hashlib.sha256(row["bundle_json"].encode()).hexdigest() == row["bundle_sha256"]
    assert len(json.loads(row["bundle_json"])["objects"]) == row["object_count"]


def test_two_exports_of_the_same_finding_agree_byte_for_byte() -> None:
    """M-10 through to the stored payload, not only to the identifiers."""
    repository = FakeRepository()
    exporter = ExportFinding(repository)

    exporter.execute(make("likely_coordination"), "trace-1")
    exporter.execute(make("likely_coordination"), "trace-2")

    first, second = repository.rows
    assert first["bundle_json"] == second["bundle_json"]
    assert first["bundle_sha256"] == second["bundle_sha256"]
    assert first["export_id"] != second["export_id"], "each export attempt is its own record"


def test_a_finding_with_no_evidence_writes_nothing() -> None:
    """M-15 survives the trip through the use case."""
    repository = FakeRepository()
    stripped = replace(make("confirmed_coordination"), evidence_refs=[])

    outcome = ExportFinding(repository).execute(stripped, "trace-1")

    assert repository.rows == []
    assert "M-15" in outcome.reason


def test_the_boundary_predicate_agrees_with_the_domain() -> None:
    """Two places may name the threshold; they may not disagree about it."""
    repository = FakeRepository()

    for verdict in (
        None,
        "insufficient_evidence",
        "no_coordination",
        "likely_coordination",
        "confirmed_coordination",
    ):
        outcome = ExportFinding(repository).execute(make(verdict), "trace-1")
        assert crosses_the_boundary(verdict) is outcome.exported, (
            f"the pre-check and the enforcement disagree about {verdict!r}"
        )
