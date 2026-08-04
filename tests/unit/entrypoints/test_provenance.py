"""D-112 — "in one query" is the requirement, so it is what gets asserted.

A traceability answer assembled from four round trips can disagree with itself
if anything changes between them, and an answer that can disagree with itself is
not evidence. These tests fail if someone splits the statement for readability,
which is exactly the change that would quietly remove the guarantee.
"""

from __future__ import annotations

import re
from typing import Any
from uuid import UUID

from asip.entrypoints.provenance import TRACE_QUERY, trace_finding

TENANT = UUID("aaaaaaaa-0000-4000-8000-0000000000d1")
FINDING = UUID("bbbbbbbb-0000-4000-8000-00000000000f")

COLUMNS = (
    "finding_id",
    "rule_name",
    "finding_trace_id",
    "detected_at",
    "window_start",
    "window_end",
    "item_count",
    "account_count",
    "shadow",
    "bundle_id",
    "bundle_trace_id",
    "capture_id",
    "source_url",
    "captured_at",
    "manifest_sha256",
    "chain_index",
    "has_timestamp",
    "items_from_this_capture",
    "items_still_pointing_here",
    "traces_that_touched_it",
    "trace_is_continuous",
    "claimed_evidence_refs",
)

ROW = (
    FINDING,
    "naive-burst-v1",
    "trace-aaa",
    "2026-08-04T09:15:00Z",
    "2026-08-04T09:12:04Z",
    "2026-08-04T09:13:02Z",
    5,
    3,
    True,
    UUID("cccccccc-0000-4000-8000-00000000000b"),
    "trace-aaa",
    UUID("dddddddd-0000-4000-8000-00000000000c"),
    "https://example.org/post/1",
    "2026-08-04T09:11:00Z",
    "a" * 64,
    3,
    True,
    6,
    6,
    1,
    True,
    [UUID("cccccccc-0000-4000-8000-00000000000b")],
)

#: The same finding after its evidence stopped resolving — what a per-module
#: migration rollback of sch_evidence leaves behind in sch_detection. Every
#: column the LEFT JOIN supplied is null; the finding's own columns survive.
FROM_EVIDENCE = (
    "bundle_id",
    "bundle_trace_id",
    "capture_id",
    "source_url",
    "captured_at",
    "manifest_sha256",
    "chain_index",
    "has_timestamp",
    "items_from_this_capture",
    "items_still_pointing_here",
    "traces_that_touched_it",
    "trace_is_continuous",
)
ORPHAN_REF = UUID("eeeeeeee-0000-4000-8000-00000000000e")
ORPHANED = tuple(
    [ORPHAN_REF] if name == "claimed_evidence_refs" else None if name in FROM_EVIDENCE else value
    for name, value in zip(COLUMNS, ROW, strict=True)
)


class CountingCursor:
    def __init__(self, log: list[str], row: tuple[Any, ...] | None) -> None:
        self._log = log
        self._row = row
        self.description = [(name,) for name in COLUMNS]

    def execute(self, sql: str, params: Any = None) -> None:
        self._log.append(sql)

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row

    def __enter__(self) -> CountingCursor:
        return self

    def __exit__(self, *exc: object) -> None:
        return None


class CountingConnection:
    """Records every statement issued, so "one query" can be asserted."""

    def __init__(self, row: tuple[Any, ...] | None = ROW) -> None:
        self.statements: list[str] = []
        self._row = row

    def cursor(self) -> CountingCursor:
        return CountingCursor(self.statements, self._row)


def test_tracing_a_finding_issues_exactly_one_statement() -> None:
    """The directive, asserted literally."""
    conn = CountingConnection()

    trace_finding(conn, TENANT, FINDING)  # type: ignore[arg-type]

    assert len(conn.statements) == 1, (
        f"D-112 requires one query; {len(conn.statements)} were issued. "
        "Four round trips can disagree with each other, and an answer that can "
        "disagree with itself is not evidence."
    )


def test_the_query_reaches_all_three_modules() -> None:
    """One query that only touched detection would satisfy the count and nothing else."""
    for schema in ("sch_detection", "sch_evidence", "sch_extraction"):
        assert schema in TRACE_QUERY, f"the trace never reaches {schema}"


def test_the_query_reads_only_published_views() -> None:
    """D-92 and D-99 — the composition root may join modules, not their tables.

    Reading a base table here would couple this query to another module's
    physical layout, which is the coupling that makes a module unremovable.
    """
    referenced = re.findall(r"sch_\w+\.(\w+)", TRACE_QUERY)
    base_tables = [name for name in referenced if not name.startswith("v_")]

    assert not base_tables, (
        f"the trace query reads base tables {sorted(set(base_tables))} instead of "
        "published views — extraction could not then rename a column without "
        "breaking a query it was never told existed"
    )


def test_the_join_is_structural_not_by_trace_id() -> None:
    """What the skeleton showed.

    `content.trace_id` holds the run that FIRST observed an item, so joining a
    finding to its evidence on trace_id returns nothing for every run after the
    first. The path that survives is finding -> evidence_refs -> bundle, which
    M-15 guarantees exists because a finding without evidence cannot be written.
    """
    join_clause = TRACE_QUERY.split("JOIN sch_evidence")[1].split("LEFT JOIN")[0]

    assert "evidence_refs" in join_clause, "the evidence join must be by reference"
    assert "trace_id" not in join_clause, (
        "the finding-to-evidence join uses trace_id, which breaks on the second "
        "run: content keeps the trace of the run that first observed it"
    )


def test_the_answer_says_what_it_found() -> None:
    trace = trace_finding(CountingConnection(), TENANT, FINDING)  # type: ignore[arg-type]

    assert trace is not None
    assert trace["traceable"] is True
    assert str(trace["capture_id"]) in trace["summary"]
    assert trace["source_url"] in trace["summary"]
    assert trace["trace_is_continuous"] is True


def test_a_finding_whose_evidence_vanished_is_not_reported_as_missing() -> None:
    """Two different facts, and a 404 for both would report the worse one as a typo.

    A finding that does not exist is a wrong identifier. A finding whose evidence
    does not resolve is a V-5 violation sitting in the database — it exists, and
    its existence is the problem. Observed live: a per-module migration rollback
    dropped sch_evidence while sch_detection kept its rows.
    """
    trace = trace_finding(CountingConnection(row=ORPHANED), TENANT, FINDING)  # type: ignore[arg-type]

    assert trace is not None, "the finding exists; saying otherwise hides the violation"
    assert trace["traceable"] is False
    assert "V-5" in trace["summary"]
    assert str(ORPHAN_REF) in trace["summary"], "the unresolvable id must be named"


def test_an_unknown_finding_is_the_only_none() -> None:
    assert trace_finding(CountingConnection(row=None), TENANT, FINDING) is None  # type: ignore[arg-type]


def test_the_orphan_case_still_costs_one_query() -> None:
    """The failure path must not be the one that quietly does four round trips."""
    conn = CountingConnection(row=ORPHANED)
    trace_finding(conn, TENANT, FINDING)  # type: ignore[arg-type]
    assert len(conn.statements) == 1
