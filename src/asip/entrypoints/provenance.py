"""D-112 — a finding traces to its originating capture in one query.

"One query" is the requirement, not a performance note. The question this
answers is asked under adversarial conditions: someone disputes a finding and
wants to know which bytes it came from. An answer assembled from four round
trips can disagree with itself if anything changes between them, and an answer
that can disagree with itself is not evidence.

So this is a single statement, and a test asserts it is a single statement.
Splitting it for readability would silently remove the guarantee.

THE JOIN IS STRUCTURAL, NOT BY TRACE
    finding -> evidence_refs[] -> evidence_bundle -> capture

M-15 guarantees the first hop exists: a finding with no evidence reference
cannot be written. The trace_id is carried alongside and reported, but it is
not the join key — see migrations/extraction/005 for what the skeleton showed
about why.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from psycopg import Connection

#: One statement. Every module is reached through its published view (D-92), so
#: this reads across three schemas without any of them knowing about the others.
#:
#: The content aggregate is a lateral subquery rather than a GROUP BY over a
#: fourth join, so a finding whose content has since been re-observed into a
#: newer capture still returns one row rather than none.
TRACE_QUERY = """
SELECT f.finding_id,
       f.rule_name,
       f.trace_id           AS finding_trace_id,
       f.detected_at,
       f.window_start,
       f.window_end,
       f.item_count,
       f.account_count,
       f.shadow,
       b.bundle_id,
       b.trace_id           AS bundle_trace_id,
       b.capture_id,
       b.source_url,
       b.captured_at,
       b.manifest_sha256,
       b.chain_index,
       b.has_timestamp,
       c.items_from_this_capture,
       c.items_still_pointing_here,
       c.traces_that_touched_it,
       f.trace_id = b.trace_id AS trace_is_continuous,
       f.evidence_refs         AS claimed_evidence_refs
  FROM sch_detection.v_findings_for_review f
  LEFT JOIN sch_evidence.v_bundles_for_review b
    ON b.tenant_id = f.tenant_id
   AND b.bundle_id = f.evidence_refs[1]
  LEFT JOIN LATERAL (
       SELECT count(*) FILTER (WHERE x.capture_id = b.capture_id)
                AS items_from_this_capture,
              count(*) FILTER (WHERE x.last_capture_id = b.capture_id)
                AS items_still_pointing_here,
              count(DISTINCT x.last_trace_id)
                AS traces_that_touched_it
         FROM sch_extraction.v_content_provenance x
        WHERE x.tenant_id = f.tenant_id
          AND (x.capture_id = b.capture_id OR x.last_capture_id = b.capture_id)
  ) c ON true
 WHERE f.tenant_id = %(tenant)s AND f.finding_id = %(finding)s
"""


def trace_finding(conn: Connection, tenant_id: UUID, finding_id: UUID) -> dict[str, Any] | None:
    """Everything between a finding and the bytes it came from, in one round trip.

    Returns None only when the finding does not exist. A finding whose evidence
    cannot be found comes back with `traceable=False` and the reason, because
    those are different facts: one is a wrong URL, the other is a V-5 violation
    sitting in the database. A 404 for both would report an integrity failure as
    a typo.
    """
    with conn.cursor() as cur:
        cur.execute(TRACE_QUERY, {"tenant": tenant_id, "finding": finding_id})
        row = cur.fetchone()
        if row is None:
            return None
        columns = [d[0] for d in cur.description or ()]

    trace = dict(zip(columns, row, strict=True))
    trace["traceable"] = trace["bundle_id"] is not None

    # Said plainly, because the answer is the point. A reader looking at a
    # disputed finding should not have to interpret six columns to learn
    # whether the chain held.
    if trace["traceable"]:
        trace["summary"] = (
            f"Finding {trace['finding_id']} came from capture {trace['capture_id']}, "
            f"sealed as bundle {trace['bundle_id']} at chain index {trace['chain_index']} "
            f"from {trace['source_url']}."
        )
    else:
        refs = ", ".join(str(r) for r in trace["claimed_evidence_refs"] or ()) or "none"
        trace["summary"] = (
            f"Finding {trace['finding_id']} cannot be traced. It claims evidence "
            f"{refs}, which does not resolve to a bundle. V-5: a finding rests on "
            "evidence, and this one rests on an identifier — it cannot be defended "
            "and must not be exported. Most likely cause is a per-module migration "
            "rollback that dropped sch_evidence while detection kept its rows."
        )
    return trace
