"""Assembling a finding for export — composition-root work.

A STIX bundle needs facts from three modules: the finding and its cluster from
detection, the captured URL and manifest digests from evidence, the account
handles from extraction. No module may reach into another's tables, so the
joining happens here, in the one place that is allowed to know they exist, and
only through published views (D-92, D-99).

Kept out of both entrypoints that need it, because two copies of "how a finding
becomes a bundle" will diverge, and the half that diverges will be the half that
decides what a recipient sees.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from psycopg import Connection

from asip.modules.export.domain.stix import ClusterMember, FindingExport


def assemble(
    conn: Connection,
    tenant_id: UUID,
    finding: dict[str, Any],
    verdict: str | None,
) -> FindingExport:
    """Turn a finding row into everything the serialiser needs.

    `verdict` is passed in rather than read here: the caller knows whether it is
    exporting on the strength of a stored verdict or one just recorded, and a
    lookup that silently disagreed with the caller would be worse than either.
    """
    evidence_refs = [UUID(str(ref)) for ref in finding.get("evidence_refs") or ()]
    source_url, digests = _evidence(conn, tenant_id, evidence_refs)

    return FindingExport(
        finding_id=UUID(str(finding["finding_id"])),
        tenant_id=tenant_id,
        rule_name=finding["rule_name"],
        source_url=source_url,
        window_start=finding["window_start"],
        window_end=finding["window_end"],
        item_count=finding["item_count"],
        account_count=finding["account_count"],
        signals=finding["signals"],
        evidence_refs=evidence_refs,
        manifest_digests=digests,
        shadow=finding["shadow"],
        detected_at=finding["detected_at"],
        members=_members(conn, tenant_id, finding.get("cluster") or []),
        verdict=verdict,
    )


def _evidence(conn: Connection, tenant_id: UUID, bundle_ids: list[UUID]) -> tuple[str, list[str]]:
    """Captured URL and manifest digests, in the order of `bundle_ids`.

    The URL comes from the evidence bundle rather than from the source record,
    because the bundle holds what was actually fetched. A source's URL can be
    edited after the fact; a sealed capture's cannot.
    """
    if not bundle_ids:
        return ("", [])

    with conn.cursor() as cur:
        cur.execute(
            "SELECT bundle_id, source_url, manifest_sha256 "
            "  FROM sch_evidence.v_bundles_for_review "
            " WHERE tenant_id = %s AND bundle_id = ANY(%s)",
            (tenant_id, bundle_ids),
        )
        rows = {str(b): (url, digest) for b, url, digest in cur.fetchall()}

    ordered = [rows[str(b)] for b in bundle_ids if str(b) in rows]
    if not ordered:
        # M-15 will refuse this downstream. Returning empty rather than raising
        # keeps the refusal in one place, where its reason is stated.
        return ("", [])
    return (ordered[0][0], [digest for _, digest in ordered])


def _members(
    conn: Connection, tenant_id: UUID, cluster: list[dict[str, Any]]
) -> list[ClusterMember]:
    """The cluster's accounts as observables.

    An account with no row in extraction is skipped rather than exported with a
    placeholder handle: a recipient cannot act on `unknown`, and inventing one
    would put a fabricated identifier into someone else's system.
    """
    if not cluster:
        return []

    account_ids = [UUID(str(entry["account_id"])) for entry in cluster]
    with conn.cursor() as cur:
        cur.execute(
            "SELECT account_id, platform, handle "
            "  FROM sch_extraction.v_accounts_for_export "
            " WHERE tenant_id = %s AND account_id = ANY(%s)",
            (tenant_id, account_ids),
        )
        known = {str(a): (platform, handle) for a, platform, handle in cur.fetchall()}

    members = []
    for entry in cluster:
        account_id = str(entry["account_id"])
        if account_id not in known:
            continue
        platform, handle = known[account_id]
        members.append(
            ClusterMember(
                account_id=UUID(account_id),
                platform=platform,
                handle=handle,
                item_count=int(entry.get("item_count") or 0),
            )
        )
    return members
