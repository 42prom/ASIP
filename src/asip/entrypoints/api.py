"""L4 — the JSON API and the console it serves.

The API is the contract; the console is a view over it. Everything the console
shows is available as JSON, so replacing the interface later — with React and
Cytoscape per D-70, or with anything else — changes nothing underneath.

Single-tenant for the skeleton: one tenant id, taken from configuration. Every
query still goes through RLS with the tenant GUC set per request, exactly as it
will with many tenants, so the isolation path is exercised from the first
screen rather than retrofitted.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from asip.entrypoints.auth import (
    SESSION_COOKIE,
    authenticator,
    guard,
    owner_connection,
    principal_of,
    require_session,
)
from asip.entrypoints.composition import Settings, build_evidence, build_fetcher
from asip.entrypoints.exporting import assemble
from asip.entrypoints.pipeline import BURST_RULE_NAME, Pipeline
from asip.entrypoints.provenance import trace_finding
from asip.modules.collection.adapters.postgres_repository import PostgresCollectionRepository
from asip.modules.detection.adapters.postgres_repository import PostgresDetectionRepository
from asip.modules.evidence.adapters.postgres_repository import PostgresEvidenceRepository
from asip.modules.export.adapters.postgres_repository import PostgresExportRepository
from asip.modules.export.application.export_finding import ExportFinding, crosses_the_boundary
from asip.modules.extraction.adapters.postgres_repository import PostgresExtractionRepository
from asip.modules.identity.adapters.postgres_repository import PostgresIdentityRepository
from asip.modules.identity.application.authenticate import AuthenticationFailed
from asip.modules.identity.application.guard import NotPermitted
from asip.modules.identity.domain.audit import verify_chain as verify_audit_chain
from asip.modules.identity.domain.roles import Permission, Principal
from asip.modules.review.adapters.postgres_repository import VERDICTS, PostgresReviewRepository

WEB_ROOT = Path(__file__).resolve().parents[3] / "web"
CANARY_ROOT = WEB_ROOT / "canary"

#: Only ever a default for the LOGIN FORM, when a caller does not name a tenant.
#: Every other use of a tenant id in this module comes from the authenticated
#: session via `acting()`.
#:
#: Deliberately not called `tenant`: a module-level name matching the local one
#: handlers bind would make a handler that forgot to bind it silently fall back
#: to this value instead of failing. That is a cross-tenant read produced by a
#: missing line, which is the exact failure this whole module exists to prevent.
#: A test asserts no module-level `tenant` exists.
DEFAULT_TENANT = UUID(os.environ.get("ASIP_TENANT_ID", "aaaaaaaa-0000-4000-8000-0000000000d1"))

app = FastAPI(title="ASIP", version="0.1.0", docs_url="/api/docs")

# Default deny. Every /api/ path needs a session except the allowlist in
# auth.py, so an endpoint added later is private until someone deliberately
# makes it public (D-47, V-7).
app.middleware("http")(require_session)


@app.exception_handler(NotPermitted)
async def _denied(_request: Request, exc: NotPermitted) -> JSONResponse:
    """A denial is a 403 that says why and names its audit entry.

    The entry id is in the response so a support conversation starts from
    "denial <id>" rather than a screenshot — and a conversation that starts
    from a screenshot ends in a widened permission.
    """
    return JSONResponse(
        {"detail": str(exc), "audit_entry": str(exc.entry_id)},
        status_code=403,
    )


def _dsn() -> str:
    return os.environ.get("ASIP_DB_URL", "postgresql://asip:asip_dev_only@127.0.0.1:5432/asip")


#: Both live in the composition root so the scheduler can use them without
#: importing the web application (D-98).
_settings = Settings.for_development
_fetcher = build_fetcher


@contextmanager
def session(tenant_id: UUID) -> Iterator[psycopg.Connection]:
    """A connection scoped to one tenant, as the application role.

    The tenant is an argument rather than a module constant, and every caller
    passes the one on the authenticated principal. That is the whole change:
    previously the API served a tenant taken from configuration, so a bug in a
    handler could not cross tenants because there was only one. Now the boundary
    is real, and RLS is what holds it.

    SET ROLE and the GUC are set per request, not per process. A tenant id that
    outlived its request would be a cross-tenant read no policy could catch (V-7).
    """
    with psycopg.connect(_dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute("SET ROLE asip_app")
            cur.execute("SELECT set_config('asip.tenant_id', %s, false)", (str(tenant_id),))
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


def acting(request: Request) -> tuple[Principal, UUID]:
    """The principal and its tenant. One call so neither is fetched without the other."""
    principal = principal_of(request)
    return principal, principal.tenant_id


def scope_of(request: Request, principal: Principal) -> UUID:
    """Which project this request is about (D-49).

    From `?project=` when given, otherwise the principal's only project. A
    principal with several must name one: guessing would silently pick a scope
    the analyst did not intend, and the guess would be invisible in the audit
    entry that records the read.

    Returns a sentinel rather than raising when there is no project, so the
    Guard produces the denial — one place decides, and the denial is audited.
    """
    named = request.query_params.get("project")
    if named:
        try:
            return UUID(named)
        except ValueError:
            raise HTTPException(status_code=400, detail="project is not a uuid") from None

    if len(principal.project_ids) == 1:
        return next(iter(principal.project_ids))

    # No project, or an ambiguous choice. UUID(int=0) is assigned to nobody, so
    # the guard denies and says why.
    return UUID(int=0)


def permit(
    request: Request,
    principal: Principal,
    permission: Permission,
    *,
    resource_type: str,
    resource_id: str,
) -> UUID:
    """Authorize a tenant-data read and record it. Returns the project scope.

    Every data endpoint goes through here, so "checked the permission" and
    "wrote the audit entry" cannot come apart (D-52).

    KNOWN GAP, stated rather than hidden: captures, bundles and extracted
    content do not yet carry project_id, so for those endpoints the permission
    is checked against the caller's project while the rows returned are the
    tenant's. That is coarser than D-49 requires. Findings and their exports are
    correctly scoped because sch_detection.findings carries the column. Closing
    it means project_id on sch_evidence.captures and sch_extraction.content, and
    a test pins the gap so it cannot be quietly forgotten.
    """
    project_id = scope_of(request, principal)
    guard(principal.tenant_id).require(
        principal,
        permission,
        tenant_id=principal.tenant_id,
        resource_type=resource_type,
        resource_id=resource_id,
        project_id=project_id,
    )
    return project_id


def permit_admin(
    principal: Principal,
    permission: Permission,
    *,
    resource_type: str,
    resource_id: str,
) -> None:
    """Authorize an administrative action. No project, because these are not
    reads of project data — they configure or operate the tenant."""
    guard(principal.tenant_id).require(
        principal,
        permission,
        tenant_id=principal.tenant_id,
        resource_type=resource_type,
        resource_id=resource_id,
    )


def _json(payload: Any) -> JSONResponse:
    """Serialise with UUIDs and datetimes rendered as strings.

    Times go out as ISO 8601 UTC (D-65). The console never formats a timestamp
    itself, so there is one place where time is rendered and one convention.
    """

    def convert(value: Any) -> Any:
        if isinstance(value, UUID):
            return str(value)
        if isinstance(value, datetime):
            return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
        # Postgres numerics arrive as Decimal, which json cannot encode.
        # Converted to float here rather than at every call site: a duration or
        # a count crossing this boundary is display data. Nothing that must not
        # lose precision — hashes, identifiers, money — is ever a Decimal here.
        if isinstance(value, Decimal):
            return float(value)
        if isinstance(value, dict):
            return {k: convert(v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [convert(v) for v in value]
        return value

    return JSONResponse(convert(payload))


# ── authentication ──────────────────────────────────────────────────────────


@app.post("/api/auth/login")
def login(payload: dict[str, str]) -> JSONResponse:
    """Exchange credentials for a session.

    The tenant is supplied by the caller because email addresses are unique per
    tenant, not globally — the same person may hold accounts at two client
    organisations, and a global lookup would leak that an address is registered
    somewhere. The console sends the tenant it was configured with.
    """
    try:
        tenant = UUID(payload.get("tenant_id") or str(DEFAULT_TENANT))
    except ValueError:
        raise HTTPException(status_code=400, detail="tenant_id is not a uuid") from None

    with owner_connection() as conn:
        try:
            opened = authenticator(conn).login(
                tenant, payload.get("email", ""), payload.get("password", "")
            )
        except AuthenticationFailed as failure:
            conn.rollback()
            # One message for wrong password, unknown address and disabled
            # account alike. Distinguishing them tells an attacker which half of
            # the guess was right.
            raise HTTPException(status_code=401, detail=str(failure)) from None
        conn.commit()

    body = _json(
        {
            "ok": True,
            "user_id": opened.user_id,
            "tenant_id": opened.tenant_id,
            "expires_at": opened.expires_at,
        }
    )
    # HttpOnly so script cannot read it; SameSite=Lax so it does not ride along
    # on a cross-site request. Not Secure in development, because the console is
    # served over http on localhost and a Secure cookie would simply never be
    # sent — set ASIP_COOKIE_SECURE=1 behind TLS.
    body.set_cookie(
        SESSION_COOKIE,
        opened.token,
        httponly=True,
        samesite="lax",
        secure=os.environ.get("ASIP_COOKIE_SECURE") == "1",
    )
    return body


@app.post("/api/auth/logout")
def logout(request: Request) -> JSONResponse:
    """Revoke this session. Idempotent.

    No permission check: ending your own session is not an action anyone needs
    authorization for, and a logout that could be denied would leave someone
    unable to sign out of a shared machine.
    """
    _principal, tenant = acting(request)
    with session(tenant) as conn:
        authenticator(conn).logout(tenant, request.state.session_id)

    body = _json({"ok": True})
    body.delete_cookie(SESSION_COOKIE)
    return body


@app.get("/api/auth/me")
def whoami(request: Request) -> JSONResponse:
    """Who the console is logged in as, and what it may therefore show.

    The console uses this to decide which screens to offer. That is a
    convenience, never the enforcement: every endpoint checks for itself, and a
    console that offered a screen it should not would still get a 403.
    """
    principal, tenant = acting(request)
    return _json(
        {
            "user_id": principal.user_id,
            "tenant_id": tenant,
            "roles": sorted(r.value for r in principal.roles),
            "projects": sorted(str(p) for p in principal.project_ids),
            "permissions": sorted(p.value for p in principal.role_permissions()),
            "grants": [
                {
                    "tenant_id": str(g.tenant_id),
                    "permissions": sorted(p.value for p in g.permissions),
                    "justification": g.justification,
                    "expires_at": g.expires_at,
                }
                for g in principal.grants
            ],
        }
    )


@app.get("/api/audit")
def audit_log(request: Request) -> JSONResponse:
    """The audit trail (D-51, D-52). Requires READ_AUDIT, which only auditors hold.

    Reading the audit log is itself audited. Not circular cleverness — "who read
    the record of who read what" is where an insider investigation starts.
    """
    principal, tenant = acting(request)
    with session(tenant) as conn:
        guard(principal.tenant_id).require(
            principal,
            Permission.READ_AUDIT,
            tenant_id=tenant,
            resource_type="audit_log",
            resource_id=str(tenant),
        )
        entries = PostgresIdentityRepository(conn).audit_entries(tenant, limit=200)
        # Verified on read, ascending, because a chain nobody checks is a chain
        # an attacker can edit at leisure (T-008).
        problems = verify_audit_chain(list(reversed(entries)))

    return _json(
        {
            "entries": [
                {
                    "entry_id": e.entry_id,
                    "chain_index": e.chain_index,
                    "actor_id": e.actor_id,
                    "action": e.action,
                    "resource_type": e.resource_type,
                    "resource_id": e.resource_id,
                    "outcome": e.outcome.value,
                    "reason": e.reason,
                    "occurred_at": e.occurred_at,
                    "entry_hash": e.entry_hash,
                }
                for e in entries
            ],
            "chain_intact": not problems,
            "problems": list(problems),
        }
    )


# ── pipeline ────────────────────────────────────────────────────────────────


@app.post("/api/pipeline/run")
def run_pipeline(request: Request) -> JSONResponse:
    """Run one full pass and return what every stage did."""
    principal, tenant = acting(request)
    settings = _settings()
    with session(tenant) as conn:
        permit_admin(
            principal,
            Permission.MANAGE_PROJECTS,
            resource_type="pipeline",
            resource_id=str(tenant),
        )
        container = build_evidence(settings, conn)
        pipeline = Pipeline(conn, container.write_bundle, _fetcher(settings), tenant)
        result = pipeline.run()
    return _json(result.as_dict())


# ── read models, one per screen ─────────────────────────────────────────────


@app.post("/api/chain/anchor")
def anchor_chain(request: Request) -> JSONResponse:
    """Attest the current chain head to an external authority (D-90).

    Run on a schedule in production. Exposed as a button here because the point
    of this phase is that everything the system does is visible.
    """
    principal, tenant = acting(request)
    with session(tenant) as conn:
        permit_admin(
            principal,
            Permission.MANAGE_PROJECTS,
            resource_type="hash_chain",
            resource_id=str(tenant),
        )
        result = build_evidence(_settings(), conn).anchor_chain.execute(tenant)
    return _json(
        {"status": result.status, "detail": result.detail, "chain_index": result.chain_index}
    )


@app.get("/api/chain/anchors")
def list_anchors(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_EVIDENCE,
            resource_type="hash_chain",
            resource_id=str(tenant),
        )
        return _json(PostgresEvidenceRepository(conn).anchors(tenant))


@app.post("/api/reprocess")
def reprocess(request: Request) -> JSONResponse:
    """Re-parse stored captures with the current extractor (D-13).

    Contacts no source. The use case is constructed without a fetcher, so
    "reprocessing accidentally refetched" is not a failure this endpoint can
    produce — see modules/extraction/application/reprocess.py.
    """
    principal, tenant = acting(request)
    from asip.modules.evidence.adapters.capture_reader import WarcCaptureReader
    from asip.modules.evidence.adapters.s3_object_store import S3ObjectStore
    from asip.modules.evidence.adapters.warc_archive import WarcBundleArchive
    from asip.modules.extraction.application.reprocess import ReprocessCaptures

    settings = _settings()
    with session(tenant) as conn:
        permit_admin(
            principal,
            Permission.MANAGE_PROJECTS,
            resource_type="extraction",
            resource_id=str(tenant),
        )
        archive = WarcBundleArchive(
            S3ObjectStore(
                bucket=settings.object_store_bucket,
                endpoint_url=settings.object_store_url,
                access_key=settings.object_store_key,
                secret_key=settings.object_store_secret,
            )
        )
        report = ReprocessCaptures(
            WarcCaptureReader(conn, archive), PostgresExtractionRepository(conn)
        ).execute(tenant)

    return _json(
        {
            "summary": report.summary,
            "captures_examined": report.captures_examined,
            "captures_reprocessed": report.captures_reprocessed,
            "items_updated": report.items_updated,
            "captures_unavailable": report.captures_unavailable,
            "items_needing_migration": report.items_needing_migration,
            "fetches_performed": report.fetches_performed,
            "problems": report.problems,
        }
    )


@app.get("/api/reprocess/backlog")
def reprocess_backlog(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    from asip.modules.extraction.domain.parser import EXTRACTOR_VERSION

    with session(tenant) as conn:
        permit_admin(
            principal,
            Permission.MANAGE_PROJECTS,
            resource_type="extraction",
            resource_id=str(tenant),
        )
        rows = PostgresExtractionRepository(conn).reprocessing_backlog(tenant, EXTRACTOR_VERSION)
    return _json({"current_extractor_version": EXTRACTOR_VERSION, "captures": rows})


@app.get("/api/dashboard")
def dashboard(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_FINDINGS,
            resource_type="dashboard",
            resource_id=str(tenant),
        )
        sources = PostgresCollectionRepository(conn).list_sources(tenant)
        jobs = PostgresCollectionRepository(conn).recent_jobs(tenant, limit=5)
        extraction = PostgresExtractionRepository(conn).counts(tenant)
        findings = PostgresDetectionRepository(conn).counts(tenant)
        exports = PostgresExportRepository(conn).list_exports(tenant, limit=5)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT count(*), "
                "       count(*) FILTER (WHERE captured_at > now() - interval '24 hours') "
                "  FROM sch_evidence.evidence_bundles WHERE tenant_id = %s",
                (tenant,),
            )
            bundles = cur.fetchone() or (0, 0)

    return _json(
        {
            "sources": {"total": len(sources), "enabled": sum(1 for s in sources if s["enabled"])},
            "bundles": {"total": bundles[0], "last_24h": bundles[1]},
            "content": extraction,
            "findings": findings,
            "exports": len(exports),
            "recent_jobs": jobs,
            # D-68: the console must never show "no activity" when the truth is
            # "we lost the source". This is the data that distinguishes them.
            "source_health": [
                {
                    "name": s["name"],
                    "last_success_at": s["last_success_at"],
                    "consecutive_failures": s["consecutive_failures"],
                    "last_failure_reason": s["last_failure_reason"],
                }
                for s in sources
            ],
        }
    )


@app.get("/api/sources")
def sources(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        permit_admin(
            principal,
            Permission.MANAGE_PROJECTS,
            resource_type="source",
            resource_id=str(tenant),
        )
        return _json(PostgresCollectionRepository(conn).list_sources(tenant))


@app.get("/api/captures")
def captures(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_EVIDENCE,
            resource_type="capture",
            resource_id="*",
        )
        return _json(PostgresCollectionRepository(conn).recent_jobs(tenant, limit=200))


@app.get("/api/bundles")
def bundles(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn, conn.cursor() as cur:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_EVIDENCE,
            resource_type="evidence_bundle",
            resource_id="*",
        )
        cur.execute(
            "SELECT b.bundle_id, b.capture_id, b.trace_id, b.source_url, b.captured_at, "
            "       b.manifest_sha256, c.chain_index, c.entry_hash, c.prev_hash, c.algorithm, "
            "       EXISTS (SELECT 1 FROM sch_evidence.tsa_tokens t "
            "                WHERE t.tenant_id = b.tenant_id AND t.bundle_id = b.bundle_id) "
            "  FROM sch_evidence.evidence_bundles b "
            "  JOIN sch_evidence.hash_chain c "
            "    ON c.tenant_id = b.tenant_id AND c.bundle_id = b.bundle_id "
            " WHERE b.tenant_id = %s ORDER BY c.chain_index DESC LIMIT 200",
            (tenant,),
        )
        columns = [
            "bundle_id",
            "capture_id",
            "trace_id",
            "source_url",
            "captured_at",
            "manifest_sha256",
            "chain_index",
            "entry_hash",
            "prev_hash",
            "algorithm",
            "has_timestamp",
        ]
        return _json([dict(zip(columns, row, strict=True)) for row in cur.fetchall()])


@app.get("/api/bundles/{bundle_id}")
def bundle_detail(request: Request, bundle_id: UUID) -> JSONResponse:
    """The evidence viewer's data, including a live re-verification."""
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_EVIDENCE,
            resource_type="evidence_bundle",
            resource_id=str(bundle_id),
        )
        with conn.cursor() as cur:
            cur.execute(
                "SELECT b.bundle_id, b.capture_id, b.trace_id, b.source_url, b.captured_at, "
                "       b.manifest_sha256, b.object_prefix, b.manifest, c.chain_index, "
                "       c.entry_hash, c.prev_hash, c.algorithm "
                "  FROM sch_evidence.evidence_bundles b "
                "  JOIN sch_evidence.hash_chain c "
                "    ON c.tenant_id = b.tenant_id AND c.bundle_id = b.bundle_id "
                " WHERE b.tenant_id = %s AND b.bundle_id = %s",
                (tenant, bundle_id),
            )
            row = cur.fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="no such bundle")
            columns = [
                "bundle_id",
                "capture_id",
                "trace_id",
                "source_url",
                "captured_at",
                "manifest_sha256",
                "object_prefix",
                "manifest",
                "chain_index",
                "entry_hash",
                "prev_hash",
                "algorithm",
            ]
            record = dict(zip(columns, row, strict=True))

            cur.execute(
                "SELECT authority_url, obtained_at, octet_length(token) "
                "  FROM sch_evidence.tsa_tokens WHERE tenant_id = %s AND bundle_id = %s",
                (tenant, bundle_id),
            )
            record["timestamps"] = [
                {"authority_url": a, "obtained_at": o, "token_bytes": n}
                for a, o, n in cur.fetchall()
            ]

        record["manifest"] = json.loads(record["manifest"])
        record["verification"] = _verify(conn, tenant, record)
    return _json(record)


def _verify(conn: psycopg.Connection, tenant: UUID, record: dict[str, Any]) -> dict[str, Any]:
    """Re-verify on demand — the one-click check the product promises.

    Built from the same container the pipeline writes with, so the timestamp is
    genuinely checked against the authority's certificate. An earlier version
    used a stub that always answered "cannot verify", which made every bundle
    read as unconfirmed — the product's central claim showing as unproven in
    the one screen that exists to demonstrate it.

    Reported per check rather than as a score. An analyst needs to name the
    check that failed, and "confidence 0.83" is not defensible in print.
    """
    from asip.contracts.evidence import BundleRef, TsaStatus

    verifier = build_evidence(_settings(), conn).verify_bundle
    result = verifier.execute(
        BundleRef(
            bundle_id=record["bundle_id"],
            tenant_id=tenant,
            chain_index=record["chain_index"],
            manifest_sha256=record["manifest_sha256"],
            tsa_status=TsaStatus.PENDING,
        )
    )
    return {
        "outcome": result.outcome.value,
        "manifest_ok": result.manifest_ok,
        "chain_ok": result.chain_ok,
        "tsa_ok": result.tsa_ok,
        "problems": list(result.problems),
    }


@app.get("/api/content")
def content(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_CONTENT,
            resource_type="content",
            resource_id="*",
        )
        return _json(PostgresExtractionRepository(conn).recent_content(tenant))


@app.get("/api/findings")
def findings(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_FINDINGS,
            resource_type="finding",
            resource_id="*",
        )
        items = PostgresDetectionRepository(conn).list_findings(tenant, _project_gap)
        verdicts = PostgresReviewRepository(conn).current_verdicts(tenant)
    for item in items:
        item["verdict"] = verdicts.get(str(item["finding_id"]))
    return _json(items)


@app.get("/api/findings/{finding_id}")
def finding_detail(request: Request, finding_id: UUID) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_FINDINGS,
            resource_type="finding",
            resource_id=str(finding_id),
        )
        finding = PostgresDetectionRepository(conn).get_finding(tenant, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="no such finding")
        finding["verdict_history"] = PostgresReviewRepository(conn).history(tenant, finding_id)
    return _json(finding)


@app.get("/api/scheduler/runs")
def scheduler_runs(request: Request) -> JSONResponse:
    """Unattended run history, including the ticks that did nothing (D-68)."""
    principal, tenant = acting(request)
    with session(tenant) as conn:
        permit_admin(
            principal,
            Permission.MANAGE_PROJECTS,
            resource_type="scheduler",
            resource_id=str(tenant),
        )
        runs = PostgresCollectionRepository(conn).recent_runs(tenant)
    return _json({"runs": runs, "health": _scheduler_check(runs[0] if runs else None)})


@app.get("/api/findings/{finding_id}/trace")
def finding_trace(request: Request, finding_id: UUID) -> JSONResponse:
    """D-112 — which bytes this finding came from, in one query.

    The question gets asked when a finding is disputed, so the answer has to be
    one statement: four round trips can disagree with each other if anything
    changes between them, and an answer that can disagree with itself is not
    evidence.
    """
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_FINDINGS,
            resource_type="finding",
            resource_id=str(finding_id),
        )
        trace = trace_finding(conn, tenant, finding_id)
    if trace is None:
        raise HTTPException(status_code=404, detail="no such finding")
    # A finding whose evidence has vanished is not a 404 — it exists, and its
    # existence is the problem. Reported as a V-5 integrity failure so it lands
    # in front of someone instead of looking like a mistyped identifier.
    return _json(trace)


@app.post("/api/findings/{finding_id}/verdict")
def record_verdict(request: Request, finding_id: UUID, payload: dict[str, str]) -> JSONResponse:
    """Record a verdict, and export if it crosses the M-06 boundary.

    This is the only place a finding becomes a STIX bundle. Export is a
    consequence of an analyst's decision, never of a rule firing — a rule with
    no measured precision (V-4) produces observations, and an observation
    handed to a recipient as though it were an assessment cannot be recalled.
    """
    principal, tenant = acting(request)
    verdict = payload.get("verdict", "")
    if verdict not in VERDICTS:
        raise HTTPException(status_code=400, detail=f"verdict must be one of {VERDICTS}")

    with session(tenant) as conn:
        # Checked before the verdict is written, not after. A verdict at or
        # above likely_coordination is what pushes a finding into someone
        # else's threat intelligence (M-06), so this is the highest-consequence
        # write in the system and the one whose authorization must not be
        # decided by whether a later step happened to succeed.
        permit(
            request,
            principal,
            Permission.RECORD_VERDICT,
            resource_type="finding",
            resource_id=str(finding_id),
        )
        PostgresReviewRepository(conn).record_verdict(
            uuid.uuid4(),
            tenant,
            finding_id,
            verdict,
            payload.get("analyst", "console"),
            payload.get("rationale", ""),
            BURST_RULE_NAME,
        )

        response: dict[str, Any] = {"ok": True, "finding_id": finding_id, "verdict": verdict}

        if not crosses_the_boundary(verdict):
            response["exported"] = False
            response["reason"] = (
                f"{verdict} stays in Tier 1. M-06 exports at likely_coordination or above."
            )
            return _json(response)

        finding = PostgresDetectionRepository(conn).get_finding(tenant, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="no such finding")

        outcome = ExportFinding(PostgresExportRepository(conn)).execute(
            assemble(conn, tenant, finding, verdict),
            str(finding.get("trace_id") or ""),
        )

    response["exported"] = outcome.exported
    response["reason"] = outcome.reason
    if outcome.exported:
        response["export_id"] = outcome.export_id
        response["bundle_sha256"] = outcome.bundle_sha256
        response["object_count"] = outcome.object_count
    return _json(response)


@app.get("/api/rules")
def rules(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_FINDINGS,
            resource_type="rule",
            resource_id="*",
        )
        return _json(PostgresDetectionRepository(conn).list_rules(tenant))


@app.get("/api/exports")
def exports(request: Request) -> JSONResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.EXPORT_STIX,
            resource_type="export",
            resource_id="*",
        )
        return _json(PostgresExportRepository(conn).list_exports(tenant))


@app.get("/api/exports/{export_id}/bundle")
def export_bundle(request: Request, export_id: UUID) -> PlainTextResponse:
    principal, tenant = acting(request)
    with session(tenant) as conn:
        _project_gap = permit(
            request,
            principal,
            Permission.EXPORT_STIX,
            resource_type="export",
            resource_id=str(export_id),
        )
        payload = PostgresExportRepository(conn).get_bundle(tenant, export_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="no such export")
    return PlainTextResponse(payload, media_type="application/json")


@app.get("/api/timeline")
def timeline(request: Request) -> JSONResponse:
    """Everything that happened, in one ordered stream.

    Captures, bundles, findings and exports on one axis so the pipeline is
    legible as a sequence rather than as four separate tables.
    """
    principal, tenant = acting(request)
    with session(tenant) as conn, conn.cursor() as cur:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_FINDINGS,
            resource_type="timeline",
            resource_id=str(tenant),
        )
        cur.execute(
            "SELECT 'capture' AS kind, requested_at AS at, trace_id, "
            "       url AS label, status AS detail "
            "  FROM sch_evidence.captures WHERE tenant_id = %(t)s "
            "UNION ALL "
            "SELECT 'bundle', captured_at, trace_id, source_url, manifest_sha256 "
            "  FROM sch_evidence.evidence_bundles WHERE tenant_id = %(t)s "
            "UNION ALL "
            "SELECT 'finding', detected_at, trace_id, rule_name, "
            "       item_count || ' items / ' || account_count || ' accounts' "
            "  FROM sch_detection.v_findings_for_review WHERE tenant_id = %(t)s "
            "UNION ALL "
            "SELECT 'export', created_at, trace_id, 'STIX 2.1', bundle_sha256 "
            "  FROM sch_export.export_jobs WHERE tenant_id = %(t)s "
            " ORDER BY at DESC LIMIT 200",
            {"t": tenant},
        )
        columns = ["kind", "at", "trace_id", "label", "detail"]
        return _json([dict(zip(columns, row, strict=True)) for row in cur.fetchall()])


@app.get("/api/graph")
def graph(request: Request) -> JSONResponse:
    """Co-participation: accounts that appear in the same finding.

    Real data, not dummy — but a trivially small graph, because the naive rule
    produces one cluster per burst. Edges mean "these two accounts were in the
    same window", which is a statement about the cluster and about nobody in
    particular (V-1).
    """
    principal, tenant = acting(request)
    with session(tenant) as conn, conn.cursor() as cur:
        _project_gap = permit(
            request,
            principal,
            Permission.READ_FINDINGS,
            resource_type="graph",
            resource_id=str(tenant),
        )
        cur.execute(
            # Through the published view, not the table (D-92, D-99).
            "SELECT fa.finding_id, fa.account_id, a.handle "
            "  FROM sch_detection.finding_accounts fa "
            "  JOIN sch_extraction.v_accounts_for_export a "
            "    ON a.account_id = fa.account_id AND a.tenant_id = fa.tenant_id "
            " WHERE fa.tenant_id = %s",
            (tenant,),
        )
        rows = cur.fetchall()

    clusters: dict[str, list[tuple[str, str]]] = {}
    for finding_id, account_id, handle in rows:
        clusters.setdefault(str(finding_id), []).append((str(account_id), handle))

    nodes = {aid: handle for members in clusters.values() for aid, handle in members}
    edges = []
    for finding_id, members in clusters.items():
        for i, (a, _) in enumerate(members):
            for b, _ in members[i + 1 :]:
                edges.append({"source": a, "target": b, "finding_id": finding_id})

    return _json(
        {
            "nodes": [{"id": aid, "label": handle} for aid, handle in nodes.items()],
            "edges": edges,
            "clusters": len(clusters),
        }
    )


#: How long the scheduler may be quiet before that is itself the news. Three
#: ticks at the default interval — one missed tick is a slow run, three is a
#: process that is not coming back.
SCHEDULER_SILENCE_LIMIT = timedelta(minutes=5)


def _scheduler_check(last: dict[str, Any] | None) -> dict[str, Any]:
    """Four states, because "no runs" and "runs, all idle" are different facts.

    Reporting a never-started scheduler as `ok` because nothing failed is the
    exact error D-68 is about: an empty result read as a healthy one.
    """
    if last is None:
        return {
            "name": "scheduler",
            "status": "unverified",
            "detail": (
                "No unattended run has ever been recorded. The pipeline runs only when "
                "someone presses the button. Start it with: make run-scheduler"
            ),
        }

    started = last["started_at"]
    age = datetime.now(UTC) - started
    stale = age > SCHEDULER_SILENCE_LIMIT
    ago = f"{int(age.total_seconds())}s ago"

    if stale:
        return {
            "name": "scheduler",
            "status": "failed",
            "detail": (
                f"Last run was {ago}, over the {int(SCHEDULER_SILENCE_LIMIT.total_seconds())}s "
                "limit. The scheduler is not running. Nothing is being collected, and "
                "nothing will report that fact except this check (D-87)."
            ),
        }
    if last["outcome"] == "failed":
        return {
            "name": "scheduler",
            "status": "failed",
            "detail": f"Running, but the last run failed {ago}: {last['detail']}",
        }
    return {
        "name": "scheduler",
        "status": "ok",
        "detail": (
            f"Last run {ago}: {last['outcome']} — {last['detail']} "
            "An idle run means nothing was due, not that nothing happened (D-68)."
        ),
    }


@app.get("/api/health")
def health(request: Request) -> JSONResponse:
    """System health. Reports what is not working as loudly as what is.

    Every dependency is probed rather than assumed, because silent degradation
    is the primary failure mode of this class of system (D-87).
    """
    checks: list[dict[str, Any]] = []

    try:
        with owner_connection() as conn, conn.cursor() as cur:
            cur.execute("SELECT count(*) FROM sch_migrations.applied")
            applied = (cur.fetchone() or (0,))[0]
        checks.append(
            {"name": "postgres", "status": "ok", "detail": f"{applied} migrations applied"}
        )
    except Exception as exc:
        checks.append({"name": "postgres", "status": "failed", "detail": str(exc)})

    try:
        from asip.modules.evidence.adapters.s3_object_store import S3ObjectStore

        store = S3ObjectStore(
            bucket=os.environ.get("ASIP_OBJECT_STORE_BUCKET", "asip-evidence"),
            endpoint_url=os.environ.get("ASIP_OBJECT_STORE_URL", "http://127.0.0.1:9000"),
            access_key=os.environ.get("ASIP_OBJECT_STORE_KEY", "asip"),
            secret_key=os.environ.get("ASIP_OBJECT_STORE_SECRET", "asip_dev_only"),
        )
        store.ensure_bucket()
        checks.append({"name": "object_store", "status": "ok", "detail": "bucket reachable"})
    except Exception as exc:
        checks.append({"name": "object_store", "status": "failed", "detail": str(exc)})

    # Deliberately reported as a known gap rather than as a passing check.
    settings = _settings()
    if settings.tsa_certificate is None:
        checks.append(
            {
                "name": "timestamp_authority",
                "status": "unverified",
                "detail": (
                    f"{settings.tsa_url} is configured for stamping but no certificate is "
                    "available, so tokens are stored and cannot be checked here. Bundles "
                    "read as incomplete rather than verified — correct, but unconfirmed."
                ),
            }
        )
    else:
        checks.append(
            {
                "name": "timestamp_authority",
                "status": "ok",
                "detail": (
                    f"{settings.tsa_url} configured with a certificate; obtained tokens are "
                    "verified in process against it."
                ),
            }
        )
    queue_url = os.environ.get("ASIP_FETCH_QUEUE_URL")
    if not queue_url:
        checks.append(
            {
                "name": "fetch_zone",
                "status": "unverified",
                "detail": (
                    "Fetching runs in this process. The credential boundary holds — the "
                    "fetcher is constructed with no database access — but there is no "
                    "process or network boundary. Set ASIP_FETCH_QUEUE_URL and run the "
                    "fetcher container for the isolation D-11 describes."
                ),
            }
        )
    else:
        try:
            from asip.modules.collection.adapters.redis_fetch_queue import RedisFetchQueue

            queue = RedisFetchQueue(queue_url)
            workers = queue.live_workers()
            pending = queue.pending_jobs()
            if workers:
                checks.append(
                    {
                        "name": "fetch_zone",
                        "status": "ok",
                        "detail": (
                            f"{len(workers)} isolated worker(s) alive ({', '.join(workers)}); "
                            f"{pending} job(s) queued. No route to the database."
                        ),
                    }
                )
            else:
                # Distinguished from "nothing to collect" on purpose (D-68): an
                # idle pipeline and a dead fleet look identical from the
                # database alone and need different responses.
                checks.append(
                    {
                        "name": "fetch_zone",
                        "status": "failed",
                        "detail": (
                            f"A queue is configured but no worker has reported. {pending} "
                            "job(s) are waiting and nothing is collecting. Start the fetch "
                            "zone: docker compose up -d fetcher."
                        ),
                    }
                )
        except Exception as exc:
            checks.append({"name": "fetch_zone", "status": "failed", "detail": str(exc)})

    return _json({"checks": checks, "generated_at": datetime.now(UTC)})


# ── the canary source, and the console ──────────────────────────────────────

if CANARY_ROOT.is_dir():
    # A page we control, fetched over real HTTP on the same path as anything
    # else (C-08). It makes the pipeline demonstrable without pointing a
    # collector at somebody else's site, and it separates "we broke it" from
    # "they changed it" the moment something stops working.
    app.mount("/canary", StaticFiles(directory=CANARY_ROOT, html=True), name="canary")

if (WEB_ROOT / "console").is_dir():
    app.mount("/static", StaticFiles(directory=WEB_ROOT / "console"), name="static")


@app.get("/api/health/tenant")
def tenant_health(request: Request) -> JSONResponse:
    """Health of this tenant's own data. Behind authentication, unlike /api/health.

    These three read tenant rows — how far the chain has been anchored, whether
    any finding points at evidence that no longer resolves (V-5), whether the
    scheduler is still running. Useful, and none of anyone else's business:
    "how many broken findings does this customer have" is not a liveness probe.

    The split is the point. /api/health answers "is the service up" for a load
    balancer and needs no session; this answers "is this tenant's data sound"
    and needs one.
    """
    principal, tenant = acting(request)

    # Authorized once, up front, and deliberately outside the try blocks below.
    # Each check catches its own exceptions so one broken dependency does not
    # hide the rest — but a denial must not be swallowed by that same handler
    # and reported as "check failed".
    with session(tenant) as conn:
        permit_admin(
            principal,
            Permission.MANAGE_PROJECTS,
            resource_type="tenant_health",
            resource_id=str(tenant),
        )

    checks: list[dict[str, Any]] = []

    try:
        with session(tenant) as conn:
            repository = PostgresEvidenceRepository(conn)
            latest = repository.latest_anchor(tenant)
            head = repository.head(tenant)
        if head is None:
            checks.append(
                {
                    "name": "chain_anchoring",
                    "status": "ok",
                    "detail": "The chain is empty — nothing to anchor yet.",
                }
            )
        elif latest is None:
            checks.append(
                {
                    "name": "chain_anchoring",
                    "status": "unverified",
                    "detail": (
                        f"Chain head is at index {head.chain_index} and has never been "
                        "anchored. A hash chain detects an edited record but not a chain "
                        "rebuilt from genesis; until an anchor exists, wholesale "
                        "replacement is undetectable."
                    ),
                }
            )
        else:
            behind = head.chain_index - latest.chain_index
            checks.append(
                {
                    "name": "chain_anchoring",
                    "status": "ok" if behind == 0 else "stale",
                    "detail": (
                        f"Anchored at index {latest.chain_index} via {latest.authority_url}. "
                        + (
                            "Head is anchored."
                            if behind == 0
                            else f"{behind} entrie(s) written since — those remain rewritable "
                            "until the next anchor."
                        )
                    ),
                }
            )
    except Exception as exc:
        checks.append({"name": "chain_anchoring", "status": "failed", "detail": str(exc)})

    # V-5, checked rather than assumed.
    #
    # The CHECK constraint on findings enforces that evidence_refs is non-empty.
    # It cannot enforce that the referenced bundles exist, because the obvious
    # mechanism — a foreign key from sch_detection to sch_evidence — would
    # couple two modules that D-99 requires to be independently removable. So
    # the reference is verified rather than constrained, and the verification
    # has to be visible or it is not a control at all.
    #
    # A non-zero count here means findings resting on evidence nobody can
    # produce, which is precisely the condition V-5 exists to prevent.
    try:
        with session(tenant) as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) FROM sch_detection.findings f "
                " WHERE f.tenant_id = %(t)s AND EXISTS ("
                "   SELECT 1 FROM unnest(f.evidence_refs) r "
                "    WHERE NOT EXISTS ("
                "      SELECT 1 FROM sch_evidence.evidence_bundles b "
                "       WHERE b.tenant_id = f.tenant_id AND b.bundle_id = r))",
                {"t": tenant},
            )
            dangling = (cur.fetchone() or (0,))[0]
        checks.append(
            {
                "name": "evidence_references",
                "status": "ok" if dangling == 0 else "failed",
                "detail": (
                    "Every finding's evidence resolves to a stored bundle."
                    if dangling == 0
                    else f"{dangling} finding(s) reference evidence bundles that cannot "
                    "be found. V-5 requires a finding to rest on evidence; these rest "
                    "on identifiers that resolve to nothing and cannot be defended."
                ),
            }
        )
    except Exception as exc:
        checks.append({"name": "evidence_references", "status": "failed", "detail": str(exc)})

    # D-87 — a scheduler that stopped is the purest form of silent degradation:
    # nothing complains, because nothing is running. The absence of runs is the
    # signal, so it has to be checked for explicitly rather than inferred from
    # an empty screen (D-68).
    try:
        with session(tenant) as conn:
            last = PostgresCollectionRepository(conn).last_run(tenant)
        checks.append(_scheduler_check(last))
    except Exception as exc:
        checks.append({"name": "scheduler", "status": "failed", "detail": str(exc)})

    return _json({"checks": checks, "generated_at": datetime.now(UTC)})


@app.get("/", response_class=HTMLResponse)
def console() -> HTMLResponse:
    return HTMLResponse((WEB_ROOT / "console" / "index.html").read_text(encoding="utf-8"))
