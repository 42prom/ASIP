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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import psycopg
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from asip.entrypoints.composition import Settings, build_evidence
from asip.entrypoints.pipeline import BURST_RULE_NAME, Pipeline
from asip.modules.collection.adapters.http_fetcher import HttpFetcher
from asip.modules.collection.adapters.postgres_repository import PostgresCollectionRepository
from asip.modules.detection.adapters.postgres_repository import PostgresDetectionRepository
from asip.modules.evidence.adapters.warc_archive import WarcBundleArchive
from asip.modules.export.adapters.postgres_repository import PostgresExportRepository
from asip.modules.extraction.adapters.postgres_repository import PostgresExtractionRepository
from asip.modules.review.adapters.postgres_repository import VERDICTS, PostgresReviewRepository

WEB_ROOT = Path(__file__).resolve().parents[3] / "web"
CANARY_ROOT = WEB_ROOT / "canary"

DEFAULT_TENANT = UUID(os.environ.get("ASIP_TENANT_ID", "aaaaaaaa-0000-4000-8000-0000000000d1"))

app = FastAPI(title="ASIP", version="0.1.0", docs_url="/api/docs")


def _dsn() -> str:
    return os.environ.get("ASIP_DB_URL", "postgresql://asip:asip_dev_only@127.0.0.1:5432/asip")


@contextmanager
def session() -> Iterator[psycopg.Connection]:
    """A connection scoped to one tenant, as the application role.

    `SET LOCAL ROLE asip_app` and the tenant GUC are set per request, not per
    process. Connection pools reuse connections across requests, and a tenant
    id that outlived its request would be a cross-tenant read no policy could
    catch (V-7).
    """
    with psycopg.connect(_dsn()) as conn:
        with conn.cursor() as cur:
            cur.execute("SET ROLE asip_app")
            cur.execute("SELECT set_config('asip.tenant_id', %s, false)", (str(DEFAULT_TENANT),))
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise


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
        if isinstance(value, dict):
            return {k: convert(v) for k, v in value.items()}
        if isinstance(value, list | tuple):
            return [convert(v) for v in value]
        return value

    return JSONResponse(convert(payload))


# ── pipeline ────────────────────────────────────────────────────────────────


@app.post("/api/pipeline/run")
def run_pipeline() -> JSONResponse:
    """Run one full pass and return what every stage did."""
    settings = Settings(
        profile=os.environ.get("ASIP_PROFILE", "dev"),
        db_url=_dsn(),
        object_store_url=os.environ.get("ASIP_OBJECT_STORE_URL", "http://127.0.0.1:9000"),
        object_store_key=os.environ.get("ASIP_OBJECT_STORE_KEY", "asip"),
        object_store_secret=os.environ.get("ASIP_OBJECT_STORE_SECRET", "asip_dev_only"),
        object_store_bucket=os.environ.get("ASIP_OBJECT_STORE_BUCKET", "asip-evidence"),
        tsa_url=os.environ.get("ASIP_TSA_URL", "https://freetsa.org/tsr"),
    )
    with session() as conn:
        container = build_evidence(settings, conn)
        pipeline = Pipeline(conn, container.write_bundle, HttpFetcher(), DEFAULT_TENANT)
        result = pipeline.run()
    return _json(result.as_dict())


# ── read models, one per screen ─────────────────────────────────────────────


@app.get("/api/dashboard")
def dashboard() -> JSONResponse:
    with session() as conn:
        sources = PostgresCollectionRepository(conn).list_sources(DEFAULT_TENANT)
        jobs = PostgresCollectionRepository(conn).recent_jobs(DEFAULT_TENANT, limit=5)
        extraction = PostgresExtractionRepository(conn).counts(DEFAULT_TENANT)
        findings = PostgresDetectionRepository(conn).counts(DEFAULT_TENANT)
        exports = PostgresExportRepository(conn).list_exports(DEFAULT_TENANT, limit=5)
        with conn.cursor() as cur:
            cur.execute(
                "SELECT count(*), "
                "       count(*) FILTER (WHERE captured_at > now() - interval '24 hours') "
                "  FROM sch_evidence.evidence_bundles WHERE tenant_id = %s",
                (DEFAULT_TENANT,),
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
def sources() -> JSONResponse:
    with session() as conn:
        return _json(PostgresCollectionRepository(conn).list_sources(DEFAULT_TENANT))


@app.get("/api/captures")
def captures() -> JSONResponse:
    with session() as conn:
        return _json(PostgresCollectionRepository(conn).recent_jobs(DEFAULT_TENANT, limit=200))


@app.get("/api/bundles")
def bundles() -> JSONResponse:
    with session() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT b.bundle_id, b.capture_id, b.trace_id, b.source_url, b.captured_at, "
            "       b.manifest_sha256, c.chain_index, c.entry_hash, c.prev_hash, c.algorithm, "
            "       EXISTS (SELECT 1 FROM sch_evidence.tsa_tokens t "
            "                WHERE t.tenant_id = b.tenant_id AND t.bundle_id = b.bundle_id) "
            "  FROM sch_evidence.evidence_bundles b "
            "  JOIN sch_evidence.hash_chain c "
            "    ON c.tenant_id = b.tenant_id AND c.bundle_id = b.bundle_id "
            " WHERE b.tenant_id = %s ORDER BY c.chain_index DESC LIMIT 200",
            (DEFAULT_TENANT,),
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
def bundle_detail(bundle_id: UUID) -> JSONResponse:
    """The evidence viewer's data, including a live re-verification."""
    settings_url = os.environ.get("ASIP_OBJECT_STORE_URL", "http://127.0.0.1:9000")
    with session() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT b.bundle_id, b.capture_id, b.trace_id, b.source_url, b.captured_at, "
                "       b.manifest_sha256, b.object_prefix, b.manifest, c.chain_index, "
                "       c.entry_hash, c.prev_hash, c.algorithm "
                "  FROM sch_evidence.evidence_bundles b "
                "  JOIN sch_evidence.hash_chain c "
                "    ON c.tenant_id = b.tenant_id AND c.bundle_id = b.bundle_id "
                " WHERE b.tenant_id = %s AND b.bundle_id = %s",
                (DEFAULT_TENANT, bundle_id),
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
                (DEFAULT_TENANT, bundle_id),
            )
            record["timestamps"] = [
                {"authority_url": a, "obtained_at": o, "token_bytes": n}
                for a, o, n in cur.fetchall()
            ]

        record["manifest"] = json.loads(record["manifest"])
        record["verification"] = _verify(conn, settings_url, record)
    return _json(record)


def _verify(conn: psycopg.Connection, store_url: str, record: dict[str, Any]) -> dict[str, Any]:
    """Re-verify on demand — the one-click check the product promises.

    Reported per check rather than as a score. An analyst needs to say which
    check failed, and "confidence 0.83" is not defensible in print.
    """
    from asip.contracts.evidence import BundleRef, TsaStatus
    from asip.modules.evidence.adapters.postgres_repository import PostgresEvidenceRepository
    from asip.modules.evidence.adapters.s3_object_store import S3ObjectStore
    from asip.modules.evidence.application.verify_bundle import VerifyBundle

    class _NoTsa:
        def stamp(self, digest_hex: str) -> bytes:
            raise ConnectionError("verification does not issue tokens")

        def verify(self, digest_hex: str, token: bytes) -> bool:
            return False

        def can_verify(self) -> bool:
            # Re-verification does not hold the certificate, so it reports the
            # timestamp as unconfirmed rather than as broken.
            return False

    store = S3ObjectStore(
        bucket=os.environ.get("ASIP_OBJECT_STORE_BUCKET", "asip-evidence"),
        endpoint_url=store_url,
        access_key=os.environ.get("ASIP_OBJECT_STORE_KEY", "asip"),
        secret_key=os.environ.get("ASIP_OBJECT_STORE_SECRET", "asip_dev_only"),
    )
    verifier = VerifyBundle(WarcBundleArchive(store), PostgresEvidenceRepository(conn), _NoTsa())
    result = verifier.execute(
        BundleRef(
            bundle_id=record["bundle_id"],
            tenant_id=DEFAULT_TENANT,
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
def content() -> JSONResponse:
    with session() as conn:
        return _json(PostgresExtractionRepository(conn).recent_content(DEFAULT_TENANT))


@app.get("/api/findings")
def findings() -> JSONResponse:
    with session() as conn:
        items = PostgresDetectionRepository(conn).list_findings(DEFAULT_TENANT)
        verdicts = PostgresReviewRepository(conn).current_verdicts(DEFAULT_TENANT)
    for item in items:
        item["verdict"] = verdicts.get(str(item["finding_id"]))
    return _json(items)


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: UUID) -> JSONResponse:
    with session() as conn:
        finding = PostgresDetectionRepository(conn).get_finding(DEFAULT_TENANT, finding_id)
        if finding is None:
            raise HTTPException(status_code=404, detail="no such finding")
        finding["verdict_history"] = PostgresReviewRepository(conn).history(
            DEFAULT_TENANT, finding_id
        )
    return _json(finding)


@app.post("/api/findings/{finding_id}/verdict")
def record_verdict(finding_id: UUID, payload: dict[str, str]) -> JSONResponse:
    verdict = payload.get("verdict", "")
    if verdict not in VERDICTS:
        raise HTTPException(status_code=400, detail=f"verdict must be one of {VERDICTS}")
    with session() as conn:
        PostgresReviewRepository(conn).record_verdict(
            uuid.uuid4(),
            DEFAULT_TENANT,
            finding_id,
            verdict,
            payload.get("analyst", "console"),
            payload.get("rationale", ""),
            BURST_RULE_NAME,
        )
    return _json({"ok": True, "finding_id": finding_id, "verdict": verdict})


@app.get("/api/rules")
def rules() -> JSONResponse:
    with session() as conn:
        return _json(PostgresDetectionRepository(conn).list_rules(DEFAULT_TENANT))


@app.get("/api/exports")
def exports() -> JSONResponse:
    with session() as conn:
        return _json(PostgresExportRepository(conn).list_exports(DEFAULT_TENANT))


@app.get("/api/exports/{export_id}/bundle")
def export_bundle(export_id: UUID) -> PlainTextResponse:
    with session() as conn:
        payload = PostgresExportRepository(conn).get_bundle(DEFAULT_TENANT, export_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="no such export")
    return PlainTextResponse(payload, media_type="application/json")


@app.get("/api/timeline")
def timeline() -> JSONResponse:
    """Everything that happened, in one ordered stream.

    Captures, bundles, findings and exports on one axis so the pipeline is
    legible as a sequence rather than as four separate tables.
    """
    with session() as conn, conn.cursor() as cur:
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
            {"t": DEFAULT_TENANT},
        )
        columns = ["kind", "at", "trace_id", "label", "detail"]
        return _json([dict(zip(columns, row, strict=True)) for row in cur.fetchall()])


@app.get("/api/graph")
def graph() -> JSONResponse:
    """Co-participation: accounts that appear in the same finding.

    Real data, not dummy — but a trivially small graph, because the naive rule
    produces one cluster per burst. Edges mean "these two accounts were in the
    same window", which is a statement about the cluster and about nobody in
    particular (V-1).
    """
    with session() as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT fa.finding_id, fa.account_id, a.handle "
            "  FROM sch_detection.finding_accounts fa "
            "  JOIN sch_extraction.accounts a ON a.account_id = fa.account_id "
            " WHERE fa.tenant_id = %s",
            (DEFAULT_TENANT,),
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


@app.get("/api/health")
def health() -> JSONResponse:
    """System health. Reports what is not working as loudly as what is.

    Every dependency is probed rather than assumed, because silent degradation
    is the primary failure mode of this class of system (D-87).
    """
    checks: list[dict[str, Any]] = []

    try:
        with session() as conn, conn.cursor() as cur:
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
    checks.append(
        {
            "name": "timestamp_authority",
            "status": "unverified",
            "detail": (
                "No live RFC 3161 token has been verified end to end. Bundles seal as "
                "tsa_pending when the authority is unreachable, which is correct, but "
                "the external attestation is untested against a real authority."
            ),
        }
    )
    checks.append(
        {
            "name": "chain_anchoring",
            "status": "not_implemented",
            "detail": (
                "chain_anchors table exists; the job that writes anchors does not. "
                "Until it runs, wholesale chain replacement is undetectable."
            ),
        }
    )

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


@app.get("/", response_class=HTMLResponse)
def console() -> HTMLResponse:
    return HTMLResponse((WEB_ROOT / "console" / "index.html").read_text(encoding="utf-8"))
