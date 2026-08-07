"""L4 — the walking skeleton, end to end.

    schedule → fetch → seal → extract → store → detect → export

Orchestration lives here rather than in any module because the sequence spans
all six of them, and a module that knew the order would be coupled to modules
it must be removable from (D-99). Every step below calls into one module and
hands the result to the next; no module calls another.

Each stage records what it did as it goes, so the console can show the pipeline
working rather than only its outcome. That is the point of this phase: a stage
that runs invisibly is a stage nobody can debug.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import psycopg

from asip.contracts.evidence import Artifact, ArtifactKind, BundleDraft, RenderParams
from asip.entrypoints.exporting import assemble
from asip.modules.collection.adapters.http_fetcher import HttpFetcher
from asip.modules.collection.adapters.postgres_repository import PostgresCollectionRepository
from asip.modules.detection.adapters.postgres_repository import PostgresDetectionRepository
from asip.modules.detection.domain.burst import (
    BurstRuleParams,
    Observation,
    find_bursts,
)
from asip.modules.evidence.application.write_bundle import WriteBundle
from asip.modules.export.adapters.postgres_repository import PostgresExportRepository
from asip.modules.export.application.export_finding import ExportFinding
from asip.modules.extraction.adapters.postgres_repository import (
    PostgresExtractionRepository,
    account_id_for,
    content_id_for,
)
from asip.modules.extraction.domain.parser import parse_capture
from asip.modules.review.adapters.postgres_repository import PostgresReviewRepository

#: The one rule the skeleton runs. Fixed id so re-running does not multiply it.
BURST_RULE_ID = UUID("d17ec7a0-0000-4000-8000-a51900000003")
BURST_RULE_NAME = "naive-burst-v1"

#: Render parameters for a fetch with no browser. Recorded rather than omitted:
#: D-23 is about a capture being reproducible, and "no browser was involved" is
#: itself a reproducibility fact a later reader needs.
NO_BROWSER_RENDER = RenderParams(
    viewport_width=0,
    viewport_height=0,
    device_pixel_ratio=1.0,
    locale="und",
    timezone="UTC",
    animations_disabled=True,
    network_idle_ms=0,
    settle_delay_ms=0,
    scroll_sequence=(),
)


@dataclass
class StageResult:
    """What one stage did. Shown verbatim in the console."""

    stage: str
    status: str
    detail: str
    counts: dict[str, int] = field(default_factory=dict)


@dataclass
class PipelineRun:
    trace_id: str
    started_at: datetime
    stages: list[StageResult] = field(default_factory=list)

    def record(self, stage: str, status: str, detail: str, **counts: int) -> None:
        self.stages.append(StageResult(stage, status, detail, dict(counts)))

    def as_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "started_at": self.started_at.isoformat(),
            "stages": [
                {
                    "stage": s.stage,
                    "status": s.status,
                    "detail": s.detail,
                    "counts": s.counts,
                }
                for s in self.stages
            ],
        }


class Pipeline:
    """Runs one full pass for a tenant."""

    def __init__(
        self,
        connection: psycopg.Connection,
        write_bundle: WriteBundle,
        fetcher: HttpFetcher,
        tenant_id: UUID,
    ) -> None:
        self._conn = connection
        self._write_bundle = write_bundle
        # The fetcher is handed no connection, ever. See http_fetcher.py: V-3
        # is enforced by what this object was constructed with.
        self._fetcher = fetcher
        self._tenant = tenant_id

        self._collection = PostgresCollectionRepository(connection)
        self._extraction = PostgresExtractionRepository(connection)
        self._detection = PostgresDetectionRepository(connection)
        self._export = PostgresExportRepository(connection)
        self._review = PostgresReviewRepository(connection)

    def run(self) -> PipelineRun:
        """One pass. Every stage reports, including when it does nothing."""
        # D-112: one trace id, carried from fetch dispatch through capture,
        # bundle, content rows and findings, so a finding traces back to its
        # originating capture in one query.
        trace_id = f"trace-{uuid.uuid4().hex[:12]}"
        now = datetime.now(UTC)
        run = PipelineRun(trace_id=trace_id, started_at=now)

        self._detection.ensure_rule(
            BURST_RULE_ID,
            self._tenant,
            BURST_RULE_NAME,
            "At least N items from at least M distinct accounts inside W seconds. "
            "Behavioural only — never reads text or stance (V-2).",
            {"window_seconds": 120, "minimum_items": 4, "minimum_accounts": 3},
        )

        due = self._collection.due_sources(self._tenant, now)
        if not due:
            # D-68: "nothing was due" is not "nothing happened". Saying so is
            # the difference between a working scheduler and a silent one.
            run.record("schedule", "idle", "No source is due for collection yet.", due=0)
            return run
        run.record("schedule", "ok", f"{len(due)} source(s) due.", due=len(due))

        for source in due:
            self._run_source(run, source, trace_id)

        return run

    def _run_source(self, run: PipelineRun, source: dict[str, Any], trace_id: str) -> None:
        source_id = source["source_id"]
        job_id = uuid.uuid4()
        started = datetime.now(UTC)

        self._collection.open_job(job_id, self._tenant, source_id, trace_id, started)
        self._conn.commit()

        # ── fetch ───────────────────────────────────────────────────────────
        outcome = self._fetcher.fetch(source["url"])
        finished = datetime.now(UTC)

        if not outcome.succeeded:
            self._collection.close_job(
                job_id, outcome.status, 0, finished, None, outcome.failure_reason
            )
            self._collection.record_health(source_id, False, finished, outcome.failure_reason)
            self._conn.commit()
            run.record(
                "fetch",
                "failed",
                f"{source['name']}: {outcome.status} — {outcome.failure_reason}",
            )
            return

        run.record(
            "fetch",
            "ok",
            f"{source['name']}: {outcome.bytes_fetched} bytes from {source['url']}",
            bytes=outcome.bytes_fetched,
        )

        # ── seal ────────────────────────────────────────────────────────────
        capture_id = uuid.uuid4()
        bundle_id = uuid.uuid4()
        body = outcome.body
        draft = BundleDraft(
            bundle_id=bundle_id,
            capture_id=capture_id,
            tenant_id=self._tenant,
            trace_id=trace_id,
            source_url=source["url"],
            captured_at=started,
            artifacts=(
                Artifact(
                    name="dom.html",
                    kind=ArtifactKind.DOM,
                    media_type=outcome.content_type.split(";")[0] or "text/html",
                    size_bytes=len(body),
                    sha256=hashlib.sha256(body).hexdigest(),
                ),
            ),
            render_params=NO_BROWSER_RENDER,
        )

        self._record_capture(capture_id, source_id, trace_id, started, finished, outcome)
        ref = self._write_bundle.execute(draft, {"dom.html": body})
        self._collection.close_job(
            job_id, outcome.status, outcome.bytes_fetched, finished, capture_id
        )
        self._collection.record_health(source_id, True, finished)
        self._conn.commit()

        run.record(
            "evidence",
            "ok",
            f"Bundle sealed at chain index {ref.chain_index}, {ref.tsa_status.value}.",
            chain_index=ref.chain_index,
        )

        # ── extract ─────────────────────────────────────────────────────────
        result = parse_capture(body, minimum_expected_items=1)
        platform = source["platform"]
        for item in result.items:
            account_id = account_id_for(platform, item.author_handle)
            self._extraction.upsert_account(
                account_id,
                self._tenant,
                platform,
                item.author_handle,
                item.author_display_name,
                item.posted_at,
            )
            self._extraction.insert_content(
                content_id=content_id_for(platform, item.external_id),
                tenant_id=self._tenant,
                capture_id=capture_id,
                source_id=source_id,
                account_id=account_id,
                trace_id=trace_id,
                posted_at=item.posted_at,
                posted_at_raw=item.posted_at_raw,
                precision=item.timestamp_precision,
                text=item.text,
                text_sha256=hashlib.sha256(item.text.encode("utf-8")).hexdigest(),
                lang=None,
                extractor_version=result.extractor_version,
                script=item.script,
            )
        self._extraction.record_run(
            uuid.uuid4(),
            self._tenant,
            capture_id,
            result.extractor_version,
            len(result.items),
            result.validation_passed,
            list(result.problems),
        )
        self._conn.commit()

        run.record(
            "extract",
            "ok" if result.validation_passed else "degraded",
            f"{len(result.items)} item(s); "
            + ("validation passed" if result.validation_passed else "; ".join(result.problems)),
            items=len(result.items),
        )

        # ── detect ──────────────────────────────────────────────────────────
        rows = self._extraction.observations_for_detection(self._tenant, source_id)
        observations = [
            Observation(
                content_id=row["content_id"],
                account_id=row["account_id"],
                capture_id=row["capture_id"],
                posted_at=row["posted_at_authoritative"],
                timestamp_precision=row["timestamp_precision"],
            )
            for row in rows
        ]
        clusters = find_bursts(observations, BurstRuleParams())

        if not clusters:
            run.record(
                "detect",
                "idle",
                f"No burst in {len(observations)} observation(s) — the rule did not fire.",
                observations=len(observations),
            )
            return

        finding_ids = []
        for cluster in clusters:
            finding_id = uuid.uuid4()
            finding_ids.append(finding_id)
            self._detection.record_finding(
                finding_id=finding_id,
                tenant_id=self._tenant,
                rule_id=BURST_RULE_ID,
                source_id=source_id,
                # D-49. Inherited from the source rather than decided here: a
                # rule has no idea what a project is, and it should not learn.
                project_id=source["project_id"],
                trace_id=trace_id,
                window_start=cluster.window_start,
                window_end=cluster.window_end,
                item_count=cluster.item_count,
                account_count=cluster.account_count,
                signals=[
                    {
                        "name": s.name,
                        "observed": s.observed,
                        "threshold": s.threshold,
                        "passed": s.passed,
                        "description": s.description,
                    }
                    for s in cluster.signals
                ],
                # V-5: the bundle this rests on. Never empty.
                evidence_refs=[bundle_id],
                # The rule has no measured precision, so every finding it makes
                # is a shadow finding and is labelled as one everywhere it
                # appears (V-4).
                shadow=True,
                accounts=list(cluster.accounts),
            )
        self._conn.commit()
        run.record(
            "detect",
            "ok",
            f"{len(clusters)} shadow finding(s) — the rule has no measured precision, "
            "so these are observations, not verdicts.",
            findings=len(clusters),
        )

        # ── export ──────────────────────────────────────────────────────────
        #
        # This stage used to write a bundle for every finding it had just made.
        # That was wrong, and wrong in the direction that cannot be undone.
        #
        # M-06 crosses the Tier 1/Tier 2 boundary only at LIKELY_COORDINATION or
        # above. A finding this run produced has no verdict yet — nobody has
        # looked at it — so every one of them is refused here. Exporting them
        # anyway would push unreviewed observations from a rule with no measured
        # precision into recipients' threat intelligence, where they are indexed,
        # forwarded, and impossible to retract.
        #
        # The refusal path runs rather than being skipped, so the boundary is
        # exercised in production and not only in tests.
        exporter = ExportFinding(self._export)
        outcomes = []
        for finding_id in finding_ids:
            finding = self._detection.get_finding(self._tenant, finding_id)
            if finding is None:
                continue
            verdict = self._review.current_verdicts(self._tenant).get(str(finding_id))
            export = assemble(
                self._conn,
                self._tenant,
                finding,
                verdict["verdict"] if verdict else None,
            )
            outcomes.append(exporter.execute(export, trace_id))
        self._conn.commit()

        exported = sum(1 for o in outcomes if o.exported)
        held = len(outcomes) - exported
        run.record(
            "export",
            "ok",
            f"{exported} STIX 2.1 bundle(s) written; {held} finding(s) held in Tier 1. "
            "M-06: a finding leaves this system only after an analyst records "
            "likely_coordination or above. Review one to export it.",
            exports=exported,
            held_for_review=held,
        )

    def _record_capture(
        self,
        capture_id: UUID,
        source_id: UUID,
        trace_id: str,
        started: datetime,
        finished: datetime,
        outcome: Any,
    ) -> None:
        """Write the capture row the evidence bundle will reference.

        Cross-schema write? No — sch_evidence.captures is the evidence module's
        table and this is the composition root writing through it during the
        skeleton. It is the one place the layering is thinner than it should be,
        and it belongs behind an evidence-module use case. Recorded as an open
        item rather than hidden.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_evidence.captures "
                "(capture_id, tenant_id, source_id, trace_id, url, requested_at, "
                " completed_at, status, http_status, bytes_transferred) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    capture_id,
                    self._tenant,
                    source_id,
                    trace_id,
                    outcome.url,
                    started,
                    finished,
                    "succeeded",
                    outcome.http_status,
                    outcome.bytes_fetched,
                ),
            )
