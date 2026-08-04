"""L3 — fetching through the isolated fetch zone (D-11).

Same surface as ``HttpFetcher``: ``fetch(url) -> FetchOutcome``. The difference
is where the work happens. This adapter publishes a job, waits for the zone to
answer, and reads the captured bytes back out of the object store.

Two adapters, one interface — not two code paths. The pipeline does not know or
care which one it holds, so running the fetch zone in-process during
development and isolated in production is a composition-root decision rather
than a branch inside the pipeline (D-98).

The bytes travel through the object store rather than through the queue. A
broker holding page content would become a second, unaudited copy of captured
material with none of the retention or tenancy controls the object store has.
"""

from __future__ import annotations

import uuid

from asip.contracts.ports.evidence import ObjectStore
from asip.contracts.ports.fetch_queue import FetchJob, FetchQueue

from .http_fetcher import STATUS_INTERNAL, STATUS_TIMEOUT, FetchOutcome


class FetchZoneUnavailable(RuntimeError):
    """No worker answered. Distinct from a fetch that failed."""


class QueuedFetcher:
    """Dispatch to the fetch zone and collect the result."""

    def __init__(
        self,
        queue: FetchQueue,
        object_store: ObjectStore,
        wait_seconds: float = 60.0,
        key_prefix: str = "captures",
    ) -> None:
        self._queue = queue
        self._objects = object_store
        self._wait = wait_seconds
        self._prefix = key_prefix

    def fetch(self, url: str) -> FetchOutcome:
        job_id = uuid.uuid4().hex
        # The key is chosen here, by the core, so the fetch zone never has to
        # derive a path from a tenant id it should not be holding.
        object_key = f"{self._prefix}/{job_id}"

        self._queue.publish_job(FetchJob(job_id=job_id, url=url, object_key=object_key))
        result = self._queue.await_result(job_id, self._wait)

        if result is None:
            # "No worker answered" and "the source failed" need different
            # responses — one means the fleet is down, the other means the site
            # is — so they are not collapsed into one status (D-113).
            return FetchOutcome(
                url=url,
                status=STATUS_TIMEOUT,
                body=b"",
                content_type="",
                http_status=None,
                bytes_fetched=0,
                failure_reason=(
                    f"no fetch worker answered within {self._wait:.0f}s. The fetch zone "
                    "may not be running: docker compose up -d fetcher, or "
                    "make run-fetcher."
                ),
            )

        if not result.succeeded:
            return FetchOutcome(
                url=url,
                status=result.status,
                body=b"",
                content_type=result.content_type,
                http_status=result.http_status,
                bytes_fetched=result.bytes_fetched,
                failure_reason=result.failure_reason,
            )

        try:
            body = self._objects.get(result.object_key)
        except Exception as exc:
            # The zone reported success but the bytes are not readable. Not a
            # fetch failure — a storage one, and saying so points at the right
            # system.
            return FetchOutcome(
                url=url,
                status=STATUS_INTERNAL,
                body=b"",
                content_type=result.content_type,
                http_status=result.http_status,
                bytes_fetched=0,
                failure_reason=(
                    f"fetch zone wrote {result.object_key} but it could not be read: {exc}"
                ),
            )

        return FetchOutcome(
            url=url,
            status=result.status,
            body=body,
            content_type=result.content_type,
            http_status=result.http_status,
            bytes_fetched=len(body),
        )
