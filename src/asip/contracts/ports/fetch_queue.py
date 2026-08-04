"""The queue between the core and the fetch zone (D-11, V-3).

This port exists so the fetch zone can be a **separate process on a separate
network**. The core publishes a job describing what to fetch; the fetch zone
consumes it, fetches, writes the bytes to object storage, and publishes an
outcome. Nothing crosses the boundary except these two messages and an object
key.

That shape is what makes V-3 structural rather than conventional. The fetch
zone cannot hold database credentials because it is never given any, and it
cannot reach the core database because its network has no route to it. If the
fleet is compromised, the attacker gets a browser pool and a bucket they can
write to — not the evidence, and not the tenants.

The job carries **no tenant secrets and no database identifiers beyond what the
fetcher needs to name its output**. A worker that could enumerate tenants from
its queue traffic would leak exactly what RLS exists to prevent.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class FetchJob:
    """What the fetch zone is asked to do.

    Deliberately thin. The fetcher does not need to know which source this is,
    which watchlist it belongs to, or why it is being collected — and anything
    it does not need is something a compromised fleet cannot disclose.
    """

    job_id: str
    url: str
    #: Where to put the bytes. Chosen by the core so the fetch zone never has
    #: to derive a path from a tenant id it should not be holding.
    object_key: str
    max_bytes: int = 8 * 1024 * 1024
    timeout_seconds: float = 15.0


@dataclass(frozen=True, slots=True)
class FetchResult:
    """What the fetch zone did. A failure is a result, not an exception."""

    job_id: str
    status: str
    object_key: str
    content_type: str
    http_status: int | None
    bytes_fetched: int
    failure_reason: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == "succeeded"


class FetchQueue(Protocol):
    """Job dispatch and result collection across the zone boundary."""

    def publish_job(self, job: FetchJob) -> None: ...

    def consume_job(self, timeout_seconds: float) -> FetchJob | None:
        """Block for a job. Returns None on timeout so a worker can shut down."""
        ...

    def publish_result(self, result: FetchResult) -> None: ...

    def await_result(self, job_id: str, timeout_seconds: float) -> FetchResult | None:
        """Wait for one job's outcome.

        Returns None on timeout rather than raising, because "no worker
        answered" is a state the caller must report differently from "the fetch
        failed" — one means the fleet is down, the other means the source is.
        """
        ...

    def worker_heartbeat(self, worker_id: str, ttl_seconds: int) -> None: ...

    def live_workers(self) -> tuple[str, ...]:
        """Which workers have reported recently.

        Surfaced on System Health so an idle pipeline is never mistaken for a
        quiet one: no workers and no captures look identical from the database
        alone, and they need different responses.
        """
        ...
