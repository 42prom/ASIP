"""L3 — the queue across the fetch-zone boundary (D-11).

Redis lists for jobs, one short-lived list per job for results. Both sides of
the boundary use this adapter; only the core side ever also holds a database
connection, and the fetch zone's container is never given one.

Why a broker rather than an HTTP call from the core into the fleet: the network
rule is easier to write and far easier to audit when traffic flows one way. The
fetch zone connects *out* to Redis and the object store and nothing connects
*in* to it, so a firewall rule that allows no inbound traffic to the fetch
network is the entire policy.
"""

from __future__ import annotations

import json
import time
from typing import Any

import redis

from asip.contracts.ports.fetch_queue import FetchJob, FetchResult

JOB_QUEUE = "asip:fetch:jobs"
RESULT_PREFIX = "asip:fetch:result:"
WORKER_PREFIX = "asip:fetch:worker:"

#: Results outlive the request that waited for them, so a core process that
#: crashed mid-wait can still find the outcome. Long enough to be useful, short
#: enough that the queue is not a second evidence store — the bytes are in the
#: object store and the record is in Postgres.
RESULT_TTL_SECONDS = 3600


class RedisFetchQueue:
    """Job dispatch and result collection over Redis."""

    def __init__(self, url: str = "redis://127.0.0.1:6379/0", socket_timeout: int = 120) -> None:
        # The socket timeout must exceed the longest blocking command, or
        # BLPOP's own wait trips it and a healthy idle worker dies with
        # "Timeout reading from socket". Generous rather than tuned: this
        # connection spends most of its life deliberately blocked.
        self._redis: Any = redis.Redis.from_url(
            url,
            decode_responses=True,
            socket_timeout=socket_timeout,
            socket_keepalive=True,
            health_check_interval=30,
        )

    # ── core side ───────────────────────────────────────────────────────────

    def publish_job(self, job: FetchJob) -> None:
        self._redis.rpush(
            JOB_QUEUE,
            json.dumps(
                {
                    "job_id": job.job_id,
                    "url": job.url,
                    "object_key": job.object_key,
                    "max_bytes": job.max_bytes,
                    "timeout_seconds": job.timeout_seconds,
                }
            ),
        )

    def await_result(self, job_id: str, timeout_seconds: float) -> FetchResult | None:
        """Block until the fetch zone answers, or give up.

        None means no worker answered in time. The caller must report that
        differently from a failed fetch — one means the fleet is down, the
        other means the source is, and they need different responses (D-113).
        """
        popped = self._redis.blpop([RESULT_PREFIX + job_id], timeout=int(timeout_seconds))
        if popped is None:
            return None
        payload = json.loads(popped[1])
        return FetchResult(**payload)

    # ── fetch-zone side ─────────────────────────────────────────────────────

    def consume_job(self, timeout_seconds: float) -> FetchJob | None:
        popped = self._redis.blpop([JOB_QUEUE], timeout=int(timeout_seconds))
        if popped is None:
            return None
        return FetchJob(**json.loads(popped[1]))

    def publish_result(self, result: FetchResult) -> None:
        key = RESULT_PREFIX + result.job_id
        self._redis.rpush(
            key,
            json.dumps(
                {
                    "job_id": result.job_id,
                    "status": result.status,
                    "object_key": result.object_key,
                    "content_type": result.content_type,
                    "http_status": result.http_status,
                    "bytes_fetched": result.bytes_fetched,
                    "failure_reason": result.failure_reason,
                }
            ),
        )
        self._redis.expire(key, RESULT_TTL_SECONDS)

    # ── health ──────────────────────────────────────────────────────────────

    def worker_heartbeat(self, worker_id: str, ttl_seconds: int = 30) -> None:
        """A key that expires unless refreshed.

        Liveness by expiry rather than by a status field: a worker that dies
        cannot forget to mark itself dead, and a stale heartbeat disappears on
        its own rather than lingering as a lie.
        """
        self._redis.set(WORKER_PREFIX + worker_id, str(time.time()), ex=ttl_seconds)

    def live_workers(self) -> tuple[str, ...]:
        keys = self._redis.keys(WORKER_PREFIX + "*")
        return tuple(sorted(str(k).removeprefix(WORKER_PREFIX) for k in keys))

    def pending_jobs(self) -> int:
        count: int = self._redis.llen(JOB_QUEUE)
        return count
