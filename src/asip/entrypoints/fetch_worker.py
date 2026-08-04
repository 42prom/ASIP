"""L4 — the fetch zone worker (D-11, V-3).

THIS PROCESS MUST NEVER BE ABLE TO REACH THE CORE DATABASE
-----------------------------------------------------------
Read the imports below. There is no psycopg, no repository, no DSN, and no
module that transitively reaches one. It talks to exactly two things: the queue
it takes jobs from, and the object store it writes bytes to.

That is V-3 stated three ways, and all three have to hold:

1. **By import** — this file imports nothing that can reach Postgres.
   ``tests/unit/collection/test_fetch_zone_isolation.py`` asserts it by walking
   the import graph, so adding one fails a test rather than passing review.
2. **By configuration** — the container gets ASIP_FETCH_QUEUE_URL and object
   store credentials. It is never given ASIP_DB_URL, so there is no credential
   to leak.
3. **By network** — docker-compose puts it on the ``fetch`` network, which has
   no route to postgres. Even with a stolen credential it could not connect.

Any one of the three could be defeated by someone determined. All three
failing at once takes a deliberate act, which is the difference between a
guarantee and a hope.

WHAT THIS PROCESS IS ALLOWED TO KNOW
------------------------------------
A URL and an object key. Not the tenant, not the source id, not the watchlist.
A compromised fleet should not be able to enumerate who is being monitored, and
the cheapest way to guarantee that is to never send it the information.

V-6: reliability here stops at retries, backoff and honest rate limiting. The
fetcher this worker wraps has a test asserting no evasion machinery exists in
it. If a source cannot be collected honestly, the correct outcome is a recorded
failure and a conversation about authorisation.
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import uuid
from types import FrameType

from asip.contracts.ports.fetch_queue import FetchResult
from asip.modules.collection.adapters.http_fetcher import HttpFetcher
from asip.modules.collection.adapters.redis_fetch_queue import RedisFetchQueue
from asip.modules.evidence.adapters.s3_object_store import S3ObjectStore

_running = True


def _stop(signum: int, frame: FrameType | None) -> None:
    """Finish the job in hand, then exit.

    A worker killed mid-fetch leaves a job with no result and a core process
    waiting out its timeout. Draining costs a few seconds and turns a confusing
    stall into a clean shutdown.
    """
    global _running
    _running = False
    print("shutdown requested; finishing current job", file=sys.stderr)


def run(
    queue: RedisFetchQueue,
    store: S3ObjectStore,
    fetcher: HttpFetcher,
    worker_id: str,
    poll_seconds: float = 5.0,
) -> None:
    print(f"fetch worker {worker_id} started — no database access by construction")
    while _running:
        queue.worker_heartbeat(worker_id, ttl_seconds=30)

        job = queue.consume_job(timeout_seconds=poll_seconds)
        if job is None:
            continue

        outcome = fetcher.fetch(job.url)

        if outcome.succeeded:
            # The bytes go to the object store; only the key crosses back. The
            # core never receives page content over the queue, so a compromised
            # broker sees metadata and not captures.
            store.put(job.object_key, outcome.body, outcome.content_type or "text/html")

        queue.publish_result(
            FetchResult(
                job_id=job.job_id,
                status=outcome.status,
                object_key=job.object_key,
                content_type=outcome.content_type,
                http_status=outcome.http_status,
                bytes_fetched=outcome.bytes_fetched,
                failure_reason=outcome.failure_reason,
            )
        )
        print(f"{job.job_id} {outcome.status} {outcome.bytes_fetched}B {job.url}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="ASIP fetch zone worker.")
    parser.add_argument(
        "--queue-url", default=os.environ.get("ASIP_FETCH_QUEUE_URL", "redis://127.0.0.1:6379/0")
    )
    parser.add_argument(
        "--object-store-url",
        default=os.environ.get("ASIP_OBJECT_STORE_URL", "http://127.0.0.1:9000"),
    )
    parser.add_argument("--bucket", default=os.environ.get("ASIP_FETCH_BUCKET", "asip-captures"))
    parser.add_argument("--worker-id", default=os.environ.get("ASIP_WORKER_ID", ""))
    args = parser.parse_args(argv)

    # Refuse to start if someone has handed this process a database credential.
    # Not paranoia: the most likely way V-3 gets broken is a well-meaning change
    # to a shared env file, and the failure would otherwise be silent.
    for leaked in ("ASIP_DB_URL", "DATABASE_URL", "PGPASSWORD", "POSTGRES_PASSWORD"):
        if os.environ.get(leaked):
            print(
                f"REFUSING TO START: {leaked} is set in the fetch zone's environment.\n"
                "V-3 — the fetch zone holds no database credentials. Remove it from this\n"
                "container's configuration rather than from this check.",
                file=sys.stderr,
            )
            return 2

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    worker_id = args.worker_id or f"fetcher-{uuid.uuid4().hex[:8]}"
    store = S3ObjectStore(
        bucket=args.bucket,
        endpoint_url=args.object_store_url,
        access_key=os.environ.get("ASIP_OBJECT_STORE_KEY", "asip"),
        secret_key=os.environ.get("ASIP_OBJECT_STORE_SECRET", "asip_dev_only"),
    )
    store.ensure_bucket()

    run(RedisFetchQueue(args.queue_url), store, HttpFetcher(), worker_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
