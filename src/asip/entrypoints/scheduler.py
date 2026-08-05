"""L4 — the unattended run. A loop, a lock, and a record of every tick.

The skeleton's first exit criterion is that a real page is fetched, sealed,
extracted and detected on *without anyone pressing a button*. Everything needed
to decide when already exists: sources carry `interval_seconds` and
`due_sources` answers the question. What was missing was something that asks it
repeatedly and writes down the answer.

THREE THINGS THIS HAS TO GET RIGHT

  Say something every tick. D-68: an empty screen never means "no activity".
  An idle tick is a recorded fact, so an operator can tell "nothing was due"
  from "the scheduler died six hours ago". D-87 calls silent degradation the
  primary failure mode of this class of system, and a scheduler that stops
  quietly is its purest form — everything looks healthy because nothing is
  complaining, and nothing is complaining because nothing is running.

  Never run twice at once. A run that takes longer than the tick would
  otherwise start a second pass over the same due sources, double-fetching real
  pages and spending real money (D-13's concern, arriving from a different
  direction). A Postgres advisory lock handles it without adding a dependency,
  and covers multiple scheduler processes rather than only multiple threads.

  Survive its own failures. One bad tick must not end the loop. A crash that
  takes the scheduler down with it is indistinguishable, from the outside, from
  a system with nothing to do.

NOT IN SCOPE — D-17's priority_score allocator and D-18's budget hard stop are
Phase 1. This schedules on `interval_seconds`, which is what `due_sources`
already implements. CLAUDE.md §10 authorises the skeleton and nothing past it.

EXPORT IS NOT UNATTENDED, BY DESIGN — M-06 puts export behind an analyst's
verdict, so an unattended run reaches `detect` and stops. The skeleton criterion
was written before that boundary was enforced; "unattended" here means the
collection-to-detection path needs no human, not that findings leave the system
on their own. See the export stage's own report.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
import uuid
from datetime import UTC, datetime
from types import FrameType
from uuid import UUID

import psycopg

from asip.entrypoints.composition import Settings, build_evidence, build_fetcher
from asip.entrypoints.pipeline import Pipeline, PipelineRun
from asip.modules.collection.adapters.postgres_repository import PostgresCollectionRepository
from asip.modules.evidence.application.write_bundle import WriteBundle

#: Any 64-bit constant works; it only has to be the same in every process that
#: must not run concurrently with the others. Derived from the name so it is
#: reproducible and greppable rather than a magic number.
SCHEDULER_LOCK_KEY = 0x4153495053434845  # "ASIPSCHE"

DEFAULT_TICK_SECONDS = 60


class Scheduler:
    def __init__(
        self,
        dsn: str,
        tenant_id: UUID,
        tick_seconds: int = DEFAULT_TICK_SECONDS,
    ) -> None:
        self._dsn = dsn
        self._tenant = tenant_id
        self._tick = tick_seconds
        self._stopping = False
        self._consecutive_failures = 0

    def stop(self, *_: object) -> None:
        """Finish the tick in progress, then exit.

        Killing a run mid-way would leave a capture without a bundle, or a
        bundle without its chain entry. The tick is short; waiting for it is
        cheaper than reasoning about partial state.
        """
        self._stopping = True

    def run_forever(self) -> int:
        print(
            f"scheduler: tick={self._tick}s tenant={self._tenant}\n"
            f"scheduler: export is NOT unattended — M-06 holds findings for review",
            flush=True,
        )
        while not self._stopping:
            started = time.monotonic()
            try:
                self.tick()
            except Exception as exc:
                self._consecutive_failures += 1
                print(
                    f"scheduler: tick failed ({self._consecutive_failures} in a row): {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            self._sleep_remainder(started)
        print("scheduler: stopped cleanly", flush=True)
        return 0

    def _sleep_remainder(self, started: float) -> None:
        """Sleep what is left of the tick, in short steps so shutdown is prompt.

        Sleeping the full interval would make SIGTERM take up to a minute to be
        noticed, which reads as a hung process during a deploy.
        """
        deadline = started + self._tick
        while not self._stopping and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))

    def tick(self) -> dict[str, object] | None:
        """One pass. Returns None when another scheduler holds the lock."""
        with self._session() as conn:
            repository = PostgresCollectionRepository(conn)

            if not self._acquire_lock(conn):
                # Not an error and not silence: somebody else is working.
                print("scheduler: another run holds the lock, skipping", flush=True)
                return None

            run_id = uuid.uuid4()
            started_at = datetime.now(UTC)
            trace_id = ""
            try:
                # Committed before the pipeline starts, so a process killed
                # mid-run still leaves a row. The row says 'failed' until
                # something promotes it — a record written only on success
                # cannot report the failures, which is its main job.
                repository.open_run(run_id, self._tenant, f"pending-{run_id.hex[:12]}", started_at)
                conn.commit()

                settings = Settings.for_development()
                container = build_evidence(settings, conn)
                result = self._pipeline(conn, container.write_bundle, settings).run()
                trace_id = result.trace_id

                outcome, detail, counts = self._summarise(result)
                repository.close_run(
                    run_id,
                    self._tenant,
                    datetime.now(UTC),
                    outcome,
                    detail,
                    counts,
                    json.dumps(result.as_dict()["stages"]),
                )
                conn.commit()
                self._consecutive_failures = 0
                print(f"scheduler: {outcome} — {detail}", flush=True)
                return {"run_id": str(run_id), "outcome": outcome, "trace_id": trace_id}

            except Exception as exc:
                conn.rollback()
                # The failure is recorded on its own connection: the one above
                # is poisoned, and a failure nobody can see is the worst
                # possible outcome of a failure.
                self._record_failure(run_id, exc)
                raise

    def _pipeline(
        self, conn: psycopg.Connection, write_bundle: WriteBundle, settings: Settings
    ) -> Pipeline:
        return Pipeline(conn, write_bundle, build_fetcher(settings), self._tenant)

    @staticmethod
    def _summarise(result: PipelineRun) -> tuple[str, str, dict[str, int]]:
        """Three outcomes, because "ran and found nothing" is not "ran".

        Collapsing idle into ok loses the distinction D-68 exists for.
        Collapsing it into failed pages someone at 3am for silence.
        """
        totals: dict[str, int] = {}
        for stage in result.stages:
            for key, value in stage.counts.items():
                totals[key] = totals.get(key, 0) + value

        # Counted by stage occurrence, not by summing a count field. `evidence`
        # reports chain_index, which is an identifier — summing it would call
        # the first capture of the day zero captures, and the eleventh ten.
        captures = sum(1 for s in result.stages if s.stage == "evidence" and s.status == "ok")

        summary = {
            "sources_due": totals.get("due", 0),
            "captures": captures,
            "items": totals.get("items", 0),
            "findings": totals.get("findings", 0),
            "exports": totals.get("exports", 0),
            "held_for_review": totals.get("held_for_review", 0),
        }

        failed = [s for s in result.stages if s.status == "failed"]
        if failed:
            return ("failed", f"{failed[0].stage}: {failed[0].detail}"[:500], summary)
        if summary["sources_due"] == 0:
            return (
                "idle",
                "No source was due. The scheduler ran and found nothing to do.",
                summary,
            )
        return (
            "ok",
            f"{summary['sources_due']} source(s) due, {captures} capture(s), "
            f"{summary['items']} item(s), {summary['findings']} finding(s), "
            f"{summary['held_for_review']} held for review (M-06).",
            summary,
        )

    def _record_failure(self, run_id: UUID, exc: Exception) -> None:
        try:
            with self._session() as conn:
                PostgresCollectionRepository(conn).close_run(
                    run_id,
                    self._tenant,
                    datetime.now(UTC),
                    "failed",
                    f"{type(exc).__name__}: {exc}"[:500],
                    {},
                    "[]",
                )
                conn.commit()
        except Exception as inner:
            # Nothing left to do but say so on the way past. The open_run row
            # still says 'failed', which is the honest default.
            print(f"scheduler: could not record failure: {inner}", file=sys.stderr, flush=True)

    @staticmethod
    def _acquire_lock(conn: psycopg.Connection) -> bool:
        """Session-scoped advisory lock, released when the connection closes.

        Chosen over a `locked_until` column because a process that dies holding
        a row lease leaves the lease behind, and every design that fixes that
        ends up reinventing a lock with a timeout. Postgres already has one.
        """
        with conn.cursor() as cur:
            cur.execute("SELECT pg_try_advisory_lock(%s)", (SCHEDULER_LOCK_KEY,))
            row = cur.fetchone()
        return bool(row and row[0])

    def _session(self) -> psycopg.Connection:
        conn = psycopg.connect(self._dsn)
        with conn.cursor() as cur:
            cur.execute("SET ROLE asip_app")
            cur.execute("SELECT set_config('asip.tenant_id', %s, false)", (str(self._tenant),))
        return conn


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the ASIP pipeline unattended.")
    parser.add_argument(
        "--dsn",
        default=os.environ.get(
            "ASIP_DB_URL", "postgresql://asip:asip_dev_only@127.0.0.1:5432/asip"
        ),
    )
    parser.add_argument(
        "--tenant",
        default=os.environ.get("ASIP_TENANT_ID", "aaaaaaaa-0000-4000-8000-0000000000d1"),
    )
    parser.add_argument(
        "--tick-seconds",
        type=int,
        default=int(os.environ.get("ASIP_SCHEDULER_TICK", DEFAULT_TICK_SECONDS)),
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="run a single tick and exit — for testing and for cron-driven deployments",
    )
    args = parser.parse_args(argv)

    scheduler = Scheduler(args.dsn, UUID(args.tenant), args.tick_seconds)

    def handle(_signum: int, _frame: FrameType | None) -> None:
        print("scheduler: shutdown requested, finishing the current tick", flush=True)
        scheduler.stop()

    signal.signal(signal.SIGINT, handle)
    signal.signal(signal.SIGTERM, handle)

    if args.once:
        result = scheduler.tick()
        print(json.dumps(result or {"skipped": "another scheduler holds the lock"}))
        return 0
    return scheduler.run_forever()


if __name__ == "__main__":
    raise SystemExit(main())
