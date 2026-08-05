"""The unattended run: what it says, and what it refuses to do twice.

The summariser is the interesting part. A scheduler that reports "ok" for a tick
that found nothing is indistinguishable from one that is broken, and a scheduler
that reports "failed" for the same tick pages someone at 3am for silence (D-68,
D-87).
"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from uuid import UUID

from asip.entrypoints.pipeline import PipelineRun, StageResult
from asip.entrypoints.scheduler import Scheduler

TENANT = UUID("aaaaaaaa-0000-4000-8000-0000000000d1")


def run_with(*stages: StageResult) -> PipelineRun:
    run = PipelineRun(trace_id="trace-test", started_at=datetime.now(UTC))
    run.stages.extend(stages)
    return run


def stage(name: str, status: str = "ok", detail: str = "", **counts: int) -> StageResult:
    return StageResult(name, status, detail, dict(counts))


# ── the three outcomes ──────────────────────────────────────────────────────


def test_a_tick_that_found_nothing_is_idle_not_ok() -> None:
    """D-68. "We looked and there was nothing" is a measurement, not a non-event."""
    outcome, detail, _ = Scheduler._summarise(
        run_with(stage("schedule", "idle", "No source is due for collection yet.", due=0))
    )

    assert outcome == "idle"
    assert "nothing to do" in detail


def test_a_tick_that_found_nothing_is_not_a_failure() -> None:
    """The other half of the same mistake — this one wakes someone up."""
    outcome, _, _ = Scheduler._summarise(run_with(stage("schedule", "idle", due=0)))
    assert outcome != "failed"


def test_a_failed_stage_makes_the_run_failed_and_names_the_stage() -> None:
    outcome, detail, _ = Scheduler._summarise(
        run_with(
            stage("schedule", "ok", due=1),
            stage("fetch", "failed", "Canary: failed_network — connection refused"),
        )
    )

    assert outcome == "failed"
    assert detail.startswith("fetch:")
    assert "connection refused" in detail


def test_a_productive_tick_reports_what_it_produced() -> None:
    outcome, detail, counts = Scheduler._summarise(
        run_with(
            stage("schedule", "ok", due=1),
            stage("fetch", "ok", bytes=3094),
            stage("evidence", "ok", chain_index=0),
            stage("extract", "ok", items=6),
            stage("detect", "ok", findings=1),
            stage("export", "ok", exports=0, held_for_review=1),
        )
    )

    assert outcome == "ok"
    assert counts == {
        "sources_due": 1,
        "captures": 1,
        "items": 6,
        "findings": 1,
        "exports": 0,
        "held_for_review": 1,
    }
    assert "M-06" in detail, "the operator must be told why nothing was exported"


def test_the_first_capture_of_the_day_is_one_capture_not_zero() -> None:
    """`evidence` reports chain_index, which is an identifier, not a count.

    Summing it would call the genesis capture zero captures and the eleventh
    ten — an off-by-everything error that looks like a working counter.
    """
    _, _, counts = Scheduler._summarise(
        run_with(stage("schedule", "ok", due=1), stage("evidence", "ok", chain_index=0))
    )

    assert counts["captures"] == 1


def test_two_captures_in_one_tick_count_as_two() -> None:
    _, _, counts = Scheduler._summarise(
        run_with(
            stage("schedule", "ok", due=2),
            stage("evidence", "ok", chain_index=7),
            stage("evidence", "ok", chain_index=8),
        )
    )

    assert counts["captures"] == 2


def test_a_failed_evidence_stage_is_not_counted_as_a_capture() -> None:
    _, _, counts = Scheduler._summarise(
        run_with(stage("schedule", "ok", due=1), stage("evidence", "failed", "sealing failed"))
    )

    assert counts["captures"] == 0


# ── the loop ────────────────────────────────────────────────────────────────


def test_stopping_does_not_wait_out_the_tick() -> None:
    """A SIGTERM that takes a minute to land reads as a hung process on deploy.

    No database: `tick` is replaced, because what is under test is the loop's
    responsiveness and nothing else.
    """
    scheduler = Scheduler("postgresql://unused", TENANT, tick_seconds=30)
    scheduler.tick = lambda: None  # type: ignore[method-assign]

    thread = threading.Thread(target=scheduler.run_forever, daemon=True)
    started = time.monotonic()
    thread.start()
    time.sleep(0.2)
    scheduler.stop()
    thread.join(timeout=10)

    assert not thread.is_alive(), "the loop ignored the stop signal"
    assert time.monotonic() - started < 5, "shutdown waited for the full tick"


def test_one_failing_tick_does_not_end_the_loop() -> None:
    """A crash that takes the scheduler down looks, from outside, exactly like a
    system with nothing to do."""
    scheduler = Scheduler("postgresql://unused", TENANT, tick_seconds=0)
    calls = {"n": 0}

    def failing() -> None:
        calls["n"] += 1
        if calls["n"] >= 3:
            scheduler.stop()
        raise RuntimeError("the database went away")

    scheduler.tick = failing  # type: ignore[method-assign]
    scheduler.run_forever()

    assert calls["n"] >= 3, "the loop stopped at the first failure"
