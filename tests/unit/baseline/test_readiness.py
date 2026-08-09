"""D-80 — a rule may not fire against a source whose baseline is not ready.

Currently violated: the burst rule fires on a source's second capture. These
tests define the gate that stops it.

The state worth the most attention is `stale`. `collecting` produces silence,
which is safe. `stale` produces *confident output computed against a world that
no longer exists*, and a boolean would collapse it into `ready`.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from asip.modules.baseline.domain.readiness import (
    MINIMUM_OBSERVED_DAYS,
    BaselineStatus,
    Readiness,
    assess,
)

NOW = datetime(2026, 8, 9, 12, 0, tzinfo=UTC)


def check(
    observed_days: int = 28,
    window_days: int = 30,
    silent_days: float = 0.0,
    started: bool = True,
) -> Readiness:
    return assess(
        observed_days=observed_days,
        window_days=window_days,
        last_collected_at=None if not started else NOW - timedelta(days=silent_days),
        now=NOW,
    )


# ── collecting ──────────────────────────────────────────────────────────────


def test_a_source_never_collected_is_not_ready() -> None:
    result = check(started=False)

    assert result.status is BaselineStatus.COLLECTING
    assert not result.may_fire
    assert "D-80" in result.reason


def test_a_young_source_is_not_ready() -> None:
    result = check(observed_days=10, window_days=11)

    assert result.status is BaselineStatus.COLLECTING
    assert not result.may_fire
    assert "10 of 28" in result.reason


def test_the_reason_says_not_yet_rather_than_nothing_happening() -> None:
    """The most misreadable output the product has (D-68)."""
    assert "not yet" in check(observed_days=3, window_days=4).reason


@pytest.mark.parametrize("days", [0, 1, 14, MINIMUM_OBSERVED_DAYS - 1])
def test_nothing_below_the_minimum_is_ever_ready(days: int) -> None:
    assert not check(observed_days=days, window_days=days + 1).may_fire


def test_the_minimum_matches_the_directive() -> None:
    """D-31 says at least 4-6 weeks. Taking the bottom of the range is
    deliberate; taking less than it would not be."""
    assert MINIMUM_OBSERVED_DAYS >= 28


# ── coverage, not elapsed time ──────────────────────────────────────────────


def test_scattered_days_are_not_a_baseline() -> None:
    """Twenty-eight days observed across two years is a scatter, not a norm.

    A weekly profile built from it could be missing whole days of the week.
    """
    result = check(observed_days=28, window_days=700)

    assert result.status is BaselineStatus.COLLECTING
    assert "coverage" in result.reason


def test_a_source_that_failed_silently_does_not_become_ready_on_schedule() -> None:
    """The failure this guards: a source broken for a fortnight would otherwise
    hit its thirty-day anniversary and start firing rules against a norm
    computed from a quarter of the data it claims."""
    result = check(observed_days=16, window_days=30)

    assert not result.may_fire


def test_good_coverage_over_a_real_window_is_ready() -> None:
    result = check(observed_days=28, window_days=30, silent_days=0)

    assert result.status is BaselineStatus.READY
    assert result.may_fire


# ── stale: the state a boolean loses ────────────────────────────────────────


def test_a_long_history_that_stopped_is_stale_not_ready() -> None:
    """The dangerous one.

    Two years of history and nothing for six months is not a usable baseline.
    Silence would be honest; firing against it is confident nonsense.
    """
    result = assess(
        observed_days=700,
        window_days=730,
        last_collected_at=NOW - timedelta(days=180),
        now=NOW,
    )

    assert result.status is BaselineStatus.STALE
    assert not result.may_fire
    assert "past, not the present" in result.reason


def test_staleness_is_checked_before_sufficiency() -> None:
    """Order matters and the wrong order is silent.

    Sufficiency first would find 700 observed days, return ready, and let rules
    fire against a norm describing a world that no longer exists.
    """
    stale = assess(
        observed_days=5000,
        window_days=5000,
        last_collected_at=NOW - timedelta(days=365),
        now=NOW,
    )

    assert stale.status is BaselineStatus.STALE


def test_a_week_of_silence_is_the_boundary() -> None:
    """A weekly profile loses its most recent example of every day-of-week
    bucket after seven days."""
    assert check(silent_days=6).status is BaselineStatus.READY
    assert check(silent_days=8).status is BaselineStatus.STALE


def test_a_young_source_that_stopped_reports_collecting_not_stale() -> None:
    """It never had a baseline to go stale. Saying "stale" would imply one
    existed and could be restored by resuming, which is only half true."""
    result = check(observed_days=3, window_days=4, silent_days=30)

    assert result.status is BaselineStatus.COLLECTING


# ── the gate itself ─────────────────────────────────────────────────────────


def test_only_ready_may_fire() -> None:
    """The single question the detection path asks. Written over every state so
    a state added later must decide explicitly."""
    for status in BaselineStatus:
        matching = [
            r
            for r in (
                check(started=False),
                check(observed_days=3, window_days=4),
                check(observed_days=28, window_days=30),
                check(observed_days=28, window_days=30, silent_days=30),
            )
            if r.status is status
        ]
        assert matching, f"no case produces {status}; it is untested"
        for result in matching:
            assert result.may_fire == (status is BaselineStatus.READY)


def test_every_answer_explains_itself() -> None:
    """An analyst reading an empty screen needs the reason, not the verdict."""
    for result in (
        check(started=False),
        check(observed_days=3, window_days=4),
        check(observed_days=28, window_days=700),
        check(observed_days=28, window_days=30, silent_days=30),
        check(),
    ):
        assert len(result.reason) > 40, f"unhelpful: {result.reason!r}"
