"""The signal that separates a news cycle from coordination.

Fifteen channels posting within a minute of a government briefing is
journalism. The same fifteen posting at 04:00 on a Sunday is not. The burst is
identical; only the baseline tells them apart.

The tests that matter most are the ones about NOT having an opinion — an
unseen or thin bucket must return None, not zero. Zero means "exactly normal",
which is a claim about a bucket nobody has ever observed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from asip.modules.baseline.domain.profile import (
    BUCKETS,
    MINIMUM_SAMPLES,
    bucket_of,
    build_profile,
)

MONDAY_09 = datetime(2026, 8, 3, 9, 0, tzinfo=UTC)  # a Monday
SUNDAY_04 = datetime(2026, 8, 9, 4, 0, tzinfo=UTC)  # a Sunday


def weekly(hour: datetime, counts: list[int]) -> dict[datetime, int]:
    """The same hour of the week across consecutive weeks."""
    return {hour + timedelta(weeks=i): c for i, c in enumerate(counts)}


# ── the bucketing ───────────────────────────────────────────────────────────


def test_monday_midnight_is_bucket_zero() -> None:
    assert bucket_of(datetime(2026, 8, 3, 0, 0, tzinfo=UTC)) == 0


def test_a_week_has_one_hundred_and_sixty_eight_buckets() -> None:
    assert BUCKETS == 168
    assert bucket_of(datetime(2026, 8, 9, 23, 0, tzinfo=UTC)) == BUCKETS - 1


def test_the_same_hour_on_different_days_is_a_different_bucket() -> None:
    """D-31 asks for hour-of-day AND day-of-week because they interact.

    A news channel's Monday 09:00 and Sunday 09:00 are different populations,
    and averaging them describes neither.
    """
    monday_nine = bucket_of(datetime(2026, 8, 3, 9, 0, tzinfo=UTC))
    sunday_nine = bucket_of(datetime(2026, 8, 9, 9, 0, tzinfo=UTC))

    assert monday_nine != sunday_nine


# ── refusing to have an opinion ─────────────────────────────────────────────


def test_an_unseen_hour_has_no_opinion() -> None:
    """None, not zero. Zero is a claim about a bucket never observed."""
    profile = build_profile("s", weekly(MONDAY_09, [10, 12, 11, 9]))

    assert profile.z_score(SUNDAY_04, 40) is None


def test_a_thin_bucket_has_no_opinion() -> None:
    """One or two samples is an accident of which weeks were sampled."""
    profile = build_profile("s", weekly(MONDAY_09, [10, 12]))

    assert MINIMUM_SAMPLES > 2
    assert profile.z_score(MONDAY_09, 500) is None


def test_a_bucket_becomes_usable_once_it_has_enough_samples() -> None:
    profile = build_profile("s", weekly(MONDAY_09, [10] * MINIMUM_SAMPLES))

    assert profile.z_score(MONDAY_09, 10) is not None


# ── the discrimination the product exists to make ───────────────────────────


def test_a_busy_hour_that_is_busy_as_usual_is_not_a_burst() -> None:
    """The evening news. Fifteen outlets at 19:00 on a Tuesday, every Tuesday.

    An absolute threshold fires on this every week. That is the false-positive
    flood D-30 says kills the product.
    """
    profile = build_profile("s", weekly(MONDAY_09, [40, 42, 38, 41, 39]))

    z = profile.z_score(MONDAY_09, 41)

    assert z is not None
    assert abs(z) < 1.0, "a normal busy hour must not read as anomalous"


def test_the_same_volume_in_a_quiet_hour_is_a_burst() -> None:
    """Identical count, opposite conclusion — which is the whole point.

    Forty posts at 09:00 Monday is Tuesday. Forty at 04:00 Sunday is not.
    """
    profile = build_profile(
        "s",
        {**weekly(MONDAY_09, [40, 42, 38, 41, 39]), **weekly(SUNDAY_04, [1, 0, 2, 1, 1])},
    )

    busy = profile.z_score(MONDAY_09, 40)
    quiet = profile.z_score(SUNDAY_04, 40)

    assert busy is not None and quiet is not None
    assert abs(busy) < 1.0
    assert quiet > 3.0, "forty posts in a dead hour must read as extraordinary"


def test_silence_is_recorded_so_a_rare_source_is_not_mistaken_for_a_busy_one() -> None:
    """Hours with no activity must be present with a count of zero.

    Omitting them makes the mean describe only the busy hours, and a channel
    posting twice a week looks like one posting constantly — so its genuine
    bursts vanish into a norm that was never real.
    """
    with_zeros = build_profile("s", weekly(MONDAY_09, [0, 0, 6, 0, 0]))
    without = build_profile("s", weekly(MONDAY_09, [6, 6, 6]))

    assert with_zeros.buckets[bucket_of(MONDAY_09)].mean < 2.0
    assert without.buckets[bucket_of(MONDAY_09)].mean == 6.0


def test_a_perfectly_regular_source_still_reports_a_change() -> None:
    """Zero variance would divide by zero.

    Reported at the threshold rather than as infinity, so it composes with
    other signals instead of dominating them — D-29 requires multiple
    independent conditions, and a signal that always wins makes the others
    decorative.
    """
    profile = build_profile("s", weekly(MONDAY_09, [5, 5, 5, 5]))

    assert profile.z_score(MONDAY_09, 5) == 0.0

    surge = profile.z_score(MONDAY_09, 50)
    assert surge is not None
    assert surge >= 3.0
    assert surge != float("inf")


def test_a_drop_is_as_visible_as_a_surge() -> None:
    """D-25: deleted content is frequently the most valuable. A source going
    quiet is a signal, not an absence of one."""
    profile = build_profile("s", weekly(MONDAY_09, [40, 42, 38, 41]))

    z = profile.z_score(MONDAY_09, 0)

    assert z is not None
    assert z < -3.0


# ── V-2 ─────────────────────────────────────────────────────────────────────


def test_a_profile_is_built_from_counts_and_times_only() -> None:
    """The authenticity path must not read text or stance.

    Structural, not a rule anyone follows: `build_profile` accepts a mapping of
    time to count. There is no parameter through which text could reach it, so
    a profile cannot encode "this source posts suspicious things" — it has
    never been shown what any of them said.
    """
    import inspect

    signature = inspect.signature(build_profile)
    parameters = set(signature.parameters)

    assert parameters == {"source_id", "counts_by_hour"}
    for forbidden in ("text", "lang", "stance", "content", "script"):
        assert not any(forbidden in p for p in parameters), f"{forbidden} reachable (V-2)"
