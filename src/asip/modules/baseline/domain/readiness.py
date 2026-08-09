"""L1 — whether a source has been watched long enough to say anything.

D-80 makes `baseline_ready` an implicit condition on every rule: a rule may not
fire against a source whose baseline is `collecting` or `stale`. Today that is
not enforced anywhere, and the burst rule fires on its second capture — which
is the product making claims it has no grounds for.

WHY THREE STATES AND NOT A BOOLEAN

    collecting  too little history. We do not know the norm, so nothing is an
                anomaly (D-31). An empty Findings screen means "not yet".
    ready       enough history, recent enough to describe the present.
    stale       we had a baseline and stopped watching. The history exists and
                no longer describes now — a channel's normal Tuesday in March
                says nothing about its Tuesday in September if we missed the
                intervening six months.

`stale` is the state a boolean loses, and it is the dangerous one: a rule
firing against a stale baseline produces confident nonsense, because the
comparison is against a world that no longer exists. Silence would at least be
honest.

WHY COVERAGE AND NOT ELAPSED TIME

Thirty days of calendar time with three days of successful collection is three
days of baseline. What matters is how much of the period was actually observed,
so readiness is measured in observed days — days on which something was
collected — rather than in days since somebody added the source.

That distinction is not pedantic. A source that fails silently for a fortnight
would otherwise become "ready" on schedule, and every rule would start firing
against a norm computed from a quarter of the data it claims.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum

#: D-31: "at least 4-6 weeks" per source. Twenty-eight observed days is the
#: bottom of that range, taken deliberately rather than the middle: the cost of
#: waiting is a later demo, and the cost of not waiting is a false positive in
#: front of a client, which is the one this product cannot afford (D-30).
MINIMUM_OBSERVED_DAYS = 28

#: How much of the window must actually have been collected. A source observed
#: on 20 of 28 days has gaps a weekly profile cannot see past — Tuesdays might
#: be entirely missing.
MINIMUM_COVERAGE = 0.8

#: After this long without a successful collection, what we know describes the
#: past. Seven days because a weekly profile is the unit: miss a week and every
#: day-of-week bucket has lost its most recent example.
STALE_AFTER = timedelta(days=7)


class BaselineStatus(StrEnum):
    COLLECTING = "collecting"
    READY = "ready"
    STALE = "stale"


@dataclass(frozen=True, slots=True)
class Readiness:
    """The answer, and the reason for it.

    The reason is not decoration: "no findings" is the product's most
    misreadable output, and an analyst looking at an empty screen needs to know
    whether that means "we looked and there is nothing" or "we are not
    permitted to look yet" (D-68).
    """

    status: BaselineStatus
    observed_days: int
    coverage: float
    reason: str

    @property
    def may_fire(self) -> bool:
        """D-80. The only question the detection path asks."""
        return self.status is BaselineStatus.READY


def assess(
    *,
    observed_days: int,
    window_days: int,
    last_collected_at: datetime | None,
    now: datetime,
    minimum_days: int = MINIMUM_OBSERVED_DAYS,
) -> Readiness:
    """Decide whether a source's baseline may be used.

    `observed_days` counts distinct days on which something was collected;
    `window_days` is the span those days fall in. Coverage is the ratio, and
    both matter — twenty-eight days observed across two years is not a
    baseline, it is a scatter.
    """
    coverage = (observed_days / window_days) if window_days > 0 else 0.0

    if last_collected_at is None:
        return Readiness(
            BaselineStatus.COLLECTING,
            observed_days,
            coverage,
            "Nothing has been collected from this source yet. Until it has, there is "
            "no norm to compare against and no rule may fire against it (D-80).",
        )

    silent_for = now - last_collected_at

    # Staleness is checked BEFORE sufficiency, because a source with two years
    # of history that stopped six months ago is stale, not ready. Checking
    # sufficiency first would call it ready and let rules fire against a norm
    # describing a world that no longer exists.
    if silent_for > STALE_AFTER and observed_days >= minimum_days:
        return Readiness(
            BaselineStatus.STALE,
            observed_days,
            coverage,
            f"Nothing collected for {silent_for.days} days. The baseline describes the "
            "past, not the present, so comparing against it would produce confident "
            "nonsense. Resume collection to restore it.",
        )

    if observed_days < minimum_days:
        return Readiness(
            BaselineStatus.COLLECTING,
            observed_days,
            coverage,
            f"{observed_days} of {minimum_days} observed days. Nothing is an anomaly "
            "until the norm is known (D-31), so no rule fires against this source yet. "
            "An empty Findings screen means 'not yet', not 'nothing happening'.",
        )

    if coverage < MINIMUM_COVERAGE:
        return Readiness(
            BaselineStatus.COLLECTING,
            observed_days,
            coverage,
            f"{observed_days} days observed across {window_days} "
            f"({coverage:.0%} coverage, {MINIMUM_COVERAGE:.0%} needed). The gaps are "
            "large enough that a weekly profile could be missing whole days of the "
            "week, and a norm with holes in it is worse than none.",
        )

    return Readiness(
        BaselineStatus.READY,
        observed_days,
        coverage,
        f"{observed_days} observed days at {coverage:.0%} coverage, last collected "
        f"{silent_for.days} day(s) ago.",
    )
