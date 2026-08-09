"""L1 — what normal looks like for one source, by hour of the week.

THE PROBLEM THIS SOLVES

The burst rule fires on "N items from M accounts inside W seconds". Run that
against real channels and it fires on the evening news: fifteen outlets posting
about the same briefing within a minute is not coordination, it is journalism.
A detector that cannot tell those apart produces the flood D-30 says kills the
product — 92% wrong, and the analyst stops reading.

What separates them is not the burst. It is whether the burst is unusual *for
this set of sources at this hour*. Georgian channels are busy at 19:00 on a
Tuesday and quiet at 04:00 on a Sunday, and a burst that is ordinary in the
first is remarkable in the second.

So: expected volume per hour-of-week, and a z-score against it (D-28 lists
"burst relative to baseline (z-score)" among the strong signals).

HOUR OF WEEK, NOT HOUR OF DAY

168 buckets rather than 24. D-31 asks for "volume by hour of day AND day of
week" because the two interact: a news channel's Monday 09:00 and Sunday 09:00
are different populations, and averaging them produces a norm that describes
neither. 168 buckets over 28 days gives 4 samples each — thin, which is exactly
why the minimum is four weeks and not one.

WHAT THIS DELIBERATELY DOES NOT READ

Counts and times. No text, no language, no stance (V-2). A profile cannot
encode "this source posts suspicious things" because it has never been shown
what any of them said — the strongest form of that guarantee, since it is not a
rule anyone has to follow.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from datetime import datetime

#: 7 days times 24 hours. A week is the shortest cycle that captures both the daily
#: rhythm and the weekday/weekend split.
BUCKETS = 168

#: Below this many observations a bucket's mean is an accident of which weeks
#: happened to be sampled. Reported rather than silently trusted.
MINIMUM_SAMPLES = 3

#: How far above the norm counts as a burst. Three sigma is roughly the 99.7th
#: percentile of a normal distribution — deliberately strict, because D-30
#: prefers catching 20% at 95% precision over 80% at 20%.
DEFAULT_Z_THRESHOLD = 3.0


def bucket_of(moment: datetime) -> int:
    """Which hour of the week a moment falls in. Monday 00:00 is bucket 0.

    UTC, always. A profile computed in local time would shift by an hour twice
    a year and every bucket either side of the change would be comparing
    different hours — a seasonal artefact indistinguishable from a behaviour
    change.
    """
    return moment.weekday() * 24 + moment.hour


@dataclass(frozen=True, slots=True)
class Bucket:
    """The norm for one hour of the week."""

    samples: int
    mean: float
    #: Population standard deviation of the observed counts.
    stdev: float

    @property
    def trustworthy(self) -> bool:
        return self.samples >= MINIMUM_SAMPLES


@dataclass(frozen=True, slots=True)
class VolumeProfile:
    """Expected posting volume per hour of the week, for one source."""

    source_id: str
    buckets: dict[int, Bucket]

    def expected(self, moment: datetime) -> Bucket | None:
        return self.buckets.get(bucket_of(moment))

    def z_score(self, moment: datetime, observed: int) -> float | None:
        """How unusual this count is for this hour. None when unknowable.

        None rather than 0.0 for an unseen or thin bucket. Zero would mean
        "exactly normal", which is a claim; None means "no opinion", which is
        the truth. A rule that treated the two alike would fire, or refuse to
        fire, on the strength of a bucket nobody has ever observed.
        """
        bucket = self.expected(moment)
        if bucket is None or not bucket.trustworthy:
            return None

        if bucket.stdev == 0.0:
            # Every observation identical. A different value is infinitely
            # surprising and the arithmetic says so by dividing by zero, which
            # is not a number anyone should act on. Treated as unknowable
            # unless the count actually differs, in which case it is a genuine
            # signal — reported at the threshold rather than as infinity so it
            # composes with other signals instead of dominating them.
            if observed == bucket.mean:
                return 0.0
            return DEFAULT_Z_THRESHOLD if observed > bucket.mean else -DEFAULT_Z_THRESHOLD

        return (observed - bucket.mean) / bucket.stdev


def build_profile(source_id: str, counts_by_hour: dict[datetime, int]) -> VolumeProfile:
    """Compute a profile from observed hourly counts.

    `counts_by_hour` maps each observed hour to how many items appeared in it.
    Hours with no activity must be present with a count of zero — omitting them
    would make the mean describe only the busy hours, and a channel that posts
    twice a week would look like one that posts constantly.
    """
    grouped: dict[int, list[int]] = {}
    for moment, count in counts_by_hour.items():
        grouped.setdefault(bucket_of(moment), []).append(count)

    buckets: dict[int, Bucket] = {}
    for index, values in grouped.items():
        n = len(values)
        mean = sum(values) / n
        variance = sum((v - mean) ** 2 for v in values) / n
        buckets[index] = Bucket(samples=n, mean=mean, stdev=math.sqrt(variance))

    return VolumeProfile(source_id=source_id, buckets=buckets)
