"""L1 — the one naive coordination rule.

    "At least N items from at least M distinct accounts within W seconds."

Deliberately unintelligent (W-01). The walking skeleton exists to prove the
pipe connects, and a clever rule here would only make it harder to tell whether
a finding came from real behaviour or from a bug.

V-2 IS WHY THIS MODULE TAKES THE INPUT IT DOES
----------------------------------------------
``Observation`` carries an account, a timestamp, and a content id. It does not
carry text, and it cannot: the read view this data arrives through
(``v_content_for_detection``) does not publish the text column at all.

That is the enforcement. Not a comment asking future code to behave — a column
list. If the authenticity path could read content, the system would learn
"coordinated = opinion we dislike" and the product would be worthless. The
signal here is timing and distinctness, both of which are properties of
*behaviour*, and neither of which changes if every account is saying something
we agree with.

V-1: the output is a cluster. There is no per-account verdict anywhere in this
file, and ``ClusterFinding`` has no field that could hold one.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import UUID

#: A rule whose window is narrower than the source's timestamp precision is
#: rejected at configuration time (D-102) — every item would land in one of two
#: buckets and the "burst" would be an artefact of rounding.
PRECISION_SECONDS = {"second": 1, "minute": 60, "hour": 3600, "day": 86400}


class RuleConfigurationError(ValueError):
    """The rule cannot produce a meaningful signal as configured."""


@dataclass(frozen=True, slots=True)
class Observation:
    """One item, seen only as behaviour.

    Note the absence of a text field. See the module docstring — it is a veto,
    not an oversight.
    """

    content_id: UUID
    account_id: UUID
    capture_id: UUID
    posted_at: datetime
    timestamp_precision: str = "second"


@dataclass(frozen=True, slots=True)
class Signal:
    """One measurement, its threshold, and whether it fired.

    Findings show every signal rather than a score (D-30). An analyst defending
    a published claim needs to say which measurement crossed which line, and
    "confidence 81" is not something anyone can defend.
    """

    name: str
    observed: float
    threshold: float
    passed: bool
    description: str


@dataclass(frozen=True, slots=True)
class ClusterFinding:
    """Accounts that acted together inside one window.

    The unit of analysis (V-1). ``accounts`` records who participated because
    the cluster is defined by its membership — but nothing here, and nothing
    downstream, attaches a judgement to any one of them.
    """

    window_start: datetime
    window_end: datetime
    content_ids: tuple[UUID, ...]
    accounts: tuple[UUID, ...]
    capture_ids: tuple[UUID, ...]
    signals: tuple[Signal, ...]

    @property
    def item_count(self) -> int:
        return len(self.content_ids)

    @property
    def account_count(self) -> int:
        return len(self.accounts)


@dataclass(frozen=True, slots=True)
class BurstRuleParams:
    """Thresholds. Three of them, because D-29 requires three signals."""

    window_seconds: int = 120
    minimum_items: int = 4
    minimum_accounts: int = 3

    def validate_against(self, precision: str) -> None:
        floor = PRECISION_SECONDS.get(precision, 1)
        if self.window_seconds < floor * 2:
            raise RuleConfigurationError(
                f"window of {self.window_seconds}s is too narrow for a source with "
                f"{precision}-level timestamps ({floor}s): every item would fall into "
                "one or two buckets and the burst would be an artefact of rounding "
                "rather than a measurement (D-102)"
            )


def find_bursts(
    observations: Sequence[Observation],
    params: BurstRuleParams | None = None,
) -> tuple[ClusterFinding, ...]:
    """Find windows where enough distinct accounts posted closely together.

    A sliding window over items sorted by authoritative time (D-101). Windows
    are greedy and non-overlapping: once a burst is emitted, scanning resumes
    after its last item, so one flurry of activity produces one finding rather
    than one per item.
    """
    settings = params or BurstRuleParams()
    if not observations:
        return ()

    for observation in observations:
        settings.validate_against(observation.timestamp_precision)

    ordered = sorted(observations, key=lambda o: o.posted_at)
    window = timedelta(seconds=settings.window_seconds)

    findings: list[ClusterFinding] = []
    start = 0
    while start < len(ordered):
        end = start
        while (
            end + 1 < len(ordered)
            and ordered[end + 1].posted_at - ordered[start].posted_at <= window
        ):
            end += 1

        group = ordered[start : end + 1]
        accounts = {o.account_id for o in group}

        if len(group) >= settings.minimum_items and len(accounts) >= settings.minimum_accounts:
            findings.append(_build_finding(group, settings))
            start = end + 1
        else:
            start += 1

    return tuple(findings)


def _build_finding(group: Sequence[Observation], settings: BurstRuleParams) -> ClusterFinding:
    accounts = sorted({o.account_id for o in group}, key=str)
    span = (group[-1].posted_at - group[0].posted_at).total_seconds()

    # Three independent measurements (D-29). Independent in the sense that
    # matters: volume, distinctness and compression can each move without the
    # others, so agreement between them is information rather than restatement.
    signals = (
        Signal(
            name="item_count",
            observed=float(len(group)),
            threshold=float(settings.minimum_items),
            passed=len(group) >= settings.minimum_items,
            description="items published inside the window",
        ),
        Signal(
            name="distinct_accounts",
            observed=float(len(accounts)),
            threshold=float(settings.minimum_accounts),
            passed=len(accounts) >= settings.minimum_accounts,
            description="distinct accounts contributing to the window",
        ),
        Signal(
            name="window_span_seconds",
            observed=span,
            threshold=float(settings.window_seconds),
            passed=span <= settings.window_seconds,
            description="elapsed time between the first and last item",
        ),
    )

    return ClusterFinding(
        window_start=group[0].posted_at,
        window_end=group[-1].posted_at,
        content_ids=tuple(o.content_id for o in group),
        accounts=tuple(accounts),
        capture_ids=tuple(sorted({o.capture_id for o in group}, key=str)),
        signals=signals,
    )
