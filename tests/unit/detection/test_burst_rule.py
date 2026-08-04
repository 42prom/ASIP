"""D-88.3 — the rule engine against synthetic clusters with known ground truth.

Two things are being tested. The obvious one is that the rule fires when it
should. The one that matters more is that it does *not* fire otherwise: a rule
that groups everything is indistinguishable from a rule that groups nothing,
and both are useless.

V-2 is checked structurally here too — `Observation` must not grow a text
field, because the moment the authenticity path can read content the system
learns "coordinated = opinion we dislike".
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from asip.modules.detection.domain import burst
from asip.modules.detection.domain.burst import (
    BurstRuleParams,
    Observation,
    RuleConfigurationError,
    find_bursts,
)

BASE = datetime(2026, 8, 4, 9, 12, 0, tzinfo=UTC)


def observation(offset_seconds: int, account: UUID, precision: str = "second") -> Observation:
    return Observation(
        content_id=uuid4(),
        account_id=account,
        capture_id=uuid4(),
        posted_at=BASE + timedelta(seconds=offset_seconds),
        timestamp_precision=precision,
    )


# ── V-2, structural ─────────────────────────────────────────────────────────


@pytest.mark.rules
def test_an_observation_carries_no_text() -> None:
    """The veto, as a property of the type the rule consumes."""
    fields = set(Observation.__annotations__)
    for banned in ("text", "content", "body", "stance", "sentiment", "embedding"):
        assert banned not in fields, (
            f"Observation exposes {banned!r} to the detection path. V-2: authenticity "
            "scoring must not read text content or stance."
        )


@pytest.mark.rules
def test_the_rule_module_never_mentions_stance_or_sentiment() -> None:
    source = inspect.getsource(burst).lower()
    for banned in ("sentiment", "stance", "polarity", "toxicity"):
        assert f"{banned}=" not in source and f".{banned}" not in source


# ── firing ──────────────────────────────────────────────────────────────────


@pytest.mark.rules
def test_a_tight_burst_from_distinct_accounts_fires() -> None:
    accounts = [uuid4() for _ in range(5)]
    observations = [observation(i * 12, accounts[i]) for i in range(5)]

    findings = find_bursts(observations, BurstRuleParams())

    assert len(findings) == 1
    assert findings[0].item_count == 5
    assert findings[0].account_count == 5


@pytest.mark.rules
def test_every_finding_carries_three_signals() -> None:
    """D-29. Fewer than three is a coincidence with formatting."""
    accounts = [uuid4() for _ in range(4)]
    findings = find_bursts([observation(i * 10, accounts[i]) for i in range(4)])
    assert len(findings[0].signals) == 3
    assert {s.name for s in findings[0].signals} == {
        "item_count",
        "distinct_accounts",
        "window_span_seconds",
    }


# ── not firing — the half that keeps the rule honest ────────────────────────


@pytest.mark.rules
def test_one_account_posting_repeatedly_does_not_fire() -> None:
    """Volume alone is not coordination. One busy account is one busy account."""
    account = uuid4()
    findings = find_bursts([observation(i * 5, account) for i in range(10)])
    assert findings == ()


@pytest.mark.rules
def test_activity_spread_over_hours_does_not_fire() -> None:
    accounts = [uuid4() for _ in range(5)]
    findings = find_bursts([observation(i * 3600, accounts[i]) for i in range(5)])
    assert findings == ()


@pytest.mark.rules
def test_too_few_accounts_does_not_fire() -> None:
    a, b = uuid4(), uuid4()
    findings = find_bursts([observation(i * 5, a if i % 2 else b) for i in range(8)])
    assert findings == ()


@pytest.mark.rules
def test_items_outside_the_window_are_excluded_from_the_cluster() -> None:
    """A burst plus a much later item is a burst, not a wider burst."""
    accounts = [uuid4() for _ in range(4)]
    observations = [observation(i * 10, accounts[i]) for i in range(4)]
    observations.append(observation(20_000, uuid4()))

    findings = find_bursts(observations)

    assert len(findings) == 1
    assert findings[0].item_count == 4


@pytest.mark.rules
def test_no_observations_produces_no_findings() -> None:
    assert find_bursts([]) == ()


# ── D-102, the correctness input ────────────────────────────────────────────


@pytest.mark.rules
def test_a_window_narrower_than_the_source_precision_is_refused() -> None:
    """A 120s window against minute-granularity timestamps is not a measurement.

    Everything lands in one or two buckets, so the "burst" is an artefact of
    rounding. The rule refuses at configuration time rather than producing a
    confident number from noise.
    """
    accounts = [uuid4() for _ in range(4)]
    observations = [observation(i * 10, accounts[i], precision="minute") for i in range(4)]

    with pytest.raises(RuleConfigurationError, match="too narrow"):
        find_bursts(observations, BurstRuleParams(window_seconds=60))


@pytest.mark.rules
def test_a_wide_enough_window_is_accepted_for_coarse_timestamps() -> None:
    accounts = [uuid4() for _ in range(4)]
    observations = [observation(i * 30, accounts[i], precision="minute") for i in range(4)]
    findings = find_bursts(observations, BurstRuleParams(window_seconds=300))
    assert len(findings) == 1


@pytest.mark.rules
def test_the_cluster_records_which_accounts_participated() -> None:
    """V-1: this describes the group. Nothing here judges a member."""
    accounts = [uuid4() for _ in range(4)]
    findings = find_bursts([observation(i * 10, accounts[i]) for i in range(4)])
    assert set(findings[0].accounts) == set(accounts)
    for field in vars(findings[0]).keys() if hasattr(findings[0], "__dict__") else ():
        assert "verdict" not in field and "score" not in field
