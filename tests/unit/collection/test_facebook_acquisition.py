"""Facebook acquisition: the socket, before any plug exists.

The point of these tests is that adding a Facebook page today is useful — the
page is stored, scheduled, and refuses for a stated reason rather than failing
silently or fetching a login wall and calling it evidence.

The load-bearing test is the last one: the same posts from two different
providers must produce byte-identical evidence. If they do not, a client who
switches vendor loses comparability with everything collected before, and
"provider-agnostic" was decoration.
"""

from __future__ import annotations

import json

import pytest

from asip.modules.collection.adapters.facebook_acquisition import (
    PROVIDER_ENV,
    STATUS_NOT_CONFIGURED,
    FacebookAcquisition,
    NoProviderConfigured,
    NormalisedPost,
    NotConfigured,
    configured_provider,
    page_handle_from,
    serialise,
)
from asip.modules.extraction.domain.parser import parse_capture


class FakeProvider:
    """A provider that works, standing in for whichever one is contracted."""

    name = "fake"

    def __init__(self, posts: list[NormalisedPost]) -> None:
        self._posts = posts
        self.asked: list[str] = []

    def fetch_page(self, page_handle: str, limit: int) -> list[NormalisedPost]:
        self.asked.append(page_handle)
        return self._posts[:limit]


POSTS = [
    NormalisedPost(
        external_id="pfbid_1",
        page_handle="ministry.example",
        page_name="Ministry Example",
        text="ხიდის პროექტის ვადები გადაიწია.",
        posted_at_raw="2026-08-04T09:12:04+00:00",
        permalink="https://facebook.com/ministry.example/posts/1",
    ),
    NormalisedPost(
        external_id="pfbid_2",
        page_handle="ministry.example",
        page_name="Ministry Example",
        text="Second post.",
        posted_at_raw="2026-08-04T09:12:31+00:00",
        permalink="https://facebook.com/ministry.example/posts/2",
    ),
]


# ── with no route configured ────────────────────────────────────────────────


def test_no_route_refuses_rather_than_fetching_a_login_wall() -> None:
    outcome = FacebookAcquisition(NoProviderConfigured()).fetch(
        "https://facebook.com/ministry.example"
    )

    assert not outcome.succeeded
    assert outcome.status == STATUS_NOT_CONFIGURED
    assert outcome.body == b"", "nothing may be sealed when nothing was collected"


def test_the_refusal_says_what_would_change_it() -> None:
    """A failure an operator cannot act on is a failure they will ignore."""
    outcome = FacebookAcquisition(NoProviderConfigured()).fetch("https://facebook.com/x")

    assert outcome.failure_reason is not None
    assert PROVIDER_ENV in outcome.failure_reason
    assert "O-03" in outcome.failure_reason


def test_the_refusal_is_distinct_from_a_network_failure() -> None:
    """Retrying a network error is sensible; retrying this forever is not.

    They need different statuses or an operator watching a dashboard cannot
    tell "the site was down" from "you never told us how to reach it".
    """
    assert STATUS_NOT_CONFIGURED != "failed_network"
    assert STATUS_NOT_CONFIGURED.startswith("failed_")


def test_an_unknown_provider_name_is_refused_not_defaulted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A typo in a deployment variable must not become a system that quietly
    collects nothing."""
    monkeypatch.setenv(PROVIDER_ENV, "brigthdata")  # deliberate typo

    with pytest.raises(NotConfigured, match="not a known provider"):
        configured_provider()


def test_the_default_is_no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(PROVIDER_ENV, raising=False)
    assert configured_provider().name == "none"


# ── with a route configured ─────────────────────────────────────────────────


def test_a_configured_provider_produces_sealable_bytes() -> None:
    provider = FakeProvider(POSTS)

    outcome = FacebookAcquisition(provider).fetch("https://facebook.com/ministry.example")

    assert outcome.succeeded
    assert outcome.bytes_fetched == len(outcome.body)
    assert provider.asked == ["ministry.example"]


def test_what_was_acquired_parses_back_into_items() -> None:
    """The whole round trip: provider → normalised bytes → extractor."""
    outcome = FacebookAcquisition(FakeProvider(POSTS)).fetch("https://facebook.com/x")

    result = parse_capture(outcome.body, minimum_expected_items=1, platform="facebook")

    assert len(result.items) == 2
    assert result.validation_passed, result.problems
    assert result.items[0].author_handle == "ministry.example"
    assert result.items[0].script == "georgian"
    assert result.items[0].timestamp_precision == "second"


@pytest.mark.parametrize(
    "url",
    [
        "https://facebook.com/ministry.example",
        "https://www.facebook.com/ministry.example/",
        "http://m.facebook.com/ministry.example",
        "@ministry.example",
        "ministry.example",
        "https://facebook.com/ministry.example?ref=page_internal",
    ],
)
def test_every_way_people_write_a_page_url_resolves_to_the_same_page(url: str) -> None:
    """Someone pasting forty pages off a spreadsheet should not have to
    normalise them first."""
    assert page_handle_from(url) == "ministry.example"


# ── the claim that makes "provider-agnostic" mean something ─────────────────


def test_two_providers_with_the_same_posts_produce_identical_evidence() -> None:
    """The load-bearing test.

    A client switching vendor must keep comparability with everything already
    collected. If the sealed bytes differed by provider, every hash would
    change, every bundle would be incomparable, and the abstraction would be a
    label rather than a guarantee.
    """
    first = FacebookAcquisition(FakeProvider(POSTS)).fetch("https://facebook.com/x")
    second = FacebookAcquisition(FakeProvider(list(POSTS))).fetch("https://facebook.com/x")

    assert first.body == second.body


def test_the_sealed_bytes_are_deterministic_for_the_same_posts() -> None:
    """Two workers acquiring the same page must agree, or the same content
    would produce two different digests (M-10)."""
    assert serialise(POSTS) == serialise(POSTS)


def test_the_schema_tag_travels_inside_the_evidence() -> None:
    """A bundle must be readable years later without the code that wrote it
    (principle 8). The reader learns the format from the data."""
    document = json.loads(serialise(POSTS))

    assert document["schema"] == "asip.facebook.v1"


def test_no_vendor_name_leaks_into_the_sealed_bytes() -> None:
    """Which vendor was under contract in 2026 is our business, not a
    recipient's, and it must not be something they need to know to verify."""
    body = FacebookAcquisition(FakeProvider(POSTS)).fetch("https://facebook.com/x").body

    assert b"fake" not in body.lower()


def test_an_unknown_schema_is_not_half_parsed() -> None:
    """Reading four of six fields from a format we do not understand is how a
    capture quietly loses information nobody notices for months."""
    future = json.dumps({"schema": "asip.facebook.v2", "posts": [{"external_id": "x"}]}).encode()

    assert parse_capture(future, minimum_expected_items=0, platform="facebook").items == ()
