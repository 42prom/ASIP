"""The Graph API provider — the first Facebook route that actually runs.

Tested through a fake transport rather than a fake provider, so the real
parsing, the real URL construction and the real error handling are what get
exercised. Substituting the whole provider would test nothing that ships.

Two things carry the most weight. Graph reports credential problems as ordinary
HTTP errors, and telling a permission problem from a network blip decides
whether an operator retries forever or fixes the token (D-113). And a post with
no text must be dropped rather than stored empty, or every count downstream
acquires rows that mean nothing.
"""

from __future__ import annotations

import urllib.error
from typing import Any

import pytest

from asip.modules.collection.adapters.facebook_acquisition import (
    NotConfigured,
    serialise,
)
from asip.modules.collection.adapters.facebook_graph import (
    API_VERSION,
    TOKEN_ENV,
    GraphApiProvider,
)
from asip.modules.extraction.domain.parser import parse_capture

PAGE = {
    "data": [
        {
            "id": "1234_5678",
            "message": "ხიდის პროექტის ვადები გადაიწია.",
            "created_time": "2026-08-04T09:12:04+0000",
            "permalink_url": "https://facebook.com/1234/posts/5678",
        },
        {
            "id": "1234_5679",
            "story": "Ministry shared a link.",
            "created_time": "2026-08-04T09:12:31+0000",
            "permalink_url": "https://facebook.com/1234/posts/5679",
        },
        # A bare photo: no message, no story. Nothing to analyse.
        {
            "id": "1234_5680",
            "created_time": "2026-08-04T09:13:00+0000",
        },
    ]
}


class FakeTransport:
    def __init__(self, payload: dict[str, Any] | Exception) -> None:
        self.payload = payload
        self.urls: list[str] = []

    def __call__(self, url: str, timeout: float) -> dict[str, Any]:
        self.urls.append(url)
        if isinstance(self.payload, Exception):
            raise self.payload
        return self.payload


def provider(payload: Any = PAGE, token: str = "tok") -> tuple[GraphApiProvider, FakeTransport]:
    transport = FakeTransport(payload)
    return GraphApiProvider(token=token, transport=transport), transport


# ── the credential ──────────────────────────────────────────────────────────


def test_no_token_refuses_with_something_actionable() -> None:
    with pytest.raises(NotConfigured) as refusal:
        GraphApiProvider(token="").fetch_page("ministry.example", 25)

    assert TOKEN_ENV in str(refusal.value)
    assert "O-03" in str(refusal.value)


def test_the_refusal_says_which_pages_a_token_can_even_read() -> None:
    """Someone who gets a token and points it at a page they do not administer
    should learn that here, not from an opaque Graph error."""
    with pytest.raises(NotConfigured, match=r"administered|authorised"):
        GraphApiProvider(token="").fetch_page("someone.else", 25)


def test_the_token_never_appears_in_the_sealed_evidence() -> None:
    """Which credential fetched something is operational, not evidential. A
    recipient verifying a bundle must not be handed a secret."""
    graph, _ = provider(token="SECRET-TOKEN-VALUE")
    posts = graph.fetch_page("ministry.example", 25)

    assert b"SECRET-TOKEN-VALUE" not in serialise(posts)


# ── the request ─────────────────────────────────────────────────────────────


def test_the_api_version_is_pinned() -> None:
    """Tracking "latest" would change response shapes under a running
    collector, which looks like the pages changing rather than us."""
    graph, transport = provider()
    graph.fetch_page("ministry.example", 25)

    assert f"/{API_VERSION}/" in transport.urls[0]
    assert API_VERSION.startswith("v")


def test_the_page_and_limit_reach_the_request() -> None:
    graph, transport = provider()
    graph.fetch_page("ministry.example", 7)

    assert "ministry.example/posts" in transport.urls[0]
    assert "limit=7" in transport.urls[0]


def test_only_the_fields_that_are_used_are_requested() -> None:
    """Every extra field lands in sealed evidence that nothing reads, and each
    one is something a recipient must be told to ignore."""
    graph, transport = provider()
    graph.fetch_page("x", 5)

    assert "fields=id%2Cmessage%2Cstory%2Ccreated_time%2Cpermalink_url" in transport.urls[0]
    for absent in ("comments", "reactions", "insights", "from"):
        assert absent not in transport.urls[0]


# ── the response ────────────────────────────────────────────────────────────


def test_posts_are_normalised() -> None:
    graph, _ = provider()
    posts = graph.fetch_page("ministry.example", 25)

    assert len(posts) == 2, "the bare photo carries nothing to analyse"
    assert posts[0].external_id == "1234_5678"
    assert posts[0].page_handle == "ministry.example"
    assert "ხიდის" in posts[0].text


def test_a_generated_story_counts_when_there_is_no_message() -> None:
    """ "X shared a link" is still an observation: the behavioural path cares
    that a post happened and when, not what it said."""
    graph, _ = provider()
    posts = graph.fetch_page("x", 25)

    assert posts[1].text == "Ministry shared a link."


def test_the_platforms_own_timestamp_is_passed_through_untouched() -> None:
    """D-100. The shared parser derives UTC and detects precision — normalising
    here would let a provider reporting whole minutes be silently upgraded to
    seconds (D-102)."""
    graph, _ = provider()
    posts = graph.fetch_page("x", 25)

    assert posts[0].posted_at_raw == "2026-08-04T09:12:04+0000"


def test_the_whole_round_trip_reaches_extracted_items() -> None:
    """Graph → normalised → sealed bytes → extractor. The path that has to work
    on the day a token arrives."""
    graph, _ = provider()
    body = serialise(graph.fetch_page("ministry.example", 25))

    result = parse_capture(body, minimum_expected_items=1, platform="facebook")

    assert len(result.items) == 2
    assert result.validation_passed, result.problems
    assert result.items[0].author_handle == "ministry.example"
    assert result.items[0].script == "georgian"
    assert result.items[0].timestamp_precision == "second"


def test_an_empty_page_yields_nothing_rather_than_failing() -> None:
    graph, _ = provider(payload={"data": []})
    assert graph.fetch_page("quiet.page", 25) == []


def test_a_post_missing_its_time_is_dropped() -> None:
    """No timestamp means nothing the behavioural path can use, and a row with
    a guessed time would be worse than no row."""
    graph, _ = provider(payload={"data": [{"id": "1", "message": "hi"}]})
    assert graph.fetch_page("x", 25) == []


# ── errors, told apart ──────────────────────────────────────────────────────


def http_error(code: int, body: bytes) -> urllib.error.HTTPError:
    import io

    return urllib.error.HTTPError("u", code, "err", {}, io.BytesIO(body))  # type: ignore[arg-type]


def test_a_permission_problem_is_not_reported_as_transient() -> None:
    """D-113. Retrying a network error is sensible; retrying an expired token
    forever is not, and an operator cannot tell them apart from "fetch failed".
    """
    failure = http_error(403, b'{"error":{"message":"Requires pages_read_engagement"}}')
    graph, _ = provider(payload=failure)

    with pytest.raises(NotConfigured, match="pages_read_engagement"):
        graph.fetch_page("x", 25)


def test_an_expired_token_says_so_rather_than_reporting_a_status() -> None:
    failure = http_error(400, b'{"error":{"message":"Error validating access token: expired"}}')
    graph, _ = provider(payload=failure)

    with pytest.raises(NotConfigured, match="expired"):
        graph.fetch_page("x", 25)


def test_a_network_failure_stays_a_network_failure() -> None:
    """Distinct from a credential problem so a retry policy can act on it."""
    graph, _ = provider(payload=urllib.error.URLError("connection reset"))

    with pytest.raises(ConnectionError, match="could not reach"):
        graph.fetch_page("x", 25)


def test_an_unreadable_error_body_still_reports_the_status() -> None:
    """Graph occasionally returns HTML. Losing the status too would leave
    nothing to act on."""
    graph, _ = provider(payload=http_error(500, b"<html>oops</html>"))

    with pytest.raises(NotConfigured, match="500"):
        graph.fetch_page("x", 25)
