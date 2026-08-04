"""D-13 — reprocessing must not refetch, and must not be able to.

The first test is the important one. It does not check that reprocessing
*didn't* fetch on some particular run; it checks that the use case has no way
to fetch at all. D-13 is called the most expensive directive to get wrong, and
a behavioural assertion would pass right up until someone added a fetcher for
one edge case.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime
from uuid import UUID

from asip.modules.extraction.application import reprocess as reprocess_module
from asip.modules.extraction.application.reprocess import ReprocessCaptures
from asip.modules.extraction.domain.parser import EXTRACTOR_VERSION, detect_script

TENANT = UUID("aaaaaaaa-0000-4000-8000-00000000000e")
CAPTURE = UUID("bbbbbbbb-0000-4000-8000-00000000000b")

#: Two items, one Latin and one Georgian. The Georgian one is what proves the
#: v2 script detection did something a v1 extraction could not have (D-63).
PAGE = (
    '<div data-asip-item="a1" data-asip-author="alpha" '
    'data-asip-posted-at="2026-08-04T09:12:04Z">Bridge timeline looks wrong</div>'
    '<div data-asip-item="g1" data-asip-author="gamma" '
    'data-asip-posted-at="2026-08-04T09:12:31Z">ეს ხიდის პროექტი</div>'
).encode()


class FakeCaptures:
    """Stored bytes, and a count of how many times they were read."""

    def __init__(self, pages: dict[UUID, bytes] | None = None) -> None:
        self.pages = pages if pages is not None else {CAPTURE: PAGE}
        self.reads = 0

    def read_capture(self, tenant_id: UUID, capture_id: UUID) -> bytes | None:
        self.reads += 1
        return self.pages.get(capture_id)


class FakeRepo:
    """Extraction storage, recording what a reprocess wrote."""

    def __init__(self, stored_version: int = 1, timestamp_drift: bool = False) -> None:
        self.updates: list[dict[str, object]] = []
        self._stored_version = stored_version
        self._drift = timestamp_drift

    def reprocessing_backlog(self, tenant_id: UUID, current: int) -> list[dict[str, object]]:
        if self._stored_version >= current:
            return []
        return [{"capture_id": CAPTURE, "oldest_extractor_version": self._stored_version}]

    def content_for_capture(self, tenant_id: UUID, capture_id: UUID) -> list[dict[str, object]]:
        posted = datetime(2026, 8, 4, 9, 12, 4, tzinfo=UTC)
        drifted = datetime(2026, 8, 4, 10, 0, 0, tzinfo=UTC)
        return [
            {
                "content_id": self.content_id_for("canary", "a1"),
                "posted_at_authoritative": drifted if self._drift else posted,
            },
            {
                "content_id": self.content_id_for("canary", "g1"),
                "posted_at_authoritative": datetime(2026, 8, 4, 9, 12, 31, tzinfo=UTC),
            },
        ]

    @staticmethod
    def content_id_for(platform: str, external_id: str) -> UUID:
        from asip.modules.extraction.adapters.postgres_repository import content_id_for

        return content_id_for(platform, external_id)

    def update_extracted(self, **kwargs: object) -> bool:
        self.updates.append(kwargs)
        return True


# ── the structural guarantee ────────────────────────────────────────────────


def test_reprocessing_cannot_be_given_a_fetcher() -> None:
    """D-13, enforced by the constructor rather than by discipline."""
    parameters = inspect.signature(ReprocessCaptures.__init__).parameters
    offenders = [
        name
        for name in parameters
        if any(word in name.lower() for word in ("fetch", "http", "client", "queue", "url"))
    ]
    assert not offenders, (
        f"ReprocessCaptures accepts {offenders}. D-13: reprocessing re-reads stored "
        "captures and contacts no source. Refetching instead costs real money."
    )


def test_the_reprocess_module_imports_no_fetcher() -> None:
    source = inspect.getsource(reprocess_module)
    for forbidden in (
        "http_fetcher",
        "HttpFetcher",
        "urllib",
        "requests",
        "httpx",
        "QueuedFetcher",
    ):
        assert forbidden not in source, f"reprocess reaches {forbidden!r} — D-13"


# ── behaviour ───────────────────────────────────────────────────────────────


def test_stored_captures_are_re_read_and_items_updated() -> None:
    captures, repo = FakeCaptures(), FakeRepo(stored_version=1)

    report = ReprocessCaptures(captures, repo).execute(TENANT)

    assert report.captures_reprocessed == 1
    assert report.items_updated == 2
    assert report.fetches_performed == 0
    assert captures.reads == 1, "the archive should be read once per capture, not per item"


def test_the_new_extractor_version_is_written() -> None:
    repo = FakeRepo(stored_version=1)
    ReprocessCaptures(FakeCaptures(), repo).execute(TENANT)
    assert all(u["extractor_version"] == EXTRACTOR_VERSION for u in repo.updates)


def test_v2_adds_the_script_the_old_version_never_recorded() -> None:
    """The reason for bumping: content extracted by v1 has no script."""
    repo = FakeRepo(stored_version=1)
    ReprocessCaptures(FakeCaptures(), repo).execute(TENANT)

    scripts = {u["script"] for u in repo.updates}
    assert scripts == {"latin", "georgian"}
    assert detect_script("ეს ხიდის პროექტი") == "georgian"


def test_nothing_is_reprocessed_when_content_is_already_current() -> None:
    captures, repo = FakeCaptures(), FakeRepo(stored_version=EXTRACTOR_VERSION)

    report = ReprocessCaptures(captures, repo).execute(TENANT)

    assert report.captures_examined == 0
    assert captures.reads == 0, "a current corpus must not re-read a single archive"


def test_a_capture_whose_bytes_are_gone_is_counted_not_fatal() -> None:
    """Retention expires bytes while rows survive until their own expiry.

    Ordinary during a reprocess of old material. A batch of a million must not
    abort because one archive has aged out.
    """
    captures = FakeCaptures(pages={})
    report = ReprocessCaptures(captures, FakeRepo(stored_version=1)).execute(TENANT)

    assert report.captures_unavailable == 1
    assert report.captures_reprocessed == 0
    assert report.items_updated == 0


def test_a_changed_authoritative_timestamp_is_reported_not_duplicated() -> None:
    """The sharp edge, surfaced rather than hidden.

    `posted_at_authoritative` is the partition key and part of the primary key,
    so an item whose newly derived timestamp differs cannot be updated in place.
    Writing it anyway would create a second row with the same content_id and
    silently double every count downstream.
    """
    repo = FakeRepo(stored_version=1, timestamp_drift=True)

    report = ReprocessCaptures(FakeCaptures(), repo).execute(TENANT)

    assert len(report.items_needing_migration) == 1
    assert report.items_updated == 1, "the item whose timestamp held should still update"


def test_the_report_states_the_number_that_matters() -> None:
    report = ReprocessCaptures(FakeCaptures(), FakeRepo(stored_version=1)).execute(TENANT)
    assert "0 refetches" in report.summary


def test_reprocessing_twice_is_safe() -> None:
    """Idempotence rests on deterministic content ids (M-10).

    The same capture re-parsed derives the same ids, so a second pass updates
    the same rows rather than creating new ones.
    """
    repo = FakeRepo(stored_version=1)
    runner = ReprocessCaptures(FakeCaptures(), repo)

    first = runner.execute(TENANT)
    second = runner.execute(TENANT)

    ids_first = {str(u["content_id"]) for u in repo.updates[: first.items_updated]}
    ids_second = {str(u["content_id"]) for u in repo.updates[first.items_updated :]}
    assert ids_first == ids_second
    assert second.fetches_performed == 0
