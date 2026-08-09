"""The first extractor for a real platform (D-88.1).

Golden-file, against a synthetic fixture whose DOM shape is copied from a live
`t.me/s/` page. R-03 keeps real captures out of this repository: they contain
real people's names and posts, which makes them T3.

The tests are about the two things that decide whether this is worth anything:
the handle must identify the *channel* (a cluster is made of participants, and
a participant that changes identity every message cannot be clustered), and the
timestamp must keep the precision the platform actually offered (D-102).
"""

from __future__ import annotations

from pathlib import Path

from asip.modules.extraction.domain.parser import parse_capture
from asip.modules.extraction.domain.telegram import parse_channel

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "telegram" / "coordinated_burst.html"


def load() -> bytes:
    return FIXTURE.read_bytes()


def parsed():  # type: ignore[no-untyped-def]
    return parse_capture(load(), minimum_expected_items=1, platform="telegram")


# ── the shape ───────────────────────────────────────────────────────────────


def test_every_message_is_found() -> None:
    assert len(parsed().items) == 5


def test_extraction_validates() -> None:
    """No problems means no item was dropped for a missing field.

    Worth asserting separately: a parser that silently skipped four of five
    messages would still "work" and would quietly halve every count downstream.
    """
    result = parsed()
    assert result.validation_passed, result.problems


def test_the_post_id_is_the_platforms_own() -> None:
    """Content ids are UUIDv5 over (platform, external_id) — M-10.

    A synthesised id would change whenever the page was re-rendered, and every
    re-observation would look like a new item.
    """
    ids = [i.external_id for i in parsed().items]
    assert ids[0] == "civicvoice_ge/1041"
    assert len(set(ids)) == len(ids), "post ids are not unique within one page"


def test_the_handle_is_the_channel_not_the_message() -> None:
    """The participant, not the post.

    If the handle were the full "channel/1041" then every message would be its
    own account, four channels would look like four hundred, and no cluster
    would ever form.
    """
    handles = [i.author_handle for i in parsed().items]
    assert handles == [
        "civicvoice_ge",
        "regionwatch",
        "dailybrief_ge",
        "northsignal",
        "civicvoice_ge",
    ]


def test_the_display_name_is_kept_but_is_not_the_identity() -> None:
    """A display name is chosen by the owner and can imitate another channel.

    Kept for the analyst to read; never used as the identifier.
    """
    first = parsed().items[0]
    assert first.author_display_name == "Civic Voice"
    assert first.author_handle == "civicvoice_ge"


def test_inline_markup_does_not_break_the_text() -> None:
    """Bold and links appear inside message bodies constantly."""
    items = {i.external_id: i for i in parsed().items}

    assert (
        items["regionwatch/882"].text
        == "The bridge timeline has slipped again — third time this year."
    )
    assert "Read more" in items["dailybrief_ge/2210"].text
    assert "<a" not in items["dailybrief_ge/2210"].text


def test_georgian_text_survives_and_is_detected() -> None:
    """D-63. Georgian is first-class, not an encoding edge case."""
    first = parsed().items[0]

    assert "ხიდის" in first.text
    assert first.script == "georgian"


# ── the part that makes clustering possible ─────────────────────────────────


def test_the_platforms_own_timestamp_is_preserved_and_derived() -> None:
    """D-100/D-101: keep the raw string, cluster on the derived UTC value."""
    first = parsed().items[0]

    assert first.posted_at_raw == "2026-08-04T09:12:04+00:00"
    assert first.posted_at.isoformat() == "2026-08-04T09:12:04+00:00"


def test_precision_is_recorded_as_seconds_despite_the_offset() -> None:
    """D-102, and the bug this extractor exposed.

    Precision was measured from the whole string's length, so an ISO timestamp
    carrying "+00:00" matched no row and fell through to the default. The
    default happened to be right here and would have been wrong for a
    minute-precision source — overstating precision, which makes a 120-second
    window look meaningful when every value in it is rounded to the minute.
    """
    assert all(i.timestamp_precision == "second" for i in parsed().items)


def test_the_four_channel_burst_is_inside_one_window() -> None:
    """What the fixture exists to encode.

    Four distinct channels within 41 seconds. Asserted here rather than only in
    the rule's own tests so the extractor and the detector cannot drift apart
    about what the data says.
    """
    items = sorted(parsed().items, key=lambda i: i.posted_at)
    burst = items[:4]

    span = (burst[-1].posted_at - burst[0].posted_at).total_seconds()
    assert span == 41
    assert len({i.author_handle for i in burst}) == 4

    # And the fifth is genuinely outside, so a passing window test means
    # something.
    assert (items[4].posted_at - burst[0].posted_at).total_seconds() > 600


# ── robustness ──────────────────────────────────────────────────────────────


def test_a_page_with_no_messages_yields_nothing_rather_than_failing() -> None:
    """A channel can legitimately be empty, and a fetch can legitimately land
    on an interstitial. Neither is a crash."""
    rows = parse_channel("<html><body><div class='tgme_page'>nothing here</div></body></html>")
    assert rows == []


def test_a_message_missing_its_time_is_reported_not_silently_dropped() -> None:
    """A parse that quietly discards items is how a detection system stops
    working without anyone noticing (D-87)."""
    broken = (
        b'<div class="tgme_widget_message" data-post="c/1">'
        b'<div class="tgme_widget_message_text">no time on this one</div></div>'
    )

    result = parse_capture(broken, minimum_expected_items=0, platform="telegram")

    assert not result.items
    assert any("timestamp" in p for p in result.problems)


def test_an_unknown_platform_falls_back_rather_than_raising() -> None:
    """The capture is already stored by the time this runs. Refusing to parse
    would turn a configuration mistake into a lost extraction; the source's
    declared capability is what tells the user nothing will come of it."""
    canary = (
        b'<div data-asip-item="a1" data-asip-author="alpha" '
        b'data-asip-posted-at="2026-08-04T09:12:04Z">hello</div>'
    )

    assert parse_capture(canary, platform="something-else").items
