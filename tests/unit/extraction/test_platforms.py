"""What the product claims it can read, and whether that claim is true.

This registry is the difference between a user believing "there is no
coordinated activity here" and knowing "nobody looked at this yet". D-68 is
written about empty screens; the same failure starts one step earlier, at the
moment someone adds a source and is not told what will happen to it.

The test that matters is the last one: a platform may only be listed as
EXTRACTS if the parser can actually read it. An optimistic entry — added when
work starts rather than when it finishes — is precisely the lie this module
exists to prevent, and it would be invisible until a client asked why their
Facebook monitoring found nothing in six months.
"""

from __future__ import annotations

from asip.modules.extraction.domain.parser import parse_capture
from asip.modules.extraction.domain.platforms import (
    BY_KEY,
    PLATFORMS,
    Support,
    extracts,
    is_known,
    platform,
)


def test_every_platform_has_a_note_written_for_a_person() -> None:
    """The note is shown verbatim in the interface. A terse one is a support
    ticket; a missing one is a blank space where an explanation should be."""
    for entry in PLATFORMS:
        assert len(entry.note) > 60, f"{entry.key}: note too short to explain anything"
        assert entry.label, f"{entry.key}: no human-readable label"


def test_keys_are_unique() -> None:
    assert len(BY_KEY) == len(PLATFORMS)


def test_an_unknown_platform_is_not_silently_accepted() -> None:
    assert not is_known("myspace")
    assert platform("myspace") is None
    assert not extracts("myspace")


def test_blocked_platforms_say_why_and_name_the_open_item() -> None:
    """A user told only "not supported" assumes it is coming next sprint.

    Naming O-03 says what it actually is: an undecided commercial route, not a
    missing feature someone forgot to build.
    """
    blocked = [p for p in PLATFORMS if p.support is Support.BLOCKED]
    assert blocked, "the registry claims everything works, which cannot be true"

    for entry in blocked:
        assert "O-03" in entry.note, f"{entry.key} does not say why it is blocked"


def test_no_blocked_platform_promises_a_workaround() -> None:
    """V-6. The product must never hint that it will get around a login or a
    bot check — a hint here becomes an expectation in a sales conversation.

    Polarity matters, and the first version of this test missed that: it
    rejected the word "circumvent" wherever it appeared, including in the
    sentence "this system will not attempt to circumvent a login", which is
    exactly the disclaimer the veto wants stated. A test that cannot tell a
    promise from its denial makes the honest wording the thing that fails.
    """
    words = ("bypass", "circumvent", "evade", "get around", "work around")
    denials = ("not ", "never ", "cannot ", "no ", "without ")

    for entry in PLATFORMS:
        lowered = entry.note.lower()
        for word in words:
            at = lowered.find(word)
            if at == -1:
                continue
            # Look back far enough to catch "will not attempt to circumvent".
            preceding = lowered[max(0, at - 40) : at]
            assert any(d in preceding for d in denials), (
                f"{entry.key} says {word!r} without denying it. The product does not "
                "defeat access controls (V-6), and the note must not suggest otherwise."
            )


def test_exactly_the_platforms_the_parser_can_read_are_marked_extracts() -> None:
    """The claim, checked against the parser rather than against intent.

    A page is genuinely extractable only if `parse_capture` finds items in it.
    Any platform marked EXTRACTS must have a shape the parser handles; a
    platform the parser cannot read must not be marked EXTRACTS.
    """
    canary_page = (
        b'<div data-asip-item="a1" data-asip-author="alpha" '
        b'data-asip-posted-at="2026-08-04T09:12:04Z">first</div>'
    )

    parsed = parse_capture(canary_page, minimum_expected_items=1)
    assert parsed.items, "the canary shape no longer parses — the registry is now wrong"

    claimed = {p.key for p in PLATFORMS if p.support is Support.EXTRACTS}
    assert claimed == {"canary"}, (
        f"{sorted(claimed)} are marked as fully read. Only 'canary' has an extractor. "
        "A platform is added to EXTRACTS when its golden fixtures pass, not when "
        "work on it begins (D-88.1)."
    )


def test_a_platform_marked_extracts_is_never_also_described_as_unreachable() -> None:
    """Guards against the label and the prose drifting apart, which is how a
    registry stops being read."""
    for entry in PLATFORMS:
        if entry.support is Support.EXTRACTS:
            assert "not reachable" not in entry.note.lower()
            assert extracts(entry.key)
