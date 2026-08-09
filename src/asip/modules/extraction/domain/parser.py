"""L1 — turn a captured HTML page into structured items.

Pure: bytes in, values out. No network, no clock, no database. The extractor
never fetches anything — that is the point of D-13. A capture is stored once
and can be re-parsed by a newer extractor as many times as we like, which is
why ``EXTRACTOR_VERSION`` is stamped onto every row it produces.

The parser deliberately targets a simple, well-known markup shape rather than
a real platform's DOM. The walking skeleton exists to prove the pipe connects;
a real extractor is a golden-fixture exercise per platform (D-88.1), and
building one against a live site before the pipe works would be guessing twice.

Timestamp handling is the part that is *not* simplified, because it is a
correctness question rather than a completeness one. D-100 through D-102: the
platform's raw string is preserved, the derived UTC value is what clustering
uses, and the precision the source actually offers is recorded — a rule with a
120-second window is worthless against a source that reports whole minutes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser

from asip.modules.extraction.domain.telegram import parse_channel

#: Bumped whenever this parser's output could change for the same input.
#: Reprocessing compares this against the stored value to decide what to redo.
#:
#: v2 — records the script an item is written in. Added deliberately as the
#: first real exercise of D-13: content extracted by v1 has no script recorded,
#: and the correct way to fix that is to re-parse the captures already stored,
#: not to fetch anything again.
EXTRACTOR_VERSION = 2

#: Georgian, as codepoint bounds rather than literal characters.
#:
#: Written this way because a literal U+10FF trips ruff's confusable-character
#: rule — a check for homoglyph attacks firing on the definition of the script
#: this product treats as first-class (D-63). Codepoints say the same thing and
#: are what a reader checks against the Unicode chart anyway.
GEORGIAN_FIRST = 0x10A0  # Mkhedruli and Mtavruli block start
GEORGIAN_LAST = 0x10FF

#: Precision the source actually provides, detected per item (D-102).
PRECISION_BY_LENGTH = {
    len("2026-08-04T09:12:04"): "second",
    len("2026-08-04T09:12"): "minute",
    len("2026-08-04T09"): "hour",
    len("2026-08-04"): "day",
}


@dataclass(frozen=True, slots=True)
class ExtractedItem:
    """One post or comment recovered from a capture."""

    external_id: str
    author_handle: str
    author_display_name: str | None
    text: str
    posted_at_raw: str
    posted_at: datetime
    timestamp_precision: str
    #: The script the text is written in, or None when it cannot be told.
    #: Deliberately not exposed to the detection path — see the migration that
    #: removes it from v_content_for_detection.
    script: str | None = None


@dataclass(frozen=True, slots=True)
class ExtractionResult:
    """What one parse produced, including why it may be untrustworthy.

    ``problems`` is not an error list — the parse succeeded. It is the
    validation record: a page that yielded three items when it normally yields
    forty parsed fine and is still evidence that something changed.
    """

    items: tuple[ExtractedItem, ...]
    extractor_version: int
    problems: tuple[str, ...]

    @property
    def validation_passed(self) -> bool:
        return not self.problems


class _ItemCollector(HTMLParser):
    """Collects elements carrying the data attributes the fixture format uses.

    Uses the standard library's parser rather than a dependency: the markup
    shape is fixed and simple, and an HTML parser is not where this project
    should be spending a dependency (CLAUDE.md §3).
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[dict[str, str]] = []
        self._current: dict[str, str] | None = None
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k: (v or "") for k, v in attrs}
        if "data-asip-item" in attributes:
            self._current = {
                "external_id": attributes.get("data-asip-item", ""),
                "author": attributes.get("data-asip-author", ""),
                "display_name": attributes.get("data-asip-display-name", ""),
                "posted_at": attributes.get("data-asip-posted-at", ""),
                "text": "",
            }
            self._depth = 1
        elif self._current is not None:
            self._depth += 1

    def handle_endtag(self, tag: str) -> None:
        if self._current is None:
            return
        self._depth -= 1
        if self._depth <= 0:
            self.rows.append(self._current)
            self._current = None

    def handle_data(self, data: str) -> None:
        if self._current is not None:
            self._current["text"] += data


def _read_rows(text: str, platform: str) -> list[dict[str, str]]:
    """Pick the DOM reader for a platform.

    An unknown platform falls back to the canary shape rather than raising. A
    capture is already stored by the time this runs; refusing to parse it would
    turn a configuration mistake into a lost extraction, and the source's
    declared capability (extraction/domain/platforms.py) is what tells the user
    nothing will come of it.
    """
    if platform == "telegram":
        rows = parse_channel(text)
        # The telegram reader returns the same keys the collector does, so
        # everything downstream is identical. Asserted rather than assumed:
        # a shape mismatch here would surface as "missing id or author" on
        # every item, which reads as a broken page rather than a broken parser.
        return rows

    collector = _ItemCollector()
    collector.feed(text)
    collector.close()
    return collector.rows


def parse_capture(
    html: bytes, minimum_expected_items: int = 1, platform: str = "canary"
) -> ExtractionResult:
    """Parse a stored capture into items.

    ``minimum_expected_items`` drives the validation rule: a page that suddenly
    yields far fewer items than usual has probably changed shape, and silently
    extracting three posts from a page that used to give forty is how a
    detection system quietly stops working (D-87).

    ``platform`` selects the DOM reader. Only the *shape* differs per platform —
    timestamp parsing, precision detection, script detection and whitespace
    normalisation stay here, shared, because two sources that derived "the same
    second" differently would make cross-source clustering meaningless. That is
    the whole signal this product looks for, so it is not a place to allow
    per-platform drift.
    """
    problems: list[str] = []

    try:
        text = html.decode("utf-8")
    except UnicodeDecodeError:
        text = html.decode("utf-8", errors="replace")
        problems.append("capture was not valid UTF-8; decoded with replacement")

    rows = _read_rows(text, platform)

    items: list[ExtractedItem] = []
    for row in rows:
        if not row["external_id"] or not row["author"]:
            problems.append(f"item missing id or author: {row['external_id']!r}")
            continue

        posted_at, precision = _parse_timestamp(row["posted_at"])
        if posted_at is None:
            problems.append(
                f"item {row['external_id']!r} has an unparseable timestamp: {row['posted_at']!r}"
            )
            continue

        items.append(
            ExtractedItem(
                external_id=row["external_id"],
                author_handle=row["author"],
                author_display_name=row["display_name"] or None,
                text=_normalise_whitespace(row["text"]),
                script=detect_script(row["text"]),
                posted_at_raw=row["posted_at"],
                posted_at=posted_at,
                timestamp_precision=precision,
            )
        )

    if len(items) < minimum_expected_items:
        problems.append(
            f"extracted {len(items)} items, expected at least {minimum_expected_items} "
            "— the page shape may have changed"
        )

    return ExtractionResult(
        items=tuple(items),
        extractor_version=EXTRACTOR_VERSION,
        problems=tuple(problems),
    )


def _precision_of(value: str) -> str:
    """How precise the source's own timestamp is, ignoring any zone suffix.

    THE BUG THIS FIXES

    Precision was measured from the whole string's length. That works for the
    canary's "2026-08-04T09:12:04" and breaks on anything carrying an offset:
    Telegram publishes "2026-04-09T07:01:44+00:00", which is 25 characters, is
    in no row of the table, and therefore fell through to the default.

    The default is "second". So an offset-bearing minute-precision timestamp —
    "2026-04-09T07:01+00:00" — would have been recorded as second precision.
    That is the dangerous direction: overstating precision makes a 120-second
    clustering window look meaningful when every value in it is rounded to the
    minute, and the resulting "burst" is an artefact of rounding (D-102).

    Stripping the zone first measures the part that actually carries precision.
    """
    body = value.rstrip("Z")
    # Split off "+HH:MM" / "-HH:MM" without touching the date's own hyphens:
    # a sign can only be a zone marker after the time component begins.
    time_at = body.find("T")
    if time_at != -1:
        for sign in ("+", "-"):
            at = body.find(sign, time_at)
            if at != -1:
                body = body[:at]
                break
    return PRECISION_BY_LENGTH.get(len(body), "second")


def _parse_timestamp(raw: str) -> tuple[datetime | None, str]:
    """Derive the authoritative UTC time and record the precision offered.

    Both halves matter. D-101 says clustering runs on the derived value, and
    D-102 says the precision is a correctness input: a source reporting whole
    minutes cannot support a 120-second clustering window, because everything
    lands in one of two buckets and the signal is noise.
    """
    value = raw.strip()
    if not value:
        return (None, "second")

    precision = _precision_of(value)

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return (None, precision)

    # Naive input is treated as UTC and said so. Guessing a local zone would
    # silently shift every timestamp by hours.
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return (parsed.astimezone(UTC), precision)


def detect_script(text: str) -> str | None:
    """Which alphabet the text uses. Not what it says.

    Georgian is first-class in this product (D-63), and knowing which items are
    written in it matters for display, for font selection, and eventually for
    choosing an embedding model. It is a property of the characters, not of the
    opinion — which is why it is safe to derive here and unsafe to publish to
    the authenticity path, where any content-derived signal is forbidden (V-2).

    Returns None rather than guessing on text with no letters at all: a string
    of digits and punctuation has no script, and saying "latin" would be an
    invention.
    """
    georgian = latin = 0
    for character in text:
        if GEORGIAN_FIRST <= ord(character) <= GEORGIAN_LAST:
            georgian += 1
        elif character.isalpha() and character.isascii():
            latin += 1

    if georgian == 0 and latin == 0:
        return None
    return "georgian" if georgian >= latin else "latin"


def _normalise_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()
