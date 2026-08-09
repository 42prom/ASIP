"""L1 — extract posts from a Telegram public channel preview.

WHY TELEGRAM AND WHY THIS PAGE

`t.me/s/<channel>` is the public web preview Telegram itself serves for public
channels. No login, no API key, no bot check — it is a plain HTML page intended
to be read by anyone, and reading it needs nothing this system is not allowed to
do (V-6). That makes it the first real platform ASIP can monitor rather than
simulate, and the acquisition-route question (O-03) does not block it.

WHY IT IS USEFUL FOR THIS PRODUCT SPECIFICALLY

A single channel is one author, so no burst rule will ever fire on it alone —
and that is the right outcome, not a limitation. The signal this product exists
to find is *many* channels posting the same thing within seconds of each other,
which is exactly what a coordinated amplification network looks like from
outside. Monitor a dozen channels and the clustering has something real to work
on: each channel is a participant, and near-simultaneous posting across them is
the observation. The unit of analysis stays the cluster (V-1).

TIMESTAMPS ARE THE REASON THIS IS WORTH DOING PROPERLY

Telegram publishes `<time datetime="2026-04-09T07:01:44+00:00">` — full second
precision with an explicit offset. That matters more than it looks: a rule with
a 120-second window is worthless against a source that reports whole minutes
(D-102), and most scraped sources report "2 hours ago". Second precision from
the platform itself is what makes near-simultaneous posting measurable at all.

WHAT THIS DELIBERATELY DOES NOT DO

No comments, no reactions, no view counts, no media. Posts and their times are
what the behavioural path needs, and every extra field is another thing to keep
correct across a DOM change. The authenticity path must not read text or stance
anyway (V-2) — `text` is extracted because the evidence bundle and the analyst
need it, never because a rule may see it.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser

#: A post's stable identity on the platform: "<channel>/<message number>".
#: Telegram puts it on the wrapper element, so it survives DOM churn elsewhere
#: on the page and gives content ids something durable to hash (M-10).
_POST_ATTR = "data-post"

_MESSAGE_CLASS = "tgme_widget_message"
_TEXT_CLASS = "tgme_widget_message_text"
_AUTHOR_CLASS = "tgme_widget_message_owner_name"

#: Collapse runs of whitespace introduced by the markup, without touching the
#: text's own content. Georgian and Latin behave identically here (D-63).
_WHITESPACE = re.compile(r"[ \t\r\f\v]+")


def _classes(attrs: dict[str, str]) -> set[str]:
    return set(attrs.get("class", "").split())


class TelegramChannelParser(HTMLParser):
    """Collect one row per message.

    Standard library rather than a dependency: the shape is narrow and stable,
    and an HTML parser is not where this project spends a dependency (§3).

    Nesting is tracked by depth counters rather than by a stack of tags. A
    message body contains arbitrary inline markup — bold, links, emoji spans —
    and matching close tags to open ones would mean reimplementing the parser's
    own job badly. Counting how deep we are inside a region of interest is
    enough to know when we have left it.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.rows: list[dict[str, str]] = []

        self._current: dict[str, str] | None = None
        self._message_depth = 0
        self._text_depth = 0
        self._author_depth = 0

    # ── open ────────────────────────────────────────────────────────────────

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {k: (v or "") for k, v in attrs}
        classes = _classes(attributes)

        if self._message_depth:
            self._message_depth += 1
        elif _MESSAGE_CLASS in classes and _POST_ATTR in attributes:
            self._message_depth = 1
            self._current = {
                "external_id": attributes[_POST_ATTR],
                "author": "",
                "text": "",
                "posted_at": "",
            }

        if self._current is None:
            return

        if self._text_depth:
            self._text_depth += 1
        elif _TEXT_CLASS in classes:
            self._text_depth = 1

        if self._author_depth:
            self._author_depth += 1
        elif _AUTHOR_CLASS in classes:
            self._author_depth = 1

        # The authoritative time, straight from the platform (D-100). Taken
        # from the attribute rather than the visible text: the attribute is
        # ISO 8601 with an offset, the visible text is "Apr 9" or "07:01".
        if tag == "time" and attributes.get("datetime") and not self._current["posted_at"]:
            self._current["posted_at"] = attributes["datetime"]

    # ── content ─────────────────────────────────────────────────────────────

    def handle_data(self, data: str) -> None:
        if self._current is None:
            return
        if self._text_depth:
            self._current["text"] += data
        elif self._author_depth:
            self._current["author"] += data

    # ── close ───────────────────────────────────────────────────────────────

    def handle_endtag(self, tag: str) -> None:
        if self._text_depth:
            self._text_depth -= 1
        if self._author_depth:
            self._author_depth -= 1

        if self._message_depth:
            self._message_depth -= 1
            if self._message_depth == 0 and self._current is not None:
                self.rows.append(self._finish(self._current))
                self._current = None

    @staticmethod
    def _finish(row: dict[str, str]) -> dict[str, str]:
        # The channel, not the message number: the handle identifies the
        # participant, and the participant is what a cluster is made of.
        channel = row["external_id"].split("/")[0]
        return {
            "external_id": row["external_id"],
            # Prefer the channel slug from the post id over the displayed name.
            # A display name is chosen by the owner and can be changed or made
            # to imitate another channel; the slug is the platform's identifier.
            "author": channel,
            "display_name": _WHITESPACE.sub(" ", row["author"]).strip(),
            "text": _WHITESPACE.sub(" ", row["text"]).strip(),
            "posted_at": row["posted_at"],
        }


def parse_channel(html: str) -> list[dict[str, str]]:
    """Rows in the shape the shared extractor expects.

    Returns raw strings; timestamp parsing, precision detection and script
    detection stay in one place (parser.py) so every platform derives them
    identically. A per-platform timestamp parser is how two sources end up
    disagreeing about what "the same second" means.
    """
    parser = TelegramChannelParser()
    parser.feed(html)
    parser.close()
    return parser.rows
