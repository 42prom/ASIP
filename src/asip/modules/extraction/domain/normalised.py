"""L1 — read ASIP's own normalised post format.

WHY A FORMAT OF OUR OWN

Sources that arrive over an API rather than as HTML have no DOM to parse; they
have whatever JSON their vendor emits. Parsing that directly would put the
vendor's schema in the extractor, in the sealed evidence, and in every bundle
handed to a recipient — so changing provider would break parsing of everything
collected before the change, and a recipient verifying a five-year-old bundle
would need to know which vendor was under contract that year.

So the acquisition adapter normalises first, and this reads the normalised
shape. The provider-specific code is a few dozen lines per vendor; everything
after it is shared and stable.

    provider JSON → adapter (per vendor) → asip.facebook.v1 → this → items

That boundary is principle 5 and principle 8 in one place: no vendor lock-in,
and an evidence object that stays readable without the code that produced it.

THE SCHEMA TAG IS INSIDE THE DATA

`{"schema": "asip.facebook.v1", ...}` — a future v2 is a new tag, never an edit
to this one, for the same reason the chain preimage carries a version. Bundles
already sealed under v1 must stay parseable forever, and a format whose meaning
depends on the reader's version is not a format.
"""

from __future__ import annotations

import json

SCHEMA_V1 = "asip.facebook.v1"

#: Every schema this reader understands. A bundle written under an unknown one
#: is reported rather than half-parsed — silently reading four of six fields is
#: how a capture quietly loses information nobody notices for months.
KNOWN_SCHEMAS = frozenset({SCHEMA_V1})


def parse_normalised_posts(text: str) -> list[dict[str, str]]:
    """Rows in the shape the shared extractor expects.

    Returns raw strings only. Timestamp parsing, precision detection and script
    detection stay in parser.py so every platform derives them identically —
    two sources disagreeing about what "the same second" means would make
    cross-source clustering meaningless, and cross-source clustering is the
    entire signal.

    A malformed document yields nothing rather than raising. The capture is
    already sealed by the time this runs; refusing to parse it would turn a
    provider's bad day into a lost extraction, and the validation rule in
    parse_capture already reports a page that produced fewer items than
    expected (D-87).
    """
    try:
        document = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []

    if not isinstance(document, dict):
        return []
    if document.get("schema") not in KNOWN_SCHEMAS:
        return []

    posts = document.get("posts")
    if not isinstance(posts, list):
        return []

    rows: list[dict[str, str]] = []
    for post in posts:
        if not isinstance(post, dict):
            continue
        rows.append(
            {
                "external_id": str(post.get("external_id", "")),
                # The page, not the post: a cluster is made of participants, and
                # a participant whose identity changed every message could never
                # be clustered.
                "author": str(post.get("page_handle", "")),
                "display_name": str(post.get("page_name", "")),
                "text": str(post.get("text", "")),
                "posted_at": str(post.get("posted_at_raw", "")),
            }
        )
    return rows
