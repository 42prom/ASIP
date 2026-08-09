"""L1 — which platforms this system can actually read, and which it cannot.

WHY THIS EXISTS

Adding a source is the first thing a new user does, and the most damaging thing
the product could do at that moment is accept a Facebook URL, fetch it happily,
extract nothing, and show an empty Findings screen. The user concludes there is
no coordinated activity. The truth is that nobody looked.

D-68 says an empty screen never means "no activity" — it must distinguish "we
measured and it is empty" from "we do not know". That directive is written about
dashboards, and it applies with more force here, because a configuration mistake
poisons every screen downstream of it for as long as it goes unnoticed.

So capability is a declared fact with a status, checked when a source is added
and surfaced in the interface. Adding an unsupported platform is allowed —
evidence is still captured and sealed, which is worth something on its own — but
it is never allowed to look like it is working.

WHY ADDING IT IS NOT SIMPLY REFUSED

A capture of a page nobody can parse yet is still a sealed, timestamped record
of what that page said at that moment. Reprocessing (D-13) exists precisely so a
later extractor can read captures taken before it was written. Refusing to
collect until an extractor exists would throw away evidence that cannot be
recreated — the page will have changed.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Support(StrEnum):
    #: A golden-fixture extractor exists. Items will be extracted.
    EXTRACTS = "extracts"
    #: Can be fetched and sealed as evidence; nothing will be extracted from it.
    #: Collection is still useful — the capture is the record — but no finding
    #: will ever come from it until an extractor lands.
    CAPTURE_ONLY = "capture_only"
    #: Reachable only through an access route that is not decided yet (O-03).
    #: An anonymous HTTP fetch returns a login wall or a JavaScript shell, so
    #: what gets sealed is a screenshot of a door, not of the room.
    BLOCKED = "blocked"

    #: The plumbing exists and the credential does not. Distinct from BLOCKED
    #: on purpose: BLOCKED means nobody has built anything, NEEDS_ROUTE means
    #: pages can be added and scheduled today and collection begins the moment
    #: a provider is configured. Telling an operator "blocked" when the only
    #: missing piece is an environment variable sends them to build something
    #: that already exists.
    NEEDS_ROUTE = "needs_route"


@dataclass(frozen=True, slots=True)
class Platform:
    key: str
    label: str
    support: Support
    #: Said in the interface, verbatim. Written for the person adding a source,
    #: not for a developer reading the enum.
    note: str


#: The honest list. A platform is added here when its extractor exists, not
#: when work on it starts — an optimistic entry is exactly the lie this module
#: exists to prevent.
PLATFORMS: tuple[Platform, ...] = (
    Platform(
        key="canary",
        label="Canary (local test page)",
        support=Support.EXTRACTS,
        note=(
            "A page this deployment serves itself, used to prove the pipeline end "
            "to end. Fully extracted."
        ),
    ),
    Platform(
        key="html",
        label="Public HTML page",
        support=Support.CAPTURE_ONLY,
        note=(
            "Any page reachable without logging in — a news site, a blog, a public "
            "forum. It will be fetched, hashed, timestamped and sealed as evidence, "
            "and nothing will be extracted from it: there is no parser for arbitrary "
            "HTML. Useful for preserving a page that may change or vanish. It will "
            "never produce a finding."
        ),
    ),
    Platform(
        key="facebook",
        label="Facebook — page",
        support=Support.NEEDS_ROUTE,
        note=(
            "Ready to collect, waiting on a provider. Add the pages now — they are "
            "stored, scheduled and will start the moment a route is configured. "
            "Facebook cannot be fetched anonymously (a login wall is what comes back, "
            "and this system does not circumvent access controls — V-6), so it goes "
            "through an authenticated provider instead: the Meta Content Library, or "
            "a licensed data vendor. Set ASIP_FACEBOOK_PROVIDER once one exists. "
            "Which route is open item O-03 — a commercial decision, and the one thing "
            "here that code cannot supply. Before applying to the Content Library, "
            "check whether raw posts may leave its environment: if they may not, they "
            "cannot be sealed as evidence, and this product's central claim does not "
            "hold for Facebook through that route."
        ),
    ),
    Platform(
        key="x",
        label="X / Twitter",
        support=Support.BLOCKED,
        note=(
            "Not reachable yet. Anonymous access is closed; the API is paid and "
            "tiered. Same decision as Facebook — see open item O-03."
        ),
    ),
    Platform(
        key="tiktok",
        label="TikTok",
        support=Support.BLOCKED,
        note=(
            "Not reachable yet. Content is rendered client-side and gated; the "
            "Research API is application-only. See open item O-03."
        ),
    ),
    Platform(
        key="telegram",
        label="Telegram — public channel",
        support=Support.EXTRACTS,
        note=(
            "Fully read. Give the channel's public preview URL — https://t.me/s/CHANNEL — "
            "and posts, authors and second-precision timestamps are extracted. No login, "
            "no API key: this is the page Telegram itself serves publicly for the channel. "
            "One channel alone will not produce a finding, because one author is not a "
            "cluster; add several and the detector looks for them posting within seconds "
            "of each other, which is what coordinated amplification looks like from "
            "outside."
        ),
    ),
)

BY_KEY = {p.key: p for p in PLATFORMS}


def platform(key: str) -> Platform | None:
    return BY_KEY.get(key)


def is_known(key: str) -> bool:
    return key in BY_KEY


def extracts(key: str) -> bool:
    """True only when items will actually be produced.

    Used to decide what to tell someone adding a source. Never used to refuse
    one: see the module docstring on why an unparseable capture is still worth
    keeping.
    """
    entry = BY_KEY.get(key)
    return entry is not None and entry.support is Support.EXTRACTS
