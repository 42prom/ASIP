"""L3 — acquiring Facebook pages, whichever route is chosen.

WHY THIS FILE EXISTS BEFORE ANY ROUTE IS DECIDED

Facebook cannot be fetched the way a public web page is fetched. An anonymous
GET returns a login wall, and going around one is V-6 — not a limitation of
this implementation but a line the project does not cross.

Every route that CAN work is an authenticated API returning JSON, not an HTTP
page returning HTML:

  Meta Content Library   free, application through ICPSR, institutional
                         affiliation required. See the warning below before
                         committing to it.
  Licensed provider      Bright Data, Datastreamer, and the vendors that
                         replaced CrowdTangle. Works immediately, priced per
                         record. SPIKE_0 asks for exactly this quote (N4).
  Graph API              only for Pages you own or that grant you access.
                         Useless for observing anyone adversarial, which is the
                         entire use case.

That is a commercial decision (O-03), and it is not one this code can make. But
the SHAPE of all three is the same — credentials in, normalised posts out — so
the socket can exist now and the plug can arrive later. That is principle 5 in
the project's own terms: provider-agnostic interfaces over vendor lock-in, and
principle 9: minimise future migration cost even at small cost now.

⚠ THE MCL CLEAN-ROOM PROBLEM, RECORDED WHERE IT WILL BE READ

Meta Content Library is often accessed through a clean room where raw data may
not leave Meta's environment. If that applies, it is incompatible with this
product's central claim: ASIP's value is that it hashes the bytes, seals them
under RFC 3161, and hands a recipient a bundle they can verify without trusting
us. Data that cannot be exported cannot be sealed.

So the question to settle BEFORE applying is not "can I get the data" but
**"can I retain the raw post and hand it to a client"**. If the answer is no,
MCL is usable for research and not for ASIP, and a licensed provider is the
only route that preserves the evidence model.

WHAT THIS DOES TODAY

Refuses clearly. A Facebook source can be added, stored and scheduled right
now; when the pipeline reaches it, this reports that no route is configured and
says which environment variable would change that. It does not fetch a login
wall and call it evidence, and it does not fail silently — a source that
collects nothing while appearing healthy is the D-87 failure this project
treats as primary.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Protocol

from asip.modules.collection.adapters.http_fetcher import STATUS_OK, FetchOutcome

#: Which provider supplies Facebook data. Configuration, never code: switching
#: providers must not require an edit to anything but this value and the one
#: adapter behind it.
PROVIDER_ENV = "ASIP_FACEBOOK_PROVIDER"

#: Status used when no route is configured. Distinct from a network failure —
#: nothing was attempted, so retrying changes nothing and the operator needs a
#: decision rather than a retry.
STATUS_NOT_CONFIGURED = "failed_not_configured"


@dataclass(frozen=True, slots=True)
class NormalisedPost:
    """One post, in ASIP's shape rather than any provider's.

    Every provider is normalised into this before anything downstream sees it,
    so the extractor and the detector never learn which vendor supplied the
    data. Changing provider then changes one adapter, not the pipeline — and a
    finding built from Bright Data is byte-identical in structure to one built
    from the Content Library, which matters when a client switches and expects
    their history to remain comparable.
    """

    external_id: str
    page_handle: str
    page_name: str
    text: str
    #: The platform's own timestamp, ISO 8601. Kept as the provider gave it —
    #: D-100 says the raw string is preserved and the derived UTC value is what
    #: clustering uses, and a provider that reports whole minutes must not be
    #: silently upgraded to seconds (D-102).
    posted_at_raw: str
    permalink: str


class FacebookProvider(Protocol):
    """What a route must offer. Deliberately tiny.

    One method, because the only thing the pipeline needs is posts for a page.
    A wide interface here would encode one vendor's capabilities and make the
    next one a bad fit.
    """

    @property
    def name(self) -> str: ...

    def fetch_page(self, page_handle: str, limit: int) -> list[NormalisedPost]: ...


class NoProviderConfigured:
    """The default. Refuses, and says what would change that.

    Not an error class and not a silent no-op. It produces an ordinary failed
    outcome carrying an actionable reason, so the source shows as failing for a
    stated cause rather than sitting healthy and empty.
    """

    name = "none"

    def fetch_page(self, page_handle: str, limit: int) -> list[NormalisedPost]:
        raise NotConfigured(
            f"No Facebook acquisition route is configured, so {page_handle} cannot be "
            f"collected. Set {PROVIDER_ENV} once a route exists (open item O-03). "
            "Anonymous fetching is not an option: Facebook returns a login wall, and "
            "this system does not circumvent access controls (V-6)."
        )


class NotConfigured(RuntimeError):
    """No route exists yet. A decision, not a fault."""


def _graph_provider() -> type:
    """Imported on use, not at module load.

    Keeps `none` — the default for every deployment without a credential —
    from paying for a module it will not call, and keeps this file free of a
    top-level dependency on a specific vendor.
    """
    from asip.modules.collection.adapters.facebook_graph import GraphApiProvider

    return GraphApiProvider


#: Providers by name. A new route is one entry and one class implementing the
#: Protocol above — the pipeline, the extractor and the evidence path are
#: untouched by adding one.
#:
#: `graph` is Facebook's own API and reads pages the token is authorised for.
#: A licensed vendor lands here as one more entry when O-03 closes.
PROVIDER_FACTORIES: dict[str, Any] = {
    NoProviderConfigured.name: lambda: NoProviderConfigured,
    "graph": _graph_provider,
}

#: Kept for callers that only need the names.
PROVIDERS = PROVIDER_FACTORIES


def configured_provider() -> FacebookProvider:
    """The provider this deployment is configured for.

    An unknown name is refused rather than falling back to `none`, because
    falling back would turn a typo in a deployment variable into a system that
    quietly collects nothing.
    """
    name = os.environ.get(PROVIDER_ENV, NoProviderConfigured.name).strip().lower()
    factory = PROVIDER_FACTORIES.get(name)
    if factory is None:
        known = ", ".join(sorted(PROVIDER_FACTORIES))
        raise NotConfigured(f"{PROVIDER_ENV}={name!r} is not a known provider. Known: {known}")
    return factory()()


class FacebookAcquisition:
    """Turns a Facebook page URL into the same outcome shape an HTTP fetch produces.

    Same shape on purpose. The pipeline seals, extracts and detects identically
    whether bytes arrived over HTTP or over an API, so switching a source from
    one to the other changes nothing downstream — including the evidence path,
    which must treat both as equally sealable.

    Holds no database access, exactly like HttpFetcher: whatever the route, the
    thing that talks to the outside world never holds a database credential
    (V-3, D-46).
    """

    def __init__(self, provider: FacebookProvider | None = None, limit: int = 50) -> None:
        self._provider = provider
        self._limit = limit

    def fetch(self, url: str) -> FetchOutcome:
        handle = page_handle_from(url)
        try:
            provider = self._provider or configured_provider()
            posts = provider.fetch_page(handle, self._limit)
        except NotConfigured as refusal:
            return FetchOutcome(
                url=url,
                status=STATUS_NOT_CONFIGURED,
                body=b"",
                content_type="",
                http_status=None,
                bytes_fetched=0,
                failure_reason=str(refusal),
            )

        body = serialise(posts)
        return FetchOutcome(
            url=url,
            status=STATUS_OK,
            body=body,
            content_type="application/vnd.asip.facebook+json",
            http_status=200,
            bytes_fetched=len(body),
        )


def page_handle_from(url: str) -> str:
    """The page's own name, from any of the ways people write a Facebook URL."""
    value = url.strip().rstrip("/").lstrip("@")

    # Scheme first, then host. The first version enumerated scheme+host pairs
    # and missed http://m.facebook.com/, which then parsed as the handle
    # "http:" — a source that would have been created, scheduled, and quietly
    # collected nothing.
    for scheme in ("https://", "http://"):
        if value.startswith(scheme):
            value = value[len(scheme) :]
            break

    for host in ("www.facebook.com/", "m.facebook.com/", "mbasic.facebook.com/", "facebook.com/"):
        if value.startswith(host):
            value = value[len(host) :]
            break

    return value.split("?")[0].split("/")[0]


def serialise(posts: list[NormalisedPost]) -> bytes:
    """The bytes that get sealed as evidence.

    JSON rather than the provider's raw response, and that is a deliberate
    trade. The raw response would be the most faithful record, but it embeds a
    vendor's schema in every bundle we ever hand a recipient — and a recipient
    verifying a five-year-old bundle should not need to know which vendor was
    under contract that year (principle 8).

    Sorted keys and a stable separator so the same posts always produce the
    same bytes, and therefore the same hash. A bundle whose digest changed
    because a dict iterated differently would be unverifiable for no reason.
    """
    import json

    return json.dumps(
        {
            "schema": "asip.facebook.v1",
            "posts": [
                {
                    "external_id": p.external_id,
                    "page_handle": p.page_handle,
                    "page_name": p.page_name,
                    "text": p.text,
                    "posted_at_raw": p.posted_at_raw,
                    "permalink": p.permalink,
                }
                for p in posts
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
