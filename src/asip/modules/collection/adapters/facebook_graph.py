"""L3 — Facebook's own Graph API. The first route that actually works.

WHAT THIS COVERS AND WHAT IT DOES NOT

The Graph API reads a Page's posts with a Page access token. That means:

  ✅  pages the client owns or administers — brand monitoring, a ministry
      watching its own channels, a campaign watching its own accounts
  ✅  pages that have granted the app access
  ⚠️  arbitrary public pages, ONLY with Page Public Content Access, which
      requires App Review and is rarely granted now
  ❌  personal profiles. Not a limitation to work around: V-1 makes the cluster
      the unit of analysis and never a named natural person (T-013)

So this does not, on its own, solve adversarial monitoring — the case where you
watch pages that would never grant you anything. That still needs a licensed
provider, and the socket takes one without changing this file.

It is built first anyway, for three reasons. It is the only route that can be
implemented completely from public documentation without waiting on a contract.
It makes the whole Facebook path real end to end, so the day a provider arrives
the only new thing is one class. And "watch our own pages" is a product someone
will pay for on its own.

NO NEW DEPENDENCY

urllib, like the HTTP fetcher. The Facebook SDK would add a dependency to talk
to a documented REST endpoint returning JSON, and §3 wants a measured
constraint before that trade.

CREDENTIALS

A token, from the environment, never stored in the database and never logged.
This class holds no database access — same as every other acquirer, so a
compromise of the thing that talks to the outside world yields no tenants
(V-3, D-46). The token is not written into the sealed evidence either: what
gets sealed is the normalised post, and which credential fetched it is our
operational business, not a recipient's.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from asip.modules.collection.adapters.facebook_acquisition import (
    NormalisedPost,
    NotConfigured,
)

#: The token. Page access token or a user token with the right page scopes.
TOKEN_ENV = "ASIP_FACEBOOK_TOKEN"

#: Pinned rather than tracking "latest". Graph deprecates versions on a
#: schedule, and a silent upgrade changes response shapes under a running
#: collector — which would look like the pages changing rather than us.
API_VERSION = "v21.0"
GRAPH_HOST = "https://graph.facebook.com"

#: Exactly what is needed to build a NormalisedPost. Requesting more would put
#: fields into sealed evidence that nothing reads, and every extra field is
#: another thing a recipient must be told to ignore.
FIELDS = "id,message,story,created_time,permalink_url"

DEFAULT_TIMEOUT = 20.0


class GraphApiProvider:
    """Reads Page posts through the Graph API."""

    name = "graph"

    def __init__(
        self,
        token: str | None = None,
        *,
        transport: Any = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._token = token if token is not None else os.environ.get(TOKEN_ENV, "")
        # Injected so tests exercise the real parsing and error handling
        # without a network or a credential. A fake that replaced the whole
        # provider would test nothing that ships.
        self._transport = transport or _urllib_get
        self._timeout = timeout

    def fetch_page(self, page_handle: str, limit: int) -> list[NormalisedPost]:
        if not self._token:
            raise NotConfigured(
                f"{TOKEN_ENV} is not set, so {page_handle} cannot be read through the "
                "Graph API. A Page access token is needed, and it only reads pages the "
                "token is authorised for — owned, administered, or granted. Arbitrary "
                "public pages additionally need Page Public Content Access, which is "
                "granted by App Review (open item O-03)."
            )

        query = urllib.parse.urlencode(
            {"fields": FIELDS, "limit": str(limit), "access_token": self._token}
        )
        url = f"{GRAPH_HOST}/{API_VERSION}/{urllib.parse.quote(page_handle)}/posts?{query}"

        # Translation lives here, around the transport, not inside it. The
        # first version put it in the urllib function — which meant every
        # future transport would have to reimplement it, and no test could
        # reach it without a network. A seam that hides the logic it is meant
        # to expose is the wrong seam.
        try:
            payload = self._transport(url, self._timeout)
        except urllib.error.HTTPError as failure:
            raise _as_refusal(failure) from None
        except urllib.error.URLError as failure:
            # Genuinely transient, and distinct from a credential problem so a
            # retry policy can act on one and not the other (D-113).
            raise ConnectionError(f"could not reach the Graph API: {failure.reason}") from None

        return [post for raw in payload.get("data", []) if (post := _to_post(raw, page_handle))]


def _urllib_get(url: str, timeout: float) -> dict[str, Any]:
    """One GET. Raises urllib's own errors; the provider translates them."""
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _as_refusal(failure: urllib.error.HTTPError) -> NotConfigured:
    """Graph's error, turned into something an operator can act on.

    Graph reports almost everything as 400 with the real cause in the body, so
    the status alone says little. Surfacing the message matters: "the fetch
    failed" sends someone to look at the network, and the cause is usually a
    scope the token does not have.
    """
    detail = _graph_error(failure)
    if failure.code in (401, 403) or "OAuth" in detail or "access token" in detail:
        return NotConfigured(
            f"Facebook refused the token: {detail}. This is a credential or permission "
            "problem, not a transient one — retrying will not fix it. Check the token "
            f"has not expired and that it is authorised for this page ({TOKEN_ENV})."
        )
    return NotConfigured(f"Graph API returned {failure.code}: {detail}")


def _graph_error(failure: urllib.error.HTTPError) -> str:
    try:
        body = json.loads(failure.read().decode("utf-8"))
        error = body.get("error", {})
        return str(error.get("message") or body)
    except Exception:
        return failure.reason or "no detail"


def _to_post(raw: dict[str, Any], page_handle: str) -> NormalisedPost | None:
    """One Graph post, normalised. None when it carries nothing to analyse.

    A post with neither `message` nor `story` is a bare photo or a life event —
    there is no text to fingerprint and no timestamp claim worth keeping, and
    admitting it would put empty rows into the corpus that every later count
    has to explain.
    """
    external_id = str(raw.get("id", ""))
    created = str(raw.get("created_time", ""))
    if not external_id or not created:
        return None

    # `story` is Facebook's generated text ("X shared a link"). Kept when there
    # is no message, because a post that exists is an observation even when the
    # page wrote nothing — the behavioural path cares that it happened and when.
    text = str(raw.get("message") or raw.get("story") or "")
    if not text:
        return None

    return NormalisedPost(
        external_id=external_id,
        page_handle=page_handle,
        page_name=page_handle,
        text=text,
        # Graph returns ISO 8601 with an offset, e.g. 2026-08-04T09:12:04+0000.
        # Kept exactly as given (D-100) — the shared parser derives UTC and
        # detects precision, so a provider reporting whole minutes is never
        # silently upgraded to seconds.
        posted_at_raw=created,
        permalink=str(raw.get("permalink_url", "")),
    )
