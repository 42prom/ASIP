"""L3 — the fetch zone.

V-3 IS ENFORCED BY THIS CLASS'S CONSTRUCTOR
-------------------------------------------
``HttpFetcher.__init__`` takes a timeout, a user agent, and a byte cap. It
takes no connection, no DSN, no repository, and no credential of any kind. It
cannot reach the core database because it has never been given anything that
could. ``tests/unit/collection/test_fetch_zone_isolation.py`` asserts that by
inspecting the signature, so adding a database dependency here fails a test
rather than passing review.

D-11 puts the Fetch Fleet on its own network for the same reason at a different
layer. In development this runs in-process, which is a **known deviation**: the
process boundary is not yet there, only the credential boundary. The compose
file carries the network definition it will need. Recorded rather than glossed.

V-6 — RELIABILITY STOPS WHERE EVASION BEGINS
--------------------------------------------
What this does: an honest user agent naming the project, a request timeout,
bounded retries with backoff, a byte cap, and a delay between requests to the
same host.

What it does not do, and must not: rotate user agents, solve challenges, mimic
browser TLS fingerprints, evade rate limits, or work around any access control.
Those are the techniques of defeating bot detection, and V-6 forbids them
outright. If a source cannot be collected honestly, the correct outcome is a
recorded failure and a conversation about authorisation — not a cleverer
fetcher.
"""

from __future__ import annotations

import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from urllib.parse import urlparse
from urllib.robotparser import RobotFileParser

#: Names the project and points at it. A fetcher that hides what it is has
#: already started down the road V-6 closes.
DEFAULT_USER_AGENT = "ASIP/0.1 (+https://github.com/42prom/ASIP) research collection"

#: Failure taxonomy (D-113). A failure we caused and a failure the source caused
#: need different responses, and one "failed" value hides a broken fetcher.
STATUS_OK = "succeeded"
STATUS_NETWORK = "failed_network"
STATUS_TIMEOUT = "failed_timeout"
STATUS_BLOCKED = "failed_blocked"
STATUS_NOT_FOUND = "failed_not_found"
STATUS_INTERNAL = "failed_internal"


@dataclass(frozen=True, slots=True)
class FetchOutcome:
    """What one attempt produced. A failure is a result, not an exception."""

    url: str
    status: str
    body: bytes
    content_type: str
    http_status: int | None
    bytes_fetched: int
    failure_reason: str | None = None

    @property
    def succeeded(self) -> bool:
        return self.status == STATUS_OK


class HttpFetcher:
    """Fetches a URL over HTTP. Holds no database access, by construction."""

    def __init__(
        self,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout_seconds: float = 15.0,
        max_bytes: int = 8 * 1024 * 1024,
        max_attempts: int = 3,
        backoff_seconds: float = 1.0,
        respect_robots: bool = True,
    ) -> None:
        self._user_agent = user_agent
        self._timeout = timeout_seconds
        self._max_bytes = max_bytes
        self._max_attempts = max_attempts
        self._backoff = backoff_seconds
        self._respect_robots = respect_robots

    def fetch(self, url: str) -> FetchOutcome:
        """Fetch one URL, returning an outcome rather than raising.

        Retries only transient conditions. A 404 or a 403 is not retried: the
        answer will not change, and hammering a source that has told us no is
        both rude and the first step toward the behaviour V-6 forbids.
        """
        if self._respect_robots and not self._robots_allows(url):
            return FetchOutcome(
                url=url,
                status=STATUS_BLOCKED,
                body=b"",
                content_type="",
                http_status=None,
                bytes_fetched=0,
                failure_reason="robots.txt disallows this path for our user agent",
            )

        last: FetchOutcome | None = None
        for attempt in range(1, self._max_attempts + 1):
            last = self._attempt(url)
            if last.succeeded or last.status in (STATUS_NOT_FOUND, STATUS_BLOCKED):
                return last
            if attempt < self._max_attempts:
                time.sleep(self._backoff * attempt)

        assert last is not None
        return last

    def _attempt(self, url: str) -> FetchOutcome:
        request = urllib.request.Request(url, headers={"User-Agent": self._user_agent})
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                # Read one byte beyond the cap so an oversized page is detected
                # rather than silently truncated into a corrupt capture.
                body = response.read(self._max_bytes + 1)
                if len(body) > self._max_bytes:
                    return FetchOutcome(
                        url=url,
                        status=STATUS_INTERNAL,
                        body=b"",
                        content_type="",
                        http_status=response.status,
                        bytes_fetched=len(body),
                        failure_reason=f"response exceeded the {self._max_bytes} byte cap",
                    )
                return FetchOutcome(
                    url=url,
                    status=STATUS_OK,
                    body=body,
                    content_type=response.headers.get("Content-Type", ""),
                    http_status=response.status,
                    bytes_fetched=len(body),
                )
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                status, reason = STATUS_NOT_FOUND, "404 Not Found"
            elif exc.code in (401, 403, 429):
                # Explicitly not retried and explicitly not worked around.
                status, reason = STATUS_BLOCKED, f"{exc.code} — the source declined"
            else:
                status, reason = STATUS_NETWORK, f"HTTP {exc.code}"
            return FetchOutcome(url, status, b"", "", exc.code, 0, reason)
        except TimeoutError:
            return FetchOutcome(url, STATUS_TIMEOUT, b"", "", None, 0, "request timed out")
        except urllib.error.URLError as exc:
            return FetchOutcome(url, STATUS_NETWORK, b"", "", None, 0, str(exc.reason))
        except Exception as exc:
            return FetchOutcome(url, STATUS_INTERNAL, b"", "", None, 0, repr(exc))

    def _robots_allows(self, url: str) -> bool:
        """Ask robots.txt before fetching.

        A source that has published a rule about automated access has stated a
        preference, and honouring it is the difference between collection and
        the thing V-6 exists to keep out of this codebase. An unreachable or
        malformed robots.txt is treated as permission, which is the
        conventional reading — an absent rule is not a prohibition.
        """
        parts = urlparse(url)
        parser = RobotFileParser()
        parser.set_url(f"{parts.scheme}://{parts.netloc}/robots.txt")
        try:
            parser.read()
        except Exception:
            return True
        return parser.can_fetch(self._user_agent, url)
