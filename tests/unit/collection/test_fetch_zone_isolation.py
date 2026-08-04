"""V-3 and V-6, asserted rather than promised.

The fetch zone holds no database credentials and cannot reach the core
database. That is an absolute veto, and a comment saying so is not enforcement
— this file inspects what the fetcher can actually be constructed with, so
adding a repository or a DSN to it fails a test rather than passing review.

V-6 is checked the same way: the module must not contain the machinery of
defeating bot detection. A grep is a blunt instrument, but the failure mode it
guards against is someone adding "just a small user-agent rotation" without
anyone noticing, and it catches exactly that.
"""

from __future__ import annotations

import inspect

from asip.modules.collection.adapters import http_fetcher
from asip.modules.collection.adapters.http_fetcher import HttpFetcher

#: Anything that would give the fetch zone a route to the core database.
DATABASE_WORDS = ("conn", "dsn", "database", "repository", "repo", "psycopg", "session")


def test_the_fetcher_cannot_be_given_database_access() -> None:
    """V-3. Checked against the constructor's real signature."""
    parameters = inspect.signature(HttpFetcher.__init__).parameters
    offenders = [
        name for name in parameters if any(word in name.lower() for word in DATABASE_WORDS)
    ]
    assert not offenders, (
        f"HttpFetcher accepts {offenders}, which would give the fetch zone a path to "
        "the core database. V-3 is absolute: the fetch zone takes jobs from a queue "
        "and writes to object storage, and holds no database credential of any kind."
    )


def test_the_fetch_module_imports_no_database_library() -> None:
    source = inspect.getsource(http_fetcher)
    for forbidden in ("import psycopg", "from psycopg", "import boto3", "import sqlalchemy"):
        assert forbidden not in source, f"fetch zone imports {forbidden!r} — V-3"


def test_the_fetcher_holds_no_database_attribute_after_construction() -> None:
    """Constructed with defaults, it must carry nothing that could reach a database."""
    fetcher = HttpFetcher()
    for attribute, value in vars(fetcher).items():
        assert not any(word in attribute.lower() for word in DATABASE_WORDS), attribute
        assert not hasattr(value, "cursor"), f"{attribute} looks like a database connection"


def test_the_user_agent_names_the_project() -> None:
    """V-6. A fetcher that hides what it is has started down the wrong road."""
    assert "ASIP" in http_fetcher.DEFAULT_USER_AGENT
    assert "http" in http_fetcher.DEFAULT_USER_AGENT


def test_no_evasion_machinery_is_present() -> None:
    """V-6. Reliability stops at retries, backoff and honest rate limiting."""
    source = inspect.getsource(http_fetcher).lower()
    for banned in (
        "user_agents = [",  # rotation
        "random.choice",  # randomised fingerprints
        "ja3",  # TLS fingerprint mimicry
        "undetected",  # the usual library names
        "cloudscraper",
        "captcha",
    ):
        assert banned not in source, (
            f"{banned!r} appears in the fetch zone. V-6 forbids code whose purpose is "
            "defeating bot detection or access controls."
        )


def test_declined_responses_are_not_retried() -> None:
    """A source that says no is not asked again in a tighter loop.

    401, 403 and 429 are answers. Retrying them is both rude and the first step
    toward the behaviour V-6 exists to keep out of this codebase.
    """
    source = inspect.getsource(http_fetcher)
    assert "STATUS_BLOCKED" in source
    assert "exc.code in (401, 403, 429)" in source
