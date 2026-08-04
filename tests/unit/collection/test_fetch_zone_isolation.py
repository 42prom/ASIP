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
from pathlib import Path

import pytest

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


# ─────────────────────────────────────────────────────────────────────────────
# The worker process, not just the fetcher class.
#
# The tests above prove HttpFetcher cannot be handed a database. These prove
# the process that runs it cannot reach one either — which is the difference
# between a careful constructor and an isolated zone (D-11).
# ─────────────────────────────────────────────────────────────────────────────


def transitive_imports(module_name: str) -> set[str]:
    """Every module reachable from one entrypoint, by walking the AST.

    Static rather than dynamic: importing the worker to inspect sys.modules
    would pull in whatever the test process already loaded, and the question is
    what the *worker* reaches, not what pytest has.
    """
    import ast

    root = Path(__file__).resolve().parents[3] / "src"
    seen: set[str] = set()
    queue = [module_name]

    while queue:
        name = queue.pop()
        if name in seen:
            continue
        seen.add(name)

        path = root / (name.replace(".", "/") + ".py")
        if not path.is_file():
            continue

        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    queue.append(alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module:
                queue.append(node.module)
    return seen


def test_the_worker_reaches_no_database_library() -> None:
    """V-3 by import graph.

    Walks everything the worker can reach and asserts no database driver is
    among it. Adding one — directly or through any module it imports — fails
    here rather than passing review.
    """
    reachable = transitive_imports("asip.entrypoints.fetch_worker")
    forbidden = {"psycopg", "psycopg2", "sqlalchemy", "asyncpg", "alembic"}
    found = {m for m in reachable if m.split(".")[0] in forbidden}
    assert not found, (
        f"the fetch worker can reach {sorted(found)}. V-3: the fetch zone holds no "
        "database credentials and cannot reach the core database."
    )


def test_the_worker_reaches_no_evidence_or_detection_module() -> None:
    """The fetch zone fetches. It does not seal, extract, or decide.

    Reaching into the evidence module from here would mean the fetch zone could
    write bundles, which is the core's job and needs the database it must not
    have.
    """
    reachable = transitive_imports("asip.entrypoints.fetch_worker")
    leaked = {
        m
        for m in reachable
        if m.startswith(
            (
                "asip.modules.detection",
                "asip.modules.extraction",
                "asip.modules.review",
                "asip.modules.export",
            )
        )
    }
    assert not leaked, f"the fetch zone reaches {sorted(leaked)}"


def test_the_worker_refuses_to_start_with_a_database_credential() -> None:
    """The likeliest way V-3 breaks is a shared env file, not malice.

    A leaked DSN in the fetch zone's environment is a configuration mistake
    that would otherwise be silent — the worker would run perfectly and the
    isolation would be gone.
    """
    from asip.entrypoints import fetch_worker

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("ASIP_DB_URL", "postgresql://someone@somewhere/asip")
        assert fetch_worker.main([]) == 2


def test_the_compose_fetch_network_excludes_postgres() -> None:
    """The routing fact, asserted against the file that establishes it."""
    compose = (Path(__file__).resolve().parents[3] / "docker-compose.yml").read_text(
        encoding="utf-8"
    )
    postgres_block = compose.split("  postgres:")[1].split("  redis:")[0]
    assert "fetch" not in postgres_block, (
        "postgres is attached to the fetch network. V-3: the fetch zone must have no "
        "route to the core database."
    )
    assert "networks: [fetch]" in compose, "the fetcher service is not isolated"
