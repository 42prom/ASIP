"""L4 — authentication for the API. Default deny, by path.

THE IMPORTANT DESIGN CHOICE IS THAT THIS IS NOT A DECORATOR

Guarding endpoints one at a time means a new endpoint is unguarded until
somebody remembers, and an unguarded endpoint looks exactly like a working one.
There is no test that fails, no error in a log, nothing to notice — until the
day someone notices.

So the middleware refuses every `/api/` request that has no valid session, and
the exceptions are an explicit allowlist in this file. Adding an endpoint makes
it private automatically; making one public is a visible edit to a list of paths
whose entries each carry a reason.

That is the same shape as the fetch zone (V-3) and the export boundary (M-06):
the safe outcome is the default, and the unsafe one costs a deliberate act.

AUTHENTICATION IS NOT AUTHORIZATION
This establishes *who* is asking and sets the tenant for the request. Whether
they may read a particular thing is decided per handler by the Guard, which
also writes the audit entry (D-52). A request that gets past this middleware has
proved it is somebody — nothing more.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID

import psycopg
from fastapi import Request
from fastapi.responses import JSONResponse

from asip.modules.identity.adapters.postgres_repository import PostgresIdentityRepository
from asip.modules.identity.application.authenticate import Authenticate
from asip.modules.identity.application.guard import Guard
from asip.modules.identity.domain.roles import Principal

#: Paths reachable without a session. Each needs a reason, because each is a
#: hole in the default.
PUBLIC_PATHS = frozenset(
    {
        # You cannot present a session before you have one.
        "/api/auth/login",
        # Liveness for a load balancer and the operator's first question when
        # something is wrong. Reports component status only — no tenant data,
        # no counts of anyone's findings.
        "/api/health",
        # FastAPI's own schema. Describes shapes, not data.
        "/api/docs",
        "/api/openapi.json",
    }
)

#: Cookie name for the browser console. The token is also accepted as a bearer
#: header so the API is usable without a browser.
SESSION_COOKIE = "asip_session"


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


def dsn() -> str:
    return os.environ.get("ASIP_DB_URL", "postgresql://asip:asip_dev_only@127.0.0.1:5432/asip")


def owner_connection() -> psycopg.Connection:
    """A connection with no tenant adopted yet.

    Resolving a session token is the one operation that cannot know its tenant
    in advance — finding out is the point of it. So this runs before the tenant
    GUC is set, reads one row by unique digest, and is used for nothing else.
    """
    return psycopg.connect(dsn())


def tenant_connection(tenant_id: UUID) -> psycopg.Connection:
    """A connection scoped to one tenant, as the application role.

    SET ROLE and the GUC are set per request rather than per process, because a
    tenant id that outlived its request would be a cross-tenant read that no
    policy could catch (V-7).
    """
    conn = psycopg.connect(dsn())
    with conn.cursor() as cur:
        cur.execute("SET ROLE asip_app")
        cur.execute("SELECT set_config('asip.tenant_id', %s, false)", (str(tenant_id),))
    return conn


def authenticator(conn: psycopg.Connection) -> Authenticate:
    return Authenticate(PostgresIdentityRepository(conn), SystemClock())


class CommittingAuditStore:
    """Writes each audit entry in its own transaction, on its own connection.

    THE BUG THIS EXISTS TO FIX, FOUND BY RUNNING IT

    The obvious wiring gives the Guard the request's connection. Allowed reads
    are then recorded correctly and **denials are not recorded at all**: a
    denial raises, the request transaction rolls back, and the audit entry —
    written moments earlier on that same connection — rolls back with it.

    Observed live before the fix: seven allowed reads in the log, zero denials,
    while the API had returned an audit entry id with each 403. The log was
    quietly a log of successes, which is exactly the failure D-52 and T-007
    exist to prevent. A denial is the more interesting record; it is what shows
    someone probing for what they may not see.

    An audit entry records that a decision was made. That is true whether or
    not the request went on to succeed, so it must not share the request's
    fate. Same reasoning as the scheduler committing its run row before doing
    any work.

    Cost: one extra connection per guarded request. Worth naming rather than
    hiding — a pool belongs here before this serves real traffic.
    """

    def __init__(self, tenant_id: UUID) -> None:
        self._tenant_id = tenant_id

    def _connect(self) -> psycopg.Connection:
        conn = psycopg.connect(dsn(), autocommit=True)
        with conn.cursor() as cur:
            cur.execute("SET ROLE asip_app")
            cur.execute("SELECT set_config('asip.tenant_id', %s, false)", (str(self._tenant_id),))
        return conn

    def audit_head(self, tenant_id: UUID):  # type: ignore[no-untyped-def]
        with self._connect() as conn:
            return PostgresIdentityRepository(conn).audit_head(tenant_id)

    def append_audit(self, entry) -> None:  # type: ignore[no-untyped-def]
        with self._connect() as conn:
            PostgresIdentityRepository(conn).append_audit(entry)


def guard(tenant_id: UUID) -> Guard:
    """A Guard whose writes survive the request being refused.

    Takes a tenant rather than a connection precisely so it cannot be handed
    the request's transaction by accident — the mistake above is not available
    to a caller of this function.
    """
    return Guard(CommittingAuditStore(tenant_id), SystemClock())


def token_from(request: Request) -> str:
    """Cookie first, then Authorization: Bearer.

    Both, because the console is a browser and the API should be usable from a
    terminal. Neither is trusted further than resolving to a stored digest.
    """
    cookie = request.cookies.get(SESSION_COOKIE)
    if cookie:
        return cookie
    header = request.headers.get("authorization", "")
    if header.lower().startswith("bearer "):
        return header[7:].strip()
    return ""


def is_public(path: str) -> bool:
    """Exact match, never a prefix.

    A prefix test would make `/api/health/../findings` public on any client that
    normalises differently from us, and "startswith" allowlists are a reliable
    source of exactly that class of bug.
    """
    return path.rstrip("/") in {p.rstrip("/") for p in PUBLIC_PATHS}


async def require_session(request: Request, call_next):  # type: ignore[no-untyped-def]
    """Reject anything under /api/ without a valid session.

    Non-API paths — the console's own HTML, CSS and JS, and the canary page —
    pass through. They contain no tenant data; the console is a shell that
    cannot render anything until its API calls succeed.
    """
    path = request.url.path

    if not path.startswith("/api/") or is_public(path):
        return await call_next(request)

    token = token_from(request)
    if not token:
        return JSONResponse(
            {"detail": "authentication required", "login": "/api/auth/login"},
            status_code=401,
        )

    with owner_connection() as conn:
        resolved = authenticator(conn).resolve(token)
        conn.commit()

    if resolved is None:
        # One answer for expired, revoked, unknown, and belonging-to-a-disabled
        # user. Distinguishing them tells an attacker which of their guesses was
        # closer, and tells a legitimate user nothing they can act on differently.
        return JSONResponse(
            {"detail": "session is not valid", "login": "/api/auth/login"},
            status_code=401,
        )

    principal, session_id = resolved
    request.state.principal = principal
    request.state.session_id = session_id
    return await call_next(request)


def principal_of(request: Request) -> Principal:
    """The authenticated principal. Present because the middleware ran.

    Raising rather than returning None: a handler that reached this point
    without a principal means the middleware was bypassed, and continuing with
    a default would turn a routing mistake into an authorization bypass.
    """
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise RuntimeError(
            "no principal on the request. This endpoint is under /api/ but the "
            "session middleware did not run — check PUBLIC_PATHS in auth.py."
        )
    return principal
