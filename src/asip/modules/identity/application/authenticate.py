"""L2 — logging in, resolving a session, logging out.

Three things this gets deliberately right, all of them boring and all of them
the usual sources of authentication bugs:

  * A wrong password and an unknown user produce the *same* answer, and both
    pay the same hashing cost. Returning early on an unknown address turns the
    login form into an oracle for which addresses are registered — and the
    timing difference alone is enough even if the message is identical.

  * The session token is returned once and never stored. Only its SHA-256 goes
    to the database, so a leaked dump yields no usable session.

  * The principal is loaded from storage on every request, never carried in the
    token. Revoking a role or a project assignment then takes effect on the
    next request rather than whenever the token happens to expire.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Protocol
from uuid import UUID

from asip.modules.identity.domain.passwords import (
    hash_password,
    needs_rehash,
    new_session_token,
    token_fingerprint,
    verify_password,
)
from asip.modules.identity.domain.roles import Principal

#: Eight hours. Long enough for a working day, short enough that a forgotten
#: browser on a shared machine is not a standing grant.
DEFAULT_SESSION_LIFETIME = timedelta(hours=8)

#: Hashed when no user matches, so an unknown address costs the same as a wrong
#: password. The value is irrelevant; only the work matters.
_DUMMY_HASH = hash_password("timing-equalisation-placeholder", n=16384, r=8, p=1)


class IdentityStore(Protocol):
    def credentials_for(self, tenant_id: UUID, email: str) -> dict[str, Any] | None: ...

    def update_password_hash(self, tenant_id: UUID, user_id: UUID, password_hash: str) -> None: ...

    def record_login(self, tenant_id: UUID, user_id: UUID, moment: datetime) -> None: ...

    def load_principal(self, tenant_id: UUID, user_id: UUID, now: datetime) -> Principal | None: ...

    def open_session(
        self,
        session_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        token_sha256: str,
        expires_at: datetime,
    ) -> None: ...

    def session_for(self, token_sha256: str, now: datetime) -> dict[str, Any] | None: ...

    def touch_session(self, tenant_id: UUID, session_id: UUID, moment: datetime) -> None: ...

    def revoke_session(self, tenant_id: UUID, session_id: UUID, moment: datetime) -> None: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class AuthenticationFailed(Exception):
    """Wrong credentials, unknown user, or a disabled account.

    One exception for all three on purpose. Distinguishing them in the response
    tells an attacker which half of the guess was right.
    """


@dataclass(frozen=True, slots=True)
class Session:
    session_id: UUID
    tenant_id: UUID
    user_id: UUID
    #: Returned once, at login. Never stored, never retrievable again.
    token: str
    expires_at: datetime


class Authenticate:
    def __init__(
        self,
        store: IdentityStore,
        clock: Clock,
        lifetime: timedelta = DEFAULT_SESSION_LIFETIME,
    ) -> None:
        self._store = store
        self._clock = clock
        self._lifetime = lifetime

    def login(self, tenant_id: UUID, email: str, password: str) -> Session:
        now = self._clock.now()
        record = self._store.credentials_for(tenant_id, email)

        # Same work whether or not the user exists. `verify_password` on the
        # dummy hash costs what a real check costs, so the response time does
        # not answer "is this address registered".
        stored = record["password_hash"] if record else _DUMMY_HASH
        matched = verify_password(password, stored)

        if not record or not matched:
            raise AuthenticationFailed("email or password is incorrect")

        user_id: UUID = record["user_id"]

        # The plaintext is legitimately in hand exactly here, which is the only
        # moment a stronger KDF cost can be applied without a password reset.
        if needs_rehash(stored):
            self._store.update_password_hash(tenant_id, user_id, hash_password(password))

        token = new_session_token()
        session_id = uuid.uuid4()
        expires_at = now + self._lifetime

        self._store.open_session(
            session_id, tenant_id, user_id, token_fingerprint(token), expires_at
        )
        self._store.record_login(tenant_id, user_id, now)

        return Session(session_id, tenant_id, user_id, token, expires_at)

    def resolve(self, token: str) -> tuple[Principal, UUID] | None:
        """Turn a bearer token into a principal and its session id.

        Returns None for anything wrong — expired, revoked, unknown, or
        belonging to a user who has since been disabled. The caller gets one
        answer to act on rather than a taxonomy of failures to interpret.
        """
        if not token:
            return None

        now = self._clock.now()
        session = self._store.session_for(token_fingerprint(token), now)
        if session is None:
            return None

        principal = self._store.load_principal(session["tenant_id"], session["user_id"], now)
        if principal is None:
            # The session is valid and the user is gone or disabled. Not an
            # error — a revocation that took effect, which is the behaviour
            # loading the principal per request exists to give.
            return None

        self._store.touch_session(session["tenant_id"], session["session_id"], now)
        return principal, session["session_id"]

    def logout(self, tenant_id: UUID, session_id: UUID) -> None:
        self._store.revoke_session(tenant_id, session_id, self._clock.now())
