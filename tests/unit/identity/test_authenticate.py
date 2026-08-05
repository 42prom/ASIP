"""Login, session resolution, logout.

Most of these are negative. A login that accepts the right password is easy;
one that leaks nothing on the wrong one, costs the same for an unknown address,
and stops working the moment a role is revoked is the part worth testing.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

import pytest

from asip.modules.identity.application.authenticate import (
    Authenticate,
    AuthenticationFailed,
)
from asip.modules.identity.domain.passwords import hash_password, token_fingerprint
from asip.modules.identity.domain.roles import Principal, Role

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
TENANT_A = UUID("aaaaaaaa-0000-4000-8000-00000000000a")
USER_A = UUID("11111111-0000-4000-8000-00000000000a")
PASSWORD = "correct horse battery staple"

FAST = {"n": 1024, "r": 8, "p": 1}


class MovableClock:
    def __init__(self) -> None:
        self.moment = NOW

    def now(self) -> datetime:
        return self.moment


class FakeStore:
    def __init__(self, *, disabled: bool = False, stored_hash: str | None = None) -> None:
        self.stored_hash = stored_hash or hash_password(PASSWORD, **FAST)
        self.disabled = disabled
        self.sessions: dict[str, dict[str, Any]] = {}
        self.revoked: list[UUID] = []
        self.logins: list[datetime] = []
        self.rehashed: list[str] = []
        self.touched: list[UUID] = []

    def credentials_for(self, tenant_id: UUID, email: str) -> dict[str, Any] | None:
        if self.disabled or email != "analyst@example.com":
            return None
        return {"user_id": USER_A, "password_hash": self.stored_hash}

    def update_password_hash(self, tenant_id: UUID, user_id: UUID, password_hash: str) -> None:
        self.stored_hash = password_hash
        self.rehashed.append(password_hash)

    def record_login(self, tenant_id: UUID, user_id: UUID, moment: datetime) -> None:
        self.logins.append(moment)

    def load_principal(self, tenant_id: UUID, user_id: UUID, now: datetime) -> Principal | None:
        if self.disabled:
            return None
        return Principal(user_id, tenant_id, frozenset({Role.ANALYST}), frozenset())

    def open_session(
        self,
        session_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        token_sha256: str,
        expires_at: datetime,
    ) -> None:
        self.sessions[token_sha256] = {
            "session_id": session_id,
            "tenant_id": tenant_id,
            "user_id": user_id,
            "expires_at": expires_at,
        }

    def session_for(self, token_sha256: str, now: datetime) -> dict[str, Any] | None:
        found = self.sessions.get(token_sha256)
        if found is None or found["session_id"] in self.revoked or found["expires_at"] <= now:
            return None
        return found

    def touch_session(self, tenant_id: UUID, session_id: UUID, moment: datetime) -> None:
        self.touched.append(session_id)

    def revoke_session(self, tenant_id: UUID, session_id: UUID, moment: datetime) -> None:
        self.revoked.append(session_id)


def make(**kwargs: Any) -> tuple[Authenticate, FakeStore, MovableClock]:
    store = FakeStore(**kwargs)
    clock = MovableClock()
    return Authenticate(store, clock), store, clock


# ── login ───────────────────────────────────────────────────────────────────


def test_the_right_password_opens_a_session() -> None:
    auth, store, _ = make()

    session = auth.login(TENANT_A, "analyst@example.com", PASSWORD)

    assert session.user_id == USER_A
    assert session.tenant_id == TENANT_A
    assert session.token
    assert store.logins == [NOW]


def test_the_wrong_password_is_refused() -> None:
    auth, _, _ = make()

    with pytest.raises(AuthenticationFailed):
        auth.login(TENANT_A, "analyst@example.com", "wrong")


def test_an_unknown_address_fails_with_the_same_message() -> None:
    """Distinguishing "no such user" from "wrong password" tells an attacker
    which half of the guess was right."""
    auth, _, _ = make()

    with pytest.raises(AuthenticationFailed) as unknown:
        auth.login(TENANT_A, "nobody@example.com", PASSWORD)
    with pytest.raises(AuthenticationFailed) as wrong:
        auth.login(TENANT_A, "analyst@example.com", "wrong")

    assert str(unknown.value) == str(wrong.value)


def test_an_unknown_address_still_pays_the_hashing_cost(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The message being identical is not enough — timing is an oracle too.

    A login that returns early for an unknown address answers "is this person
    registered here" in a few microseconds, which is a disclosure even when the
    error text is identical. Counted rather than timed: a wall-clock assertion
    would be flaky on shared CI and would not say *why* it failed.
    """
    from asip.modules.identity.application import authenticate

    calls: list[str] = []
    real = authenticate.verify_password

    def counting(password: str, stored: str) -> bool:
        calls.append(stored)
        return real(password, stored)

    monkeypatch.setattr(authenticate, "verify_password", counting)
    auth, _, _ = make()

    with pytest.raises(AuthenticationFailed):
        auth.login(TENANT_A, "nobody@example.com", PASSWORD)
    unknown_user_calls = len(calls)

    calls.clear()
    with pytest.raises(AuthenticationFailed):
        auth.login(TENANT_A, "analyst@example.com", "wrong")
    wrong_password_calls = len(calls)

    assert unknown_user_calls == wrong_password_calls == 1, (
        "an unknown address must do the same hashing work as a wrong password"
    )


def test_a_disabled_account_cannot_log_in() -> None:
    auth, _, _ = make(disabled=True)

    with pytest.raises(AuthenticationFailed):
        auth.login(TENANT_A, "analyst@example.com", PASSWORD)


def test_a_weak_stored_hash_is_upgraded_at_login() -> None:
    """The only moment the plaintext is legitimately in hand."""
    auth, store, _ = make(stored_hash=hash_password(PASSWORD, n=1024, r=8, p=1))

    auth.login(TENANT_A, "analyst@example.com", PASSWORD)

    assert store.rehashed, "a below-strength hash was left in place"
    assert store.rehashed[0].startswith("scrypt$n=16384")


# ── the token ───────────────────────────────────────────────────────────────


def test_only_the_fingerprint_is_stored() -> None:
    """A leaked dump must yield no usable session."""
    auth, store, _ = make()

    session = auth.login(TENANT_A, "analyst@example.com", PASSWORD)

    assert session.token not in store.sessions
    assert token_fingerprint(session.token) in store.sessions


def test_two_logins_produce_different_tokens() -> None:
    auth, _, _ = make()

    first = auth.login(TENANT_A, "analyst@example.com", PASSWORD)
    second = auth.login(TENANT_A, "analyst@example.com", PASSWORD)

    assert first.token != second.token


# ── resolve ─────────────────────────────────────────────────────────────────


def test_a_valid_token_resolves_to_a_principal() -> None:
    auth, _, _ = make()
    session = auth.login(TENANT_A, "analyst@example.com", PASSWORD)

    resolved = auth.resolve(session.token)

    assert resolved is not None
    principal, session_id = resolved
    assert principal.user_id == USER_A
    assert session_id == session.session_id


@pytest.mark.parametrize("token", ["", "not-a-token", "x" * 43])
def test_a_bad_token_resolves_to_nothing(token: str) -> None:
    auth, _, _ = make()
    assert auth.resolve(token) is None


def test_an_expired_session_resolves_to_nothing() -> None:
    auth, _, clock = make()
    session = auth.login(TENANT_A, "analyst@example.com", PASSWORD)

    clock.moment = NOW + timedelta(hours=9)

    assert auth.resolve(session.token) is None


def test_a_revoked_session_resolves_to_nothing() -> None:
    auth, _, _ = make()
    session = auth.login(TENANT_A, "analyst@example.com", PASSWORD)

    auth.logout(TENANT_A, session.session_id)

    assert auth.resolve(session.token) is None


def test_disabling_a_user_invalidates_a_live_session() -> None:
    """The principal is loaded per request, not carried in the token, so a
    revocation takes effect on the next request rather than at token expiry."""
    auth, store, _ = make()
    session = auth.login(TENANT_A, "analyst@example.com", PASSWORD)
    assert auth.resolve(session.token) is not None

    store.disabled = True

    assert auth.resolve(session.token) is None


def test_resolving_records_that_the_session_was_used() -> None:
    auth, store, _ = make()
    session = auth.login(TENANT_A, "analyst@example.com", PASSWORD)

    auth.resolve(session.token)

    assert store.touched == [session.session_id]
