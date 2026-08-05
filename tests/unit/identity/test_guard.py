"""D-52 — the audit entry is not something a caller can forget to write.

The design claim under test: asking whether you may do something *is* recording
that you asked. If these were two functions, every endpoint would be one
forgotten line away from an unaudited read, and the forgotten line would be
invisible because the endpoint still works.
"""

from __future__ import annotations

import contextlib
import inspect
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest

from asip.modules.identity.application import guard as guard_module
from asip.modules.identity.application.guard import Guard, NotPermitted
from asip.modules.identity.domain.audit import AuditEntry, AuditOutcome, verify_chain
from asip.modules.identity.domain.roles import Permission, Principal, Role

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
TENANT_A = UUID("aaaaaaaa-0000-4000-8000-00000000000a")
TENANT_B = UUID("bbbbbbbb-0000-4000-8000-00000000000b")
PROJECT_1 = UUID("11111111-0000-4000-8000-000000000001")
PROJECT_2 = UUID("22222222-0000-4000-8000-000000000002")


class FakeStore:
    """An append-only store, because the real one grants no UPDATE or DELETE.

    If this fake offered a way to modify an entry it would be modelling a table
    that does not exist, and tests written against it would pass for code that
    cannot work in production.
    """

    def __init__(self) -> None:
        self.entries: list[AuditEntry] = []

    def audit_head(self, tenant_id: UUID) -> AuditEntry | None:
        owned = [e for e in self.entries if e.tenant_id == tenant_id]
        return owned[-1] if owned else None

    def append_audit(self, entry: AuditEntry) -> None:
        self.entries.append(entry)


class FixedClock:
    def now(self) -> datetime:
        return NOW


def analyst(projects: frozenset[UUID] = frozenset({PROJECT_1})) -> Principal:
    return Principal(uuid4(), TENANT_A, frozenset({Role.ANALYST}), projects)


def make() -> tuple[Guard, FakeStore]:
    store = FakeStore()
    return Guard(store, FixedClock()), store


# ── the entry is written either way ─────────────────────────────────────────


def test_an_allowed_read_is_recorded() -> None:
    guard, store = make()

    guard.check(
        analyst(),
        Permission.READ_FINDINGS,
        tenant_id=TENANT_A,
        resource_type="finding",
        resource_id="f-1",
        project_id=PROJECT_1,
    )

    assert len(store.entries) == 1
    assert store.entries[0].outcome is AuditOutcome.ALLOWED
    assert store.entries[0].action == "read_findings"


def test_a_denied_read_is_also_recorded() -> None:
    """T-007. A log of successes cannot show someone probing for what they are
    not allowed to see — the denials are the interesting rows."""
    guard, store = make()

    guard.check(
        analyst(),
        Permission.READ_FINDINGS,
        tenant_id=TENANT_A,
        resource_type="finding",
        resource_id="f-1",
        project_id=PROJECT_2,
    )

    assert len(store.entries) == 1
    assert store.entries[0].outcome is AuditOutcome.DENIED
    assert str(PROJECT_2) in store.entries[0].reason


def test_the_resource_that_was_asked_about_is_recorded() -> None:
    """ "Who looked at what" needs the what, or the log answers half the
    question (D-52)."""
    guard, store = make()

    guard.check(
        analyst(),
        Permission.READ_EVIDENCE,
        tenant_id=TENANT_A,
        resource_type="evidence_bundle",
        resource_id="bundle-42",
        project_id=PROJECT_1,
    )

    assert store.entries[0].resource_type == "evidence_bundle"
    assert store.entries[0].resource_id == "bundle-42"


def test_every_public_guard_method_writes_an_entry() -> None:
    """The design claim, exercised rather than grepped for.

    Discovered by introspection, so a `may_i()` added later — which would be
    used, because it is more convenient — is covered the day it appears rather
    than the day someone remembers. A new method with a different signature
    fails here too, which is the right outcome: it needs its own thinking.
    """
    public = [
        name
        for name, _ in inspect.getmembers(Guard, inspect.isfunction)
        if not name.startswith("_")
    ]
    assert public, "introspection found no public methods — the test is not testing"

    for name in public:
        guard, store = make()
        # Denied on purpose: `require` raises and `check` returns, and the
        # entry must be written either way.
        with contextlib.suppress(NotPermitted):
            getattr(guard, name)(
                analyst(),
                Permission.READ_FINDINGS,
                tenant_id=TENANT_A,
                resource_type="finding",
                resource_id="f-1",
                project_id=PROJECT_2,
            )

        assert len(store.entries) == 1, f"Guard.{name} decided without recording it (D-52)"


def test_the_guard_module_has_exactly_one_write_path() -> None:
    """Two append sites would eventually disagree about what gets recorded."""
    source = inspect.getsource(guard_module)
    calls = source.count("self._store.append_audit(")

    assert calls == 1, f"{calls} audit write paths in guard.py; there should be one"


# ── require() ───────────────────────────────────────────────────────────────


def test_require_raises_on_denial_and_still_records() -> None:
    guard, store = make()

    with pytest.raises(NotPermitted) as raised:
        guard.require(
            analyst(),
            Permission.READ_FINDINGS,
            tenant_id=TENANT_A,
            resource_type="finding",
            resource_id="f-1",
            project_id=PROJECT_2,
        )

    assert len(store.entries) == 1, "a raised denial must still be audited"
    assert raised.value.entry_id == store.entries[0].entry_id


def test_the_denial_names_the_entry_so_it_can_be_looked_up() -> None:
    """A user told "denied" and nothing else cannot be helped, and a support
    conversation that starts from a screenshot ends in a widened permission."""
    guard, _ = make()

    with pytest.raises(NotPermitted) as raised:
        guard.require(
            analyst(),
            Permission.MANAGE_TENANTS,
            tenant_id=TENANT_A,
            resource_type="tenant",
            resource_id=str(TENANT_A),
        )

    assert raised.value.entry_id is not None
    assert len(str(raised.value)) > 40


def test_require_returns_the_entry_when_allowed() -> None:
    guard, store = make()

    entry = guard.require(
        analyst(),
        Permission.READ_FINDINGS,
        tenant_id=TENANT_A,
        resource_type="finding",
        resource_id="f-1",
        project_id=PROJECT_1,
    )

    assert entry == store.entries[0]


# ── the chain ───────────────────────────────────────────────────────────────


def test_successive_checks_form_a_verifiable_chain() -> None:
    guard, store = make()
    actor = analyst()

    for n in range(5):
        guard.check(
            actor,
            Permission.READ_FINDINGS,
            tenant_id=TENANT_A,
            resource_type="finding",
            resource_id=f"f-{n}",
            project_id=PROJECT_1,
        )

    assert verify_chain(store.entries) == ()
    assert [e.chain_index for e in store.entries] == [0, 1, 2, 3, 4]


def test_the_entry_lands_on_the_actors_own_tenant_chain() -> None:
    """A cross-tenant attempt belongs in the record of the person who made it.

    Recording it only against the target tenant would let someone probe tenants
    they hold no grant for and leave no trace anywhere they are accountable.
    """
    guard, store = make()

    guard.check(
        analyst(),
        Permission.READ_FINDINGS,
        tenant_id=TENANT_B,
        resource_type="finding",
        resource_id="f-1",
        project_id=PROJECT_1,
    )

    assert store.entries[0].tenant_id == TENANT_A
    assert store.entries[0].outcome is AuditOutcome.DENIED


def test_two_tenants_keep_separate_chains() -> None:
    """Verifying tenant A's audit log must not require reading tenant B's."""
    guard, store = make()
    a = analyst()
    b = Principal(uuid4(), TENANT_B, frozenset({Role.ANALYST}), frozenset({PROJECT_1}))

    for actor in (a, b, a, b):
        guard.check(
            actor,
            Permission.READ_FINDINGS,
            tenant_id=actor.tenant_id,
            resource_type="finding",
            resource_id="f-1",
            project_id=PROJECT_1,
        )

    for tenant in (TENANT_A, TENANT_B):
        segment = [e for e in store.entries if e.tenant_id == tenant]
        assert [e.chain_index for e in segment] == [0, 1]
        assert verify_chain(segment) == ()
