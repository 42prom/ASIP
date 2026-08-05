"""V-7, D-49, D-50 — asserted against the model, not against one call site.

Two of these map to threats the register marks non-tradeable: T-002 (cross-
tenant leak) and T-003 (super-admin boundary failure). "Any change that weakens
them is vetoed regardless of business justification."

The tests are written over `ROLE_PERMISSIONS` and the type signatures rather
than over a handful of examples, so a role added next year is covered the day
it is added rather than the day someone remembers to write its test.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from asip.modules.identity.domain.roles import (
    DATA_PERMISSIONS,
    ROLE_PERMISSIONS,
    Decision,
    ElevatedGrant,
    Permission,
    Principal,
    Role,
    authorize,
)

NOW = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
TENANT_A = UUID("aaaaaaaa-0000-4000-8000-00000000000a")
TENANT_B = UUID("bbbbbbbb-0000-4000-8000-00000000000b")
PROJECT_1 = UUID("11111111-0000-4000-8000-000000000001")
PROJECT_2 = UUID("22222222-0000-4000-8000-000000000002")


def principal(
    role: Role,
    *,
    tenant: UUID = TENANT_A,
    projects: frozenset[UUID] = frozenset({PROJECT_1}),
    grants: tuple[ElevatedGrant, ...] = (),
) -> Principal:
    return Principal(uuid4(), tenant, frozenset({role}), projects, grants)


# ── D-50 / T-003: super_admin cannot read data ──────────────────────────────


def test_super_admin_holds_no_data_permission() -> None:
    """The counterintuitive one, and the point of D-50.

    An operator who *cannot* read client data cannot be compelled to, and
    cannot be suspected of having done so. It protects us as much as them.
    """
    overlap = ROLE_PERMISSIONS[Role.SUPER_ADMIN] & DATA_PERMISSIONS

    assert not overlap, (
        f"super_admin was granted {sorted(p.value for p in overlap)}. "
        "D-50: no tenant data access by default. Temporary access is a grant."
    )


def test_super_admin_is_denied_a_finding_in_its_own_tenant() -> None:
    decision = authorize(
        principal(Role.SUPER_ADMIN),
        Permission.READ_FINDINGS,
        tenant_id=TENANT_A,
        project_id=PROJECT_1,
        now=NOW,
    )

    assert not decision
    assert "not granted" in decision.reason


def test_auditor_reads_the_log_and_never_the_data() -> None:
    """The one role whose value depends on not seeing what it audits."""
    auditor = ROLE_PERMISSIONS[Role.AUDITOR]

    assert auditor == frozenset({Permission.READ_AUDIT})
    assert not (auditor & DATA_PERMISSIONS)


def test_no_role_holds_every_permission() -> None:
    """The shape "see everything" would take if someone built it by accretion."""
    everything = set(Permission)
    for role, granted in ROLE_PERMISSIONS.items():
        assert set(granted) != everything, f"{role.value} has become a superuser (V-7)"


def test_no_role_mixes_audit_reading_with_data_reading() -> None:
    """T-009. Whoever watches the watchers must not also be the watched.

    A role that could read data *and* the audit log could read a tenant's
    findings and then read its own trail to see whether anyone noticed.
    """
    for role, granted in ROLE_PERMISSIONS.items():
        if Permission.READ_AUDIT in granted:
            assert not (granted & DATA_PERMISSIONS), (
                f"{role.value} reads both the audit log and tenant data"
            )


# ── D-49 / T-007: compartmentalisation, and no wildcard ─────────────────────


def test_a_data_permission_without_a_project_is_denied() -> None:
    """Where "see everything" would live if it existed.

    There is no value of project_id meaning "all of them" — omitting it is a
    denial, never a widening.
    """
    decision = authorize(
        principal(Role.ANALYST), Permission.READ_FINDINGS, tenant_id=TENANT_A, now=NOW
    )

    assert not decision
    assert "see everything" in decision.reason


def test_an_analyst_is_denied_a_project_they_are_not_assigned_to() -> None:
    decision = authorize(
        principal(Role.ANALYST, projects=frozenset({PROJECT_1})),
        Permission.READ_FINDINGS,
        tenant_id=TENANT_A,
        project_id=PROJECT_2,
        now=NOW,
    )

    assert not decision
    assert str(PROJECT_2) in decision.reason


def test_an_analyst_reads_an_assigned_project() -> None:
    assert authorize(
        principal(Role.ANALYST),
        Permission.READ_FINDINGS,
        tenant_id=TENANT_A,
        project_id=PROJECT_1,
        now=NOW,
    )


def test_project_scope_cannot_express_a_wildcard() -> None:
    """Structural, not behavioural.

    `project_ids` is a frozenset of UUIDs. A string wildcard cannot be a member
    of it in any way the rest of the code would honour — and an empty set means
    "no projects", never "all projects".
    """
    empty = Principal(uuid4(), TENANT_A, frozenset({Role.ANALYST}), frozenset())

    decision = authorize(
        empty, Permission.READ_FINDINGS, tenant_id=TENANT_A, project_id=PROJECT_1, now=NOW
    )

    assert not decision, "an unassigned analyst read a project"


def test_every_data_permission_is_compartmentalised() -> None:
    """Written over DATA_PERMISSIONS so a new one is covered when it is added.

    The failure this prevents: someone adds READ_TIMELINE, forgets to put it in
    DATA_PERMISSIONS, and it becomes readable tenant-wide with no project check
    and no test to notice.
    """
    holder = Principal(
        uuid4(),
        TENANT_A,
        frozenset(Role),  # every role at once — still must not bypass scoping
        frozenset({PROJECT_1}),
    )

    for permission in DATA_PERMISSIONS:
        decision = authorize(holder, permission, tenant_id=TENANT_A, now=NOW)
        assert not decision, f"{permission.value} was allowed with no project scope"


def test_holding_every_role_still_does_not_see_another_project() -> None:
    holder = Principal(uuid4(), TENANT_A, frozenset(Role), frozenset({PROJECT_1}))

    assert not authorize(
        holder, Permission.READ_FINDINGS, tenant_id=TENANT_A, project_id=PROJECT_2, now=NOW
    )


# ── D-47 / T-002: the tenant boundary ───────────────────────────────────────


def test_a_user_cannot_read_another_tenant() -> None:
    decision = authorize(
        principal(Role.ANALYST, tenant=TENANT_A),
        Permission.READ_FINDINGS,
        tenant_id=TENANT_B,
        project_id=PROJECT_1,
        now=NOW,
    )

    assert not decision
    assert str(TENANT_B) in decision.reason


def test_crossing_tenants_needs_a_grant_naming_that_tenant() -> None:
    """A grant for tenant B does not open tenant C."""
    grant = ElevatedGrant(
        tenant_id=TENANT_B,
        permissions=frozenset({Permission.MANAGE_USERS}),
        justification="incident 4412: locked-out tenant admin",
        granted_by=uuid4(),
        expires_at=NOW + timedelta(hours=1),
    )
    actor = principal(Role.SUPER_ADMIN, grants=(grant,))

    assert authorize(actor, Permission.MANAGE_USERS, tenant_id=TENANT_B, now=NOW)
    assert not authorize(actor, Permission.MANAGE_USERS, tenant_id=UUID(int=99), now=NOW), (
        "a grant for one tenant opened another"
    )


# ── D-50: temporary means temporary ─────────────────────────────────────────


def test_an_expired_grant_grants_nothing() -> None:
    """The 2am emergency grant nobody revoked."""
    grant = ElevatedGrant(
        tenant_id=TENANT_B,
        permissions=frozenset({Permission.MANAGE_USERS}),
        justification="incident 4412",
        granted_by=uuid4(),
        expires_at=NOW - timedelta(seconds=1),
    )

    assert not authorize(
        principal(Role.SUPER_ADMIN, grants=(grant,)),
        Permission.MANAGE_USERS,
        tenant_id=TENANT_B,
        now=NOW,
    )


def test_a_grant_cannot_be_created_without_an_expiry() -> None:
    """Structural. `expires_at` has no default, so a permanent grant is not a
    thing this type can hold."""
    with pytest.raises(TypeError):
        ElevatedGrant(  # type: ignore[call-arg]
            tenant_id=TENANT_B,
            permissions=frozenset({Permission.MANAGE_USERS}),
            justification="forever",
            granted_by=uuid4(),
        )


def test_a_grant_does_not_bypass_project_scoping() -> None:
    """Elevation crosses the tenant boundary; it does not dissolve D-49.

    Otherwise every grant would be a temporary "see everything", which is the
    permission that does not exist.
    """
    grant = ElevatedGrant(
        tenant_id=TENANT_B,
        permissions=frozenset({Permission.READ_FINDINGS}),
        justification="incident 4412",
        granted_by=uuid4(),
        expires_at=NOW + timedelta(hours=1),
    )

    assert not authorize(
        principal(Role.SUPER_ADMIN, grants=(grant,)),
        Permission.READ_FINDINGS,
        tenant_id=TENANT_B,
        now=NOW,
    ), "a grant allowed a tenant-wide read with no project"


# ── the decision itself ─────────────────────────────────────────────────────


def test_a_denial_always_explains_itself() -> None:
    """A denial that cannot explain itself becomes a support ticket, and the
    fastest way to close a support ticket is to widen a permission."""
    denials = [
        authorize(
            principal(Role.READ_ONLY), Permission.MANAGE_TENANTS, tenant_id=TENANT_A, now=NOW
        ),
        authorize(principal(Role.ANALYST), Permission.READ_FINDINGS, tenant_id=TENANT_A, now=NOW),
        authorize(
            principal(Role.ANALYST),
            Permission.READ_FINDINGS,
            tenant_id=TENANT_B,
            project_id=PROJECT_1,
            now=NOW,
        ),
    ]

    for decision in denials:
        assert not decision
        assert len(decision.reason) > 40, f"unhelpful denial: {decision.reason!r}"


def test_a_decision_is_falsy_when_denied() -> None:
    """`if not authorize(...)` must do the obvious thing.

    A truthy object returned from a denied check is how authorization bypasses
    get written by accident.
    """
    assert not bool(Decision(False, "no"))
    assert bool(Decision(True, "yes"))
