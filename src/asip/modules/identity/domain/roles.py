"""L1 — who may do what, and to which rows.

The whole point of this file is that **"see everything" is not expressible**.
D-49 says it does not exist as a permission and V-7 makes adding one a veto.
Both are easy to state and easy to erode: a wildcard here, a `None` meaning
"all" there, and six months later nobody can say what an analyst can read.

So the types refuse it:

  * `Scope.project_ids` is a `frozenset[UUID]`. There is no `"*"`, no `None`,
    no `all_projects` flag. A set that cannot contain a wildcard cannot grant
    one — the same reasoning that keeps a person out of a STIX grouping (M-17).
  * Every data permission requires a concrete `project_id` at the call site and
    denies without one. A caller that "forgot" the project is denied, not
    widened.
  * `ElevatedGrant.expires_at` is mandatory. A grant that cannot be permanent
    cannot quietly become permanent.

D-50 IS DELIBERATE AND COUNTERINTUITIVE
`super_admin` holds no data permission at all. It configures the system and
cannot read a finding. That is threat T-003 — the super-admin cross-tenant
boundary failure, carried over from the Amirani register as T-013 — and it
protects the operator as much as the tenant: an operator who *cannot* read
client data cannot be compelled or suspected of it.

Roles compose. A person who administers a tenant and also analyses it holds two
roles; the answer is not to widen either one.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import UUID


class Permission(StrEnum):
    """One action. Deliberately fine-grained: a coarse permission is a wildcard
    wearing a different name."""

    # System administration. None of these touch tenant data.
    MANAGE_TENANTS = "manage_tenants"
    MANAGE_RULES = "manage_rules"
    MANAGE_SYSTEM_CONFIG = "manage_system_config"

    # Tenant administration. Also not data: D-49 separates running a tenant
    # from reading what it collected.
    MANAGE_USERS = "manage_users"
    MANAGE_PROJECTS = "manage_projects"

    # Tenant data. Every one of these requires a project scope.
    READ_FINDINGS = "read_findings"
    READ_CONTENT = "read_content"
    READ_EVIDENCE = "read_evidence"
    RECORD_VERDICT = "record_verdict"
    EXPORT_STIX = "export_stix"
    REQUEST_BULK_EXPORT = "request_bulk_export"
    APPROVE_BULK_EXPORT = "approve_bulk_export"

    # The audit log. Its own category because an auditor reads it and never
    # reads data, and nobody who reads data should silently also read it.
    READ_AUDIT = "read_audit"


#: Permissions that touch tenant data. The set exists so "does this need a
#: project scope" is answered in one place rather than at each call site, and so
#: a new data permission that forgets to join it fails a test rather than
#: quietly becoming readable tenant-wide.
DATA_PERMISSIONS = frozenset(
    {
        Permission.READ_FINDINGS,
        Permission.READ_CONTENT,
        Permission.READ_EVIDENCE,
        Permission.RECORD_VERDICT,
        Permission.EXPORT_STIX,
        Permission.REQUEST_BULK_EXPORT,
        Permission.APPROVE_BULK_EXPORT,
    }
)


class Role(StrEnum):
    SUPER_ADMIN = "super_admin"
    TENANT_ADMIN = "tenant_admin"
    ANALYST = "analyst"
    REVIEWER = "reviewer"
    READ_ONLY = "read_only"
    AUDITOR = "auditor"


ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    # D-50 / T-003. No data permission. Not an oversight — the point.
    Role.SUPER_ADMIN: frozenset(
        {
            Permission.MANAGE_TENANTS,
            Permission.MANAGE_RULES,
            Permission.MANAGE_SYSTEM_CONFIG,
        }
    ),
    # "Own tenant's users and projects" (D-49), read literally. Administering a
    # tenant is not the same job as analysing its data, and an admin who needs
    # both holds both roles — visibly, in the audit log.
    Role.TENANT_ADMIN: frozenset(
        {
            Permission.MANAGE_USERS,
            Permission.MANAGE_PROJECTS,
            Permission.APPROVE_BULK_EXPORT,
        }
    ),
    Role.ANALYST: frozenset(
        {
            Permission.READ_FINDINGS,
            Permission.READ_CONTENT,
            Permission.READ_EVIDENCE,
            Permission.RECORD_VERDICT,
            Permission.EXPORT_STIX,
            Permission.REQUEST_BULK_EXPORT,
        }
    ),
    # The review queue and nothing else. A reviewer confirms a verdict; they do
    # not go browsing.
    Role.REVIEWER: frozenset({Permission.READ_FINDINGS, Permission.RECORD_VERDICT}),
    Role.READ_ONLY: frozenset({Permission.READ_FINDINGS}),
    # "Audit log only, never data." The one role whose value depends on it not
    # being able to see what it is auditing.
    Role.AUDITOR: frozenset({Permission.READ_AUDIT}),
}


@dataclass(frozen=True, slots=True)
class ElevatedGrant:
    """Temporary access under D-50. Justified, time-limited, audited.

    `expires_at` has no default and is not optional. The failure this prevents
    is the standard one: an emergency grant issued at 2am that nobody revokes,
    which is indistinguishable from a permanent privilege a year later.
    """

    tenant_id: UUID
    permissions: frozenset[Permission]
    justification: str
    granted_by: UUID
    expires_at: datetime

    def active_at(self, moment: datetime) -> bool:
        return moment < self.expires_at


@dataclass(frozen=True, slots=True)
class Principal:
    """Who is asking. Assembled from storage, never from a request body."""

    user_id: UUID
    tenant_id: UUID
    roles: frozenset[Role]
    #: Explicit membership. No wildcard exists, so an empty set means "no
    #: project data", never "all project data".
    project_ids: frozenset[UUID] = frozenset()
    grants: tuple[ElevatedGrant, ...] = ()

    def role_permissions(self) -> frozenset[Permission]:
        granted: set[Permission] = set()
        for role in self.roles:
            granted |= ROLE_PERMISSIONS.get(role, frozenset())
        return frozenset(granted)


@dataclass(frozen=True, slots=True)
class Decision:
    """Allowed or not, and why.

    The reason is not decoration. A denial that cannot explain itself produces
    a support ticket, and the fastest way to close a support ticket is to widen
    a permission.
    """

    allowed: bool
    reason: str

    def __bool__(self) -> bool:
        return self.allowed


def authorize(
    principal: Principal,
    permission: Permission,
    *,
    tenant_id: UUID,
    now: datetime,
    project_id: UUID | None = None,
) -> Decision:
    """The single authorization decision. Deny by default, at every step.

    `project_id` is keyword-only and defaults to None so that omitting it is
    visible at the call site rather than accidental — and omitting it for a data
    permission is a denial, never a widening.
    """
    active_grants = tuple(g for g in principal.grants if g.active_at(now))

    # ── the tenant boundary (D-47, V-7, T-002) ──────────────────────────────
    if tenant_id != principal.tenant_id:
        crossing = [
            g for g in active_grants if g.tenant_id == tenant_id and permission in g.permissions
        ]
        if not crossing:
            return Decision(
                False,
                f"{principal.user_id} belongs to tenant {principal.tenant_id} and asked about "
                f"{tenant_id}. Crossing tenants requires an unexpired grant naming both the "
                "tenant and the permission (D-50).",
            )

    # ── does anything grant it at all ───────────────────────────────────────
    from_roles = principal.role_permissions()
    from_grants: set[Permission] = set()
    for grant in active_grants:
        if grant.tenant_id == tenant_id:
            from_grants |= grant.permissions

    if permission not in from_roles and permission not in from_grants:
        held = ", ".join(sorted(r.value for r in principal.roles)) or "none"
        return Decision(
            False,
            f"{permission.value} is not granted by any of: {held}. "
            "Add the role that carries it, or issue a time-limited grant — never "
            "widen an existing role (V-7).",
        )

    # ── compartmentalisation (D-49, V-7, T-007) ─────────────────────────────
    #
    # This is where "see everything" would live if it existed. It does not: a
    # data permission without a concrete project in the principal's own set is
    # denied, and there is no value of project_id meaning "all of them".
    if permission in DATA_PERMISSIONS:
        if project_id is None:
            return Decision(
                False,
                f"{permission.value} reads tenant data and was asked without a project. "
                "There is no tenant-wide read: D-49 compartmentalises by project and "
                '"see everything" does not exist as a permission.',
            )
        if project_id not in principal.project_ids:
            return Decision(
                False,
                f"{principal.user_id} is not assigned to project {project_id}. "
                "An analyst sees assigned projects only (D-49).",
            )

    return Decision(True, f"{permission.value} granted")
