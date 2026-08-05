"""L3 — identity persistence. Writes only to sch_identity (D-91).

Every method here is tenant-scoped by RLS rather than by the WHERE clauses
below. The clauses are there for index selectivity and readability; the
isolation is the database's, because a filter that has to be remembered is a
filter that will eventually be forgotten (T-002).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import psycopg

from asip.modules.identity.domain.audit import AuditEntry
from asip.modules.identity.domain.roles import ElevatedGrant, Permission, Principal, Role


class PostgresIdentityRepository:
    def __init__(self, connection: psycopg.Connection) -> None:
        self._conn = connection

    # ── users ───────────────────────────────────────────────────────────────

    def create_tenant(self, tenant_id: UUID, name: str, retention_days: int = 365) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_identity.tenants (tenant_id, name, retention_days) "
                "VALUES (%s, %s, %s) ON CONFLICT (tenant_id) DO NOTHING",
                (tenant_id, name, retention_days),
            )

    def create_user(
        self,
        user_id: UUID,
        tenant_id: UUID,
        email: str,
        password_hash: str,
        display_name: str = "",
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_identity.users "
                "(user_id, tenant_id, email, password_hash, display_name) "
                "VALUES (%s, %s, %s, %s, %s) ON CONFLICT (user_id) DO NOTHING",
                (user_id, tenant_id, email.lower(), password_hash, display_name),
            )

    def credentials_for(self, tenant_id: UUID, email: str) -> dict[str, Any] | None:
        """The stored hash for a login attempt, or None.

        Returns None for a disabled account rather than the hash, so a disabled
        user cannot authenticate even if the caller forgets to check.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, password_hash FROM sch_identity.users "
                " WHERE tenant_id = %s AND email = %s AND disabled_at IS NULL",
                (tenant_id, email.lower()),
            )
            row = cur.fetchone()
        return None if row is None else {"user_id": row[0], "password_hash": row[1]}

    def update_password_hash(self, tenant_id: UUID, user_id: UUID, password_hash: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE sch_identity.users SET password_hash = %s "
                " WHERE tenant_id = %s AND user_id = %s",
                (password_hash, tenant_id, user_id),
            )

    def record_login(self, tenant_id: UUID, user_id: UUID, moment: datetime) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE sch_identity.users SET last_login_at = %s "
                " WHERE tenant_id = %s AND user_id = %s",
                (moment, tenant_id, user_id),
            )

    # ── roles, projects, grants ─────────────────────────────────────────────

    def assign_role(self, tenant_id: UUID, user_id: UUID, role: Role) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_identity.user_roles (user_id, tenant_id, role) "
                "VALUES (%s, %s, %s) ON CONFLICT (user_id, role) DO NOTHING",
                (user_id, tenant_id, role.value),
            )

    def create_project(self, project_id: UUID, tenant_id: UUID, name: str) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_identity.projects (project_id, tenant_id, name) "
                "VALUES (%s, %s, %s) ON CONFLICT (project_id) DO NOTHING",
                (project_id, tenant_id, name),
            )

    def assign_project(self, tenant_id: UUID, user_id: UUID, project_id: UUID) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_identity.project_assignments "
                "(user_id, project_id, tenant_id) VALUES (%s, %s, %s) "
                "ON CONFLICT (user_id, project_id) DO NOTHING",
                (user_id, project_id, tenant_id),
            )

    def load_principal(self, tenant_id: UUID, user_id: UUID, now: datetime) -> Principal | None:
        """Assemble a principal from storage. Never from a request body.

        Roles, project assignments and grants are read here rather than carried
        in a token, so revoking one takes effect on the next request instead of
        whenever the token happens to expire.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM sch_identity.users "
                " WHERE tenant_id = %s AND user_id = %s AND disabled_at IS NULL",
                (tenant_id, user_id),
            )
            if cur.fetchone() is None:
                return None

            cur.execute(
                "SELECT role FROM sch_identity.user_roles WHERE tenant_id = %s AND user_id = %s",
                (tenant_id, user_id),
            )
            roles = frozenset(Role(r[0]) for r in cur.fetchall())

            cur.execute(
                "SELECT a.project_id FROM sch_identity.project_assignments a "
                "  JOIN sch_identity.projects p ON p.project_id = a.project_id "
                " WHERE a.tenant_id = %s AND a.user_id = %s AND p.archived_at IS NULL",
                (tenant_id, user_id),
            )
            projects = frozenset(r[0] for r in cur.fetchall())

            cur.execute(
                "SELECT tenant_id, permissions, justification, granted_by, expires_at "
                "  FROM sch_identity.elevated_grants "
                " WHERE granted_to = %s AND revoked_at IS NULL AND expires_at > %s",
                (user_id, now),
            )
            grants = tuple(
                ElevatedGrant(
                    tenant_id=row[0],
                    permissions=frozenset(Permission(p) for p in row[1]),
                    justification=row[2],
                    granted_by=row[3],
                    expires_at=row[4],
                )
                for row in cur.fetchall()
            )

        return Principal(user_id, tenant_id, roles, projects, grants)

    # ── sessions ────────────────────────────────────────────────────────────

    def open_session(
        self,
        session_id: UUID,
        tenant_id: UUID,
        user_id: UUID,
        token_sha256: str,
        expires_at: datetime,
    ) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_identity.sessions "
                "(session_id, tenant_id, user_id, token_sha256, expires_at) "
                "VALUES (%s, %s, %s, %s, %s)",
                (session_id, tenant_id, user_id, token_sha256, expires_at),
            )

    def session_for(self, token_sha256: str, now: datetime) -> dict[str, Any] | None:
        """Resolve a token fingerprint to a session.

        Deliberately NOT tenant-scoped in its arguments: the caller does not
        know the tenant yet — resolving the token is how they find out. RLS
        still applies, so this runs before the tenant GUC is set, as the owner,
        and it is the one query in the system with that property. It reads a
        single row by unique digest and returns identifiers only.
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT session_id, tenant_id, user_id, expires_at FROM sch_identity.sessions "
                " WHERE token_sha256 = %s AND revoked_at IS NULL AND expires_at > %s",
                (token_sha256, now),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "session_id": row[0],
            "tenant_id": row[1],
            "user_id": row[2],
            "expires_at": row[3],
        }

    def touch_session(self, tenant_id: UUID, session_id: UUID, moment: datetime) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE sch_identity.sessions SET last_seen_at = %s "
                " WHERE tenant_id = %s AND session_id = %s",
                (moment, tenant_id, session_id),
            )

    def revoke_session(self, tenant_id: UUID, session_id: UUID, moment: datetime) -> None:
        with self._conn.cursor() as cur:
            cur.execute(
                "UPDATE sch_identity.sessions SET revoked_at = %s "
                " WHERE tenant_id = %s AND session_id = %s AND revoked_at IS NULL",
                (moment, tenant_id, session_id),
            )

    # ── audit ───────────────────────────────────────────────────────────────

    def audit_head(self, tenant_id: UUID) -> AuditEntry | None:
        """The tenant's current chain head, or None before the first entry."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT entry_id, tenant_id, chain_index, prev_hash, actor_id, action, "
                "       resource_type, resource_id, outcome, reason, occurred_at, "
                "       entry_hash, algorithm "
                "  FROM sch_identity.audit_log WHERE tenant_id = %s "
                " ORDER BY chain_index DESC LIMIT 1",
                (tenant_id,),
            )
            row = cur.fetchone()
        return None if row is None else _to_entry(row)

    def append_audit(self, entry: AuditEntry) -> None:
        """Insert one entry. There is no update or delete counterpart.

        Not an omission — asip_app holds no UPDATE or DELETE grant on this
        table, so the missing methods reflect missing privileges rather than
        the other way round (D-51, T-008).
        """
        with self._conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sch_identity.audit_log "
                "(entry_id, tenant_id, chain_index, prev_hash, actor_id, action, "
                " resource_type, resource_id, outcome, reason, occurred_at, entry_hash, "
                " algorithm) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (
                    entry.entry_id,
                    entry.tenant_id,
                    entry.chain_index,
                    entry.prev_hash,
                    entry.actor_id,
                    entry.action,
                    entry.resource_type,
                    entry.resource_id,
                    entry.outcome.value,
                    entry.reason,
                    entry.occurred_at,
                    entry.entry_hash,
                    entry.algorithm,
                ),
            )

    def audit_entries(self, tenant_id: UUID, limit: int = 100) -> list[AuditEntry]:
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT entry_id, tenant_id, chain_index, prev_hash, actor_id, action, "
                "       resource_type, resource_id, outcome, reason, occurred_at, "
                "       entry_hash, algorithm "
                "  FROM sch_identity.audit_log WHERE tenant_id = %s "
                " ORDER BY chain_index DESC LIMIT %s",
                (tenant_id, limit),
            )
            return [_to_entry(row) for row in cur.fetchall()]

    def audit_segment(self, tenant_id: UUID, start: int, end: int) -> list[AuditEntry]:
        """A contiguous slice in ascending order, for chain verification."""
        with self._conn.cursor() as cur:
            cur.execute(
                "SELECT entry_id, tenant_id, chain_index, prev_hash, actor_id, action, "
                "       resource_type, resource_id, outcome, reason, occurred_at, "
                "       entry_hash, algorithm "
                "  FROM sch_identity.audit_log "
                " WHERE tenant_id = %s AND chain_index BETWEEN %s AND %s "
                " ORDER BY chain_index",
                (tenant_id, start, end),
            )
            return [_to_entry(row) for row in cur.fetchall()]


def _to_entry(row: tuple[Any, ...]) -> AuditEntry:
    from asip.modules.identity.domain.audit import AuditOutcome

    return AuditEntry(
        entry_id=row[0],
        tenant_id=row[1],
        chain_index=row[2],
        prev_hash=row[3],
        actor_id=row[4],
        action=row[5],
        resource_type=row[6],
        resource_id=row[7],
        outcome=AuditOutcome(row[8]),
        reason=row[9],
        occurred_at=row[10],
        entry_hash=row[11],
        algorithm=row[12],
    )
