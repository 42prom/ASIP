"""L2 — check the permission and record that you checked, in one call.

THE REASON THESE ARE NOT TWO FUNCTIONS
D-52 requires reads to be audited. If `authorize()` and `record_audit()` are
separate calls, every endpoint is one forgotten line away from an unaudited
read — and the forgotten line is invisible, because the endpoint still works.
Nobody notices until someone asks "who looked at this finding" and the answer
is silence for the six months since that endpoint shipped.

So there is one operation. Asking whether you may do something *is* recording
that you asked. A caller cannot take the permission check without the audit
entry, because there is no API that offers it.

The denial is audited too, and is often the more interesting record: a log of
successes cannot show someone probing for what they are not allowed to see
(T-007).

THE ENTRY IS WRITTEN BEFORE THE ANSWER IS RETURNED
Not after the handler succeeds. An audit entry written after the work would be
missing for exactly the requests that crashed halfway — which are the ones most
worth investigating.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from uuid import UUID

from asip.modules.identity.domain.audit import AuditEntry, AuditOutcome, link
from asip.modules.identity.domain.roles import Decision, Permission, Principal, authorize


class AuditStore(Protocol):
    """What the guard needs from storage. Append and read the head — there is
    no update or delete, because the table grants neither (D-51)."""

    def audit_head(self, tenant_id: UUID) -> AuditEntry | None: ...

    def append_audit(self, entry: AuditEntry) -> None: ...


class Clock(Protocol):
    def now(self) -> datetime: ...


class NotPermitted(PermissionError):
    """The action was denied. Carries the reason and the audit entry id.

    The entry id is included so a support conversation can start from "denial
    <id>" rather than from a screenshot — and so a user cannot be told a denial
    was not recorded when it was.
    """

    def __init__(self, decision: Decision, entry_id: UUID) -> None:
        super().__init__(decision.reason)
        self.decision = decision
        self.entry_id = entry_id


@dataclass(frozen=True, slots=True)
class GuardResult:
    decision: Decision
    entry: AuditEntry


class Guard:
    def __init__(self, store: AuditStore, clock: Clock) -> None:
        self._store = store
        self._clock = clock

    def check(
        self,
        principal: Principal,
        permission: Permission,
        *,
        tenant_id: UUID,
        resource_type: str,
        resource_id: str,
        project_id: UUID | None = None,
    ) -> GuardResult:
        """Decide, record, and return both. Never raises on a denial."""
        now = self._clock.now()
        decision = authorize(
            principal, permission, tenant_id=tenant_id, project_id=project_id, now=now
        )

        # The entry goes on the *acting* principal's own tenant chain, not the
        # tenant being acted upon. A cross-tenant attempt under a grant belongs
        # in the record of the person who made it; putting it only on the target
        # tenant's chain would let someone probe tenants they have no grant for
        # and leave no trace anywhere they are accountable.
        entry = link(
            self._store.audit_head(principal.tenant_id),
            entry_id=uuid.uuid4(),
            tenant_id=principal.tenant_id,
            actor_id=principal.user_id,
            action=permission.value,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=AuditOutcome.ALLOWED if decision.allowed else AuditOutcome.DENIED,
            occurred_at=now,
            reason=decision.reason,
        )
        self._store.append_audit(entry)

        return GuardResult(decision, entry)

    def require(
        self,
        principal: Principal,
        permission: Permission,
        *,
        tenant_id: UUID,
        resource_type: str,
        resource_id: str,
        project_id: UUID | None = None,
    ) -> AuditEntry:
        """Same as `check`, but raises on denial.

        The form endpoints should use: a handler that forgets to inspect a
        returned decision proceeds as though it were allowed, and this one
        cannot be ignored by accident.
        """
        result = self.check(
            principal,
            permission,
            tenant_id=tenant_id,
            resource_type=resource_type,
            resource_id=resource_id,
            project_id=project_id,
        )
        if not result.decision.allowed:
            raise NotPermitted(result.decision, result.entry.entry_id)
        return result.entry
