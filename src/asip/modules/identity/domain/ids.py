"""L1 — deterministic identifiers owned by identity.

Its own namespace rather than extraction's. Two reasons, and the second is the
real one:

  * D-99. Importing `ASIP_NAMESPACE` from extraction would make identity
    undeployable without it, and identity is the module every other one will
    eventually depend on.

  * Domain separation. A project id and an account id derived from the same
    namespace could, in principle, collide — and more practically, sharing a
    namespace means a change made for one module's reasons silently moves the
    other module's identifiers. These are different kinds of thing and they get
    different namespaces on purpose.

Deterministic so that seeding twice produces the same project rather than two,
and so a migration can name the default project without looking it up (M-10).
"""

from __future__ import annotations

from uuid import UUID, uuid5

#: Namespace for identity-owned deterministic ids. Frozen: changing it renames
#: every derived project, orphaning the assignments that point at them.
IDENTITY_NAMESPACE = UUID("7c3e91d2-0000-4000-8000-a51900000005")


def default_project_id(tenant_id: UUID) -> UUID:
    """The project a tenant's sources belong to before anyone organises them.

    A tenant needs at least one project the moment it has a source, because
    D-49 compartmentalises by project and there is no "no project" that an
    analyst could be assigned to. Rather than making the first project a manual
    step that blocks collection, every tenant has one derived from its own id.
    """
    return uuid5(IDENTITY_NAMESPACE, f"project|default|{tenant_id}")
