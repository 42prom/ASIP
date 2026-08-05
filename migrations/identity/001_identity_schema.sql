-- sch_identity — tenants, users, roles, projects, grants, audit (D-91).
--
-- The module that decides who may do what. Two things here are enforced by the
-- database rather than by application code, because application code is where
-- the forgotten WHERE clause lives (T-002):
--
--   1. RLS on every table carrying tenant_id, FORCEd so the owner is subject
--      to it too (D-47, V-7).
--   2. The audit log is append-only at the GRANT level. asip_app can SELECT and
--      INSERT and holds no UPDATE or DELETE on it, so "the application deleted
--      its own audit trail" is not a bug that can occur (D-51, T-008).
--
-- WHAT IS NOT HERE
--
-- No "see everything" flag, no is_superuser column, no tenant_id nullable to
-- mean "all tenants". D-49 says the permission does not exist and V-7 makes
-- adding one a veto; the schema is written so there is nowhere to put it.
-- Crossing a tenant boundary requires a row in elevated_grants with a
-- non-null expiry, which is auditable and expires on its own (D-50, T-003).

CREATE SCHEMA IF NOT EXISTS sch_identity;
GRANT USAGE ON SCHEMA sch_identity TO asip_app, asip_retention;

CREATE OR REPLACE FUNCTION sch_identity.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE
    AS 'SELECT nullif(current_setting(''asip.tenant_id'', true), '''')::uuid';


-- ─────────────────────────────────────────────────────────────────────────────
-- Tenants
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE sch_identity.tenants (
    tenant_id      uuid        PRIMARY KEY,
    name           text        NOT NULL,
    -- D-54: retention is configurable per tenant. Here from the start because
    -- retrofitting a retention policy onto data already collected under no
    -- policy is a legal problem, not a schema problem.
    retention_days integer     NOT NULL DEFAULT 365,
    created_at     timestamptz NOT NULL DEFAULT now(),
    disabled_at    timestamptz,

    CONSTRAINT tenants_retention_sane CHECK (retention_days BETWEEN 1 AND 3650)
);


-- ─────────────────────────────────────────────────────────────────────────────
-- Users and roles
--
-- password_hash stores algorithm, parameters and salt alongside the digest, so
-- a stronger KDF can be adopted later without invalidating existing passwords:
-- verification dispatches on what is stored, not on what is current. Migration
-- cost paid once, in the format, rather than every time the recommendation
-- changes.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE sch_identity.users (
    user_id       uuid        PRIMARY KEY,
    tenant_id     uuid        NOT NULL REFERENCES sch_identity.tenants (tenant_id),
    email         text        NOT NULL,
    password_hash text        NOT NULL,
    display_name  text        NOT NULL DEFAULT '',
    disabled_at   timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,

    -- Unique per tenant, not globally: the same person may hold accounts at two
    -- client organisations, and a global unique constraint would leak the fact
    -- that an address is already registered somewhere (an enumeration oracle).
    CONSTRAINT users_email_unique_per_tenant UNIQUE (tenant_id, email),
    CONSTRAINT users_email_shaped CHECK (email ~ '^[^@[:space:]]+@[^@[:space:]]+$')
);

CREATE INDEX users_tenant_idx ON sch_identity.users (tenant_id);

CREATE TABLE sch_identity.user_roles (
    user_id   uuid NOT NULL REFERENCES sch_identity.users (user_id) ON DELETE CASCADE,
    tenant_id uuid NOT NULL REFERENCES sch_identity.tenants (tenant_id),
    role      text NOT NULL,
    granted_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, role),
    -- The list is closed at the database level. A typo'd role would otherwise
    -- silently grant nothing, which looks identical to a permissions bug and
    -- gets "fixed" by widening something.
    CONSTRAINT user_roles_known CHECK (
        role IN ('super_admin', 'tenant_admin', 'analyst', 'reviewer', 'read_only', 'auditor')
    )
);


-- ─────────────────────────────────────────────────────────────────────────────
-- Projects and assignments — the unit of compartmentalisation (D-49, T-007)
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE sch_identity.projects (
    project_id uuid        PRIMARY KEY,
    tenant_id  uuid        NOT NULL REFERENCES sch_identity.tenants (tenant_id),
    name       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    archived_at timestamptz,

    CONSTRAINT projects_name_unique_per_tenant UNIQUE (tenant_id, name)
);

-- Membership is explicit rows. There is deliberately no "all projects" flag:
-- an analyst with no rows here sees no project data, and the only way to widen
-- that is to insert rows that name which projects — visibly, and auditably.
CREATE TABLE sch_identity.project_assignments (
    user_id    uuid        NOT NULL REFERENCES sch_identity.users (user_id) ON DELETE CASCADE,
    project_id uuid        NOT NULL REFERENCES sch_identity.projects (project_id) ON DELETE CASCADE,
    tenant_id  uuid        NOT NULL REFERENCES sch_identity.tenants (tenant_id),
    assigned_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, project_id)
);

CREATE INDEX project_assignments_user_idx
    ON sch_identity.project_assignments (tenant_id, user_id);


-- ─────────────────────────────────────────────────────────────────────────────
-- Elevated grants (D-50, T-003)
--
-- The only way to act outside your own tenant. expires_at is NOT NULL with no
-- default: a grant that cannot be permanent cannot quietly become permanent,
-- and the failure being prevented is the 2am emergency grant nobody revokes.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE sch_identity.elevated_grants (
    grant_id      uuid        PRIMARY KEY,
    -- The tenant being ACTED UPON, which is the whole point: this row is the
    -- record of a boundary being crossed.
    tenant_id     uuid        NOT NULL REFERENCES sch_identity.tenants (tenant_id),
    granted_to    uuid        NOT NULL REFERENCES sch_identity.users (user_id),
    granted_by    uuid        NOT NULL REFERENCES sch_identity.users (user_id),
    permissions   text[]      NOT NULL,
    justification text        NOT NULL,
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,

    CONSTRAINT grants_expire CHECK (expires_at > created_at),
    -- Twelve hours. Long enough for an incident, short enough that nobody
    -- treats it as a standing arrangement.
    CONSTRAINT grants_are_short CHECK (expires_at <= created_at + interval '12 hours'),
    CONSTRAINT grants_justified CHECK (length(btrim(justification)) >= 20),
    CONSTRAINT grants_grant_something CHECK (cardinality(permissions) > 0),
    -- Self-granting defeats the control entirely.
    CONSTRAINT grants_not_self CHECK (granted_to <> granted_by)
);

CREATE INDEX elevated_grants_active_idx
    ON sch_identity.elevated_grants (granted_to, expires_at);


-- ─────────────────────────────────────────────────────────────────────────────
-- Sessions
--
-- The token itself is never stored — only its SHA-256. A leaked database dump
-- then yields no usable session, the same reasoning that applies to passwords.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE sch_identity.sessions (
    session_id uuid        PRIMARY KEY,
    tenant_id  uuid        NOT NULL REFERENCES sch_identity.tenants (tenant_id),
    user_id    uuid        NOT NULL REFERENCES sch_identity.users (user_id) ON DELETE CASCADE,
    token_sha256 char(64)  NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    last_seen_at timestamptz,

    CONSTRAINT sessions_expire CHECK (expires_at > created_at),
    CONSTRAINT sessions_token_is_hex CHECK (token_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX sessions_user_idx ON sch_identity.sessions (tenant_id, user_id);


-- ─────────────────────────────────────────────────────────────────────────────
-- The audit log (D-51, D-52, T-008, T-009)
--
-- Append-only and hash-chained, the same discipline as evidence. Records reads,
-- not just writes: in an intelligence system "who looked at what" matters more
-- than "who changed what", and an analyst reading a tenant they were never
-- assigned to leaves no trace in a write-only log.
--
-- One chain per tenant. A single shared chain would mean verifying tenant A's
-- audit log required reading tenant B's entries.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE TABLE sch_identity.audit_log (
    entry_id      uuid        PRIMARY KEY,
    tenant_id     uuid        NOT NULL REFERENCES sch_identity.tenants (tenant_id),
    chain_index   bigint      NOT NULL,
    prev_hash     char(64)    NOT NULL,
    actor_id      uuid        NOT NULL,
    action        text        NOT NULL,
    resource_type text        NOT NULL,
    resource_id   text        NOT NULL,
    outcome       text        NOT NULL,
    reason        text        NOT NULL DEFAULT '',
    occurred_at   timestamptz NOT NULL,
    entry_hash    char(64)    NOT NULL,
    algorithm     text        NOT NULL DEFAULT 'sha256',

    CONSTRAINT audit_chain_unique_per_tenant UNIQUE (tenant_id, chain_index),
    CONSTRAINT audit_outcome_known CHECK (outcome IN ('allowed', 'denied')),
    CONSTRAINT audit_hash_is_hex CHECK (entry_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_prev_is_hex CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT audit_index_non_negative CHECK (chain_index >= 0)
);

CREATE INDEX audit_log_tenant_time_idx ON sch_identity.audit_log (tenant_id, occurred_at DESC);
CREATE INDEX audit_log_actor_idx ON sch_identity.audit_log (tenant_id, actor_id, occurred_at DESC);
-- T-009: "what did anyone read about this finding" has to be answerable
-- without a sequential scan, or nobody will ask it.
CREATE INDEX audit_log_resource_idx
    ON sch_identity.audit_log (tenant_id, resource_type, resource_id);


-- ─────────────────────────────────────────────────────────────────────────────
-- RLS (D-47, V-7, T-002). FORCE so the table owner is subject to the policy.
--
-- Every table below carries tenant_id and every one gets a policy. There is no
-- exception and no "internal" table that skips it — the forgotten WHERE clause
-- this defends against is written by us, not by an attacker.
-- ─────────────────────────────────────────────────────────────────────────────
ALTER TABLE sch_identity.tenants             ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_identity.tenants             FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_identity.users               ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_identity.users               FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_identity.user_roles          ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_identity.user_roles          FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_identity.projects            ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_identity.projects            FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_identity.project_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_identity.project_assignments FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_identity.elevated_grants     ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_identity.elevated_grants     FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_identity.sessions            ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_identity.sessions            FORCE  ROW LEVEL SECURITY;
ALTER TABLE sch_identity.audit_log           ENABLE ROW LEVEL SECURITY;
ALTER TABLE sch_identity.audit_log           FORCE  ROW LEVEL SECURITY;

-- The tenants table keys on tenant_id itself rather than carrying one.
CREATE POLICY tenants_tenant_isolation ON sch_identity.tenants
    USING (tenant_id = sch_identity.current_tenant())
    WITH CHECK (tenant_id = sch_identity.current_tenant());

CREATE POLICY users_tenant_isolation ON sch_identity.users
    USING (tenant_id = sch_identity.current_tenant())
    WITH CHECK (tenant_id = sch_identity.current_tenant());

CREATE POLICY user_roles_tenant_isolation ON sch_identity.user_roles
    USING (tenant_id = sch_identity.current_tenant())
    WITH CHECK (tenant_id = sch_identity.current_tenant());

CREATE POLICY projects_tenant_isolation ON sch_identity.projects
    USING (tenant_id = sch_identity.current_tenant())
    WITH CHECK (tenant_id = sch_identity.current_tenant());

CREATE POLICY project_assignments_tenant_isolation ON sch_identity.project_assignments
    USING (tenant_id = sch_identity.current_tenant())
    WITH CHECK (tenant_id = sch_identity.current_tenant());

CREATE POLICY elevated_grants_tenant_isolation ON sch_identity.elevated_grants
    USING (tenant_id = sch_identity.current_tenant())
    WITH CHECK (tenant_id = sch_identity.current_tenant());

CREATE POLICY sessions_tenant_isolation ON sch_identity.sessions
    USING (tenant_id = sch_identity.current_tenant())
    WITH CHECK (tenant_id = sch_identity.current_tenant());

CREATE POLICY audit_log_tenant_isolation ON sch_identity.audit_log
    USING (tenant_id = sch_identity.current_tenant())
    WITH CHECK (tenant_id = sch_identity.current_tenant());


-- ─────────────────────────────────────────────────────────────────────────────
-- Grants
-- ─────────────────────────────────────────────────────────────────────────────
REVOKE ALL ON ALL TABLES IN SCHEMA sch_identity FROM PUBLIC;

GRANT SELECT, INSERT ON sch_identity.tenants, sch_identity.users,
                        sch_identity.user_roles, sch_identity.projects,
                        sch_identity.project_assignments,
                        sch_identity.elevated_grants, sch_identity.sessions
    TO asip_app;

-- Column-scoped, not blanket. An application that can UPDATE users freely can
-- change a tenant_id, which is a cross-tenant move disguised as an edit.
GRANT UPDATE (password_hash, display_name, disabled_at, last_login_at)
    ON sch_identity.users TO asip_app;
GRANT UPDATE (revoked_at, last_seen_at) ON sch_identity.sessions TO asip_app;
GRANT UPDATE (revoked_at) ON sch_identity.elevated_grants TO asip_app;
GRANT UPDATE (name, retention_days, disabled_at) ON sch_identity.tenants TO asip_app;
GRANT DELETE ON sch_identity.user_roles, sch_identity.project_assignments TO asip_app;

-- ── THE AUDIT LOG IS APPEND-ONLY (D-51, T-008) ──────────────────────────────
--
-- SELECT and INSERT. No UPDATE, no DELETE, for anyone — including the retention
-- role, which may expire evidence and content but never the record of who
-- looked at them. "The audit log is never truncated, never rotated
-- destructively."
--
-- This is the single most important GRANT in the schema. A system that can
-- delete its own audit trail has no audit trail; it has a log.
GRANT SELECT, INSERT ON sch_identity.audit_log TO asip_app;
GRANT SELECT ON sch_identity.audit_log TO asip_retention;

-- Retention may remove operational rows, never the audit chain.
GRANT SELECT, DELETE ON sch_identity.sessions, sch_identity.elevated_grants
    TO asip_retention;
GRANT SELECT ON sch_identity.tenants, sch_identity.users, sch_identity.projects
    TO asip_retention;


-- ─────────────────────────────────────────────────────────────────────────────
-- Published read view (D-92) — what other modules may know about a principal.
--
-- Not the password hash, not the session token, not the audit chain. A module
-- that needs to know who is acting needs an id and a tenant, and nothing here
-- tempts it into deciding permissions for itself: authorization lives in one
-- place (modules/identity/domain/roles.py) and this view carries no permission
-- columns at all.
-- ─────────────────────────────────────────────────────────────────────────────
CREATE VIEW sch_identity.v_active_users WITH (security_invoker = true) AS
    SELECT u.user_id, u.tenant_id, u.email, u.display_name, u.last_login_at
      FROM sch_identity.users u
     WHERE u.disabled_at IS NULL;

COMMENT ON VIEW sch_identity.v_active_users IS
    'D-92 published contract: who exists. No credentials, no permissions — '
    'authorization is decided in identity and nowhere else.';

GRANT SELECT ON sch_identity.v_active_users TO asip_app;
