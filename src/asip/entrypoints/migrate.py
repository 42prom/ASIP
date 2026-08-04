"""L4 — the migration runner.

Plain numbered SQL files rather than Alembic. The justification is
Simplicity-First (CLAUDE.md §3): there is no SQLAlchemy in this system, so
Alembic would arrive purely as a migration framework; and none of what these
migrations contain — RLS policies, FORCE ROW LEVEL SECURITY, range partitions,
role grants, published views — is anything Alembic autogenerates. It would add
a dependency and a DSL in exchange for hand-written SQL either way. This runner
is the part that is actually missing, and it is small enough to read in full.

Layout, one directory per module, because each module owns exactly one schema
(D-91) and migrations are how that ownership is expressed:

    migrations/<module>/NNN_<name>.sql
    migrations/<module>/NNN_<name>.rollback.sql

Applied migrations are recorded in sch_migrations.applied. Each file runs
inside a transaction together with the row recording it, so a failure leaves
neither the DDL nor the record — the same both-or-neither property the
evidence chain depends on.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

import psycopg

MIGRATIONS_ROOT = Path(__file__).resolve().parents[3] / "migrations"

BOOTSTRAP = """
CREATE SCHEMA IF NOT EXISTS sch_migrations;
CREATE TABLE IF NOT EXISTS sch_migrations.applied (
    module      text        NOT NULL,
    version     text        NOT NULL,
    name        text        NOT NULL,
    applied_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (module, version)
);
"""


@dataclass(frozen=True)
class Migration:
    module: str
    version: str
    name: str
    path: Path

    @property
    def rollback_path(self) -> Path:
        return self.path.with_suffix("").with_suffix(".rollback.sql")

    def __str__(self) -> str:
        return f"{self.module}/{self.version}_{self.name}"


def discover(root: Path = MIGRATIONS_ROOT) -> list[Migration]:
    """Every migration, ordered by version within module, module by module."""
    found: list[Migration] = []
    if not root.is_dir():
        return found

    for module_dir in sorted(p for p in root.iterdir() if p.is_dir()):
        for path in sorted(module_dir.glob("*.sql")):
            if path.name.endswith(".rollback.sql"):
                continue
            version, _, name = path.stem.partition("_")
            if not version.isdigit():
                raise ValueError(f"{path} does not start with a numeric version (NNN_name.sql)")
            found.append(Migration(module_dir.name, version, name, path))
    return found


def applied_versions(conn: psycopg.Connection) -> set[tuple[str, str]]:
    with conn.cursor() as cur:
        cur.execute("SELECT module, version FROM sch_migrations.applied")
        return {(row[0], row[1]) for row in cur.fetchall()}


def apply(conn: psycopg.Connection, migration: Migration) -> None:
    """Apply one migration and record it, in a single transaction."""
    sql = migration.path.read_text(encoding="utf-8")
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(sql)
        cur.execute(
            "INSERT INTO sch_migrations.applied (module, version, name) VALUES (%s, %s, %s)",
            (migration.module, migration.version, migration.name),
        )


def rollback(conn: psycopg.Connection, migration: Migration) -> None:
    """Roll one migration back and forget it, in a single transaction."""
    if not migration.rollback_path.is_file():
        raise FileNotFoundError(
            f"{migration} has no rollback file at {migration.rollback_path}. "
            "A migration without a tested rollback is not finished."
        )
    sql = migration.rollback_path.read_text(encoding="utf-8")
    with conn.transaction(), conn.cursor() as cur:
        cur.execute(sql)
        cur.execute(
            "DELETE FROM sch_migrations.applied WHERE module = %s AND version = %s",
            (migration.module, migration.version),
        )


def migrate_up(conn: psycopg.Connection, root: Path = MIGRATIONS_ROOT) -> list[Migration]:
    """Apply every migration not yet recorded. Returns what was applied."""
    with conn.cursor() as cur:
        cur.execute(BOOTSTRAP)
    conn.commit()

    done = applied_versions(conn)
    newly_applied = []
    for migration in discover(root):
        if (migration.module, migration.version) in done:
            continue
        apply(conn, migration)
        newly_applied.append(migration)
    return newly_applied


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply ASIP database migrations.")
    parser.add_argument("--dsn", required=True, help="PostgreSQL connection string")
    parser.add_argument(
        "--rollback",
        metavar="MODULE/VERSION",
        help="Roll one migration back, e.g. evidence/001",
    )
    parser.add_argument("--status", action="store_true", help="List migrations and their state")
    args = parser.parse_args(argv)

    with psycopg.connect(args.dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(BOOTSTRAP)
        conn.commit()

        if args.status:
            done = applied_versions(conn)
            for migration in discover():
                mark = "applied" if (migration.module, migration.version) in done else "pending"
                print(f"  {mark:8} {migration}")
            return 0

        if args.rollback:
            module, _, version = args.rollback.partition("/")
            target = next(
                (m for m in discover() if m.module == module and m.version == version), None
            )
            if target is None:
                print(f"no migration {args.rollback}", file=sys.stderr)
                return 1
            rollback(conn, target)
            print(f"rolled back {target}")
            return 0

        applied = migrate_up(conn)
        if not applied:
            print("nothing to apply")
        for migration in applied:
            print(f"applied {migration}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
