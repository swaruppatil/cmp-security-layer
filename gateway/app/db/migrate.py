"""Minimal SQL migration runner.

Applies ``migrations/NNN_*.sql`` files in order, each in its own transaction, and records them in
``schema_migrations``. A session advisory lock stops two gateway instances migrating at once.

    uv run python -m app.db.migrate            # apply pending migrations
    uv run python -m app.db.migrate --status   # list applied / pending
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import asyncpg

from app.config import Settings

MIGRATIONS_DIR = Path(__file__).parent / "migrations"
LOCK_ID = 727_001  # arbitrary, unique to this app


def migration_files() -> list[Path]:
    return sorted(p for p in MIGRATIONS_DIR.glob("*.sql") if p.name[:3].isdigit())


async def applied_versions(conn: asyncpg.Connection) -> set[str]:
    await conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_migrations (
               version text PRIMARY KEY,
               applied_at timestamptz NOT NULL DEFAULT now()
           )"""
    )
    rows = await conn.fetch("SELECT version FROM schema_migrations")
    return {r["version"] for r in rows}


async def migrate(dsn: str) -> list[str]:
    """Apply pending migrations; return the names applied."""
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute("SELECT pg_advisory_lock($1)", LOCK_ID)
        try:
            done = await applied_versions(conn)
            applied: list[str] = []
            for path in migration_files():
                if path.stem in done:
                    continue
                async with conn.transaction():
                    await conn.execute(path.read_text())
                    await conn.execute("INSERT INTO schema_migrations (version) VALUES ($1)", path.stem)
                applied.append(path.stem)
            return applied
        finally:
            await conn.execute("SELECT pg_advisory_unlock($1)", LOCK_ID)
    finally:
        await conn.close()


async def enable_dashboard_role(dsn: str, password: str) -> None:
    """Let the read-only ``dashboard_reader`` role (created by migration 005) log in with ``password``.

    Done at startup rather than in a migration so the password comes from the environment
    (``DASHBOARD_DB_PASSWORD``) and never sits in a file. Re-running just sets the same password."""
    conn = await asyncpg.connect(dsn)
    try:
        # Several gateway instances starting at once would race on the role row ("tuple concurrently
        # updated"); the migration lock serialises them.
        await conn.execute("SELECT pg_advisory_lock($1)", LOCK_ID)
        try:
            literal = await conn.fetchval("SELECT quote_literal($1::text)", password)
            await conn.execute(f"ALTER ROLE dashboard_reader WITH LOGIN PASSWORD {literal}")
        finally:
            await conn.execute("SELECT pg_advisory_unlock($1)", LOCK_ID)
    finally:
        await conn.close()


async def status(dsn: str) -> list[tuple[str, bool]]:
    conn = await asyncpg.connect(dsn)
    try:
        done = await applied_versions(conn)
        return [(p.stem, p.stem in done) for p in migration_files()]
    finally:
        await conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--status", action="store_true", help="show applied and pending migrations")
    args = parser.parse_args()
    dsn = Settings(admin_api_key="unused-for-migrations").database_url
    if args.status:
        for name, done in asyncio.run(status(dsn)):
            print(f"{'applied' if done else 'pending'}  {name}")
        return
    applied = asyncio.run(migrate(dsn))
    print("applied: " + (", ".join(applied) if applied else "nothing (up to date)"))


if __name__ == "__main__":
    try:
        main()
    except (OSError, asyncpg.PostgresError) as exc:
        print(f"migration failed: {exc}", file=sys.stderr)
        sys.exit(1)
