"""PostgreSQL access (asyncpg): caller keys, bans, strikes, canaries, audit events, policies."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

import asyncpg
import orjson

from app.auth.models import ApiKeyRecord

# inspect: POST /v1/inspect and the session calls · outbound: POST /v1/inspect/outbound · proxy: /v1/ai/*
VALID_SCOPES = frozenset({"inspect", "outbound", "proxy"})


class Repository:
    def __init__(self, pool: asyncpg.Pool) -> None:
        self._pool = pool

    # ---------- auth ----------
    async def find_key_by_prefix(self, prefix: str) -> ApiKeyRecord | None:
        row = await self._pool.fetchrow(
            """SELECT id, name, prefix, key_hash, scopes, status, expires_at
                 FROM api_keys WHERE prefix = $1""",
            prefix,
        )
        if row is None:
            return None
        # Fire-and-forget would race the pool in tests; a cache miss is rare, so update inline.
        await self._pool.execute("UPDATE api_keys SET last_used_at = now() WHERE id = $1", row["id"])
        return ApiKeyRecord(
            id=row["id"],
            name=row["name"],
            prefix=row["prefix"],
            key_hash=row["key_hash"],
            scopes=tuple(row["scopes"]),
            status=row["status"],
            expires_at=row["expires_at"],
        )

    # ---------- caller api keys ----------
    _KEY_COLUMNS = "id, name, prefix, scopes, status, created_at, expires_at, revoked_at, last_used_at"

    async def create_api_key(
        self,
        name: str,
        prefix: str,
        key_hash: str,
        scopes: list[str],
        expires_at: datetime | None,
    ) -> dict[str, Any]:
        row = await self._pool.fetchrow(
            f"""INSERT INTO api_keys (name, prefix, key_hash, scopes, expires_at)
                     VALUES ($1, $2, $3, $4, $5)
                  RETURNING {self._KEY_COLUMNS}""",  # noqa: S608 - constant column list
            name,
            prefix,
            key_hash,
            scopes,
            expires_at,
        )
        assert row is not None
        return dict(row)

    async def ensure_api_key(self, name: str, prefix: str, key_hash: str, scopes: list[str]) -> bool:
        """Create the key unless one with this prefix exists (startup bootstrap). True if created."""
        created = await self._pool.fetchval(
            """INSERT INTO api_keys (name, prefix, key_hash, scopes) VALUES ($1, $2, $3, $4)
               ON CONFLICT (prefix) DO NOTHING RETURNING id""",
            name,
            prefix,
            key_hash,
            scopes,
        )
        return created is not None

    async def list_api_keys(self) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(f"SELECT {self._KEY_COLUMNS} FROM api_keys ORDER BY created_at")  # noqa: S608
        return [dict(r) for r in rows]

    async def revoke_api_key(self, key_id: UUID) -> str | None:
        """Revoke a key; return its hash (for cache invalidation) or None if not found."""
        key_hash = await self._pool.fetchval(
            """UPDATE api_keys SET status = 'revoked', revoked_at = COALESCE(revoked_at, now())
                WHERE id = $1 RETURNING key_hash""",
            key_id,
        )
        return str(key_hash) if key_hash is not None else None

    # ---------- bans ----------
    _BAN_COLUMNS = (
        "id, entity_type, value, reason, source, evidence, permanent, expires_at, "
        "created_at, created_by, revoked_at, revoked_by"
    )

    @staticmethod
    def _ban(row: Any) -> dict[str, Any]:
        out = dict(row)
        if isinstance(out.get("evidence"), str):
            out["evidence"] = orjson.loads(out["evidence"])
        return out

    async def load_active_bans(self) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            f"""SELECT {self._BAN_COLUMNS} FROM bans
                 WHERE revoked_at IS NULL AND (permanent OR expires_at > now())"""  # noqa: S608 - constant
        )
        return [self._ban(r) for r in rows]

    async def create_ban(
        self,
        *,
        entity_type: str,
        value: str,
        reason: str,
        source: str,
        evidence: dict[str, Any],
        permanent: bool,
        expires_at: datetime | None,
        created_by: str,
    ) -> dict[str, Any]:
        row = await self._pool.fetchrow(
            f"""INSERT INTO bans (entity_type, value, reason, source, evidence, permanent, expires_at,
                                  created_by)
                     VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8)
                  RETURNING {self._BAN_COLUMNS}""",  # noqa: S608 - constant column list
            entity_type,
            value,
            reason,
            source,
            orjson.dumps(evidence).decode(),
            permanent,
            expires_at,
            created_by,
        )
        assert row is not None
        return self._ban(row)

    async def create_bans_bulk(self, rows: list[dict[str, Any]]) -> int:
        """Insert many permanent bans (blacklist import) in one statement."""
        if not rows:
            return 0
        await self._pool.executemany(
            """INSERT INTO bans (entity_type, value, reason, source, evidence, permanent, expires_at,
                                 created_by)
                    VALUES ($1, $2, $3, $4, '{}'::jsonb, true, NULL, $5)""",
            [(r["entity_type"], r["value"], r["reason"], r["source"], r["created_by"]) for r in rows],
        )
        return len(rows)

    async def revoke_ban(self, ban_id: UUID, revoked_by: str) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            f"""UPDATE bans
                   SET revoked_at = COALESCE(revoked_at, now()), revoked_by = COALESCE(revoked_by, $2)
                 WHERE id = $1
             RETURNING {self._BAN_COLUMNS}""",  # noqa: S608 - constant column list
            ban_id,
            revoked_by,
        )
        return self._ban(row) if row else None

    async def list_bans(
        self,
        *,
        active_only: bool,
        entity_type: str | None,
        value: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            f"""SELECT {self._BAN_COLUMNS} FROM bans
                 WHERE ($1::bool IS FALSE OR (revoked_at IS NULL AND (permanent OR expires_at > now())))
                   AND ($2::text IS NULL OR entity_type = $2)
                   AND ($3::text IS NULL OR value = $3)
              ORDER BY created_at DESC
                 LIMIT $4""",  # noqa: S608 - constant column list
            active_only,
            entity_type,
            value,
            limit,
        )
        return [self._ban(r) for r in rows]

    # ---------- strikes ----------
    async def record_strike(
        self,
        *,
        entity_type: str,
        value: str,
        reason: str,
        evidence_kind: str,
        request_id: str | None,
        ban_id: UUID | None,
    ) -> None:
        await self._pool.execute(
            """INSERT INTO strikes (entity_type, value, reason, evidence_kind, request_id, ban_id)
                    VALUES ($1, $2, $3, $4, $5, $6)""",
            entity_type,
            value,
            reason,
            evidence_kind,
            request_id,
            ban_id,
        )

    async def list_strikes(self, entity_type: str, value: str, limit: int = 50) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            """SELECT id, entity_type, value, reason, evidence_kind, request_id, ban_id, created_at
                 FROM strikes WHERE entity_type = $1 AND value = $2
             ORDER BY created_at DESC LIMIT $3""",
            entity_type,
            value,
            limit,
        )
        return [dict(r) for r in rows]

    # ---------- canaries (Stage 7) ----------
    async def create_canary(self, label: str, token_hash: str) -> dict[str, Any]:
        row = await self._pool.fetchrow(
            """INSERT INTO canaries (label, token_hash) VALUES ($1, $2)
               RETURNING id, label, created_at, revoked_at""",
            label,
            token_hash,
        )
        assert row is not None
        return dict(row)

    async def list_canaries(self) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            "SELECT id, label, created_at, revoked_at FROM canaries ORDER BY created_at"
        )
        return [dict(r) for r in rows]

    async def revoke_canary(self, canary_id: UUID) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            """UPDATE canaries SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL
               RETURNING id, label, created_at, revoked_at""",
            canary_id,
        )
        return dict(row) if row else None

    async def active_canary_hashes(self) -> list[str]:
        rows = await self._pool.fetch("SELECT token_hash FROM canaries WHERE revoked_at IS NULL")
        return [r["token_hash"] for r in rows]

    # ---------- audit events (Stage 9) ----------
    EVENT_COLUMNS = (
        "id",
        "ts",
        "request_id",
        "api_key_id",
        "mode",
        "endpoint",
        "action",
        "enforced_action",
        "risk",
        "reasons",
        "checks",
        "user_id",
        "ip",
        "device_id",
        "session_id",
        "message_id",
        "session_state",
        "cmp_action",
        "channel",
        "policy_id",
        "policy_version",
        "model_version",
        "ruleset_version",
        "latency_ms",
        "text_hash",
        "text_chars",
        "redacted_excerpt",
    )

    async def insert_events(self, events: list[dict[str, Any]]) -> None:
        cols = ", ".join(self.EVENT_COLUMNS)
        params = ", ".join(
            f"${i + 1}" + ("::jsonb" if c == "checks" else "") for i, c in enumerate(self.EVENT_COLUMNS)
        )
        rows = []
        for e in events:
            row = []
            for c in self.EVENT_COLUMNS:
                v = e.get(c)
                if c in ("id", "api_key_id", "policy_id") and v is not None:
                    v = UUID(str(v))
                elif c == "ts":
                    v = datetime.fromisoformat(str(v))
                elif c == "checks":
                    v = orjson.dumps(v or []).decode()
                row.append(v)
            rows.append(row)
        await self._pool.executemany(
            f"INSERT INTO security_events ({cols}) VALUES ({params}) ON CONFLICT (id) DO NOTHING",  # noqa: S608
            rows,
        )

    @staticmethod
    def _event(row: Any) -> dict[str, Any]:
        out = dict(row)
        if isinstance(out.get("checks"), str):
            out["checks"] = orjson.loads(out["checks"])
        return out

    async def search_events(self, f: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        """Newest first. ``f`` keys: action, cmp_action, reason, mode, channel, user_id, ip, session_id,
        api_key_id, label, since, until, before (ts cursor for the next page)."""
        where, args = [], []

        def add(cond: str, value: Any) -> None:
            args.append(value)
            where.append(cond.replace("?", f"${len(args)}"))

        simple = {
            "action": "action = ?",
            "cmp_action": "cmp_action = ?",
            "channel": "channel = ?",
            "api_key_id": "api_key_id = ?",
            "mode": "mode = ?",
            "user_id": "user_id = ?",
            "ip": "ip = ?",
            "session_id": "session_id = ?",
            "label": "label = ?",
            "since": "ts >= ?",
            "until": "ts < ?",
            "before": "ts < ?",
        }
        for key, cond in simple.items():
            if f.get(key) is not None:
                add(cond, f[key])
        if f.get("reason"):
            add("? = ANY(reasons)", f["reason"])
        args.append(limit)
        sql = (
            "SELECT * FROM security_events"
            + (" WHERE " + " AND ".join(where) if where else "")
            + f" ORDER BY ts DESC LIMIT ${len(args)}"
        )
        rows = await self._pool.fetch(sql, *args)
        return [self._event(r) for r in rows]

    async def get_event(self, event_id: UUID) -> dict[str, Any] | None:
        row = await self._pool.fetchrow("SELECT * FROM security_events WHERE id = $1", event_id)
        return self._event(row) if row else None

    async def label_event(
        self, event_id: UUID, label: str | None, note: str | None, by: str
    ) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            """UPDATE security_events
                  SET label = $2::text, label_note = $3::text, labeled_by = $4::text,
                      labeled_at = CASE WHEN $2::text IS NULL THEN NULL ELSE now() END
                WHERE id = $1 RETURNING *""",
            event_id,
            label,
            note,
            by,
        )
        return self._event(row) if row else None

    async def events_summary(
        self, since: datetime, channel: str | None, api_key_id: UUID | None = None
    ) -> dict[str, Any]:
        args: list[Any] = [since]
        conds = []
        for column, value in (("channel", channel), ("api_key_id", api_key_id)):
            if value is not None:
                args.append(value)
                conds.append(f"AND {column} = ${len(args)}")
        channel_cond = " ".join(conds)
        totals = await self._pool.fetchrow(
            f"""SELECT count(*) AS total,
                       count(*) FILTER (WHERE action = 'block') AS blocked,
                       count(*) FILTER (WHERE action = 'restrict') AS restricted,
                       count(*) FILTER (WHERE action = 'throttle') AS throttled,
                       count(*) FILTER (WHERE action <> enforced_action) AS monitor_only,
                       count(*) FILTER (WHERE label = 'false_positive') AS false_positives,
                       count(*) FILTER (WHERE label = 'true_positive') AS true_positives,
                       percentile_cont(0.5) WITHIN GROUP (ORDER BY latency_ms) AS p50_ms,
                       percentile_cont(0.95) WITHIN GROUP (ORDER BY latency_ms) AS p95_ms,
                       percentile_cont(0.99) WITHIN GROUP (ORDER BY latency_ms) AS p99_ms
                  FROM security_events WHERE ts >= $1 {channel_cond}""",  # noqa: S608
            *args,
        )
        by_action = await self._pool.fetch(
            f"SELECT mode, action, count(*) AS n FROM security_events WHERE ts >= $1 {channel_cond} "  # noqa: S608
            "GROUP BY mode, action ORDER BY n DESC",
            *args,
        )
        reasons = await self._pool.fetch(
            f"SELECT r AS reason, count(*) AS n FROM security_events, unnest(reasons) AS r "  # noqa: S608
            f"WHERE ts >= $1 {channel_cond} GROUP BY r ORDER BY n DESC LIMIT 20",
            *args,
        )
        hourly = await self._pool.fetch(
            f"""SELECT date_trunc('hour', ts) AS hour, count(*) AS total,
                       count(*) FILTER (WHERE action IN ('block', 'restrict', 'throttle')) AS flagged
                  FROM security_events WHERE ts >= $1 {channel_cond}
                 GROUP BY 1 ORDER BY 1""",  # noqa: S608
            *args,
        )
        out = dict(totals) if totals else {}
        out["by_mode_action"] = [dict(r) for r in by_action]
        out["top_reasons"] = [dict(r) for r in reasons]
        out["hourly"] = [dict(r) for r in hourly]
        return out

    # ---------- policies (Stage 9) ----------
    POLICY_FIELDS = (
        "id, name, channel, session_state, endpoint_pattern, sensitive, mode, thresholds, actions, "
        "description, version, active, created_at, updated_at"
    )

    @staticmethod
    def _policy(row: Any) -> dict[str, Any]:
        out = dict(row)
        for k in ("thresholds", "actions"):
            if isinstance(out.get(k), str):
                out[k] = orjson.loads(out[k])
        return out

    async def active_policies(self) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(f"SELECT {self.POLICY_FIELDS} FROM policies WHERE active")  # noqa: S608
        return [self._policy(r) for r in rows]

    async def list_policies(self, channel: str | None, include_inactive: bool) -> list[dict[str, Any]]:
        conds, args = [], []
        if channel is not None:
            args.append(channel)
            conds.append("(channel = $1 OR channel IS NULL)")
        if not include_inactive:
            conds.append("active")
        sql = f"SELECT {self.POLICY_FIELDS} FROM policies" + (
            " WHERE " + " AND ".join(conds) if conds else ""
        )  # noqa: S608
        rows = await self._pool.fetch(sql + " ORDER BY created_at", *args)
        return [self._policy(r) for r in rows]

    async def get_policy(self, policy_id: UUID) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(f"SELECT {self.POLICY_FIELDS} FROM policies WHERE id = $1", policy_id)  # noqa: S608
        return self._policy(row) if row else None

    async def policy_versions(self, policy_id: UUID) -> list[dict[str, Any]]:
        rows = await self._pool.fetch(
            "SELECT version, body, created_at, created_by FROM policy_versions WHERE policy_id = $1 ORDER BY version",
            policy_id,
        )
        return [
            {**dict(r), "body": orjson.loads(r["body"]) if isinstance(r["body"], str) else r["body"]}
            for r in rows
        ]

    async def save_policy(
        self, policy_id: UUID | None, body: dict[str, Any], by: str
    ) -> dict[str, Any] | None:
        """Create (``policy_id`` None) or replace a policy; either way a new row in policy_versions."""
        async with self._pool.acquire() as conn, conn.transaction():
            fields = (
                body["name"],
                body.get("channel"),
                body.get("session_state"),
                body["endpoint_pattern"],
                body["sensitive"],
                body["mode"],
                orjson.dumps(body["thresholds"]).decode(),
                orjson.dumps(body["actions"]).decode(),
                body["description"],
            )
            if policy_id is None:
                row = await conn.fetchrow(
                    f"""INSERT INTO policies (name, channel, session_state, endpoint_pattern, sensitive, mode,
                                              thresholds, actions, description)
                        VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9) RETURNING {self.POLICY_FIELDS}""",  # noqa: S608
                    *fields,
                )
            else:
                row = await conn.fetchrow(
                    f"""UPDATE policies SET name = $2, channel = $3, session_state = $4, endpoint_pattern = $5,
                               sensitive = $6, mode = $7, thresholds = $8::jsonb, actions = $9::jsonb,
                               description = $10, version = version + 1, updated_at = now()
                         WHERE id = $1 AND active RETURNING {self.POLICY_FIELDS}""",  # noqa: S608
                    policy_id,
                    *fields,
                )
            if row is None:
                return None
            snapshot = {
                k: body.get(k)
                for k in (
                    "name",
                    "channel",
                    "session_state",
                    "endpoint_pattern",
                    "sensitive",
                    "mode",
                    "thresholds",
                    "actions",
                    "description",
                )
            }
            await conn.execute(
                "INSERT INTO policy_versions (policy_id, version, body, created_by) VALUES ($1, $2, $3::jsonb, $4)",
                row["id"],
                row["version"],
                orjson.dumps(snapshot).decode(),
                by,
            )
            return self._policy(row)

    async def deactivate_policy(self, policy_id: UUID) -> dict[str, Any] | None:
        row = await self._pool.fetchrow(
            f"""UPDATE policies SET active = false, updated_at = now()
                 WHERE id = $1 AND active AND name <> 'global-default'
             RETURNING {self.POLICY_FIELDS}""",  # noqa: S608
            policy_id,
        )
        return self._policy(row) if row else None
