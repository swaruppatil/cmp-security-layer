"""In-memory fakes so unit tests run without Redis, Postgres or real HTTP services."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import re
import struct
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import fakeredis
import httpx

from app.auth.keys import generate_key
from app.auth.models import ApiKeyRecord
from app.config import Settings
from app.deps import Deps, Probe

ADMIN_KEY = "test-admin-key-123"


def make_settings(**overrides: Any) -> Settings:
    base: dict[str, Any] = {
        "admin_api_key": ADMIN_KEY,
        "max_prompt_chars": 50,
        "ready_probe_timeout_ms": 100,
        "audit_claim_idle_seconds": 1,
    }
    base.update(overrides)
    return Settings(**base)


class FakeRedis(fakeredis.FakeAsyncRedis):
    """fakeredis (runs the real Lua scripts via lupa) that also records what was published."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.published: list[tuple[str, str]] = []

    async def publish(self, channel: Any, message: Any) -> int:  # type: ignore[override]
        self.published.append((str(channel), str(message)))
        return int(await super().publish(channel, message))


class FakeRepo:
    """Implements the Repository methods the gateway uses."""

    def __init__(self) -> None:
        self.keys: dict[UUID, dict[str, Any]] = {}
        self.bans: dict[UUID, dict[str, Any]] = {}
        self.strikes: list[dict[str, Any]] = []
        self.canaries: dict[UUID, dict[str, Any]] = {}
        self.prompts: dict[UUID, dict[str, Any]] = {}
        self.events: dict[UUID, dict[str, Any]] = {}
        self.fail_event_inserts = False
        self.policies: dict[UUID, dict[str, Any]] = {}
        self.versions: list[dict[str, Any]] = []
        default = uuid.uuid4()
        self.policies[default] = {
            "id": default,
            "name": "global-default",
            "channel": None,
            "session_state": None,
            "endpoint_pattern": "*",
            "sensitive": False,
            "mode": "enforce",
            "thresholds": {},
            "actions": {},
            "description": "",
            "version": 1,
            "active": True,
            "created_at": datetime.now(UTC),
            "updated_at": datetime.now(UTC),
        }
        self.fail_ban_loads = False

    # --- audit events ---
    async def insert_events(self, events: list[dict[str, Any]]) -> None:
        if self.fail_event_inserts:
            raise ConnectionError("postgres down")
        for e in events:
            row = {
                **e,
                "id": UUID(e["id"]),
                "ts": datetime.fromisoformat(e["ts"]),
                "label": None,
                "label_note": None,
                "labeled_by": None,
                "labeled_at": None,
            }
            self.events.setdefault(row["id"], row)

    async def search_events(self, f: dict[str, Any], limit: int) -> list[dict[str, Any]]:
        rows = sorted(self.events.values(), key=lambda r: r["ts"], reverse=True)

        def ok(r: dict[str, Any]) -> bool:
            for k in ("action", "cmp_action", "channel", "mode", "user_id", "ip", "session_id", "label"):
                if f.get(k) is not None and r.get(k) != f[k]:
                    return False
            if f.get("api_key_id") is not None and r.get("api_key_id") != str(f["api_key_id"]):
                return False
            if f.get("reason") and f["reason"] not in r["reasons"]:
                return False
            return not (f.get("before") is not None and r["ts"] >= f["before"])

        return [r for r in rows if ok(r)][:limit]

    async def get_event(self, event_id: UUID) -> dict[str, Any] | None:
        return self.events.get(event_id)

    async def label_event(
        self, event_id: UUID, label: str | None, note: str | None, by: str
    ) -> dict[str, Any] | None:
        row = self.events.get(event_id)
        if row is None:
            return None
        row.update(
            label=label, label_note=note, labeled_by=by, labeled_at=datetime.now(UTC) if label else None
        )
        return row

    async def events_summary(
        self, since: datetime, channel: str | None, api_key_id: Any = None
    ) -> dict[str, Any]:
        rows = [
            r
            for r in self.events.values()
            if r["ts"] >= since and (channel is None or r["channel"] == channel)
        ]
        count = lambda pred: sum(1 for r in rows if pred(r))  # noqa: E731
        return {
            "total": len(rows),
            "blocked": count(lambda r: r["action"] == "block"),
            "restricted": count(lambda r: r["action"] == "restrict"),
            "throttled": count(lambda r: r["action"] == "throttle"),
            "monitor_only": count(lambda r: r["action"] != r["enforced_action"]),
            "false_positives": count(lambda r: r["label"] == "false_positive"),
            "true_positives": count(lambda r: r["label"] == "true_positive"),
            "p50_ms": None,
            "p95_ms": None,
            "p99_ms": None,
            "by_mode_action": [],
            "top_reasons": [],
            "hourly": [],
        }

    # --- policies ---
    async def active_policies(self) -> list[dict[str, Any]]:
        return [dict(p) for p in self.policies.values() if p["active"]]

    async def list_policies(self, channel: str | None, include_inactive: bool) -> list[dict[str, Any]]:
        return [
            dict(p)
            for p in self.policies.values()
            if (channel is None or p["channel"] in (None, channel)) and (include_inactive or p["active"])
        ]

    async def get_policy(self, policy_id: UUID) -> dict[str, Any] | None:
        p = self.policies.get(policy_id)
        return dict(p) if p else None

    async def policy_versions(self, policy_id: UUID) -> list[dict[str, Any]]:
        return [v for v in self.versions if v["policy_id"] == policy_id]

    async def save_policy(
        self, policy_id: UUID | None, body: dict[str, Any], by: str
    ) -> dict[str, Any] | None:
        keys = (
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
        body = {"channel": None, "session_state": None, **body}
        if policy_id is None:
            for p in self.policies.values():
                if p["active"] and all(
                    p[k] == body[k] for k in ("channel", "session_state", "endpoint_pattern")
                ):
                    raise ValueError("duplicate key value violates unique constraint")
            policy_id = uuid.uuid4()
            self.policies[policy_id] = {
                "id": policy_id,
                "version": 1,
                "active": True,
                "created_at": datetime.now(UTC),
                "updated_at": datetime.now(UTC),
                **{k: body[k] for k in keys},
            }
        else:
            p = self.policies.get(policy_id)
            if p is None or not p["active"]:
                return None
            p.update({k: body[k] for k in keys}, version=p["version"] + 1, updated_at=datetime.now(UTC))
        row = self.policies[policy_id]
        self.versions.append(
            {
                "policy_id": policy_id,
                "version": row["version"],
                "body": {k: body[k] for k in keys},
                "created_at": datetime.now(UTC),
                "created_by": by,
            }
        )
        return dict(row)

    async def deactivate_policy(self, policy_id: UUID) -> dict[str, Any] | None:
        p = self.policies.get(policy_id)
        if p is None or not p["active"] or p["name"] == "global-default":
            return None
        p["active"] = False
        return dict(p)

    # --- protected prompts ---
    async def create_protected_prompt(
        self, label: str, shingles: list[str], word_count: int
    ) -> dict[str, Any]:
        pid = uuid.uuid4()
        self.prompts[pid] = {
            "id": pid,
            "label": label,
            "shingles": shingles,
            "word_count": word_count,
            "created_at": datetime.now(UTC),
            "revoked_at": None,
        }
        return {k: v for k, v in self.prompts[pid].items() if k != "shingles"}

    async def list_protected_prompts(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in r.items() if k != "shingles"} for r in self.prompts.values()]

    async def revoke_protected_prompt(self, prompt_id: UUID) -> dict[str, Any] | None:
        r = self.prompts.get(prompt_id)
        if r is None or r["revoked_at"] is not None:
            return None
        r["revoked_at"] = datetime.now(UTC)
        return {k: v for k, v in r.items() if k != "shingles"}

    async def active_prompt_shingles(self) -> list[dict[str, Any]]:
        return [
            {"id": r["id"], "shingles": r["shingles"]}
            for r in self.prompts.values()
            if r["revoked_at"] is None
        ]

    # --- canaries ---
    async def create_canary(self, label: str, token_hash: str) -> dict[str, Any]:
        cid = uuid.uuid4()
        self.canaries[cid] = {
            "id": cid,
            "label": label,
            "token_hash": token_hash,
            "created_at": datetime.now(UTC),
            "revoked_at": None,
        }
        return {k: v for k, v in self.canaries[cid].items() if k != "token_hash"}

    async def list_canaries(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in c.items() if k != "token_hash"} for c in self.canaries.values()]

    async def revoke_canary(self, canary_id: UUID) -> dict[str, Any] | None:
        c = self.canaries.get(canary_id)
        if c is None or c["revoked_at"] is not None:
            return None
        c["revoked_at"] = datetime.now(UTC)
        return {k: v for k, v in c.items() if k != "token_hash"}

    async def active_canary_hashes(self) -> list[str]:
        return [c["token_hash"] for c in self.canaries.values() if c["revoked_at"] is None]

    # --- helpers for tests ---
    def add_key(
        self,
        scopes: tuple[str, ...] = ("inspect", "outbound", "proxy"),
        status: str = "active",
        expires_at: datetime | None = None,
    ) -> str:
        new = generate_key()
        kid = uuid.uuid4()
        self.keys[kid] = {
            "id": kid,
            "name": "test",
            "prefix": new.prefix,
            "key_hash": new.key_hash,
            "scopes": list(scopes),
            "status": status,
            "created_at": datetime.now(UTC),
            "expires_at": expires_at,
            "revoked_at": None,
            "last_used_at": None,
        }
        return new.plaintext

    # --- Repository interface ---
    async def find_key_by_prefix(self, prefix: str) -> ApiKeyRecord | None:
        for k in self.keys.values():
            if k["prefix"] == prefix:
                return ApiKeyRecord(
                    id=k["id"],
                    name=k["name"],
                    prefix=k["prefix"],
                    key_hash=k["key_hash"],
                    scopes=tuple(k["scopes"]),
                    status=k["status"],
                    expires_at=k["expires_at"],
                )
        return None

    async def create_api_key(
        self, name: str, prefix: str, key_hash: str, scopes: list[str], expires_at: Any
    ) -> dict[str, Any]:
        kid = uuid.uuid4()
        self.keys[kid] = {
            "id": kid,
            "name": name,
            "prefix": prefix,
            "key_hash": key_hash,
            "scopes": scopes,
            "status": "active",
            "created_at": datetime.now(UTC),
            "expires_at": expires_at,
            "revoked_at": None,
            "last_used_at": None,
        }
        return {k: v for k, v in self.keys[kid].items() if k != "key_hash"}

    async def ensure_api_key(self, name: str, prefix: str, key_hash: str, scopes: list[str]) -> bool:
        if any(k["prefix"] == prefix for k in self.keys.values()):
            return False
        await self.create_api_key(name, prefix, key_hash, scopes, None)
        return True

    async def list_api_keys(self) -> list[dict[str, Any]]:
        return [{k: v for k, v in key.items() if k != "key_hash"} for key in self.keys.values()]

    async def revoke_api_key(self, key_id: UUID) -> str | None:
        key = self.keys.get(key_id)
        if key is None:
            return None
        key["status"] = "revoked"
        return str(key["key_hash"])

    # --- bans / strikes ---
    @staticmethod
    def _is_active(b: dict[str, Any]) -> bool:
        return b["revoked_at"] is None and (b["permanent"] or b["expires_at"] > datetime.now(UTC))

    async def load_active_bans(self) -> list[dict[str, Any]]:
        if self.fail_ban_loads:
            raise ConnectionError("postgres down")
        return [dict(b) for b in self.bans.values() if self._is_active(b)]

    async def create_ban(self, **fields: Any) -> dict[str, Any]:
        bid = uuid.uuid4()
        self.bans[bid] = {
            "id": bid,
            "created_at": datetime.now(UTC),
            "revoked_at": None,
            "revoked_by": None,
            **fields,
        }
        return dict(self.bans[bid])

    async def create_bans_bulk(self, rows: list[dict[str, Any]]) -> int:
        for r in rows:
            await self.create_ban(**r, evidence={}, permanent=True, expires_at=None)
        return len(rows)

    async def revoke_ban(self, ban_id: UUID, revoked_by: str) -> dict[str, Any] | None:
        b = self.bans.get(ban_id)
        if b is None:
            return None
        b["revoked_at"] = b["revoked_at"] or datetime.now(UTC)
        b["revoked_by"] = b["revoked_by"] or revoked_by
        return dict(b)

    async def list_bans(
        self,
        *,
        active_only: bool,
        entity_type: str | None,
        value: str | None,
        limit: int,
    ) -> list[dict[str, Any]]:
        out = [
            dict(b)
            for b in self.bans.values()
            if (not active_only or self._is_active(b))
            and (entity_type is None or b["entity_type"] == entity_type)
            and (value is None or b["value"] == value)
        ]
        return out[:limit]

    async def record_strike(self, **fields: Any) -> None:
        self.strikes.append(dict(fields))

    async def list_strikes(self, entity_type: str, value: str, limit: int = 50) -> list[dict[str, Any]]:
        return [s for s in self.strikes if s["entity_type"] == entity_type and s["value"] == value][:limit]


Handler = Callable[[httpx.Request], httpx.Response]


def upstream_echo(request: httpx.Request) -> httpx.Response:
    """Default fake AI app: echoes what it received."""
    return httpx.Response(
        200,
        json={
            "path": request.url.path,
            "method": request.method,
            "body": request.content.decode(),
            "headers": {k: v for k, v in request.headers.items()},
        },
    )


def rules_agree(text: str) -> float:
    """Default fake score: what a sane model says. Text the rule engine finds high-severity scores
    0.95 (so provisional phrase-rule blocks are confirmed, as the real model does), the rest 0.01."""
    from app.detectors.engine import analyze

    return 0.95 if analyze([text], allowed_link_domains=(), max_links=5).severity == "high" else 0.01


def ml_scores(
    score_for: Callable[[str], float] = rules_agree, thresholds: dict[str, float] | None = None
) -> Handler:
    """Fake ML service: answers /v1/score like the real one, with one score per text. With
    ``thresholds`` it also sends the model's calibrated operating point and score components."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/health":
            return httpx.Response(200, json={"status": "ok"})
        texts = json.loads(request.content)["texts"]
        body: dict[str, Any] = {
            "model_version": "fake-1",
            "latency_ms": 0.1,
            "results": [{"score": score_for(t)} for t in texts],
        }
        if thresholds:
            body["thresholds"] = thresholds
            for r in body["results"]:
                r["components"] = {"ngram": r["score"], "nearest_attack_family": "instruction_override"}
        return httpx.Response(200, json=body)

    return handler


def bow_vector(text: str, dim: int = 64) -> list[float]:
    """Unit-length hashed bag of words: texts sharing most words get a high cosine."""
    v = [0.0] * dim
    for w in re.findall(r"\w+", text.lower()):
        v[int(hashlib.md5(w.encode()).hexdigest(), 16) % dim] += 1.0  # noqa: S324 - not security
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


def encode_vector(v: list[float]) -> str:
    return base64.b64encode(struct.pack(f"<{len(v)}e", *v)).decode()


def ml_conversational(
    score_for: Callable[[str], float] = lambda _t: 0.05,
    thresholds: dict[str, float] | None = None,
    calls: list[dict[str, Any]] | None = None,
) -> Handler:
    """Fake ML service with everything conversation analysis uses: thresholds, components (attack
    and benign similarity derived from the score) and, when asked, bag-of-words vectors."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        if calls is not None:
            calls.append(body)
        results = []
        for t in body["texts"]:
            sc = score_for(t)
            results.append(
                {
                    "score": sc,
                    "components": {
                        "ngram": sc,
                        "embedding": sc,
                        "attack_similarity": sc,
                        "benign_similarity": 1 - sc,
                        "nearest_attack_family": "x",
                    },
                    "vector": encode_vector(bow_vector(t)) if body.get("return_vectors") else None,
                }
            )
        return httpx.Response(
            200,
            json={
                "model_version": "fake-conv",
                "latency_ms": 0.1,
                "thresholds": thresholds or {"block": 0.9, "restrict": 0.7},
                "results": results,
            },
        )

    return handler


def make_deps(
    upstream: Handler = upstream_echo, probes: list[Probe] | None = None, ml: Handler | None = None
) -> Deps:
    async def ok() -> None:
        return None

    return Deps(
        redis=FakeRedis(),
        db=None,
        upstream=httpx.AsyncClient(transport=httpx.MockTransport(upstream), base_url="http://upstream"),
        ml=httpx.AsyncClient(transport=httpx.MockTransport(ml or ml_scores()), base_url="http://ml"),
        probes=probes
        if probes is not None
        else [Probe("redis", ok), Probe("postgres", ok), Probe("ml-service", ok)],
    )
