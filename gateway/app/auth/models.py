from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID


@dataclass(frozen=True)
class Principal:
    """Who is calling the gateway: one caller API key (CMP's enricher, its processor, a test tool …).

    There are no tenants: the gateway protects one product. Keys differ only in name and scopes."""

    api_key_id: UUID
    name: str
    api_key_prefix: str
    scopes: frozenset[str]

    def has_scope(self, scope: str) -> bool:
        return scope in self.scopes


@dataclass(frozen=True)
class ApiKeyRecord:
    """An api_keys row, as the auth service needs it."""

    id: UUID
    name: str
    prefix: str
    key_hash: str
    scopes: tuple[str, ...]
    status: str
    expires_at: datetime | None
