"""API key format, generation and hashing.

Format: ``cmpsk_<prefix>_<secret>``

* ``prefix`` — 10 hex characters, stored in clear and indexed, so a key can be looked up without
  scanning every hash. It also lets admins identify a key ("cmpsk_3fa9c1d2e0_…") without seeing it.
* ``secret`` — 32 random bytes, URL-safe base64.

Only the SHA-256 of the full key is stored. A slow password hash (bcrypt/argon2) is not needed:
keys are 256-bit random values, so brute force is infeasible, and SHA-256 keeps verification in
microseconds on the hot path.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass

KEY_SCHEME = "cmpsk"
PREFIX_HEX_CHARS = 10
SECRET_BYTES = 32


@dataclass(frozen=True)
class ParsedKey:
    prefix: str
    full: str


@dataclass(frozen=True)
class NewKey:
    plaintext: str  # shown to the admin exactly once
    prefix: str
    key_hash: str


def hash_key(full_key: str) -> str:
    return hashlib.sha256(full_key.encode("utf-8")).hexdigest()


def generate_key() -> NewKey:
    prefix = secrets.token_hex(PREFIX_HEX_CHARS // 2)
    secret = secrets.token_urlsafe(SECRET_BYTES)
    plaintext = f"{KEY_SCHEME}_{prefix}_{secret}"
    return NewKey(plaintext=plaintext, prefix=prefix, key_hash=hash_key(plaintext))


def parse_key(raw: str | None) -> ParsedKey | None:
    """Return the parsed key, or None if it is not in the expected format."""
    if not raw:
        return None
    raw = raw.strip()
    parts = raw.split("_", 2)
    if len(parts) != 3:
        return None
    scheme, prefix, secret = parts
    if scheme != KEY_SCHEME or len(prefix) != PREFIX_HEX_CHARS or not secret:
        return None
    if any(c not in "0123456789abcdef" for c in prefix):
        return None
    if len(raw) > 128:
        return None
    return ParsedKey(prefix=prefix, full=raw)


def hashes_match(stored_hash: str, candidate_full_key: str) -> bool:
    """Constant-time comparison of a stored hash with a presented key."""
    return hmac.compare_digest(stored_hash, hash_key(candidate_full_key))


def extract_presented_key(authorization: str | None, x_api_key: str | None) -> str | None:
    """Accept ``Authorization: Bearer <key>`` or ``X-API-Key: <key>``."""
    if x_api_key:
        return x_api_key.strip()
    if authorization:
        scheme, _, value = authorization.partition(" ")
        if scheme.lower() == "bearer" and value:
            return value.strip()
    return None
