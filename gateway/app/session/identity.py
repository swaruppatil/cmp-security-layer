"""Keyed hashes for customer data the gateway must recognise but should not keep.

* ``customer_key`` — CMP's customer id (an Aeroplan number, a profile id …) becomes ``cu_<hex>``.
  That is the ``user`` identity everywhere: rate limits, reputation, strikes, bans, the audit trail
  and the dashboard. An admin can ban either form: a raw id is hashed on the way in.
* ``identifier_hash`` — booking references, emails, phones … a session may see in AI replies, stored
  as hashes of their normalised value.

HMAC-SHA256 with ``IDENTITY_HASH_KEY``: without the key, a hash cannot be reversed by trying every
booking reference or Aeroplan number.
"""

from __future__ import annotations

import hashlib
import hmac

from app.detectors import sensitive

CUSTOMER_PREFIX = "cu_"


def _mac(key: str, message: str) -> str:
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def customer_key(key: str, customer_id: str | None) -> str | None:
    """``cu_<32 hex>`` for a raw customer id; an already-hashed value is returned unchanged."""
    if customer_id is None or not customer_id.strip():
        return None
    value = customer_id.strip()
    if value.startswith(CUSTOMER_PREFIX):
        return value
    return CUSTOMER_PREFIX + _mac(key, f"customer:{value}")[:32]


def identifier_hash(key: str, type_: str, value: str, *, normalized: bool = False) -> str:
    norm = value if normalized else sensitive.normalize_value(type_, value)
    return _mac(key, f"id:{type_}:{norm}")[:24]


def hash_identifiers(key: str, identifiers: dict[str, list[str]]) -> dict[str, set[str]]:
    return {t: {identifier_hash(key, t, v) for v in vals if v.strip()} for t, vals in identifiers.items()}
