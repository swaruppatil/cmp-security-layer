"""Publish a passed customer message to CMP's Kafka topic.

CMP's enricher publishes each customer message to a Kafka topic for the AI agent. With the gateway in
the path, the enricher sends the record it *would* publish along with the inspect request
(``InspectRequest.publish``); when the decision is ``deliver`` or ``forward_without_tools`` the gateway
publishes that record itself, with the message text replaced by the redacted text when anything was
redacted, and with headers that carry the decision. A refused message is never published. The
response says whether the publish happened (``published``), so the enricher can fall back to
publishing on its own if the broker was unreachable.

Connection: ``KAFKA_BOOTSTRAP_SERVERS`` (empty = publishing disabled). Amazon MSK with IAM
authentication is the default (``KAFKA_SECURITY_PROTOCOL=SASL_SSL``, ``KAFKA_SASL_MECHANISM=AWS_MSK_IAM``:
the task role signs a token per connection). SCRAM (``SCRAM-SHA-512`` with ``KAFKA_SASL_USERNAME`` /
``KAFKA_SASL_PASSWORD``), plain ``SSL`` and ``PLAINTEXT`` (local brokers) are also supported.

The producer is created lazily on the first publish and kept for the life of the process; every
``send`` is bounded by ``KAFKA_TIMEOUT_MS`` so a slow broker cannot hold a decision hostage.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
import time
from typing import Any

import orjson

from app.config import Settings

log = logging.getLogger("gateway.kafka")


class PublishError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _headers(items: dict[str, str]) -> list[tuple[str, bytes]]:
    return [(k, v.encode()) for k, v in items.items()]


class KafkaPublisher:
    """One producer per process. ``enabled`` is False when no bootstrap servers are configured."""

    def __init__(self, settings: Settings) -> None:
        self._s = settings
        self._producer: Any | None = None
        self._lock = asyncio.Lock()
        self.enabled = bool(settings.kafka_bootstrap_servers.strip())
        self.topic = settings.kafka_topic
        self.allowed_topics = {settings.kafka_topic} | {
            t.strip() for t in settings.kafka_topics_allowed.split(",") if t.strip()
        }
        self.failures = 0

    async def _start(self) -> Any:
        from aiokafka import AIOKafkaProducer

        s = self._s
        kwargs: dict[str, Any] = {
            "bootstrap_servers": [b.strip() for b in s.kafka_bootstrap_servers.split(",") if b.strip()],
            "client_id": s.kafka_client_id,
            "acks": "all",
            "request_timeout_ms": s.kafka_timeout_ms,
            "linger_ms": 0,
            "enable_idempotence": True,
        }
        protocol = s.kafka_security_protocol
        if protocol in ("SSL", "SASL_SSL"):
            kwargs["security_protocol"] = protocol
            kwargs["ssl_context"] = ssl.create_default_context()
        else:
            kwargs["security_protocol"] = "PLAINTEXT"
        if protocol == "SASL_SSL":
            if s.kafka_sasl_mechanism == "AWS_MSK_IAM":
                kwargs["sasl_mechanism"] = "OAUTHBEARER"
                kwargs["sasl_oauth_token_provider"] = MskIamTokenProvider(s.kafka_aws_region)
            else:
                kwargs["sasl_mechanism"] = s.kafka_sasl_mechanism
                kwargs["sasl_plain_username"] = s.kafka_sasl_username
                kwargs["sasl_plain_password"] = (
                    s.kafka_sasl_password.get_secret_value() if s.kafka_sasl_password else ""
                )
        producer = AIOKafkaProducer(**kwargs)
        await asyncio.wait_for(producer.start(), timeout=s.kafka_timeout_ms / 1000)
        log.info("kafka producer connected", extra={"topic": self.topic})
        return producer

    async def producer(self) -> Any:
        if self._producer is None:
            async with self._lock:
                if self._producer is None:
                    self._producer = await self._start()
        return self._producer

    async def publish(
        self, key: str | None, value: Any, headers: dict[str, str], topic: str | None = None
    ) -> dict[str, Any]:
        """Send one record to ``topic`` (default: the configured topic); returns ``{"topic",
        "partition", "offset", "ms"}``. Raises ``PublishError`` (``topic_not_allowed`` for a topic
        outside the allow-list)."""
        if not self.enabled:
            raise PublishError("disabled")
        topic = topic or self.topic
        if topic not in self.allowed_topics:
            raise PublishError("topic_not_allowed")
        started = time.perf_counter()
        try:
            producer = await self.producer()
            payload = value.encode() if isinstance(value, str) else orjson.dumps(value)
            meta = await asyncio.wait_for(
                producer.send_and_wait(
                    topic, payload, key=key.encode() if key else None, headers=_headers(headers)
                ),
                timeout=self._s.kafka_timeout_ms / 1000,
            )
        except TimeoutError:
            self.failures += 1
            raise PublishError("timeout") from None
        except Exception as exc:  # noqa: BLE001 - any broker/client failure is reported to the caller
            self.failures += 1
            log.warning("kafka publish failed: %s", type(exc).__name__)
            raise PublishError(type(exc).__name__) from None
        return {
            "topic": meta.topic,
            "partition": meta.partition,
            "offset": meta.offset,
            "ms": round((time.perf_counter() - started) * 1000, 1),
        }

    async def close(self) -> None:
        if self._producer is not None:
            try:
                await asyncio.wait_for(self._producer.stop(), timeout=5)
            except Exception as exc:  # noqa: BLE001 - shutting down: nothing to do but note it
                log.warning("kafka producer stop failed: %s", type(exc).__name__)
            self._producer = None


class MskIamTokenProvider:
    """OAUTHBEARER token provider for Amazon MSK IAM authentication (signed with the task role)."""

    def __init__(self, region: str) -> None:
        self._region = region

    async def token(self) -> str:
        from aws_msk_iam_sasl_signer import MSKAuthTokenProvider

        token, _expiry_ms = await asyncio.to_thread(MSKAuthTokenProvider.generate_auth_token, self._region)
        return str(token)

    def extensions(self) -> dict[str, str]:
        return {}


def set_path(obj: Any, path: str, value: Any) -> bool:
    """Set ``path`` ("body.text", "messages[0].content") inside a JSON-like value in place.
    Returns False when the path does not resolve."""
    import re

    parts = [p for p in re.split(r"\.|(\[\d+\])", path) if p]
    node = obj
    for i, part in enumerate(parts):
        last = i == len(parts) - 1
        if part.startswith("["):
            idx = int(part[1:-1])
            if not isinstance(node, list) or idx >= len(node):
                return False
            if last:
                node[idx] = value
                return True
            node = node[idx]
        else:
            if not isinstance(node, dict) or part not in node:
                return False
            if last:
                node[part] = value
                return True
            node = node[part]
    return False
