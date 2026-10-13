"""Checks on an AI reply before it is delivered (``POST /v1/inspect/outbound``, proxied responses).

Run in this order by ``build_outbound_pipeline``; a block stops the rest:

1. ``reply_size`` — very long replies are restricted (flagged; delivered).
2. ``canary``     — a canary token (or its prefix) in the reply: the system prompt leaked → BLOCK.
3. ``reply_data`` — sensitive data in the reply:
   * secrets → BLOCK (or redact, ``OUTBOUND_SECRET_ACTION``);
   * card / SIN / SSN / passport / IBAN / date of birth → always redacted;
   * identifiers (email, phone, booking ref, ticket, Aeroplan) must be in scope. The scope is the
     caller's ``allowed_identifiers`` if it sent one, otherwise the **session's**: identifiers the
     customer typed in this session are always allowed; a *verified* session also allows the ones from
     its identity verification and treats anything else as out of scope → BLOCK
     (``OUTBOUND_UNAUTHORIZED_ACTION``). In an anonymous session (or with no scope at all) other
     identifiers get ``OUTBOUND_UNSCOPED_ACTION`` (default: redact);
   * many distinct identifiers not known to be the customer's (out of scope, or unscoped) in one reply
     → BLOCK (a record dump), whatever the scope.
4. ``reply_links`` — markdown images and links outside ALLOWED_LINK_DOMAINS are stripped: a client
   that renders an image fetches its URL, which can carry data out.

Each check edits ``ctx.deliver`` (the text that may be sent); none of them returns the values found.
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.config import Settings
from app.detectors import sensitive
from app.detectors.structure import MD_IMAGE, URL
from app.outbound.canary import CanaryService, scan
from app.pipeline.checks import Check
from app.pipeline.context import RequestContext
from app.pipeline.models import Action, CheckResult
from app.session.identity import identifier_hash

MD_IMAGE_FULL = re.compile(r"!\[[^\]]*\]\([^)]*\)")


def make_reply_size_check(settings: Settings) -> Check:
    async def reply_size_check(ctx: RequestContext) -> CheckResult:
        n = len(ctx.text)
        if n > settings.outbound_max_chars:
            return CheckResult(
                name="reply_size",
                passed=False,
                score=0.5,
                action=Action.RESTRICT,
                reason="reply_too_long",
                detail={"chars": n, "limit": settings.outbound_max_chars},
            )
        return CheckResult(name="reply_size", passed=True, detail={"chars": n})

    return reply_size_check


def make_canary_check(canaries: CanaryService) -> Check:
    async def canary_check(ctx: RequestContext) -> CheckResult:
        hashes, fragment = scan(ctx.text)
        if not hashes and not fragment:
            return CheckResult(name="canary", passed=True)
        known = bool(set(hashes) & await canaries.active())
        return CheckResult(
            name="canary",
            passed=False,
            score=1.0,
            action=Action.BLOCK,
            reason="canary_leak",
            detail={"known_token": known, "full_token": bool(hashes), "partial": fragment and not hashes},
            strike=True,
            # Only an active token proves the leak; a stray prefix is strong evidence.
            evidence="deterministic" if known else "probabilistic",
        )

    return canary_check


def make_reply_data_check(settings: Settings) -> Check:
    always = sensitive.parse_types(settings.outbound_always_redact)
    scoped = sensitive.parse_types(settings.outbound_scope_types)
    hash_key = settings.identity_hash_key.get_secret_value()

    async def reply_data_check(ctx: RequestContext) -> CheckResult | None:
        text = ctx.deliver if ctx.deliver is not None else ctx.text
        findings = sensitive.find(text)
        if not findings:
            return None
        allowed = ctx.allowed_identifiers
        allowed_norm = (
            {t: {sensitive.normalize_value(t, v) for v in vals} for t, vals in allowed.items()}
            if allowed is not None
            else None
        )
        # No list from the caller: the session's scope (hashes), strict only once it is verified.
        session_scope = ctx.allowed_identifier_hashes if allowed_norm is None else None
        strict = allowed_norm is not None or (session_scope is not None and ctx.session_state == "verified")

        def in_scope(type_: str, value: str) -> bool | None:
            """True / False, or None when there is no scope to compare with."""
            if allowed_norm is not None:
                return value in allowed_norm.get(type_, set())
            if session_scope is not None:
                h = identifier_hash(hash_key, type_, value, normalized=True)
                if h in session_scope.get(type_, set()):
                    return True
                return False if strict else None
            return None

        redact: list[sensitive.SensitiveFinding] = []
        secrets_found: list[str] = []
        out_of_scope: dict[str, int] = {}
        unscoped: list[str] = []
        distinct_out: set[tuple[str, str]] = set()
        for f, value in sensitive.values(text, findings):
            if f.category == "secret":
                secrets_found.append(f.type)
                redact.append(f)
            elif f.type in always:
                redact.append(f)
            elif f.type in scoped:
                verdict = in_scope(f.type, value)
                if verdict is None:
                    unscoped.append(f.type)
                    # Not known to be this customer's: counts towards a record dump like out-of-scope data.
                    distinct_out.add((f.type, value))
                    if settings.outbound_unscoped_action == "redact":
                        redact.append(f)
                elif not verdict:
                    out_of_scope[f.type] = out_of_scope.get(f.type, 0) + 1
                    distinct_out.add((f.type, value))
                    redact.append(f)
        ctx.redactions = [f.public() | {"redacted": f in redact} for f in findings]
        ctx.deliver = sensitive.redact(text, redact)
        scope_source = "caller" if allowed is not None else "session" if session_scope is not None else "none"
        detail = {
            "types": sorted({f.type for f in findings}),
            "redacted": sorted({f.type for f in redact}),
            "secrets": sorted(set(secrets_found)),
            "out_of_scope": out_of_scope,
            "unscoped": sorted(set(unscoped)),
            "scope_provided": allowed is not None,
            "scope": scope_source,
            "scope_strict": strict,
        }

        def block(reason: str, score: float) -> CheckResult:
            return CheckResult(
                name="reply_data",
                passed=False,
                score=score,
                action=Action.BLOCK,
                reason=reason,
                detail=detail,
                strike=True,
                evidence="probabilistic",
            )

        if secrets_found and settings.outbound_secret_action == "block":  # noqa: S105
            return block("secret_in_reply", 1.0)
        if len(distinct_out) >= settings.outbound_bulk_identifiers:
            return block("bulk_data", 1.0)
        if out_of_scope and settings.outbound_unauthorized_action == "block":
            return block("unauthorized_data", 0.95)
        if unscoped and settings.outbound_unscoped_action == "block":
            return CheckResult(
                name="reply_data",
                passed=False,
                score=0.6,
                action=Action.BLOCK,
                reason="unverified_identifiers",
                detail=detail,
            )
        return CheckResult(name="reply_data", passed=True, detail=detail)

    return reply_data_check


def make_reply_links_check(settings: Settings) -> Check:
    allowed = tuple(d.strip().lower() for d in settings.allowed_link_domains.split(",") if d.strip())

    def ok_host(url: str) -> bool:
        host = (urlsplit(url).hostname or "").lower()
        return any(host == d or host.endswith("." + d) for d in allowed)

    async def reply_links_check(ctx: RequestContext) -> CheckResult | None:
        text = ctx.deliver if ctx.deliver is not None else ctx.text
        images = links = 0
        if settings.outbound_strip_images:
            images = len(MD_IMAGE.findall(text))
            text = MD_IMAGE_FULL.sub("[image removed]", text)
        if settings.outbound_strip_unknown_links:

            def strip(m: re.Match[str]) -> str:
                nonlocal links
                if ok_host(m.group(0)):
                    return m.group(0)
                links += 1
                return "[link removed]"

            text = URL.sub(strip, text)
        if not images and not links:
            return None
        ctx.deliver = text
        return CheckResult(
            name="reply_links", passed=True, detail={"images_removed": images, "links_removed": links}
        )

    return reply_links_check
