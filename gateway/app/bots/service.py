"""Bot score: combine an identity's features into 0..1 and pick a throttle tier.

Weights (deliberately simple and readable; trainable later):

| signal      | condition                                                          | weight |
|-------------|--------------------------------------------------------------------|--------|
| timer       | gap variation (CV) < BOT_REGULAR_CV over ≥ BOT_MIN_GAPS fast gaps  | 0.45   |
| fast_typing | ≥ half of the recent long messages faster than BOT_FAST_CPS        | 0.35   |
| campaign    | the same long message from ≥ BOT_CAMPAIGN_IDENTITIES identities     | 0.40   |
| repetition  | ≥ BOT_DUP_COUNT near-duplicates of this message in the window      | 0.30   |
| rate        | more than BOT_RATE_PER_MINUTE requests in the last minute          | 0.30   |
| automation_ua | user agent of an HTTP library / headless browser (web channel only) | 0.25 |
| missing_ua  | no user agent where one is expected (proxy mode)                   | 0.15   |
| hosting_ip  | IP inside BOT_HOSTING_CIDRS                                        | 0.15   |

No single signal reaches the "likely bot" tier (0.6) on its own; it takes two independent ones.
The score is the highest over the request's identities (user, device, session, IP). IPs in NEVER_BAN_CIDRS —
shared proxies such as CMP's own servers — are not profiled: all their users would look like one bot.

Tiers: < BOT_SUSPECT_AT normal; suspect → the end user's rate-limit buckets cost BOT_SUSPECT_COST per
request; likely → BOT_LIKELY_COST; ≥ BOT_BLOCK_AT → throttled for BOT_COOLDOWN_SECONDS. Repeated
throttles become strikes and bans through the Stage 3 ladder, so a persistent bot escalates.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.bots.features import Event, Features, bands, compute, simhash
from app.config import Settings
from app.entities import Entity, parse_cidr_list, parse_ip
from app.state.scripts import BOT

WEIGHTS = {
    "timer": 0.45,
    "fast_typing": 0.35,
    "campaign": 0.40,
    "repetition": 0.30,
    "rate": 0.30,
    "automation_ua": 0.25,
    "missing_ua": 0.15,
    "hosting_ip": 0.15,
}


@dataclass
class BotAssessment:
    score: float
    tier: str  # normal | suspect | likely | bot
    cost: float  # multiplier for the end user's rate-limit buckets
    signals: list[str]
    features: dict[str, dict[str, Any]] = field(default_factory=dict)
    campaign_identities: int = 0


def identity_signals(f: Features, s: Settings) -> list[str]:
    out = []
    if f.gap_cv is not None and f.mean_gap_s is not None:
        if f.gap_cv < s.bot_regular_cv and f.mean_gap_s <= s.bot_regular_max_gap_seconds:
            out.append("timer")
    if f.judged >= 2 and f.fast_share >= 0.5:
        out.append("fast_typing")
    if f.duplicates >= s.bot_dup_count:
        out.append("repetition")
    if f.rate_per_min > s.bot_rate_per_minute:
        out.append("rate")
    return out


def tier_for(score: float, s: Settings) -> tuple[str, float]:
    if score >= s.bot_block_at:
        return "bot", s.bot_likely_cost
    if score >= s.bot_likely_at:
        return "likely", s.bot_likely_cost
    if score >= s.bot_suspect_at:
        return "suspect", s.bot_suspect_cost
    return "normal", 1.0


class BotService:
    def __init__(self, redis: Any, settings: Settings, clock: Callable[[], float] = time.time) -> None:
        self._s = settings
        self._script = redis.register_script(BOT)
        self._never = parse_cidr_list(settings.never_ban_cidrs)
        self._hosting = (
            parse_cidr_list(settings.bot_hosting_cidrs) if settings.bot_hosting_cidrs.strip() else []
        )
        self._agents = tuple(
            a.strip().lower() for a in settings.bot_automation_user_agents.split(",") if a.strip()
        )
        self.clock = clock

    def _in(self, ip: str | None, nets: list[Any]) -> bool:
        addr = parse_ip(ip)
        return addr is not None and any(addr in n for n in nets if addr.version == n.version)

    def profiled(self, entities: list[Entity]) -> list[Entity]:
        """Who to profile. A request with a user or device id is profiled through that identity only:
        an IP may be shared by many people (Wi-Fi, carrier NAT), whose traffic together would look like
        one fast bot. Anonymous requests are profiled by IP — except trusted shared IPs (never-ban list).
        A session id alone is not an identity a bot has to keep (chats are free to open), so such
        requests are profiled by the session *and* the IP (BOT_PROFILE_IP_FOR_SESSION_ONLY)."""
        personal = [e for e in entities if e.type != "ip"]
        ips = [e for e in entities if e.type == "ip" and not self._in(e.value, self._never)]
        if any(e.type in ("user", "device") for e in personal):
            return personal
        if personal:  # session only
            return personal + (ips if self._s.bot_profile_ip_for_session_only else [])
        return ips

    async def assess(
        self,
        entities: list[Entity],
        text: str,
        *,
        user_agent: str | None,
        user_agent_expected: bool,
        ip: str | None,
    ) -> BotAssessment | None:
        s = self._s
        who = self.profiled(entities)
        if not who:
            return None
        now_ms = int(self.clock() * 1000)
        words = len(text.split())
        fp = simhash(text) if text else None
        current = Event(now_ms, len(text), fp)
        campaign_keys = (
            [f"botc:{b}" for b in bands(fp)] if fp is not None and words >= s.bot_campaign_min_words else []
        )
        raw = await self._script(
            keys=[f"bot:{e.key()}" for e in who] + campaign_keys,
            args=[
                len(who),
                now_ms,
                current.encode(),
                s.bot_window_events,
                s.bot_ttl_seconds,
                s.bot_campaign_window_seconds * 1000,
                who[0].key(),
            ],
        )
        signals: set[str] = set()
        per: dict[str, dict[str, Any]] = {}
        for e, hist in zip(who, raw[: len(who)], strict=True):
            history = [ev for ev in (Event.decode(x) for x in hist) if ev is not None]
            f = compute(
                history,
                current,
                min_gaps=s.bot_min_gaps,
                fast_cps=s.bot_fast_cps,
                fast_min_chars=s.bot_fast_min_chars,
                dup_distance=s.bot_dup_distance,
            )
            sig = identity_signals(f, s)
            signals.update(sig)
            per[e.type] = {
                "events": f.events,
                "rate_per_min": f.rate_per_min,
                "gap_cv": f.gap_cv,
                "mean_gap_s": f.mean_gap_s,
                "fast_share": f.fast_share,
                "duplicates": f.duplicates,
                "signals": sig,
            }
        campaign = int(raw[len(who)])
        if campaign >= s.bot_campaign_identities:
            signals.add("campaign")
        if user_agent and any(a in user_agent.lower() for a in self._agents):
            signals.add("automation_ua")
        elif user_agent_expected and not user_agent:
            signals.add("missing_ua")
        if self._hosting and self._in(ip, self._hosting):
            signals.add("hosting_ip")
        score = round(min(1.0, sum(WEIGHTS[x] for x in signals)), 3)
        tier, cost = tier_for(score, s)
        return BotAssessment(score, tier, cost, sorted(signals), per, campaign)
