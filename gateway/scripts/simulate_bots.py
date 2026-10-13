"""Simulate human and scripted sessions through the gateway and report who gets throttled.

    docker compose up -d --wait
    cd gateway && uv run python -m scripts.simulate_bots          # in-process gateway, real Redis/Postgres

Message *content* comes from the benign seed dataset (ordinary customer messages), so what separates
bots from people here is behaviour only: timing, typing speed, repetition and coordination. Time is
simulated: the gateway's bot clock is replaced with a fake one advanced between messages, so a
30-minute session runs in a second. Rate-limit buckets keep using Redis time and are set high, so
every *throttle* in the report comes from the bot tier itself. "Slowed" counts sessions that reached
the likely-bot tier, where the end user's real buckets drain 10× faster — with the default limits
that throttles within a few messages (``test_likely_tier_drains_the_users_bucket_faster`` shows it).

Profiles:

| profile        | behaviour                                                         | expected        |
|----------------|-------------------------------------------------------------------|-----------------|
| human          | think 3–40 s, types 3–7 chars/s, different messages               | never throttled |
| timer_template | one template with a changing number, exactly every 2 s            | throttled       |
| fast_paster    | different long messages every 0.5–1.5 s                           | slowed          |
| jittered_timer | different messages every 3 s ± 3 %                                | throttled       |
| burst          | 40 different short-gap messages in under a minute                 | slowed          |
| campaign       | the same long message from 8 different users, one each            | flagged         |
| slow_poller    | the same status question exactly every 2 minutes                  | left alone      |
"""

from __future__ import annotations

import json
import random
import uuid
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

DATA = Path(__file__).resolve().parents[2] / "datasets" / "benign" / "seed.jsonl"
SEED = 20261013


class FakeClock:
    def __init__(self, start: float = 1_800_000_000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds


def messages() -> list[str]:
    rows = [json.loads(line)["text"] for line in DATA.read_text().splitlines() if line.strip()]
    return [r for r in rows if len(r.split()) >= 4]


@dataclass
class SessionResult:
    profile: str
    sent: int = 0
    throttled_at: int | None = None  # index of the first throttled message
    tiers: Counter[str] = field(default_factory=Counter)
    signals: Counter[str] = field(default_factory=Counter)


Step = tuple[float, str]  # (seconds to wait before sending, message)


def human(rng: random.Random, pool: list[str], n: int = 20) -> Iterator[Step]:
    for _ in range(n):
        msg = rng.choice(pool)
        yield rng.uniform(3, 40) + len(msg) / rng.uniform(3, 7), msg


def timer_template(rng: random.Random, _pool: list[str], n: int = 30) -> Iterator[Step]:
    for i in range(n):
        yield 2.0, f"Please send me the status and ticket details for booking reference {1000 + i}"


def fast_paster(rng: random.Random, pool: list[str], n: int = 30) -> Iterator[Step]:
    long_ones = [m for m in pool if len(m) >= 40]
    for _ in range(n):
        yield rng.uniform(0.5, 1.5), rng.choice(long_ones)


def jittered_timer(rng: random.Random, pool: list[str], n: int = 30) -> Iterator[Step]:
    for _ in range(n):
        yield 3.0 * rng.uniform(0.97, 1.03), rng.choice(pool)


def burst(rng: random.Random, pool: list[str], n: int = 40) -> Iterator[Step]:
    for _ in range(n):
        yield rng.uniform(0.3, 2.5), rng.choice(pool)


def slow_poller(_rng: random.Random, _pool: list[str], n: int = 15) -> Iterator[Step]:
    for _ in range(n):
        yield 120.0, "Is flight AC854 from Toronto to Vancouver on time today?"


PROFILES: dict[str, tuple[Callable[..., Iterator[Step]], int]] = {
    "human": (human, 20),
    "timer_template": (timer_template, 5),
    "fast_paster": (fast_paster, 5),
    "jittered_timer": (jittered_timer, 5),
    "burst": (burst, 5),
    "slow_poller": (slow_poller, 3),
}
CAMPAIGN_MESSAGE = "I want a full refund for my cancelled flight and compensation for the hotel I had to book"


def _send(c: Any, auth: dict[str, str], user: str, text: str) -> dict[str, Any]:
    body = {
        "session_id": f"sim-{user}",
        "message": text,
        "customer_id": user,
        "ip": f"198.51.100.{random.randint(1, 254)}",  # noqa: S311
    }
    d: dict[str, Any] = c.post("/v1/inspect", json=body, headers=auth).json()
    return d


def run(c: Any, auth: dict[str, str], clock: FakeClock) -> dict[str, Any]:
    """Replay every profile through ``c`` (a TestClient on an app whose bot clock is ``clock``)."""
    rng = random.Random(SEED)  # noqa: S311 - a simulation, not cryptography
    random.seed(SEED)
    pool = messages()
    results: list[SessionResult] = []
    for profile, (gen, sessions) in PROFILES.items():
        for _ in range(sessions):
            user = f"sim-{profile}-{uuid.uuid4().hex[:8]}"
            res = SessionResult(profile)
            for i, (wait, text) in enumerate(gen(rng, pool)):
                clock.advance(wait)
                d = _send(c, auth, user, text)
                res.sent += 1
                bot = next((x for x in d["checks"] if x["name"] == "bot"), None)
                if bot:
                    res.tiers[bot["detail"]["tier"]] += 1
                    res.signals.update(bot["detail"]["signals"])
                if d["action"] == "throttle" and res.throttled_at is None:
                    res.throttled_at = i
            results.append(res)
    # Campaign: one message each from many users, a few seconds apart.
    camp = SessionResult("campaign")
    for _ in range(8):
        clock.advance(rng.uniform(5, 30))
        d = _send(c, auth, f"sim-campaign-{uuid.uuid4().hex[:8]}", CAMPAIGN_MESSAGE)
        camp.sent += 1
        bot = next((x for x in d["checks"] if x["name"] == "bot"), None)
        if bot:
            camp.tiers[bot["detail"]["tier"]] += 1
            camp.signals.update(bot["detail"]["signals"])
    results.append(camp)
    return summarise(results)


def summarise(results: list[SessionResult]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for profile in [*PROFILES, "campaign"]:
        rs = [r for r in results if r.profile == profile]
        tiers: Counter[str] = sum((r.tiers for r in rs), Counter())
        signals: Counter[str] = sum((r.signals for r in rs), Counter())
        first = [r.throttled_at for r in rs if r.throttled_at is not None]
        out[profile] = {
            "sessions": len(rs),
            "messages": sum(r.sent for r in rs),
            "sessions_throttled": sum(1 for r in rs if r.throttled_at is not None),
            "sessions_slowed": sum(1 for r in rs if r.tiers["likely"] or r.tiers["bot"]),
            "first_throttle_at_message": min(first) + 1 if first else None,
            "tiers": dict(tiers),
            "signals": dict(signals),
        }
    return out


def main() -> None:
    from fastapi.testclient import TestClient

    from app.main import create_app
    from scripts.eval_multiturn import base_settings

    clock = FakeClock()
    cfg = base_settings(rl_user_capacity=1_000_000, rl_ip_capacity=1_000_000, rl_session_capacity=1_000_000)
    with TestClient(create_app(settings=cfg)) as c:
        c.app.state.bots.clock = clock  # type: ignore[attr-defined]
        admin = {"x-admin-key": cfg.admin_api_key.get_secret_value()}
        key = c.post("/admin/api-keys", json={"name": f"botsim-{uuid.uuid4().hex[:8]}"}, headers=admin).json()
        summary = run(c, {"authorization": f"Bearer {key['api_key']}"}, clock)
    print(f"{'profile':16} {'sessions':>8} {'throttled':>9} {'slowed':>6} {'first at':>8}  tiers / signals")
    for profile, v in summary.items():
        print(
            f"{profile:16} {v['sessions']:8} {v['sessions_throttled']:9} {v['sessions_slowed']:6} "
            f"{v['first_throttle_at_message']!s:>8}  {v['tiers']}  {v['signals']}"
        )


if __name__ == "__main__":
    main()
