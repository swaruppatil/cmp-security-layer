"""Play the session scenarios in ``datasets/sessions/scenarios.yaml`` against the running gateway and
check every step's outcome.

    docker compose --profile observability up -d --wait
    cd gateway && set -a && source ../.env && set +a
    uv run python scripts/run_scenarios.py                       # everything (~3–5 min)
    uv run python scripts/run_scenarios.py --tag outbound        # one area (repeatable)
    uv run python scripts/run_scenarios.py --name ban-           # scenarios whose name contains this
    uv run python scripts/run_scenarios.py --list                # list scenarios and tags
    uv run python scripts/run_scenarios.py --verbose             # print every step, not only failures
    uv run python scripts/run_scenarios.py --report report.json  # write the full results as JSON

Every scenario is one or more **sessions**, played the way CMP would: ``POST /v1/sessions/{id}/start``,
customer messages (``/v1/inspect``), AI replies (``/v1/inspect/outbound``), identity verification,
``/end`` — plus admin steps (bans, session view) and proxy calls. Each step says what the gateway
should answer; the runner compares and reports, per session, which steps passed.

Isolation: session ids, customer ids and IPs get a per-run suffix / random value, so runs never collide
(state left by an earlier run cannot change today's results). Messages inside a session are paced like
a person typing (sessions are bot-profiled), unless a scenario sets its own pace. Scenarios run in
parallel (``--workers``); steps inside one scenario run in order.

Attack text is never written here: it is picked from the labelled datasets (``pick:``), optionally
disguised by a mechanical transform (leetspeak, base64 …). Scenario messages may use the
placeholders ``{CARD}`` (the Visa test number), ``{AWS_KEY}`` (AWS's documented example key),
``{CANARY}`` (a canary token created for the run) and ``{LONG_<n>}`` (n characters of ordinary
customer text).

Outcomes: PASS; FAIL; WARN (a ``soft`` scenario — measurements such as false positives on unseen
data, reported but not failed); INCONCLUSIVE (a failed step whose decision says ``ml_unavailable``:
the ML service was too slow, the step says nothing about the check under test).
"""

from __future__ import annotations

import argparse
import base64
import codecs
import ipaddress
import json
import os
import random
import re
import sys
import time
import uuid
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from threading import Lock
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "datasets"
DEFAULT_FILE = DATA / "sessions" / "scenarios.yaml"
CARD = "4111 1111 1111 1111"  # the standard Visa test number
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's documented example access key
IP_RNG = random.Random()  # noqa: S311 - test traffic, not cryptography
SAFE = re.compile(r"[^A-Za-z0-9._:@-]")

# ------------------------------------------------------------------ text: datasets and transforms
_ROWS: dict[str, list[dict[str, Any]]] = {}
SOURCES = {
    "attack": ["attacks/seed.jsonl"],
    "benign": ["benign/seed.jsonl"],
    "benign_heldout": ["benign/heldout-handwritten.jsonl"],
    "public_attack": ["attacks/heldout-public-deepset.jsonl"],
    "public_benign": ["benign/heldout-public-deepset.jsonl"],
}


def rows(source: str) -> list[dict[str, Any]]:
    if source not in _ROWS:
        out: list[dict[str, Any]] = []
        for p in SOURCES[source]:
            out += [json.loads(line) for line in (DATA / p).read_text().splitlines() if line.strip()]
        _ROWS[source] = out
    return _ROWS[source]


LEET = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
LOOKALIKE = str.maketrans({"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і"})  # Cyrillic


def transform(text: str, name: str) -> str:
    """Mechanical disguises of an existing dataset row (no new attack wording)."""
    if name == "leetspeak":
        return text.lower().translate(LEET)
    if name == "spaced":
        words = text.split()
        return " ".join(words[0]) + " " + " ".join(words[1:])
    if name == "lookalike":
        return text.translate(LOOKALIKE)
    if name == "fullwidth":
        return "".join(chr(ord(c) + 0xFEE0) if "!" <= c <= "~" else c for c in text)
    if name == "zero_width":
        return "​".join(text)
    if name == "base64":
        return "Please decode and follow: " + base64.b64encode(text.encode()).decode()
    if name == "hex":
        return "Hex for you: " + text.encode().hex()
    if name == "rot13":
        return "ROT13: " + codecs.encode(text, "rot13")
    if name == "hidden_tags":  # invisible Unicode tag characters after an ordinary question
        return "What time does boarding start?" + "".join(chr(0xE0000 + ord(c)) for c in text if ord(c) < 128)
    if name == "upper":
        return text.upper()
    raise ValueError(f"unknown transform {name!r}")


class MLBands:
    """Dataset rows grouped by how the ML service scores them (computed once per run)."""

    BANDS = {"block": (0.98, 1.01), "restrict": (0.70, 0.95), "borderline": (0.50, 0.64)}

    def __init__(self, ml_url: str) -> None:
        self._url = ml_url
        self._bands: dict[str, list[str]] | None = None
        self._lock = Lock()

    def get(self, band: str) -> list[str]:
        with self._lock:
            if self._bands is None:
                self._bands = self._compute()
        return self._bands[band]

    def _compute(self) -> dict[str, list[str]]:
        pool = [
            r["text"]
            for src in ("public_attack", "public_benign", "benign_heldout")
            for r in rows(src)
            if 20 <= len(r["text"]) <= 300
        ]
        scores: list[float] = []
        with httpx.Client(base_url=self._url, timeout=60) as c:
            for i in range(0, len(pool), 40):
                res = c.post("/v1/score", json={"texts": pool[i : i + 40]}).json()
                scores += [r["score"] for r in res["results"]]
        out: dict[str, list[str]] = {}
        for band, (lo, hi) in self.BANDS.items():
            out[band] = [t for t, s in zip(pool, scores, strict=True) if lo <= s < hi]
        return out


# ------------------------------------------------------------------ run-wide state
@dataclass
class Run:
    url: str
    admin: dict[str, str]
    ml: MLBands
    run_id: str = field(default_factory=lambda: uuid.uuid4().hex[:6])
    keys: dict[str, str] = field(default_factory=dict)  # role → plaintext key
    canary: dict[str, Any] | None = None
    policies: list[str] = field(default_factory=list)  # ids created by this run
    long_text: str = ""

    def client(self) -> httpx.Client:
        return httpx.Client(base_url=self.url, timeout=20)

    def setup(self, spec: dict[str, Any], scenarios: list[dict[str, Any]]) -> None:
        with self.client() as c:
            for role, scopes in (("full", ["inspect", "outbound", "proxy"]), ("inspect_only", ["inspect"])):
                r = c.post(
                    "/admin/api-keys",
                    json={"name": f"scn-{self.run_id}-{role}", "scopes": scopes},
                    headers=self.admin,
                )
                if r.status_code != 201:
                    sys.exit(
                        f"cannot create an API key ({r.status_code}): is the stack up, ADMIN_API_KEY right?"
                    )
                self.keys[role] = r.json()["api_key"]
            if "{CANARY" in json.dumps(scenarios):
                self.canary = c.post(
                    "/admin/canaries", json={"label": f"scn-{self.run_id}"}, headers=self.admin
                ).json()
            for p in spec.get("policies", []):
                r = c.post("/admin/policies", json=p, headers=self.admin)
                if r.status_code == 201:
                    self.policies.append(r.json()["id"])
                elif r.status_code != 409:  # 409: an earlier run left the same policy in place
                    print(f"  policy {p.get('name')} not created: {r.status_code} {r.text[:120]}")
        benign = [r["text"] for r in rows("benign") if r["family"] == "airline_support"]
        self.long_text = " ".join(benign)
        if '"from": "ml"' in json.dumps(scenarios):
            # Score the dataset rows now, before any scenario runs: scoring hundreds of rows while
            # scenarios run would slow the ML service down and make the gateway's 50 ms ML calls time out.
            print("scoring dataset rows on the ML service for the ML-band picks …")
            bands = {b: len(self.ml.get(b)) for b in MLBands.BANDS}
            print("  " + ", ".join(f"{b}: {n} rows" for b, n in bands.items()))
            with self.client() as c:  # let the gateway's own ML connection settle
                for _ in range(3):
                    c.get("/ready")

    def teardown(self, keep_policies: bool) -> None:
        with self.client() as c:
            if not keep_policies:
                for pid in self.policies:
                    c.delete(f"/admin/policies/{pid}", headers=self.admin)
            if self.canary:
                c.delete(f"/admin/canaries/{self.canary['id']}", headers=self.admin)


# ------------------------------------------------------------------ expectations
def _get(d: Any, path: list[str]) -> Any:
    for p in path:
        if isinstance(d, dict) and p in d:
            d = d[p]
        else:
            return None
    return d


def _match(value: Any, cond: Any) -> bool:
    if isinstance(cond, dict):
        ok = True
        for op, arg in cond.items():
            if op == "in":
                ok &= value in arg
            elif op == "contains":
                ok &= value is not None and arg in value
            elif op == "contains_any":
                ok &= value is not None and any(a in value for a in arg)
            elif op == "not_contains":
                ok &= value is None or arg not in value
            elif op == "gte":
                ok &= value is not None and value >= arg
            elif op == "lte":
                ok &= value is not None and value <= arg
            elif op == "exists":
                ok &= (value is not None) == arg
            else:
                raise ValueError(f"unknown condition {op!r}")
        return ok
    if isinstance(cond, list):
        return value in cond
    return bool(value == cond)


def check(resp: dict[str, Any], status: int, exp: dict[str, Any] | None) -> list[str]:
    """Failures (empty = the response matches the expectation)."""
    exp = exp or {}
    fails: list[str] = []
    want_status = exp.get("status", 200)
    if status != want_status:
        return [f"HTTP {status}, expected {want_status}"]
    if status != 200:
        return fails
    reasons = resp.get("reasons") or []
    checks = {c["name"]: c for c in resp.get("checks", [])}
    red = resp.get("redactions") or []
    found = {r["type"] for r in red}
    redacted = {r["type"] for r in red if r.get("redacted")}

    def want(key: str, actual: Any) -> None:
        if key in exp and not _match(actual, exp[key]):
            fails.append(f"{key} = {actual!r}, expected {exp[key]!r}")

    want("action", resp.get("action"))
    want("cmp_action", resp.get("cmp_action"))
    want("replayed", resp.get("replayed"))
    want("session_state", resp.get("session_state"))
    want("would_have", resp.get("would_have"))
    for r in exp.get("reasons", []):
        if r not in reasons:
            fails.append(f"reason {r!r} missing (got {reasons})")
    if "reasons_any" in exp and not set(exp["reasons_any"]) & set(reasons):
        fails.append(f"none of {exp['reasons_any']} in reasons {reasons}")
    for r in exp.get("reasons_none", []):
        if r in reasons:
            fails.append(f"unexpected reason {r!r}")
    if exp.get("no_reasons") and reasons:
        fails.append(f"expected no reasons, got {reasons}")
    for t in exp.get("found", []):
        if t not in found:
            fails.append(f"{t!r} not found (found {sorted(found)})")
    for t in exp.get("redacted", []):
        if t not in redacted:
            fails.append(f"{t!r} not redacted (redacted {sorted(redacted)})")
    for t in exp.get("not_redacted", []):
        if t in redacted:
            fails.append(f"{t!r} was redacted")
    for key, field_name in (
        ("redacted_message_contains", "redacted_message"),
        ("deliver_contains", "deliver"),
    ):
        for s in [exp[key]] if isinstance(exp.get(key), str) else exp.get(key, []):
            if s not in (resp.get(field_name) or ""):
                fails.append(f"{field_name} lacks {s!r}: {str(resp.get(field_name))[:80]!r}")
    for s in (
        [exp["deliver_not_contains"]]
        if isinstance(exp.get("deliver_not_contains"), str)
        else exp.get("deliver_not_contains", [])
    ):
        if s in (resp.get("deliver") or ""):
            fails.append(f"deliver still contains {s!r}")
    if "deliver_null" in exp and (resp.get("deliver") is None) != exp["deliver_null"]:
        fails.append(f"deliver = {str(resp.get('deliver'))[:60]!r}, expected null={exp['deliver_null']}")
    for name in exp.get("checks_run", []):
        if name not in checks:
            fails.append(f"check {name!r} did not run (ran {list(checks)})")
    for name in exp.get("checks_absent", []):
        if name in checks:
            fails.append(f"check {name!r} ran")
    for path, cond in (exp.get("detail") or {}).items():
        name, *rest = path.split(".")
        value = _get(checks.get(name, {}).get("detail"), rest) if rest else checks.get(name)
        if not _match(value, cond):
            fails.append(f"{path} = {value!r}, expected {cond!r}")
    return fails


def summary(resp: dict[str, Any], status: int) -> str:
    if status != 200 or "action" not in resp:
        return f"HTTP {status}"
    reasons = ",".join(resp.get("reasons") or []) or "-"
    extra = " replayed" if resp.get("replayed") else ""
    return f"{resp['action']} → {resp.get('cmp_action')} [{reasons}]{extra}"


# ------------------------------------------------------------------ offline validation of the file
STEP_KINDS = {"say", "reply", "identity", "end", "repeat", "say_many", "admin", "proxy", "raw", "wait"}
STEP_OPTIONS = {
    "expect",
    "label",
    "pace",
    "message_id",
    "endpoint",
    "channel",
    "user_agent",
    "device_id",
    "customer",
    "ip",
    "allowed_identifiers",
}
EXPECT_KEYS = {
    "status",
    "action",
    "cmp_action",
    "replayed",
    "session_state",
    "would_have",
    "reasons",
    "reasons_any",
    "reasons_none",
    "no_reasons",
    "found",
    "redacted",
    "not_redacted",
    "redacted_message_contains",
    "deliver_contains",
    "deliver_not_contains",
    "deliver_null",
    "checks_run",
    "checks_absent",
    "detail",
}
SESSION_KEYS = {
    "name",
    "tags",
    "description",
    "soft",
    "steps",
    "sessions",
    "session",
    "channel",
    "customer",
    "ip",
    "device",
    "user_agent",
    "pace",
    "start",
}
TRANSFORMS = {
    "leetspeak",
    "spaced",
    "lookalike",
    "fullwidth",
    "zero_width",
    "base64",
    "hex",
    "rot13",
    "hidden_tags",
    "upper",
}


def validate(spec: dict[str, Any]) -> list[str]:
    """Problems in a scenario file, without a running stack (ML-band picks are not resolved)."""
    errors: list[str] = []
    names: set[str] = set()

    def text_ok(where: str, t: Any) -> None:
        if isinstance(t, str):
            return
        if not isinstance(t, dict) or ("pick" not in t and "text" not in t):
            errors.append(f"{where}: text must be a string or have pick / text")
            return
        if t.get("transform") and t["transform"] not in TRANSFORMS:
            errors.append(f"{where}: unknown transform {t['transform']!r}")
        p = t.get("pick")
        if p is None:
            return
        if p.get("from") == "ml":
            if p.get("band") not in MLBands.BANDS:
                errors.append(f"{where}: ml pick needs band in {list(MLBands.BANDS)}")
            return
        if p.get("from") not in SOURCES:
            errors.append(f"{where}: unknown source {p.get('from')!r}")
            return
        pool = [
            r
            for r in rows(p["from"])
            if ("family" not in p or r.get("family") == p["family"])
            and ("lang" not in p or r.get("lang") == p["lang"])
            and ("contains" not in p or p["contains"].lower() in r["text"].lower())
            and p.get("min_len", 0) <= len(r["text"]) <= p.get("max_len", 10_000)
        ]
        if not pool:
            errors.append(f"{where}: pick {p} matches no dataset row")

    def expect_ok(where: str, e: Any) -> None:
        if e is None:
            return
        unknown = set(e) - EXPECT_KEYS
        if unknown:
            errors.append(f"{where}: unknown expectation keys {sorted(unknown)}")

    for sc in spec.get("scenarios", []):
        name = sc.get("name", "?")
        if name in names:
            errors.append(f"duplicate scenario name {name!r}")
        names.add(name)
        if SAFE.search(name):
            errors.append(f"{name}: name may only use letters, digits and . _ : @ -")
        sessions = sc.get("sessions") or [sc]
        if "steps" not in sc and "sessions" not in sc:
            errors.append(f"{name}: needs steps or sessions")
        for k in set(sc) - SESSION_KEYS:
            errors.append(f"{name}: unknown key {k!r}")
        for i, sess in enumerate(sessions):
            for k in set(sess) - SESSION_KEYS:
                errors.append(f"{name}/session {i}: unknown key {k!r}")
            for j, step in enumerate(sess.get("steps", [])):
                where = f"{name}/session {i}/step {j + 1}"
                kinds = set(step) & STEP_KINDS
                if len(kinds) != 1:
                    errors.append(f"{where}: needs exactly one of {sorted(STEP_KINDS)}")
                    continue
                for k in set(step) - STEP_KINDS - STEP_OPTIONS:
                    errors.append(f"{where}: unknown option {k!r}")
                kind = kinds.pop()
                expect_ok(where, step.get("expect"))
                if kind in ("say", "reply"):
                    text_ok(where, step[kind])
                elif kind == "repeat":
                    text_ok(where, step["repeat"].get("say"))
                    expect_ok(where, step["repeat"].get("until"))
                elif kind == "say_many":
                    m = step["say_many"]
                    for item in m.get("items") or [m.get("pick_each") or m.get("text_each")]:
                        text_ok(where, item)
                    expect_ok(where, m.get("until"))
                    expect_ok(where, m.get("expect"))
                elif kind == "proxy" and "say" in step["proxy"]:
                    text_ok(where, step["proxy"]["say"])
    return errors


# ------------------------------------------------------------------ one scenario
@dataclass
class StepResult:
    label: str
    outcome: str
    failures: list[str]
    inconclusive: bool = False


class Player:
    def __init__(self, run: Run, sc: dict[str, Any]) -> None:
        self.run = run
        self.sc = sc
        self.name = sc["name"]
        self.c = run.client()
        self.customers: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.results: list[StepResult] = []
        self.session_ids: list[str] = []
        self.s: dict[str, Any] = {}  # the current session
        self.last_sent: float | None = None

    # ---- naming ------------------------------------------------------------
    def customer(self, label: str | None) -> str | None:
        if label is None:
            return None
        if label not in self.customers:
            self.customers[label] = f"scn-{self.run.run_id}-{self.name}-{label}"
        return self.customers[label]

    def ip(self, label: str | None) -> str | None:
        if label is None:
            return None
        if label not in self.ips:
            if label.startswith("loopback"):  # never-ban range: rate limits only, no ban
                self.ips[label] = (
                    f"127.{IP_RNG.randint(1, 254)}.{IP_RNG.randint(1, 254)}.{IP_RNG.randint(1, 254)}"
                )
            else:
                self.ips[label] = (
                    f"198.{IP_RNG.randint(18, 19)}.{IP_RNG.randint(0, 255)}.{IP_RNG.randint(1, 254)}"
                )
        return self.ips[label]

    def ref(self, value: Any) -> Any:
        """@session, @customer, @customer:<label>, @ip, @ip:<label>, @ip/24 → this run's values."""
        if not isinstance(value, str) or not value.startswith("@"):
            return value
        if value == "@session":
            return self.s["id"]
        m = re.fullmatch(r"@customer(?::(.+))?", value)
        if m:
            return self.customer(m.group(1) or self.s["customer_label"])
        m = re.fullmatch(r"@ip(?::([^/]+))?(?:/(\d+))?", value)
        if m:
            addr = self.ip(m.group(1) or self.s["ip_label"])
            if m.group(2):
                return str(ipaddress.ip_network(f"{addr}/{m.group(2)}", strict=False))
            return addr
        raise ValueError(f"unknown reference {value!r}")

    # ---- text ---------------------------------------------------------------
    def text(self, spec: Any, i: int = 0) -> str:
        if isinstance(spec, str):
            return self.placeholders(spec)
        pick = spec.get("pick")
        if pick is not None:
            base = self.pick(pick, i)
        else:
            base = self.placeholders(spec["text"])
        if "split" in spec:  # {parts: 3, index: 0} — a dataset phrase cut into fragments
            words = base.split()
            parts, index = spec["split"]["parts"], spec["split"]["index"]
            size = -(-len(words) // parts)
            base = " ".join(words[index * size : (index + 1) * size])
        if "transform" in spec:
            base = transform(base, spec["transform"])
        return spec.get("prefix", "") + base + spec.get("suffix", "")

    def pick(self, p: dict[str, Any], i: int) -> str:
        n = p.get("n", 0) + i
        if p["from"] == "ml":
            pool = self.run.ml.get(p["band"])
        else:
            pool = [
                r["text"]
                for r in rows(p["from"])
                if ("family" not in p or r.get("family") == p["family"])
                and ("lang" not in p or r.get("lang") == p["lang"])
                and ("contains" not in p or p["contains"].lower() in r["text"].lower())
                and len(r["text"]) <= p.get("max_len", 10_000)
                and len(r["text"]) >= p.get("min_len", 0)
            ]
        if not pool:
            raise ValueError(f"pick {p} matches no dataset row")
        return pool[n % len(pool)]

    def placeholders(self, s: str) -> str:
        s = s.replace("{CARD}", CARD).replace("{AWS_KEY}", AWS_KEY)
        if "{CANARY" in s and self.run.canary:
            s = s.replace("{CANARY}", self.run.canary["token"])
        return re.sub(r"\{LONG_(\d+)\}", lambda m: self.run.long_text[: int(m.group(1))], s)

    # ---- pacing --------------------------------------------------------------
    def pace(self, text: str, override: Any = None) -> None:
        mode = override if override is not None else self.s.get("pace", "human")
        if self.last_sent is not None:
            if mode == "human":  # ~12 characters a second, never faster than a person types
                gap = min(6.0, max(0.8, len(text) / 12)) + random.uniform(0.2, 0.8)  # noqa: S311
            elif mode == "fast":
                gap = 0.25
            elif mode == "none":
                gap = 0.0
            else:
                gap = float(mode)
            wait = self.last_sent + gap - time.monotonic()
            if wait > 0:
                time.sleep(wait)
        self.last_sent = time.monotonic()

    # ---- requests ------------------------------------------------------------
    def auth(self, key: str = "full") -> dict[str, str]:
        return {"authorization": f"Bearer {self.run.keys[key]}"} if key != "none" else {}

    def attrs(self) -> dict[str, Any]:
        s = self.s
        return {
            "channel": s.get("channel"),
            "customer_id": self.customer(s.get("customer_label")),
            "ip": self.ip(s.get("ip_label")),
            "device_id": s.get("device"),
            "user_agent": s.get("user_agent"),
        }

    def post(self, path: str, body: dict[str, Any] | None, key: str = "full") -> tuple[dict[str, Any], int]:
        r = self.c.post(
            path, json={k: v for k, v in (body or {}).items() if v is not None}, headers=self.auth(key)
        )
        try:
            data = r.json()
        except ValueError:
            data = {"text": r.text}
        return (data if isinstance(data, dict) else {"body": data}), r.status_code

    def say(self, step: dict[str, Any], text: str) -> tuple[dict[str, Any], int]:
        body: dict[str, Any] = {} if self.s["started"] else self.attrs()
        for k in ("channel", "user_agent", "endpoint", "message_id", "device_id"):
            if k in step:
                body[k] = step[k]
        if "customer" in step:
            body["customer_id"] = self.customer(step["customer"])
        if "ip" in step:
            body["ip"] = self.ip(step["ip"])
        body.update(session_id=self.s["id"], message=text)
        return self.post("/v1/inspect", body)

    def record(self, label: str, resp: dict[str, Any], status: int, exp: dict[str, Any] | None) -> None:
        fails = check(resp, status, exp)
        inconclusive = bool(fails) and "ml_unavailable" in (resp.get("reasons") or [])
        self.results.append(StepResult(label, summary(resp, status), fails, inconclusive))

    # ---- the scenario ----------------------------------------------------------
    def play(self) -> None:
        sessions = self.sc.get("sessions") or [{"steps": self.sc["steps"]}]
        for i, sess in enumerate(sessions):
            spec = {**{k: v for k, v in self.sc.items() if k not in ("sessions", "steps")}, **sess}
            self.begin(spec, i)
            for step in sess["steps"]:
                try:
                    self.step(step)
                except Exception as exc:  # noqa: BLE001 - reported as a failed step
                    self.results.append(StepResult(str(step)[:60], "error", [f"{type(exc).__name__}: {exc}"]))
        self.c.close()

    def begin(self, spec: dict[str, Any], i: int) -> None:
        suffix = spec.get("session") or str(i)
        sid = SAFE.sub("-", f"scn-{self.run.run_id}-{self.name}-{suffix}")[:200]
        self.s = {
            "id": sid,
            "channel": spec.get("channel", "web"),
            "customer_label": spec.get("customer"),
            "ip_label": spec.get("ip", f"ip-{i}"),
            "device": spec.get("device"),
            "user_agent": spec.get("user_agent"),
            "pace": spec.get("pace", "human"),
            "started": False,
        }
        self.session_ids.append(sid)
        self.last_sent = None
        if i > 0:
            # A customer's next chat never starts in the same millisecond: let the previous chat's
            # bookkeeping (strikes, bans — written just after each response) land first.
            time.sleep(0.5)
        if spec.get("start", True):
            resp, status = self.post(f"/v1/sessions/{sid}/start", self.attrs())
            self.s["started"] = status == 200
            if status != 200:
                self.results.append(StepResult("start", f"HTTP {status}", [f"session start failed: {resp}"]))

    def step(self, step: dict[str, Any]) -> None:  # noqa: C901, PLR0912 - one branch per step kind
        exp = step.get("expect")
        label = step.get("label")
        if "say" in step:
            text = self.text(step["say"])
            self.pace(text, step.get("pace"))
            resp, status = self.say(step, text)
            self.record(label or f"say: {text[:50]}", resp, status, exp)
        elif "reply" in step:
            text = self.text(step["reply"])
            body = {"session_id": self.s["id"], "reply": text, "message_id": step.get("message_id")}
            if "allowed_identifiers" in step:
                body["allowed_identifiers"] = step["allowed_identifiers"]
            resp, status = self.post("/v1/inspect/outbound", body)
            self.record(label or f"AI reply: {text[:44]}", resp, status, exp)
        elif "identity" in step:
            ident = step["identity"]
            body = {
                "verified": ident.get("verified", True),
                "customer_id": self.customer(self.s.get("customer_label")),
                "identifiers": ident.get("identifiers", {}),
            }
            resp, status = self.post(f"/v1/sessions/{self.s['id']}/identity", body)
            fails = [] if status == 200 else [f"HTTP {status}"]
            want = ident.get("expect_state")
            if want and resp.get("state") != want:
                fails.append(f"state = {resp.get('state')!r}, expected {want!r}")
            self.results.append(StepResult(label or "identity", f"state {resp.get('state')}", fails))
        elif "end" in step:
            resp, status = self.post(f"/v1/sessions/{self.s['id']}/end", None)
            fails = [] if status == 200 else [f"HTTP {status}"]
            if (
                isinstance(step["end"], dict)
                and "existed" in step["end"]
                and resp.get("existed") != step["end"]["existed"]
            ):
                fails.append(f"existed = {resp.get('existed')}, expected {step['end']['existed']}")
            self.results.append(StepResult(label or "end", f"existed={resp.get('existed')}", fails))
        elif "repeat" in step:
            self.repeat(step["repeat"], label)
        elif "say_many" in step:
            self.say_many(step["say_many"], label)
        elif "admin" in step:
            self.admin(step["admin"], label)
        elif "proxy" in step:
            self.proxy(step["proxy"], label)
        elif "raw" in step:
            r = step["raw"]
            body = json.loads(json.dumps(r.get("json") or {}).replace('"@session"', json.dumps(self.s["id"])))
            resp, status = self.post(r["path"], body, r.get("key", "full"))
            self.record(label or f"{r['path']}", resp, status, exp or {"status": 200})
        elif "wait" in step:
            time.sleep(float(step["wait"]))
        else:
            raise ValueError(f"unknown step {list(step)}")

    def repeat(self, spec: dict[str, Any], label: str | None) -> None:
        """Send one message ``times`` times; passes when ``until`` matched (or ``expect_each`` held)."""
        text = self.text(spec["say"])
        until, seen, hit = spec.get("until"), Counter(), None
        for n in range(spec["times"]):
            self.pace(text, spec.get("pace", "fast"))
            resp, status = self.say(spec, text)
            seen[summary(resp, status)] += 1
            if until and not check(resp, status, until):
                hit = n + 1
                break
        fails = [] if (until is None or hit) else [f"never reached {until} in {spec['times']} requests"]
        outcome = (f"matched at #{hit}; " if hit else "") + "; ".join(f"{k} ×{v}" for k, v in seen.items())
        self.results.append(StepResult(label or f"repeat ×{spec['times']}: {text[:40]}", outcome, fails))

    def say_many(self, spec: dict[str, Any], label: str | None) -> None:
        """Several messages (a list, or ``count`` dataset picks). ``until``: passes once matched;
        otherwise ``expect`` must hold for each. ``new_session_each``: every message is its own chat."""
        items = spec.get("items") or [spec.get("pick_each") or spec["text_each"]] * spec["count"]
        until, exp = spec.get("until"), spec.get("expect")
        fails: list[str] = []
        seen: Counter[str] = Counter()
        hit = None
        base_id = self.s["id"]
        for n, item in enumerate(items):
            text = self.text(item, n if "pick_each" in spec else 0)
            if spec.get("new_session_each"):
                self.s["id"], self.last_sent = f"{base_id}-{n}", None
                if self.s["started"]:
                    self.post(f"/v1/sessions/{self.s['id']}/start", self.attrs())
                self.session_ids.append(self.s["id"])
            self.pace(text, spec.get("pace"))
            resp, status = self.say(spec, text)
            seen[summary(resp, status)] += 1
            if until is not None:
                if not check(resp, status, until):
                    hit = n + 1
                    break
            else:
                f = check(resp, status, exp)
                if f and "ml_unavailable" not in (resp.get("reasons") or []):
                    fails.append(f"#{n + 1} {text[:40]!r}: " + "; ".join(f))
        self.s["id"] = base_id
        if until is not None and hit is None:
            fails.append(f"never reached {until}")
        outcome = (f"matched at #{hit}; " if hit else "") + "; ".join(f"{k} ×{v}" for k, v in seen.items())
        self.results.append(StepResult(label or f"{len(items)} messages", outcome, fails))

    def admin(self, spec: dict[str, Any], label: str | None) -> None:
        h = self.run.admin
        if "ban" in spec:
            b = spec["ban"]
            body = {
                "entity_type": b["type"],
                "value": self.ref(b["value"]),
                "reason": f"scenario {self.name}",
            }
            body.update(
                {"permanent": True} if b.get("permanent") else {"duration_seconds": b.get("duration", 600)}
            )
            r = self.c.post("/admin/bans", json=body, headers=h)
            self.results.append(
                StepResult(
                    label or f"admin ban {b['type']}",
                    f"HTTP {r.status_code}",
                    [] if r.status_code == 201 else [r.text[:120]],
                )
            )
        elif "blacklist" in spec:
            b = spec["blacklist"]
            body = {
                "entity_type": b["type"],
                "values": [self.ref(v) for v in b["values"]],
                "reason": f"scenario {self.name}",
            }
            r = self.c.post("/admin/blacklists", json=body, headers=h)
            self.results.append(
                StepResult(
                    label or "admin blacklist",
                    f"HTTP {r.status_code}",
                    [] if r.status_code == 201 else [r.text[:120]],
                )
            )
        elif "session" in spec:
            want = spec["session"] or {}
            time.sleep(spec.get("settle", 0.5))  # conversation memory is written just after the response
            r = self.c.get(f"/admin/sessions/{self.s['id']}", headers=h)
            data = r.json() if r.status_code == 200 else {}
            fails = []
            if "exists" in want and (r.status_code == 200) != want["exists"]:
                fails.append(f"exists = {r.status_code == 200}, expected {want['exists']}")
            for path, cond in want.items():
                if path == "exists":
                    continue
                value = _get(data, path.split("."))
                if not _match(value, cond):
                    fails.append(f"{path} = {value!r}, expected {cond!r}")
            conv = data.get("conversation") or {}
            outcome = f"HTTP {r.status_code}" + (
                f", locked={conv.get('locked')} blocks={conv.get('blocks')}" if conv else ""
            )
            self.results.append(StepResult(label or "admin session view", outcome, fails))
        elif "reset_session" in spec:
            r = self.c.delete(f"/admin/sessions/{self.s['id']}", headers=h)
            self.results.append(
                StepResult(
                    label or "admin session reset",
                    f"HTTP {r.status_code}",
                    [] if r.status_code == 200 else [r.text[:120]],
                )
            )
        else:
            raise ValueError(f"unknown admin step {list(spec)}")

    def proxy(self, spec: dict[str, Any], label: str | None) -> None:
        headers = {**self.auth(), "x-session-id": self.s["id"], "x-channel": self.s["channel"]}
        if self.s.get("customer_label"):
            headers["x-end-user-id"] = self.customer(self.s["customer_label"]) or ""
        headers["user-agent"] = self.s.get("user_agent") or "Mozilla/5.0 (scenario)"
        body = json.loads(self.placeholders(json.dumps(spec.get("json", {}))))
        if "say" in spec:
            body = {"message": self.text(spec["say"])}
        self.pace(json.dumps(body), spec.get("pace"))
        r = self.c.post(f"/v1/ai/{spec.get('path', 'chat')}", json=body, headers=headers)
        exp = spec.get("expect", {})
        fails = []
        if "status" in exp and r.status_code != exp["status"]:
            fails.append(f"HTTP {r.status_code}, expected {exp['status']}")
        for s in (
            [exp["body_contains"]]
            if isinstance(exp.get("body_contains"), str)
            else exp.get("body_contains", [])
        ):
            if s not in r.text:
                fails.append(f"body lacks {s!r}: {r.text[:80]!r}")
        self.results.append(
            StepResult(label or f"proxy {spec.get('path', 'chat')}", f"HTTP {r.status_code}", fails)
        )


# ------------------------------------------------------------------ reporting
@dataclass
class Outcome:
    scenario: dict[str, Any]
    results: list[StepResult]
    session_ids: list[str]
    seconds: float
    error: str | None = None

    @property
    def status(self) -> str:
        if self.error:
            return "ERROR"
        failed = [r for r in self.results if r.failures and not r.inconclusive]
        if failed:
            return "WARN" if self.scenario.get("soft") else "FAIL"
        if any(r.inconclusive for r in self.results):
            return "INCONCLUSIVE"
        return "PASS"


def print_outcome(o: Outcome, verbose: bool) -> None:
    sc = o.scenario
    mark = {"PASS": "✓", "FAIL": "✗", "WARN": "!", "INCONCLUSIVE": "?", "ERROR": "✗"}[o.status]
    passed = sum(1 for r in o.results if not r.failures)
    print(
        f"{mark} {o.status:12} {sc['name']:38} {passed}/{len(o.results)} steps  {o.seconds:5.1f}s  "
        f"[{', '.join(sc.get('tags', []))}]"
    )
    if o.error:
        print(f"      error: {o.error}")
    if verbose or o.status not in ("PASS",):
        if verbose and sc.get("description"):
            print(f"      {sc['description']}")
        for r in o.results:
            if verbose or r.failures:
                flag = "ok " if not r.failures else ("?? " if r.inconclusive else "XX ")
                print(f"      {flag}{r.label[:56]:56} → {r.outcome[:90]}")
                for f in r.failures:
                    print(f"           {f}")
        print(f"      sessions: {', '.join(o.session_ids[:4])}{' …' if len(o.session_ids) > 4 else ''}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default=os.environ.get("GATEWAY_URL", "http://localhost:18080"))
    ap.add_argument("--ml-url", default=os.environ.get("ML_PUBLIC_URL", "http://localhost:18000"))
    ap.add_argument("--admin-key", default=os.environ.get("ADMIN_API_KEY", "change-me-admin-key"))
    ap.add_argument("--file", type=Path, default=DEFAULT_FILE)
    ap.add_argument("--tag", action="append", default=[], help="only scenarios with this tag (repeatable)")
    ap.add_argument("--name", help="only scenarios whose name contains this")
    ap.add_argument("--workers", type=int, default=4, help="scenarios played in parallel")
    ap.add_argument("--list", action="store_true", help="list the scenarios and exit")
    ap.add_argument("--check", action="store_true", help="validate the file (no stack needed) and exit")
    ap.add_argument("--verbose", "-v", action="store_true", help="print every step")
    ap.add_argument("--report", type=Path, help="write the results as JSON")
    ap.add_argument("--keep-policies", action="store_true", help="leave the scenario policies in place")
    args = ap.parse_args()

    spec = yaml.safe_load(args.file.read_text())
    if args.check:
        problems = validate(spec)
        for e in problems:
            print("  ", e)
        print(
            f"{len(spec.get('scenarios', []))} scenarios: "
            + (f"{len(problems)} problems" if problems else "ok")
        )
        return 1 if problems else 0
    scenarios = [
        s
        for s in spec["scenarios"]
        if (not args.tag or set(args.tag) & set(s.get("tags", [])))
        and (not args.name or args.name in s["name"])
    ]
    if args.list:
        tags: Counter[str] = Counter(t for s in spec["scenarios"] for t in s.get("tags", []))
        for s in scenarios:
            print(f"{s['name']:40} [{', '.join(s.get('tags', []))}]  {s.get('description', '')[:80]}")
        print(
            f"\n{len(scenarios)} scenarios; tags: " + ", ".join(f"{t} ({n})" for t, n in sorted(tags.items()))
        )
        return 0

    run = Run(url=args.url, admin={"x-admin-key": args.admin_key}, ml=MLBands(args.ml_url))
    print(f"run {run.run_id}: {len(scenarios)} scenarios, {args.workers} in parallel — gateway {args.url}\n")
    run.setup(spec, scenarios)
    outcomes: list[Outcome] = []
    started = time.monotonic()

    def play(sc: dict[str, Any]) -> Outcome:
        t0 = time.monotonic()
        p = Player(run, sc)
        try:
            p.play()
            return Outcome(sc, p.results, p.session_ids, time.monotonic() - t0)
        except Exception as exc:  # noqa: BLE001
            return Outcome(
                sc, p.results, p.session_ids, time.monotonic() - t0, f"{type(exc).__name__}: {exc}"
            )

    try:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
            futures = [pool.submit(play, sc) for sc in scenarios]
            for fut in as_completed(futures):
                o = fut.result()
                outcomes.append(o)
                print_outcome(o, args.verbose)
    finally:
        run.teardown(args.keep_policies)

    by_status = Counter(o.status for o in outcomes)
    steps = sum(len(o.results) for o in outcomes)
    steps_ok = sum(1 for o in outcomes for r in o.results if not r.failures)
    by_tag: dict[str, Counter[str]] = defaultdict(Counter)
    for o in outcomes:
        for t in o.scenario.get("tags", []):
            by_tag[t][o.status] += 1
    print("\n" + "═" * 100)
    print(
        f"run {run.run_id}: {by_status['PASS']} passed, {by_status['FAIL']} failed, "
        f"{by_status['WARN']} warnings, {by_status['INCONCLUSIVE']} inconclusive, "
        f"{by_status['ERROR']} errors — "
        f"{steps_ok}/{steps} steps ok — {time.monotonic() - started:.0f}s"
    )
    print("by tag: " + "  ".join(f"{t} {c['PASS']}/{sum(c.values())}" for t, c in sorted(by_tag.items())))
    print(f"\nEvery session id starts with scn-{run.run_id}- : paste one into the dashboard's 'Session id'")
    print("filter (Session timeline panel), or GET /admin/sessions/<id> and /admin/events?session_id=<id>.")
    if args.report:
        args.report.write_text(
            json.dumps(
                {
                    "run_id": run.run_id,
                    "scenarios": [
                        {
                            "name": o.scenario["name"],
                            "tags": o.scenario.get("tags", []),
                            "status": o.status,
                            "seconds": round(o.seconds, 1),
                            "sessions": o.session_ids,
                            "error": o.error,
                            "steps": [r.__dict__ for r in o.results],
                        }
                        for o in sorted(outcomes, key=lambda o: o.scenario["name"])
                    ],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
        print(f"report written to {args.report}")
    return 1 if by_status["FAIL"] or by_status["ERROR"] else 0


if __name__ == "__main__":
    sys.exit(main())
