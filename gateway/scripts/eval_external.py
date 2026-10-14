"""Baseline: run the external labelled datasets (datasets/external/data/) through the current gateway.

    python3 -I datasets/external/fetch_external.py              # once: download (pinned) + convert
    docker compose up -d --wait
    cd gateway
    uv run python -m scripts.eval_external                      # everything; multi-turn sampled
    uv run python -m scripts.eval_external --source garak --limit 100
    uv run python -m scripts.eval_external --mt-limit 0         # single-turn only

An in-process gateway against the Docker stores and the real ML service, as eval_multiturn. Every
single-turn row is its own CMP session from its own address (a fresh /64 of 2001:db8::/32 per run), so
no row's bans, strikes or counters reach another. Multi-turn conversations are replayed as one session
each. Bot profiling is off (replayed messages arrive milliseconds apart) and rate limits are lifted;
everything else is the gateway's current configuration.

An attack row is *caught* when the gateway restricts or blocks it; a benign row is a *false positive*
when it does. A conversation is caught / flagged when any turn is. ``decided by`` is the first check
whose own verdict equals the final action (as in the dashboard). The local held-out sets the ML model
was tuned against (datasets/attacks|benign/heldout-*) run too, as an in-distribution reference.

Writes datasets/external/reports/baseline-<date>.{json,md}. The JSON keeps every miss and every false
positive (text, family, ML score) for review; the markdown keeps counts only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import ipaddress
import json
import random
import statistics
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

import httpx

from app.routes import inspect_tool_results
from scripts.eval_multiturn import CachingTransport, Replayer, base_settings

ROOT = Path(__file__).resolve().parents[2]
EXTERNAL = ROOT / "datasets" / "external" / "data"
REPORTS = ROOT / "datasets" / "external" / "reports"
LOCAL = {
    "local-attacks-heldout": ROOT / "datasets" / "attacks" / "heldout-public-deepset.jsonl",
    "local-benign-heldout-deepset": ROOT / "datasets" / "benign" / "heldout-public-deepset.jsonl",
    "local-benign-heldout-handwritten": ROOT / "datasets" / "benign" / "heldout-handwritten.jsonl",
}
FLAGGED = ("restrict", "block")
# Tool-result content (datasets/build_tool_content.py, build_external_splits.py): sent to
# POST /v1/inspect/tool-result as one tool output each.
TOOL_FILES = {
    "toolcontent-attacks": ROOT / "datasets" / "tool" / "attacks" / "heldout-toolcontent.jsonl",
    "toolcontent-benign": ROOT / "datasets" / "tool" / "benign" / "heldout-toolcontent.jsonl",
    # Sealed held-out: sentences no training row was derived from (build_tool_content.NORMAL_SEALED).
    "sealed-attacks": ROOT / "datasets" / "tool" / "attacks" / "heldout-toolcontent-sealed.jsonl",
    "sealed-benign": ROOT / "datasets" / "tool" / "benign" / "heldout-toolcontent-sealed.jsonl",
    "external-indirect-as-tool-data": ROOT / "datasets" / "attacks" / "heldout-external.jsonl",
}
CONV_REASONS = {
    "conversation_risk",
    "persistent_probing",
    "split_payload",
    "retry_after_block",
    "conversation_locked",
}
# A fresh /64 of the IPv6 documentation range per run: a deterministic block bans the address and bans
# outlive the run; the scenario library and smoke test ban addresses and ranges in 198.18.0.0/15.
_R = random.SystemRandom()
IPS = ipaddress.ip_network(f"2001:db8:{_R.getrandbits(16):x}:{_R.getrandbits(16):x}::/64")
IP_BASE = 1


def in_heldout(text: str, share: float = 0.2) -> bool:
    """The held-out rule of datasets/build_external_splits.py (first 60 normalised characters, hashed):
    with --heldout-only, external rows the ML model may have been trained on are left out."""
    key = " ".join(text.split()).casefold()[:60]
    return int(hashlib.sha256(key.encode()).hexdigest()[:8], 16) / 0xFFFFFFFF < share


def read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


def load_single(
    sources: set[str] | None, limit: int | None, local: bool, rng: random.Random
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    files = {p.stem: p for p in sorted(EXTERNAL.glob("*.jsonl")) if not p.stem.startswith("multiturn-")}
    if local:
        files.update(LOCAL)
    for name, path in files.items():
        if sources and name not in sources:
            continue
        got = read(path)
        for r in got:
            r["source"] = name  # local files carry their own origin in "source"; report by file
            r.setdefault("category", "benign" if r["label"] == "benign" else "direct_injection")
            r.setdefault("use", "reference")
        if limit and len(got) > limit:
            got = rng.sample(got, limit)
        rows += got
    return rows


def load_multi(mt_limit: int, rng: random.Random) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for path in sorted(EXTERNAL.glob("multiturn-*.jsonl")):
        by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in read(path):
            by_cat[r["category"]].append(r)
        # Half the budget to attacks (spread evenly over cipher families), half to the two benign kinds.
        for cat, rows in sorted(by_cat.items()):
            others = max(1, len(by_cat) - 1)
            share = mt_limit // 2 if cat == "jailbreak" else mt_limit // 2 // others
            fams: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for r in rows:
                fams[r["family"]].append(r)
            per = max(1, share // len(fams))
            for fam_rows in fams.values():
                out += rng.sample(fam_rows, min(per, len(fam_rows)))
    return out


class Pool:
    """One in-process gateway per worker thread (each TestClient owns an event loop)."""

    def __init__(self, cfg: Any, cache: CachingTransport) -> None:
        self.cfg, self.cache, self.local = cfg, cache, threading.local()
        self.all: list[Replayer] = []
        self.lock = threading.Lock()

    def get(self) -> Replayer:
        rp: Replayer | None = getattr(self.local, "rp", None)
        if rp is None:
            rp = self.local.rp = Replayer(self.cfg, self.cache)
            app = rp.client.app
            if not any(getattr(r, "path", "") == "/v1/inspect/tool-result" for r in app.routes):
                app.include_router(inspect_tool_results.router)  # until main.py registers it
            key = rp.client.post(
                "/admin/api-keys",
                json={"name": f"eval-tool-{rp.run_id}", "scopes": ["tool"]},
                headers={"x-admin-key": self.cfg.admin_api_key.get_secret_value()},
            )
            self.local.tool_auth = {"authorization": f"Bearer {key.json()['api_key']}"}
            with self.lock:
                self.all.append(rp)
        return rp

    def close(self) -> None:
        for rp in self.all:
            rp.close()


def outcome(d: dict[str, Any]) -> dict[str, Any]:
    checks = d.get("checks", [])
    ml = next((c for c in checks if c["name"] == "ml"), None)
    decider = next((c["name"] for c in checks if c.get("action") == d["action"]), None)
    return {
        "action": d["action"],
        "reasons": d["reasons"],
        "decided_by": decider or ("-" if d["action"] == "allow" else "policy"),
        "fired": sorted({c["name"] for c in checks if c.get("action") in FLAGGED}),
        "ml_score": (ml or {}).get("detail", {}).get("score"),
    }


def run_single(pool: Pool, run_id: str, i: int, row: dict[str, Any]) -> dict[str, Any]:
    rp = pool.get()
    body = {"session_id": f"ext-{run_id}-{i}", "message": row["text"], "ip": str(IPS[IP_BASE + i])}
    t = time.perf_counter()
    res = rp.client.post("/v1/inspect", json=body, headers=rp.auth)
    ms = (time.perf_counter() - t) * 1000
    if res.status_code != 200:
        return {
            "action": f"http_{res.status_code}",
            "reasons": [],
            "decided_by": "http",
            "fired": [],
            "ml_score": None,
            "ms": ms,
        }
    return {**outcome(res.json()), "ms": ms}


def run_multi(pool: Pool, run_id: str, i: int, conv: dict[str, Any]) -> dict[str, Any]:
    rp = pool.get()
    sid, ip = f"extmt-{run_id}-{i}", str(IPS[IP_BASE + 70_000 + i])
    turns = []
    for text in conv["turns"]:
        res = rp.client.post(
            "/v1/inspect", json={"session_id": sid, "message": text, "ip": ip}, headers=rp.auth
        )
        turns.append(
            outcome(res.json())
            if res.status_code == 200
            else {"action": f"http_{res.status_code}", "reasons": []}
        )
    first = next((k for k, t in enumerate(turns) if t["action"] in FLAGGED), None)
    return {
        "flagged": first is not None,
        "blocked": any(t["action"] == "block" for t in turns),
        "first_flag_turn": first,
        "decided_by": turns[first]["decided_by"] if first is not None else "-",
        "by_conversation": any(CONV_REASONS & set(t["reasons"]) for t in turns),
        "turns": len(turns),
        "turns_flagged": sum(t["action"] in FLAGGED for t in turns),
        # one letter per turn: a(llow) r(estrict) b(lock) t(hrottle) i(nspect)
        "pattern": "".join(t["action"][0] for t in turns),
    }


def load_tool() -> list[dict[str, Any]]:
    rows = []
    for name, path in TOOL_FILES.items():
        if not path.exists():
            continue
        for r in read(path):
            if name.startswith("external") and r["family"] != "indirect_injection":
                continue
            rows.append({**r, "set": name})
    return rows


def run_tool(pool: Pool, run_id: str, i: int, row: dict[str, Any]) -> dict[str, Any]:
    rp = pool.get()
    body = {"session_id": f"exttool-{run_id}-{i}", "tool_name": "eval", "result": {"note": row["text"]}}
    res = rp.client.post("/v1/inspect/tool-result", json=body, headers=pool.local.tool_auth)
    if res.status_code != 200:
        return {"action": f"http_{res.status_code}", "cmp_action": None, "decided_by": "http", "reasons": []}
    d = res.json()
    return {**outcome(d), "cmp_action": d["cmp_action"]}


def summarise_tool(rows: list[dict[str, Any]], res: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for i, r in enumerate(rows):
        groups[(r["set"], r["label"], r["family"])].append(i)
    out = []
    for (name, label, family), idx in sorted(groups.items()):
        rs = [res[i] for i in idx]
        out.append(
            {
                "set": name,
                "label": label,
                "family": family,
                "n": len(idx),
                "flagged": sum(x["action"] in FLAGGED for x in rs),
                "withheld": sum(x["cmp_action"] == "withhold" for x in rs),
                "sanitized": sum(x["cmp_action"] == "deliver_without_tools" for x in rs),
                "decided_by": dict(
                    Counter(x["decided_by"] for x in rs if x["action"] in FLAGGED).most_common()
                ),
            }
        )
    return out


def ml_thresholds(url: str, model: str = "chat") -> dict[str, float] | None:
    """The calibrated thresholds the gateway uses for this model (ML_USE_MODEL_THRESHOLDS); None when
    the service does not report them (the gateway's ML_RESTRICT_AT / ML_BLOCK_AT then apply)."""
    try:
        t = httpx.get(f"{url}/v1/model", params={"model": model}, timeout=5).json().get("thresholds")
    except (httpx.HTTPError, ValueError):
        return None
    return {k: round(float(t[k]), 4) for k in ("restrict", "block")} if t else None


def ml_model(url: str, key: str = "model_version") -> str:
    """A model version the run measured (results only compare across the same models): the chat
    model's, or with ``key="tool_model_version"`` the tool-content model's (None: the service has none
    and the tool route was answered by the chat model)."""
    try:
        return str(httpx.get(f"{url}/health", timeout=5).json().get(key))
    except httpx.HTTPError:
        return "unknown"


def pct(n: int, d: int) -> str:
    return f"{n}/{d} ({100 * n / d:.1f}%)" if d else "—"


def summarise_single(rows: list[dict[str, Any]], res: list[dict[str, Any]]) -> dict[str, Any]:
    groups: dict[tuple[str, str, str], list[int]] = defaultdict(list)
    for i, r in enumerate(rows):
        groups[(r["source"], r["label"], r["category"])].append(i)
    table = []
    for (src, label, cat), idx in sorted(groups.items()):
        rs = [res[i] for i in idx]
        flagged = sum(x["action"] in FLAGGED for x in rs)
        fams: dict[str, list[bool]] = defaultdict(list)
        for i in idx:
            fams[str(rows[i].get("family"))].append(res[i]["action"] in FLAGGED)
        table.append(
            {
                "source": src,
                "label": label,
                "category": cat,
                "use": rows[idx[0]].get("use"),
                "n": len(idx),
                "flagged": flagged,
                "blocked": sum(x["action"] == "block" for x in rs),
                "restricted": sum(x["action"] == "restrict" for x in rs),
                "errors": sum(x["action"].startswith("http_") for x in rs),
                "decided_by": dict(
                    Counter(x["decided_by"] for x in rs if x["action"] in FLAGGED).most_common()
                ),
                "families": {f: {"n": len(v), "flagged": sum(v)} for f, v in sorted(fams.items())},
            }
        )
    return {"groups": table}


def by_category(rows: list[dict[str, Any]], res: list[dict[str, Any]]) -> dict[str, dict[str, int]]:
    out: dict[str, Counter[str]] = defaultdict(Counter)
    for r, x in zip(rows, res, strict=True):
        key = f"{r['label']}/{r['category']}"
        out[key]["n"] += 1
        out[key]["flagged"] += x["action"] in FLAGGED
        out[key]["blocked"] += x["action"] == "block"
        for c in x["fired"]:
            out[key][f"fired:{c}"] += 1
    return {k: dict(v) for k, v in sorted(out.items())}


def summarise_multi(convs: list[dict[str, Any]], res: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[int]] = defaultdict(list)
    for i, c in enumerate(convs):
        groups[(c["label"], c["category"])].append(i)
    out = []
    for (label, cat), idx in sorted(groups.items()):
        rs = [res[i] for i in idx]
        firsts = [x["first_flag_turn"] for x in rs if x["first_flag_turn"] is not None]
        out.append(
            {
                "label": label,
                "category": cat,
                "n": len(idx),
                "flagged": sum(x["flagged"] for x in rs),
                "blocked": sum(x["blocked"] for x in rs),
                "by_conversation_check": sum(x["by_conversation"] for x in rs),
                "median_first_flag_turn": statistics.median(firsts) if firsts else None,
                "turns": sum(x["turns"] for x in rs),
                "turns_flagged": sum(x["turns_flagged"] for x in rs),
                "decided_by": dict(Counter(x["decided_by"] for x in rs if x["flagged"]).most_common()),
                "families": {
                    f: {
                        "n": sum(convs[i]["family"] == f for i in idx),
                        "flagged": sum(res[i]["flagged"] for i in idx if convs[i]["family"] == f),
                    }
                    for f in sorted({convs[i]["family"] for i in idx})
                },
            }
        )
    return out


def markdown(
    meta: dict[str, Any],
    single: dict[str, Any],
    cats: dict[str, Any],
    multi: list[dict[str, Any]],
    lat: dict[str, float],
    tool: list[dict[str, Any]] | None = None,
) -> str:
    L = [
        f"# External datasets — baseline against the current gateway ({meta['date']})",
        "",
        f"Rows: {meta['single_rows']} single-turn, {meta['multi_convs']} multi-turn conversations "
        f"(sample of {meta['multi_available']}). Seed {meta['seed']}. ML model `{meta['ml_model']}`, "
        f"thresholds {meta['ml_thresholds']}; tool model `{meta.get('ml_tool_model')}`, thresholds "
        f"{meta.get('ml_tool_thresholds')}. Bot profiling off, rate limits lifted.",
        f"Inspect latency (in-process, single-turn): p50 {lat['p50']:.0f} ms, p95 {lat['p95']:.0f} ms.",
        "",
        "Attacks: *caught* = restricted or blocked. Benign: *flagged* = a false positive.",
        "",
        "## By category (all sources)",
        "",
        "| label / category | n | caught or flagged | blocked | checks that fired (count) |",
        "|---|---|---|---|---|",
    ]
    for k, v in cats.items():
        fired = ", ".join(
            f"{c.split(':', 1)[1]} {n}"
            for c, n in sorted(v.items(), key=lambda kv: -kv[1])
            if c.startswith("fired:")
        )
        L.append(
            f"| {k} | {v['n']} | {pct(v['flagged'], v['n'])} | {pct(v['blocked'], v['n'])} | {fired or '—'} |"
        )
    L += [
        "",
        "## By source",
        "",
        "| source | use | label / category | n | caught or flagged | blocked | decided by |",
        "|---|---|---|---|---|---|---|",
    ]
    for g in single["groups"]:
        dec = ", ".join(f"{k} {v}" for k, v in g["decided_by"].items()) or "—"
        L.append(
            f"| {g['source']} | {g['use']} | {g['label']}/{g['category']} | {g['n']} | "
            f"{pct(g['flagged'], g['n'])} | {pct(g['blocked'], g['n'])} | {dec} |"
        )
    L += [
        "",
        "## Weakest attack families (≥ 5 rows, lowest catch rate)",
        "",
        "| source | family | n | caught |",
        "|---|---|---|---|",
    ]
    fams = [
        (g["source"], f, v)
        for g in single["groups"]
        if g["label"] == "attack"
        for f, v in g["families"].items()
        if v["n"] >= 5
    ]
    for src, f, v in sorted(fams, key=lambda t: t[2]["flagged"] / t[2]["n"])[:20]:
        L.append(f"| {src} | {f} | {v['n']} | {pct(v['flagged'], v['n'])} |")
    if multi:
        L += [
            "",
            "## Multi-turn (each conversation one session)",
            "",
            "`obfuscated_benign`: a harmless goal delivered through the same cipher / word-mapping set-up "
            "as the attacks. Blocking it is expected in a customer chat; it is not a false positive.",
            "",
            "| label / category | conversations | caught or flagged | blocked | via conversation check "
            "| median first flagged turn | turns flagged | decided by |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for m in multi:
            dec = ", ".join(f"{k} {v}" for k, v in m["decided_by"].items()) or "—"
            cells = [
                f"{m['label']}/{m['category']}",
                m["n"],
                pct(m["flagged"], m["n"]),
                pct(m["blocked"], m["n"]),
                m["by_conversation_check"],
                m["median_first_flag_turn"],
                pct(m["turns_flagged"], m["turns"]),
                dec,
            ]
            L.append("| " + " | ".join(str(c) for c in cells) + " |")
    if tool:
        L += [
            "",
            "## Tool results (POST /v1/inspect/tool-result, one tool output per row)",
            "",
            f"Tool-content model: `{meta.get('ml_tool_model')}` (None: the chat model answered).",
            "",
            "| set | label / family | n | caught or flagged | withheld | parts removed | decided by |",
            "|---|---|---|---|---|---|---|",
        ]
        for t in tool:
            dec = ", ".join(f"{k} {v}" for k, v in t["decided_by"].items()) or "—"
            L.append(
                f"| {t['set']} | {t['label']}/{t['family']} | {t['n']} | {pct(t['flagged'], t['n'])} | "
                f"{t['withheld']} | {t['sanitized']} | {dec} |"
            )
    L += ["", "Misses and false positives (text, family, ML score) are in the JSON report next to this file."]
    return "\n".join(L) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--source", action="append", help="only these sources (file stems); repeatable")
    p.add_argument("--limit", type=int, help="at most N rows per single-turn source (random, seeded)")
    p.add_argument("--mt-limit", type=int, default=400, help="multi-turn conversations to sample (0 = none)")
    p.add_argument("--no-local", action="store_true", help="skip the local held-out reference sets")
    p.add_argument("--no-tool", action="store_true", help="skip the tool-result content")
    p.add_argument(
        "--heldout-only",
        action="store_true",
        help="external rows only from the held-out split (compare models after training on the rest)",
    )
    p.add_argument("--workers", type=int, default=6)
    p.add_argument("--seed", type=int, default=7)
    p.add_argument(
        "--set", action="append", default=[], metavar="NAME=VALUE", help="override a gateway setting"
    )
    args = p.parse_args()
    if not EXTERNAL.exists():
        raise SystemExit("no converted data: run  python3 -I datasets/external/fetch_external.py  first")

    overrides: dict[str, Any] = {"bot_enabled": False}
    for item in args.set:
        name, _, value = item.partition("=")
        overrides[name] = json.loads(value) if value[:1].isdigit() or value in ("true", "false") else value
    cfg = base_settings(**overrides)
    rng = random.Random(args.seed)  # noqa: S311 - reproducible sampling, not security
    rows = load_single(set(args.source) if args.source else None, args.limit, not args.no_local, rng)
    mt_all = sum(len(read(p)) for p in EXTERNAL.glob("multiturn-*.jsonl"))
    convs = load_multi(args.mt_limit, rng) if args.mt_limit and not args.source else []
    tool_rows = load_tool() if not (args.no_tool or args.source) else []
    if args.heldout_only:  # local reference sets are held-out files already; Tensor Trust is never trained
        rows = [r for r in rows if r["use"] in ("reference", "eval_only") or in_heldout(r["text"])]
    run_id = f"{dt.datetime.now():%H%M%S}"
    print(f"single-turn rows: {len(rows)}; multi-turn conversations: {len(convs)}; workers {args.workers}")

    pool = Pool(cfg, CachingTransport())
    t0 = time.time()
    try:
        with ThreadPoolExecutor(args.workers) as ex:
            res = list(ex.map(lambda ir: run_single(pool, run_id, *ir), enumerate(rows)))
            print(f"  single-turn done in {time.time() - t0:.0f}s")
            mres = list(ex.map(lambda ic: run_multi(pool, run_id, *ic), enumerate(convs)))
            print(f"  multi-turn done in {time.time() - t0:.0f}s")
            tres = list(ex.map(lambda it: run_tool(pool, run_id, *it), enumerate(tool_rows)))
            print(f"  tool results done in {time.time() - t0:.0f}s ({len(tool_rows)} rows)")
    finally:
        pool.close()

    ms = sorted(x["ms"] for x in res) or [0.0]
    lat = {"p50": ms[len(ms) // 2], "p95": ms[int(len(ms) * 0.95) - 1 if len(ms) > 1 else 0]}
    single = summarise_single(rows, res)
    cats = by_category(rows, res)
    multi = summarise_multi(convs, mres)
    tool = summarise_tool(tool_rows, tres)
    date = f"{dt.date.today():%Y-%m-%d}"
    meta = {
        "date": date,
        "ml_model": ml_model(cfg.ml_url),
        "ml_tool_model": ml_model(cfg.ml_url, "tool_model_version"),
        "seed": args.seed,
        "single_rows": len(rows),
        "multi_convs": len(convs),
        "multi_available": mt_all,
        "ml_thresholds": (ml_thresholds(cfg.ml_url) if cfg.ml_use_model_thresholds else None)
        or {"restrict": cfg.ml_restrict_at, "block": cfg.ml_block_at},
        "ml_tool_thresholds": ml_thresholds(cfg.ml_url, "tool") if cfg.ml_use_model_thresholds else None,
        "overrides": overrides,
        "limit": args.limit,
        "sources": args.source,
        "heldout_only": args.heldout_only,
    }
    keep = ("text", "source", "category", "family", "use")
    misses = [
        {**{k: r.get(k) for k in keep}, **x}
        for r, x in zip(rows, res, strict=True)
        if r["label"] == "attack" and x["action"] not in FLAGGED
    ]
    fps = [
        {**{k: r.get(k) for k in keep}, **x}
        for r, x in zip(rows, res, strict=True)
        if r["label"] == "benign" and x["action"] in FLAGGED
    ]
    REPORTS.mkdir(parents=True, exist_ok=True)
    # A partial run (some sources, a row limit, a smaller multi-turn sample) never overwrites a full one.
    parts = [*(args.source or []), *([f"limit{args.limit}"] if args.limit else [])]
    if args.no_tool:
        parts.append("notool")
    if args.heldout_only:
        parts.append("heldout")
    if args.mt_limit != 400 or args.no_local:
        parts.append(f"mt{args.mt_limit}" + ("-nolocal" if args.no_local else ""))
    stem = "-".join([f"baseline-{date}", *parts])
    (REPORTS / f"{stem}.json").write_text(
        json.dumps(
            {
                "meta": meta,
                "latency_ms": lat,
                "by_category": cats,
                "single": single,
                "multi": multi,
                "tool": tool,
                "tool_misses": [
                    {"text": r["text"], "set": r["set"], **x}
                    for r, x in zip(tool_rows, tres, strict=True)
                    if r["label"] == "attack" and x["action"] not in FLAGGED
                ],
                "tool_false_positives": [
                    {"text": r["text"], "set": r["set"], **x}
                    for r, x in zip(tool_rows, tres, strict=True)
                    if r["label"] == "benign" and x["action"] in FLAGGED
                ],
                "misses": misses,
                "false_positives": fps,
                "multi_misses": [
                    {"id": c["id"], "family": c["family"], "category": c["category"]}
                    for c, x in zip(convs, mres, strict=True)
                    if c["label"] == "attack" and not x["flagged"]
                ],
                "multi_false_positives": [
                    {"id": c["id"], "family": c["family"], "category": c["category"], **x}
                    for c, x in zip(convs, mres, strict=True)
                    if c["label"] == "benign" and x["flagged"]
                ],
            },
            indent=1,
            ensure_ascii=False,
        )
    )
    (REPORTS / f"{stem}.md").write_text(markdown(meta, single, cats, multi, lat, tool))
    print(f"wrote {(REPORTS / stem).relative_to(ROOT)}.{{md,json}}")


if __name__ == "__main__":
    main()
