"""Replay labelled multi-turn conversations through the gateway and report what Stage 6 adds.

    docker compose up -d --wait
    cd gateway
    uv run python -m scripts.eval_multiturn                     # held-out set, current settings
    uv run python -m scripts.eval_multiturn --sweep             # choose thresholds on calib.jsonl
    uv run python -m scripts.eval_multiturn --set conv_restrict_at=1.2 --set conv_window_lift=0.2

Runs an in-process gateway against the Docker stores and the real ML service. Every conversation is
replayed twice: every turn in a new session (nothing remembered — the single-turn baseline) and the
whole conversation as one session (Stage 6). Requests carry no customer id; a deterministic block bans
only that session, and bot profiling is off because replayed turns arrive milliseconds apart.

Attack conversations count as *caught* when any turn from the first attack turn on is restricted or
blocked; *turns to catch* counts from that first attack turn (0 = the first attack turn itself).
Benign conversations count as *flagged* when any turn is restricted or blocked; "added by Stage 6"
is when the conversation check is what flagged it.

ML answers are cached by request body for the whole run (the model is deterministic), so a sweep
re-scores nothing it has already seen.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import statistics
import uuid
from collections import defaultdict
from pathlib import Path
from typing import Any

import httpx
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "datasets" / "multiturn"
REPORTS = Path(__file__).resolve().parents[1] / "reports"
FLAGGED = ("restrict", "block")
CONV_REASONS = {
    "conversation_risk",
    "persistent_probing",
    "split_payload",
    "retry_after_block",
    "conversation_locked",
}

# Grid, most sensitive value first in each list. The sweep keeps the most sensitive combination
# whose conversation check stays within the false-positive budget on calib.jsonl's benign chats
# (thresholds from a false-positive budget, as in Stage 5). calib.jsonl is built from half of the
# held-out rows; the report uses heldout.jsonl, built from the other half.
SWEEP = {
    "conv_window_ml_action": ["block", "restrict", "off"],
    "conv_window_lift": [0.25, 0.4, 0.55],
    "conv_restrict_at": [0.8, 1.0, 1.2],
}


class CachingTransport(httpx.AsyncBaseTransport):
    """Answers repeated ML requests from a cache shared across runs. Each replayer gets its own
    instance (``fresh()``) because connections belong to one event loop."""

    def __init__(self, cache: dict[tuple[str, bytes], tuple[int, bytes]] | None = None) -> None:
        self._inner = httpx.AsyncHTTPTransport()
        self._cache = cache if cache is not None else {}

    def fresh(self) -> CachingTransport:
        return CachingTransport(self._cache)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        body = await request.aread()
        key = (str(request.url), body)
        if key not in self._cache:
            res = await self._inner.handle_async_request(request)
            self._cache[key] = (res.status_code, await res.aread())
        status, content = self._cache[key]
        return httpx.Response(status, content=content, headers={"content-type": "application/json"})


def base_settings(**overrides: Any) -> Settings:
    values: dict[str, Any] = {
        "redis_url": os.environ.get("IT_REDIS_URL", "redis://localhost:16379"),
        "database_url": os.environ.get("IT_DATABASE_URL", "postgresql://sec:sec@localhost:15432/security"),
        "ml_url": os.environ.get("IT_ML_URL", "http://localhost:18000"),
        "upstream_ai_url": os.environ.get("IT_UPSTREAM_URL", "http://localhost:19000"),
        "admin_api_key": os.environ.get("ADMIN_API_KEY", "change-me-admin-key"),
        "max_prompt_chars": 4000,
        "rl_api_key_capacity": 1_000_000,
        "rl_global_capacity": 1_000_000,
        "rl_endpoint_capacity": 1_000_000,
        "rl_session_capacity": 1_000_000,
        "ml_timeout_ms": 2000,  # measuring accuracy, not latency
        "log_level": "warning",
    }
    values.update(overrides)
    return Settings(**values)


def load(name: str) -> list[dict[str, Any]]:
    return [json.loads(line) for line in (DATA / name).read_text().splitlines() if line.strip()]


class Replayer:
    def __init__(self, cfg: Settings, cache: CachingTransport) -> None:
        self.client = TestClient(create_app(settings=cfg))
        self.client.__enter__()
        ml = httpx.AsyncClient(transport=cache.fresh(), base_url=cfg.ml_url)
        self.client.app.state.ml._http = ml  # type: ignore[attr-defined]
        self.client.app.state.conversations._ml._http = ml  # type: ignore[attr-defined]
        admin = {"x-admin-key": cfg.admin_api_key.get_secret_value()}
        key = self.client.post(
            "/admin/api-keys",
            json={"name": f"eval-{uuid.uuid4().hex[:8]}", "scopes": ["inspect"]},
            headers=admin,
        )
        self.auth = {"authorization": f"Bearer {key.json()['api_key']}"}
        self.run_id = uuid.uuid4().hex[:6]

    def close(self) -> None:
        self.client.__exit__(None, None, None)

    def replay(self, conv: dict[str, Any], tracked: bool) -> list[dict[str, Any]]:
        out = []
        session = f"{self.run_id}-{conv['id']}"
        for i, turn in enumerate(conv["turns"]):
            # Tracked: the whole conversation is one CMP session. Single-turn baseline: every turn is a
            # new session, so nothing is remembered between turns.
            sid = session if tracked else f"{session}-turn{i}"
            body: dict[str, Any] = {"session_id": sid, "message": turn["text"]}
            d = self.client.post("/v1/inspect", json=body, headers=self.auth).json()
            out.append({"action": d["action"], "reasons": d["reasons"]})
        return out


def summarise(
    convs: list[dict[str, Any]], single: dict[str, list], tracked: dict[str, list]
) -> dict[str, Any]:
    by_kind: dict[str, dict[str, Any]] = defaultdict(lambda: defaultdict(list))
    for conv in convs:
        k, s, t = by_kind[conv["kind"]], single[conv["id"]], tracked[conv["id"]]
        start = conv["attack_start"]
        if conv["label"] == "attack":
            for mode, turns in (("single", s), ("stage6", t)):
                hits = [i - start for i, r in enumerate(turns) if i >= start and r["action"] in FLAGGED]
                k[f"caught_{mode}"].append(bool(hits))
                if hits:
                    k[f"turns_{mode}"].append(hits[0])
                k[f"blocked_{mode}"].append(any(r["action"] == "block" for r in turns[start:]))
            first = next((r for r in t[start:] if r["action"] in FLAGGED), None)
            if first and not any(r["action"] in FLAGGED for r in s[start:]):
                k["added_by"].extend(sorted(CONV_REASONS & set(first["reasons"])))
        else:
            k["flagged_single"].append(any(r["action"] in FLAGGED for r in s))
            k["flagged_stage6"].append(any(r["action"] in FLAGGED for r in t))
            k["added_stage6"].append(any(CONV_REASONS & set(r["reasons"]) for r in t))
            k["turns"].append(len(t))
            k["turn_flags_stage6"].append(sum(r["action"] in FLAGGED for r in t))

    def rate(xs: list[bool]) -> str:
        return f"{sum(xs)}/{len(xs)}"

    out: dict[str, Any] = {}
    for kind, k in by_kind.items():
        if "caught_single" in k:
            out[kind] = {
                "n": len(k["caught_single"]),
                "caught_single_turn": rate(k["caught_single"]),
                "caught_stage6": rate(k["caught_stage6"]),
                "blocked_single_turn": rate(k["blocked_single"]),
                "blocked_stage6": rate(k["blocked_stage6"]),
                "median_turns_to_catch_single": statistics.median(k["turns_single"])
                if k["turns_single"]
                else None,
                "median_turns_to_catch_stage6": statistics.median(k["turns_stage6"])
                if k["turns_stage6"]
                else None,
                "caught_only_by_stage6_via": dict(
                    sorted((r, k["added_by"].count(r)) for r in set(k["added_by"]))
                ),
            }
        else:
            out[kind] = {
                "n": len(k["flagged_single"]),
                "flagged_single_turn": rate(k["flagged_single"]),
                "flagged_stage6": rate(k["flagged_stage6"]),
                "flagged_by_conversation_check": rate(k["added_stage6"]),
                "turns": sum(k["turns"]),
                "turns_flagged_stage6": sum(k["turn_flags_stage6"]),
            }
    return out


def score_cfg(summary: dict[str, Any]) -> tuple[float, float]:
    """(share of attack conversations caught, share of benign conversations the conversation check flagged)."""
    caught = sum(int(v["caught_stage6"].split("/")[0]) for v in summary.values() if "caught_stage6" in v)
    total = sum(v["n"] for v in summary.values() if "caught_stage6" in v)
    benign = [v for v in summary.values() if "flagged_by_conversation_check" in v]
    added = sum(int(v["flagged_by_conversation_check"].split("/")[0]) for v in benign)
    return caught / max(total, 1), added / max(sum(v["n"] for v in benign), 1)


def evaluate(
    name: str, overrides: dict[str, Any], cache: CachingTransport, single: dict[str, list] | None = None
) -> tuple[dict[str, Any], dict[str, list]]:
    convs = load(name)
    # Replayed turns arrive milliseconds apart: bot profiling would judge the replay, not the content.
    rp = Replayer(base_settings(**{"bot_enabled": False, **overrides}), cache)
    try:
        if single is None:
            single = {c["id"]: rp.replay(c, tracked=False) for c in convs}
        tracked = {c["id"]: rp.replay(c, tracked=True) for c in convs}
    finally:
        rp.close()
    return summarise(convs, single, tracked), single


def markdown(title: str, cfg: dict[str, Any], summary: dict[str, Any], sweep: list | None) -> str:
    lines = [
        f"# {title}",
        "",
        "Settings: " + ", ".join(f"`{k}={v}`" for k, v in cfg.items()),
        "",
        "| kind | n | caught, single-turn | caught, Stage 6 | blocked, single-turn | blocked, Stage 6 | median turns to catch (single → Stage 6) | caught only by Stage 6, via |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for kind, v in summary.items():
        if "caught_stage6" in v:
            lines.append(
                f"| {kind} | {v['n']} | {v['caught_single_turn']} | {v['caught_stage6']} | {v['blocked_single_turn']} | {v['blocked_stage6']} | "
                f"{v['median_turns_to_catch_single']} → {v['median_turns_to_catch_stage6']} | "
                f"{', '.join(f'{r} {n}' for r, n in v['caught_only_by_stage6_via'].items()) or '—'} |"
            )
    lines += [
        "",
        "| benign kind | conversations | turns | flagged, single-turn | flagged, Stage 6 | flagged by the conversation check | turns flagged, Stage 6 |",
        "|---|---|---|---|---|---|---|",
    ]
    for kind, v in summary.items():
        if "flagged_stage6" in v:
            lines.append(
                f"| {kind} | {v['n']} | {v['turns']} | {v['flagged_single_turn']} | {v['flagged_stage6']} | "
                f"{v['flagged_by_conversation_check']} | {v['turns_flagged_stage6']} |"
            )
    if sweep:
        lines += [
            "",
            "## Sweep on the calibration set (calib.jsonl)",
            "",
            "| settings | attack conversations caught | benign conversations flagged by the conversation check |",
            "|---|---|---|",
        ]
        for cfg_i, caught, added in sweep:
            lines.append(f"| {cfg_i} | {caught:.3f} | {added:.3f} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", default="heldout.jsonl")
    p.add_argument("--sweep", action="store_true", help="grid-search conversation thresholds on calib.jsonl")
    p.add_argument(
        "--max-added-fp",
        type=float,
        default=0.025,
        help="sweep: max share of benign conversations the conversation check may flag",
    )
    p.add_argument("--set", action="append", default=[], metavar="NAME=VALUE")
    args = p.parse_args()
    overrides: dict[str, Any] = {}
    for item in args.set:
        name, _, value = item.partition("=")
        overrides[name] = json.loads(value) if value[:1].isdigit() or value in ("true", "false") else value

    cache = CachingTransport()
    sweep_rows = None
    if args.sweep:
        sweep_rows, single = [], None
        for combo in itertools.product(*SWEEP.values()):
            cfg = dict(zip(SWEEP, combo, strict=True))
            summary, single = evaluate("calib.jsonl", {**overrides, **cfg}, cache, single)
            caught, added = score_cfg(summary)
            sweep_rows.append((cfg, caught, added))
            print(f"  {cfg}: attacks caught {caught:.3f}, benign flagged by conversation {added:.3f}")
        ok = [r for r in sweep_rows if r[2] <= args.max_added_fp]
        # Most attacks caught, then fewest false alarms; ties keep grid order (most sensitive first).
        best = max(ok, key=lambda r: (r[1], -r[2])) if ok else min(sweep_rows, key=lambda r: r[2])
        print(f"chosen on calib set: {best[0]}")
        overrides.update(best[0])

    summary, _ = evaluate(args.data, overrides, cache)
    print(json.dumps(summary, indent=2))
    REPORTS.mkdir(exist_ok=True)
    stem = f"multiturn-{Path(args.data).stem}"
    effective = {
        k: getattr(base_settings(**overrides), k)
        for k in (
            "conv_floor",
            "conv_decay",
            "conv_restrict_at",
            "conv_block_at",
            "conv_window_lift",
            "conv_window_ml_action",
            "conv_window_turns",
            "conv_retry_similarity",
            "conv_max_blocks",
            "conv_setup_boost",
        )
    }
    (REPORTS / f"{stem}.json").write_text(
        json.dumps({"settings": effective, "summary": summary, "sweep": sweep_rows}, indent=2, default=str)
    )
    (REPORTS / f"{stem}.md").write_text(
        markdown(f"Multi-turn evaluation — {args.data}", effective, summary, sweep_rows)
    )
    print(f"wrote {REPORTS.relative_to(ROOT)}/{stem}.md")


if __name__ == "__main__":
    main()
