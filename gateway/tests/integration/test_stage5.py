"""Stage 5 against the real stack: held-out data through the whole gateway (rules + ensemble).

    docker compose up -d --wait && uv run pytest -m integration -s tests/integration/test_stage5.py

The ML service reports its own held-out numbers (``GET /v1/model``); this test measures what the
*gateway* decides, which is what a caller experiences: rules and model together, with the model's
calibrated thresholds. Every message is its own new session, so nothing carries over between them.
"""

from __future__ import annotations

import statistics
import time
from collections import Counter

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.integration.test_stack import msg, new_key, settings
from tests.integration.test_stage4 import DATASETS, rows

pytestmark = pytest.mark.integration
ML_URL = "http://localhost:18000"


def heldout(name: str) -> list[dict[str, str]]:
    out = []
    for sub in ("attacks", "benign"):
        path = DATASETS / sub / f"heldout-{name}.jsonl"
        if path.exists():
            out += rows(f"{sub}/{path.name}")
    return out


def bulk_settings():
    return settings(
        max_prompt_chars=4000,
        rl_api_key_capacity=100_000,
        rl_global_capacity=100_000,
        rl_endpoint_capacity=100_000,
        ml_timeout_ms=1000,  # measuring accuracy here, not latency
    )


def test_heldout_sets_through_the_gateway() -> None:
    sets = {"public-deepset": heldout("public-deepset"), "handwritten": heldout("handwritten")}
    report = {}
    with TestClient(create_app(settings=bulk_settings())) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        for name, data in sets.items():
            actions: dict[str, Counter[str]] = {"attack": Counter(), "benign": Counter()}
            decided_by: Counter[str] = Counter()
            fps = []
            for r in data:
                d = c.post("/v1/inspect", json=msg(r["text"]), headers=auth).json()
                actions[r["label"]][d["action"]] += 1
                if d["action"] != "allow":
                    decided_by[d["checks"][-1]["name"]] += 1
                    if r["label"] == "benign":
                        fps.append((d["action"], d["reasons"], r["text"][:90]))
            n_att, n_ben = sum(actions["attack"].values()), sum(actions["benign"].values())
            caught = actions["attack"]["block"] + actions["attack"]["restrict"]
            report[name] = {
                "recall": caught / n_att if n_att else None,
                "fpr": (actions["benign"]["block"] + actions["benign"]["restrict"]) / n_ben,
            }
            print(
                f"\n{name}: attacks {dict(actions['attack'])} of {n_att}; benign {dict(actions['benign'])} "
                f"of {n_ben}; decided by {dict(decided_by)}"
            )
            for fp in fps[:8]:
                print("  FP:", fp)

    # Loose floors: the point is the printed report; these only catch a broken model or wiring.
    assert report["public-deepset"]["recall"] >= 0.7
    assert report["public-deepset"]["fpr"] <= 0.15
    assert report["handwritten"]["fpr"] <= 0.15


def test_ml_service_reports_calibrated_thresholds_and_heldout_metrics() -> None:
    info = httpx.get(f"{ML_URL}/v1/model", timeout=5).json()
    assert info["version"].startswith("ensemble-")
    assert 0.5 <= info["thresholds"]["restrict"] < info["thresholds"]["block"] <= 0.98
    assert {"public-deepset", "handwritten"} <= set(info["metrics"]["heldout"])
    assert info["embedder"].startswith("fastembed:")


def test_ml_tier_latency_through_the_gateway() -> None:
    """Gateway-side ML latency for a typical customer message (service time + HTTP hop)."""
    with TestClient(create_app(settings=bulk_settings())) as c:
        _k, key = new_key(c)
        auth = {"authorization": f"Bearer {key}"}
        totals, service = [], []
        for i in range(150):
            started = time.perf_counter()
            d = c.post(
                "/v1/inspect",
                json=msg(f"My bag {i} never arrived in Calgary, what can I do?"),
                headers=auth,
            ).json()
            totals.append((time.perf_counter() - started) * 1000)
            ml = next(x for x in d["checks"] if x["name"] == "ml")
            service.append(ml["detail"]["service_latency_ms"])

    def p(xs: list[float], q: float) -> str:
        return f"{sorted(xs)[int(len(xs) * q) - 1]:.1f}"

    print(
        f"\nfull pipeline p50 {p(totals, 0.5)} ms p99 {p(totals, 0.99)} ms; "
        f"ML service p50 {p(service, 0.5)} ms p99 {p(service, 0.99)} ms"
    )
    assert statistics.median(totals) < 50
