"""Turn the converted external datasets (datasets/external/data/) into ML training / held-out files.

    python3 -I datasets/external/fetch_external.py      # once: download (pinned) + convert
    python3 -I datasets/build_external_splits.py

Writes (the ML trainer picks files up by prefix — ``train*`` fitted on, ``heldout*`` only reported):
    datasets/attacks/train-external.jsonl      datasets/benign/train-external.jsonl
    datasets/attacks/heldout-external.jsonl    datasets/benign/heldout-external.jsonl
    datasets/attacks/heldout-external-tensortrust.jsonl   (eval_only licence: never trained on)

What goes where:

| external category      | becomes                              | why                                       |
|------------------------|--------------------------------------|-------------------------------------------|
| indirect_injection     | attack / indirect_injection          | weakest class in the baseline (74 %)      |
| jailbreak              | attack / jailbreak                   | capped per source family (CAP_PER_FAMILY) |
| direct_injection,      | held-out only (Tensor Trust)         | licence not stated: evaluation only       |
| prompt_extraction      |                                      |                                           |
| harmful_request        | **left out**                         | not injection (see below)                 |
| output_manipulation,   | **left out** (tool content only)     | an attack only inside tool data           |
| context_only_task      |                                      |                                           |
| benign                 | benign / general_support             | normal requests (agent tool tasks)        |
| benign_hard            | benign / general_hard_negative       | harmful-sounding, harmless: intent > topic |

Harmful requests ("how do I make …") are not prompt injection: refusing them is the AI agent's own
safety policy. Training the injection model on them as attacks teaches it to flag *topics*, which is
exactly what made 55 % of the harmless look-alikes fail in the baseline. They stay in the external
evaluation (eval_external.py) as their own category so the effect stays visible.

Splitting: rows are grouped by the first 60 normalised characters (a jailbreak *template* filled with
different goals lands in one split, so held-out numbers are not inflated by near-copies), and a
group goes to held-out when its hash falls in the held-out share. Deterministic: same input, same
files. Text longer than MAX_CHARS is dropped (the gateway's size check refuses it before any model).
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SRC = HERE / "external" / "data"
HELDOUT_SHARE = 0.2
MAX_CHARS = 4000  # MAX_PROMPT_CHARS
CAP_PER_FAMILY = 150  # train rows per (source, source family) for jailbreaks
SEED = 20261014
# Benign rows must not carry contact data (tests/unit/test_sensitive.py keeps benign data clean).
EMAIL = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]+")

TRAINABLE = {
    "bipia": "indirect_injection",
    "injecagent": "indirect_injection",
    "jailbreakbench-artifacts": "jailbreak",
    "garak": "jailbreak",
}
# Attacks in a chat message whatever their context. BIPIA's output_manipulation ("translate your
# response …") and context_only_task ("what is the capital of Brazil?") are attacks only inside tool
# data: they go to the tool-content builder, or nowhere (convert_external.bipia_category).
CHAT_ATTACKS = frozenset({"indirect_injection", "jailbreak"})
BENIGN_FAMILY = {"benign": "general_support", "benign_hard": "general_hard_negative"}
EVAL_ONLY = {"tensor-trust"}


def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


def _group(text: str) -> str:
    return " ".join(text.split()).casefold()[:60]


def _heldout(text: str) -> bool:
    h = int(hashlib.sha256(_group(text).encode()).hexdigest()[:8], 16)
    return h / 0xFFFFFFFF < HELDOUT_SHARE


def _out(row: dict[str, Any], label: str, family: str) -> dict[str, Any]:
    return {
        "text": row["text"],
        "label": label,
        "family": family,
        "lang": row.get("lang", "en"),
        "source": f"external:{row['source']}:{row.get('family')}",
    }


def build() -> dict[str, list[dict[str, Any]]]:
    if not SRC.exists():
        raise SystemExit("no converted data: run  python3 -I datasets/external/fetch_external.py  first")
    out: dict[str, list[dict[str, Any]]] = defaultdict(list)
    rng = random.Random(SEED)  # noqa: S311 - reproducible data, not security
    for path in sorted(SRC.glob("*.jsonl")):
        name = path.stem
        if name.startswith("multiturn-"):
            continue  # every conversation is blocked on its first turn (see the baseline): no signal
        rows = [r for r in _read(path) if len(r["text"]) <= MAX_CHARS]
        if name in EVAL_ONLY:
            for r in rows:
                fam = (
                    "prompt_exfiltration" if r["category"] == "prompt_extraction" else "instruction_override"
                )
                out["attacks/heldout-external-tensortrust"].append(_out(r, "attack", fam))
            continue
        capped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for r in rows:
            split = "heldout" if _heldout(r["text"]) else "train"
            if r["label"] == "benign" and EMAIL.search(r["text"]):
                continue
            if r["label"] == "benign":
                out[f"benign/{split}-external"].append(_out(r, "benign", BENIGN_FAMILY[r["category"]]))
            elif name in TRAINABLE and r["category"] in CHAT_ATTACKS:
                row = _out(r, "attack", TRAINABLE[name])
                if split == "train" and TRAINABLE[name] == "jailbreak":
                    capped[str(r.get("family"))].append(row)
                else:
                    out[f"attacks/{split}-external"].append(row)
        for fam_rows in capped.values():
            out["attacks/train-external"] += (
                rng.sample(fam_rows, CAP_PER_FAMILY) if len(fam_rows) > CAP_PER_FAMILY else fam_rows
            )
    return out


def main() -> int:
    files = build()
    for rel, rows in sorted(files.items()):
        path = HERE / f"{rel}.jsonl"
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        fams = Counter(r["family"] for r in rows)
        print(
            f"  {rel + '.jsonl':44} {len(rows):5} rows  "
            + ", ".join(f"{k} {v}" for k, v in fams.most_common())
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
