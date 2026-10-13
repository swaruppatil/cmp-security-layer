"""Compose labelled multi-turn conversations from the existing single-turn datasets.

    python3 datasets/build_multiturn.py

No new message text is written here: every turn is an existing dataset row, a piece of one, or a
mechanical rewrite of one (case, punctuation, a dropped word, a polite prefix). Two files:

* ``multiturn/tune.jsonl``    — built from training rows (``seed*``/``train*``). A regression check
  only: the model has seen these rows, so they are too easy to choose thresholds with.
* ``multiturn/calib.jsonl``   — built from one half of the held-out rows; used to choose the
  conversation thresholds (``scripts/eval_multiturn.py --sweep``).
* ``multiturn/heldout.jsonl`` — built from the *other* half of the held-out rows; used to report.

The held-out rows are split by a hash of their text, so a row is in exactly one of the two halves
and calibration never sees a turn that appears in the report set.

Kinds (``kind``):

| kind              | turns                                                           | label  |
|-------------------|-----------------------------------------------------------------|--------|
| split_payload     | 1–3 normal turns, then one attack row split into 2–3 consecutive turns | attack |
| probing           | 1–2 normal turns, then 4–6 attack rows in a row                 | attack |
| retry_after_block | normal turn(s), an attack row, then 2 mechanical rewrites of it | attack |
| benign_long       | 8–16 normal rows (hard negatives and short replies included)    | benign |
| benign_mixed      | 8–12 normal rows, at least half off-topic (general questions)    | benign |

``benign_mixed`` exists because joined windows of unrelated questions look like a common
injection pattern ("question, question, then an instruction") to the model; the tune set must
contain that case so thresholds are chosen with it in view.

Each turn has ``attack: true|false``; ``attack_start`` is the first attack turn (None for benign).
"""

from __future__ import annotations

import json
import random
import re
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
SEED = 20261012
POLITE = ["ok then ", "please ", "fine, ", "again: ", "let me rephrase: ", "so "]


def read(prefixes: tuple[str, ...], sub: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted((HERE / sub).glob("*.jsonl")):
        if path.name.startswith(prefixes):
            rows += [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    return rows


def split_words(text: str, parts: int, rng: random.Random) -> list[str]:
    words = text.split()
    cuts = sorted(rng.sample(range(2, len(words) - 1), parts - 1))
    pieces, last = [], 0
    for c in [*cuts, len(words)]:
        pieces.append(" ".join(words[last:c]))
        last = c
    return pieces


def rewrite(text: str, rng: random.Random) -> str:
    """A mechanical variant: what a person does when retrying without changing the request."""
    t = text
    if rng.random() < 0.5:
        t = t.lower()
    t = re.sub(r"[!?.]+$", "", t.strip())
    words = t.split()
    if len(words) > 6 and rng.random() < 0.6:
        del words[rng.randrange(1, len(words) - 1)]
    return rng.choice(POLITE) + " ".join(words)


def turns(texts: list[str], attack_flags: list[bool]) -> list[dict[str, Any]]:
    return [{"text": t, "attack": a} for t, a in zip(texts, attack_flags, strict=True)]


def build(attacks: list[dict[str, Any]], benign: list[dict[str, Any]], counts: dict[str, int], tag: str,
          rng: random.Random) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    long_attacks = [a for a in attacks if len(a["text"].split()) >= 8]

    def normal(k: int) -> list[str]:
        return [r["text"] for r in rng.sample(benign, k)]

    def add(kind: str, label: str, texts: list[str], flags: list[bool], families: list[str]) -> None:
        start = flags.index(True) if True in flags else None
        out.append({"id": f"{tag}-{kind}-{len([c for c in out if c['kind'] == kind])}", "kind": kind,
                    "label": label, "attack_start": start, "families": sorted(set(families)),
                    "turns": turns(texts, flags)})

    for _ in range(counts["split_payload"]):
        a = rng.choice(long_attacks)
        pre = normal(rng.randint(1, 3))
        parts = split_words(a["text"], rng.choice([2, 3]) if len(a["text"].split()) >= 12 else 2, rng)
        add("split_payload", "attack", pre + parts, [False] * len(pre) + [True] * len(parts), [a["family"]])
    for _ in range(counts["probing"]):
        pre = normal(rng.randint(1, 2))
        chosen = rng.sample(attacks, rng.randint(4, 6))
        add("probing", "attack", pre + [a["text"] for a in chosen], [False] * len(pre) + [True] * len(chosen),
            [a["family"] for a in chosen])
    for _ in range(counts["retry_after_block"]):
        a = rng.choice(attacks)
        pre = normal(rng.randint(1, 2))
        texts = pre + [a["text"], rewrite(a["text"], rng), rewrite(a["text"], rng)]
        add("retry_after_block", "attack", texts, [False] * len(pre) + [True] * 3, [a["family"]])
    for _ in range(counts["benign_long"]):
        texts = normal(rng.randint(8, 16))
        add("benign_long", "benign", texts, [False] * len(texts), [])
    off_topic = [r for r in benign if r.get("family") in ("general_question", "public_benign")]
    for _ in range(counts.get("benign_mixed", 0)):
        k = rng.randint(8, 12)
        texts = [r["text"] for r in rng.sample(off_topic, k // 2 + 1)] + normal(k - k // 2 - 1)
        rng.shuffle(texts)
        add("benign_mixed", "benign", texts, [False] * len(texts), [])
    return out


def write(name: str, rows: list[dict[str, Any]]) -> None:
    path = HERE / "multiturn" / name
    path.parent.mkdir(exist_ok=True)
    path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
    kinds: dict[str, int] = {}
    for r in rows:
        kinds[r["kind"]] = kinds.get(r["kind"], 0) + 1
    print(f"{path.relative_to(HERE.parent)}: {len(rows)} conversations {kinds}")


def half(rows: list[dict[str, Any]], which: int) -> list[dict[str, Any]]:
    import hashlib

    return [r for r in rows if int(hashlib.sha256(r["text"].encode()).hexdigest(), 16) % 2 == which]


def main() -> None:
    rng = random.Random(SEED)
    h_attacks, h_benign = read(("heldout",), "attacks"), read(("heldout",), "benign")
    tune = build(read(("seed", "train"), "attacks"), read(("seed", "train"), "benign"),
                 {"split_payload": 60, "probing": 40, "retry_after_block": 40, "benign_long": 80,
                  "benign_mixed": 40}, "tune", rng)
    calib = build(half(h_attacks, 0), half(h_benign, 0),
                  {"split_payload": 20, "probing": 10, "retry_after_block": 20, "benign_long": 30,
                   "benign_mixed": 15}, "calib", rng)
    held = build(half(h_attacks, 1), half(h_benign, 1),
                 {"split_payload": 30, "probing": 15, "retry_after_block": 30, "benign_long": 40,
                  "benign_mixed": 20}, "heldout", rng)
    write("tune.jsonl", tune)
    write("calib.jsonl", calib)
    write("heldout.jsonl", held)


if __name__ == "__main__":
    main()
