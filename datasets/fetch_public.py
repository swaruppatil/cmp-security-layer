"""Fetch public, openly licensed datasets and convert them to the gateway's JSONL schema.

    cd ml-service && uv run --with pyarrow --with pandas python ../datasets/fetch_public.py

Sources (each listed with its licence; add entries to SOURCES to widen training and evaluation):

| name      | what                                                         | licence            |
|-----------|--------------------------------------------------------------|--------------------|
| deepset   | prompt injections vs. benign, EN/DE                          | apache-2.0         |
| bitext    | 27k customer-support utterances (orders, refunds, accounts…) | CDLA-Sharing-1.0   |
| jackhhao  | jailbreak prompts vs. ordinary LLM prompts                   | apache-2.0         |
| gandalf   | "ignore your instructions" attacks (Lakera Gandalf)          | MIT                |
| spml      | chatbot user prompts labelled injection / not (SPML)         | MIT                |

Bitext and SPML are benign *hard negatives* for this gateway: real customer-support language full of
"cancel", "refund", "change my order", "I want my money back" — the words a template model otherwise
learns as attack signals. jackhhao's benign half is ordinary, off-topic LLM usage (trivia, role-play
characters, homework), which also serves as the "not an airline question" reference for the off-topic
check.

Splits. A source that publishes train/test keeps them: *train* is fitted on, *test* is held out. A
single-file source is split by a hash of the text into train / calib / heldout; ``calib*.jsonl`` is
never fitted on and is used only to choose the model's thresholds, ``heldout*.jsonl`` only to report.
Big sources are sampled (``max_rows``) so they do not drown the airline data. Rows that appear in a
held-out split are removed from the training split.

Output: ``datasets/{attacks,benign}/{train,calib,heldout}-public-<name>.jsonl``. Raw downloads are
cached under ``datasets/public/raw/`` (git-ignored).
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).parent
RAW = HERE / "public" / "raw"
SEED = 20261014
MAX_CHARS = 1500  # longer prompts are essays / whole documents, not chat messages

# Bitext placeholders → plausible values, so the text reads like a message rather than a template.
PLACEHOLDERS = {
    "Order Number": ["12345678", "98-7654", "A1B2C3", "4471", "ORD-20931"],
    "Account Type": ["premium", "standard", "pro", "free"],
    "Account Category": ["premium", "standard", "pro", "free"],
    "Invoice Number": ["INV-2049", "77812", "2026-00312"],
    "Person Name": ["John Smith", "Marie Tremblay", "A. Patel"],
    "Delivery City": ["Toronto", "Montreal", "Vancouver"],
    "Delivery Country": ["Canada", "France", "the US"],
    "Salutation": ["", "Hi,", "Hello,"],
    "Client First Name": ["Sam", "Léa", "Omar"],
    "Client Last Name": ["Nguyen", "Roy", "Khan"],
    "Customer Support Phone Number": ["1-888-247-2262"],
    "Customer Support Email": ["support@example.com"],
    "Company Name": ["the company"],
    "Website URL": ["the website"],
    "Currency Symbol": ["$"],
    "Refund Amount": ["120", "45.99", "300"],
    "Money Amount": ["120", "45.99", "300"],
    "Date": ["March 3", "next Friday", "2026-11-02"],
    "Date Range": ["March 3-10"],
    "Store Location": ["downtown"],
    "Online Order Interaction": ["my order"],
    "Online Company Portal Info": ["my account"],
    "Online Customer Support Channel": ["the live chat"],
    "Upgrade Account": ["premium"],
    "Shipping Cut-off Time": ["6 pm"],
    "Standard Shipping": ["standard shipping"],
    "Program Name": ["the loyalty program"],
}
PLACEHOLDER = re.compile(r"\{\{\s*([^}]+?)\s*\}\}")
# Characters str.splitlines() treats as line breaks but JSONL readers must not.
ODD_BREAKS = re.compile("[\u2028\u2029\x85\x0b\x0c\x1c-\x1e]")


def fill_placeholders(text: str, rng: random.Random) -> str:
    def repl(m: re.Match[str]) -> str:
        key = m.group(1).strip()
        return rng.choice(PLACEHOLDERS.get(key, [key.lower()]))

    return re.sub(r"\s+", " ", PLACEHOLDER.sub(repl, text)).strip()


SOURCES: list[dict[str, Any]] = [
    {
        "name": "deepset",
        "dataset": "deepset/prompt-injections",
        "license": "apache-2.0",
        "files": {
            "train": "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
            "heldout": "data/test-00000-of-00001-701d16158af87368.parquet",
        },
        "text_column": "text",
        "label": ("label", {1}),  # (column, values meaning attack)
        "families": ("public_injection", "public_benign"),
    },
    {
        "name": "bitext",
        "dataset": "bitext/Bitext-customer-support-llm-chatbot-training-dataset",
        "license": "cdla-sharing-1.0",
        "files": {"all": "Bitext_Sample_Customer_Support_Training_Dataset_27K_responses-v11.csv"},
        "text_column": "instruction",
        "label": None,  # every row is benign
        "families": (None, "public_support"),
        "hash_split": {"train": 0.7, "calib": 0.15, "heldout": 0.15},
        "max_rows": {"train": 4000, "calib": 800, "heldout": 800},
        "clean": fill_placeholders,
    },
    {
        "name": "jackhhao",
        "dataset": "jackhhao/jailbreak-classification",
        "license": "apache-2.0",
        "files": {
            "train": "default/jailbreak_dataset_train.csv",
            "heldout": "default/jailbreak_dataset_test.csv",
        },
        "text_column": "prompt",
        "label": ("type", {"jailbreak"}),
        "families": ("public_jailbreak", "public_general"),
    },
    {
        "name": "gandalf",
        "dataset": "Lakera/gandalf_ignore_instructions",
        "license": "mit",
        "files": {
            "train": "data/train-00000-of-00001-ded53be747ff55cd.parquet",
            "calib": "data/validation-00000-of-00001-94481a2a09ff2fff.parquet",
            "heldout": "data/test-00000-of-00001-bc92128b9288a6d1.parquet",
        },
        "text_column": "text",
        "label": "attack",  # every row is an attack
        "families": ("public_injection", None),
    },
    {
        "name": "spml",
        "dataset": "reshabhs/SPML_Chatbot_Prompt_Injection",
        "license": "mit",
        "files": {"all": "spml_prompt_injection.csv"},
        "text_column": "User Prompt",
        "label": ("Prompt injection", {1, 1.0, "1", "1.0"}),
        "families": ("public_injection", "public_chatbot"),
        "hash_split": {"train": 0.8, "heldout": 0.2},
        "max_rows": {"train": 2200, "heldout": 700},
        # Rows derived from Gandalf overlap with the Lakera set above; low-"Degree" injections are
        # mild requests to bend a persona ("suggest a meal with nuts anyway") that read as benign here.
        "exclude": lambda row: (
            str(row.get("Source") or "") == "Gandalf"
            or (str(row.get("Prompt injection")) in {"1", "1.0"} and float(row.get("Degree") or 0) < 6)
        ),
    },
]

# Rough language tag for reporting only.
GERMAN = re.compile(r"\b(?:und|nicht|ich|ist|die|der|das|wie|was|sind|mit|für|auf|eine?)\b", re.I)
FRENCH = re.compile(r"\b(?:je|vous|est|les|des|une|pas|pour|mon|ma|votre|avec|être|svp)\b", re.I)


def lang_of(text: str) -> str:
    if len(GERMAN.findall(text)) >= 2:
        return "de"
    if len(FRENCH.findall(text)) >= 2:
        return "fr"
    return "en"


def download(source: dict[str, Any]) -> dict[str, Path]:
    paths = {}
    for split, rel in source["files"].items():
        dest = RAW / str(source["name"]) / Path(str(rel)).name
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            url = f"https://huggingface.co/datasets/{source['dataset']}/resolve/main/{rel}"
            with urllib.request.urlopen(url, timeout=120) as res:  # noqa: S310 - fixed https URL
                dest.write_bytes(res.read())
        paths[split] = dest
    return paths


def read_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".parquet":
        import pyarrow.parquet as pq

        return pq.read_table(path).to_pylist()
    import pandas as pd

    return pd.read_csv(path, dtype=str, keep_default_na=False).to_dict("records")  # type: ignore[no-any-return]


def is_attack(source: dict[str, Any], row: dict[str, Any]) -> bool | None:
    """True / False, or None when the row has no usable label."""
    spec = source["label"]
    if spec is None:
        return False
    if spec == "attack":
        return True
    column, values = spec
    raw = row.get(column)
    if raw is None or raw == "":
        return None
    return raw in values or str(raw).strip() in {str(v) for v in values}


def hash_bucket(text: str, shares: dict[str, float]) -> str:
    x = int(hashlib.sha256(text.encode("utf-8")).hexdigest()[:8], 16) / 0xFFFFFFFF
    acc = 0.0
    for name, share in shares.items():
        acc += share
        if x < acc:
            return name
    return next(reversed(shares))


def convert(source: dict[str, Any], paths: dict[str, Path]) -> dict[str, tuple[int, int]]:
    rng = random.Random(f"{SEED}:{source['name']}")  # noqa: S311 - reproducible sampling
    clean: Callable[[str, random.Random], str] = source.get("clean") or (lambda t, _r: t)
    exclude: Callable[[dict[str, Any]], bool] = source.get("exclude") or (lambda _row: False)
    attack_family, benign_family = source["families"]

    # Collect rows per split (hash-splitting single-file sources).
    per_split: dict[str, list[dict[str, Any]]] = {}
    for split, path in paths.items():
        for row in read_rows(path):
            if exclude(row):
                continue
            text = clean(ODD_BREAKS.sub(" ", str(row.get(source["text_column"]) or "")).strip(), rng)
            if not text or len(text) > MAX_CHARS:
                continue
            attack = is_attack(source, row)
            if attack is None:
                continue
            target = hash_bucket(text, source["hash_split"]) if split == "all" else split
            per_split.setdefault(target, []).append(
                {
                    "text": text,
                    "label": "attack" if attack else "benign",
                    "family": attack_family if attack else benign_family,
                    "lang": lang_of(text),
                    "source": f"public:{source['dataset']} ({source['license']}) {target}",
                }
            )

    # Held-out splits first, so their texts can be excluded from training; then sample.
    seen: set[str] = set()
    counts: dict[str, tuple[int, int]] = {}
    for split in sorted(per_split, key=lambda s: {"heldout": 0, "calib": 1, "train": 2}.get(s, 3)):
        rows = []
        for r in per_split[split]:
            key = r["text"].casefold()
            if key in seen:
                continue
            seen.add(key)
            rows.append(r)
        cap = (source.get("max_rows") or {}).get(split)
        if cap is not None and len(rows) > cap:
            # Keep the class balance of the source when sampling.
            attacks = [r for r in rows if r["label"] == "attack"]
            benign = [r for r in rows if r["label"] == "benign"]
            share = len(attacks) / len(rows)
            rows = rng.sample(attacks, min(len(attacks), round(cap * share))) + rng.sample(
                benign, min(len(benign), cap - min(len(attacks), round(cap * share)))
            )
            rng.shuffle(rows)
        attacks = [r for r in rows if r["label"] == "attack"]
        benign = [r for r in rows if r["label"] == "benign"]
        for subset, sub in ((attacks, "attacks"), (benign, "benign")):
            out = HERE / sub / f"{split}-public-{source['name']}.jsonl"
            if subset:
                out.write_text(
                    "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in subset), encoding="utf-8"
                )
            elif out.exists():
                out.unlink()
        counts[split] = (len(attacks), len(benign))
    return counts


if __name__ == "__main__":
    for src in SOURCES:
        for split, (n_attack, n_benign) in convert(src, download(src)).items():
            print(
                f"{src['dataset']} ({src['license']}) {split}: {n_attack} attacks, {n_benign} benign "
                f"→ {split}-public-{src['name']}.jsonl"
            )
