"""Fetch public, openly licensed prompt-injection datasets and convert them to held-out JSONL.

    cd ml-service && uv run --with pyarrow python ../datasets/fetch_public.py

Each source keeps its own published split: its *train* split becomes training data, its *test*
split is held out (scored, never fitted on). Rows that appear in both are kept only in the test split.
Each source is listed with its licence; add entries to SOURCES to widen training and evaluation.

Output (one line per example, same schema as the seed data):
    datasets/{attacks,benign}/train-public-<name>.jsonl
    datasets/{attacks,benign}/heldout-public-<name>.jsonl
Raw downloads are cached under datasets/public/raw/ (git-ignored).
"""

from __future__ import annotations

import json
import re
import urllib.request
from pathlib import Path

HERE = Path(__file__).parent
RAW = HERE / "public" / "raw"

SOURCES = [
    {
        "name": "deepset",
        "dataset": "deepset/prompt-injections",
        "license": "apache-2.0",
        "files": {
            "train": "data/train-00000-of-00001-9564e8b05b4757ab.parquet",
            "heldout": "data/test-00000-of-00001-701d16158af87368.parquet",
        },
        "text_column": "text",
        "label_column": "label",  # 1 = injection, 0 = benign
    },
]

# Rough language tag for reporting only (this dataset mixes English and German).
GERMAN = re.compile(r"\b(?:und|nicht|ich|ist|die|der|das|wie|was|sind|mit|für|auf|eine?)\b", re.I)


def lang_of(text: str) -> str:
    return "de" if len(GERMAN.findall(text)) >= 2 else "en"


def download(source: dict[str, object]) -> dict[str, Path]:
    paths = {}
    for split, rel in source["files"].items():  # type: ignore[attr-defined]
        dest = RAW / str(source["name"]) / Path(str(rel)).name
        if not dest.exists():
            dest.parent.mkdir(parents=True, exist_ok=True)
            url = f"https://huggingface.co/datasets/{source['dataset']}/resolve/main/{rel}"
            with urllib.request.urlopen(url, timeout=60) as res:  # noqa: S310 - fixed https URL
                dest.write_bytes(res.read())
        paths[split] = dest
    return paths


def convert(source: dict[str, object], paths: dict[str, Path]) -> dict[str, tuple[int, int]]:
    import pyarrow.parquet as pq

    def read(path: Path) -> list[dict[str, object]]:
        return pq.read_table(path).to_pylist()

    # Held-out first, so its texts can be excluded from training.
    order = sorted(paths, key=lambda split: split != "heldout")
    seen: set[str] = set()
    counts = {}
    for split in order:
        attacks, benign = [], []
        for row in read(paths[split]):
            text = str(row[str(source["text_column"])]).strip()
            if not text or text in seen:
                continue
            seen.add(text)
            label = int(row[str(source["label_column"])])  # type: ignore[call-overload]
            record = {
                "text": text,
                "label": "attack" if label == 1 else "benign",
                "family": "public_injection" if label == 1 else "public_benign",
                "lang": lang_of(text),
                "source": f"public:{source['dataset']} ({source['license']}) {split}",
            }
            (attacks if label == 1 else benign).append(record)
        for rows, sub in ((attacks, "attacks"), (benign, "benign")):
            out = HERE / sub / f"{split}-public-{source['name']}.jsonl"
            out.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        counts[split] = (len(attacks), len(benign))
    return counts


if __name__ == "__main__":
    for src in SOURCES:
        for split, (n_attack, n_benign) in convert(src, download(src)).items():
            print(f"{src['dataset']} ({src['license']}) {split}: {n_attack} attacks, {n_benign} benign "
                  f"→ {split}-public-{src['name']}.jsonl")
