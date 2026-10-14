"""Fetch openly licensed external attack / benign datasets, pinned, and convert them to labelled JSONL.

    python3 -I datasets/external/fetch_external.py            # download (cached) + convert
    python3 -I datasets/external/fetch_external.py --download # download only
    python3 -I datasets/external/fetch_external.py --list     # sources, licences, use

Only the files listed in SOURCES are downloaded (data files — never code, never pickles), each pinned
to the commit / revision it was taken from; ``manifest.json`` records source, licence, revision, file,
size and SHA-256. Raw files are cached under ``datasets/external/raw/`` (git-ignored).

Output (``datasets/external/data/``), one JSON object per line:
    single-turn  {"text", "label": attack|benign, "category", "family", "lang", "source", "use"}
    multi-turn   {"turns": [...], "label", "category", "family", "source", "use"}   (multiturn-*.jsonl)

category: direct_injection | indirect_injection | jailbreak | prompt_extraction | harmful_request |
benign | benign_hard (benign text that resembles an attack). use: "train+eval" or "eval_only" (licence
not confirmed — never train on it). Only prompts / user turns are kept: model responses in these
datasets are dropped.

Excluded on purpose: non-commercial licences (Scale AI MHJ, rockCO78 multi-turn — CC-BY-NC), gated
WildJailbreak (needs a Hugging Face acceptance), sources whose attacks live in Python code (AgentDojo,
PromptInject — phase 2), PoisonedRAG (false facts in retrieval data, invisible to a gateway).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw"
OUT = HERE / "data"
MANIFEST = HERE / "manifest.json"
UA = {"User-Agent": "cmp-security-layer-dataset-fetch"}

SOURCES: list[dict[str, Any]] = [
    {
        "name": "bipia",
        "host": "github",
        "repo": "microsoft/BIPIA",
        "license": "MIT",
        "use": "train+eval",
        "files": [
            "benchmark/text_attack_train.json",
            "benchmark/text_attack_test.json",
            "benchmark/code_attack_train.json",
            "benchmark/code_attack_test.json",
        ],
    },
    {
        "name": "injecagent",
        "host": "github",
        "repo": "uiuc-kang-lab/InjecAgent",
        "license": "MIT",
        "use": "train+eval",
        "files": ["data/attacker_cases_dh.jsonl", "data/attacker_cases_ds.jsonl", "data/user_cases.jsonl"],
    },
    {
        "name": "jailbreakbench-artifacts",
        "host": "github",
        "repo": "JailbreakBench/artifacts",
        "license": "MIT",
        "use": "train+eval",
        "pattern": r"^attack-artifacts/[^/]+/[^/]+/[^/]+\.json$",  # per-model files (prompts + responses)
    },
    {
        "name": "jailbreakbench-behaviors",
        "host": "hf",
        "repo": "JailbreakBench/JBB-Behaviors",
        "license": "MIT",
        "use": "train+eval",
        "files": ["data/harmful-behaviors.csv", "data/benign-behaviors.csv"],
    },
    {
        "name": "advbench",
        "host": "github",
        "repo": "llm-attacks/llm-attacks",
        "license": "MIT",
        "use": "train+eval",
        "files": ["data/advbench/harmful_behaviors.csv", "data/advbench/harmful_strings.csv"],
    },
    {
        "name": "garak",
        "host": "github",
        "repo": "NVIDIA/garak",
        "license": "Apache-2.0",
        "use": "train+eval",
        "pattern": r"^garak/data/(dan/[^/]+\.json|autodan/autodan_prompts\.json|autodan/autodan_init\.txt"
        r"|inthewild_jailbreak_llms\.json|agent_breaker/prompts\.yaml)$",
    },
    {
        "name": "tensor-trust",
        "host": "github",
        "repo": "HumanCompatibleAI/tensor-trust-data",
        "license": "none stated",
        "use": "eval_only",
        "files": [
            "benchmarks/hijacking-robustness/v1/hijacking_robustness_dataset.jsonl",
            "benchmarks/extraction-robustness/v1/extraction_robustness_dataset.jsonl",
            "detecting-extractions/v1/prompt_extraction_detection.jsonl",
        ],
    },
    {
        "name": "multiturn-tomgibbs",
        "host": "hf",
        "repo": "tom-gibbs/multi-turn_jailbreak_attack_datasets",
        "license": "MIT",
        "use": "train+eval",
        "files": ["Harmful Dataset.csv", "Completely-Benign Dataset.csv", "Semi-Benign Dataset.csv"],
    },
]


def get_json(url: str) -> Any:
    req = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(req, timeout=60) as res:  # noqa: S310 - fixed https hosts
        return json.load(res)


def resolve(src: dict[str, Any]) -> tuple[str, list[tuple[str, int]]]:
    """(pinned revision, [(path, size)]) for a source."""
    if src["host"] == "github":
        repo = get_json(f"https://api.github.com/repos/{src['repo']}")
        sha = get_json(f"https://api.github.com/repos/{src['repo']}/commits/{repo['default_branch']}")["sha"]
        tree = get_json(f"https://api.github.com/repos/{src['repo']}/git/trees/{sha}?recursive=1")["tree"]
        blobs = {t["path"]: t.get("size", 0) for t in tree if t["type"] == "blob"}
    else:
        info = get_json(f"https://huggingface.co/api/datasets/{src['repo']}?blobs=true")
        sha = info["sha"]
        blobs = {s["rfilename"]: s.get("size", 0) for s in info["siblings"]}
    if "files" in src:
        missing = [f for f in src["files"] if f not in blobs]
        if missing:
            raise SystemExit(f"{src['name']}: files not found upstream: {missing}")
        files = [(f, blobs[f]) for f in src["files"]]
    else:
        pat = re.compile(src["pattern"])
        files = sorted((p, s) for p, s in blobs.items() if pat.search(p))
    return sha, files


def url_for(src: dict[str, Any], sha: str, path: str) -> str:
    quoted = urllib.parse.quote(path)
    if src["host"] == "github":
        return f"https://raw.githubusercontent.com/{src['repo']}/{sha}/{quoted}"
    return f"https://huggingface.co/datasets/{src['repo']}/resolve/{sha}/{quoted}"


def download() -> dict[str, Any]:
    manifest: dict[str, Any] = {"sources": {}}
    for src in SOURCES:
        sha, files = resolve(src)
        entries = []
        for path, size in files:
            dest = RAW / src["name"] / path
            if not dest.exists() or dest.stat().st_size != size:
                dest.parent.mkdir(parents=True, exist_ok=True)
                req = urllib.request.Request(url_for(src, sha, path), headers=UA)
                with urllib.request.urlopen(req, timeout=120) as res:  # noqa: S310
                    dest.write_bytes(res.read())
            entries.append(
                {"path": path, "bytes": dest.stat().st_size, "sha256": hashlib.sha256(dest.read_bytes()).hexdigest()}
            )
        manifest["sources"][src["name"]] = {
            "repo": src["repo"],
            "host": src["host"],
            "revision": sha,
            "license": src["license"],
            "use": src["use"],
            "files": entries,
        }
        total = sum(e["bytes"] for e in entries)
        print(f"  {src['name']:26} {len(entries):3} files {total / 1e6:6.2f} MB  @ {sha[:10]}  ({src['license']})")
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--download", action="store_true", help="download only, do not convert")
    ap.add_argument("--list", action="store_true", help="list the sources and exit")
    args = ap.parse_args()
    if args.list:
        for s in SOURCES:
            print(f"{s['name']:26} {s['host']:6} {s['repo']:48} {s['license']:12} {s['use']}")
        return 0
    print("downloading (cached files are kept):")
    download()
    if args.download:
        return 0
    from convert_external import convert_all  # noqa: PLC0415 - sibling module, after download

    convert_all(RAW, OUT, json.loads(MANIFEST.read_text()))
    return 0


if __name__ == "__main__":
    sys.path.insert(0, str(HERE))
    sys.exit(main())
