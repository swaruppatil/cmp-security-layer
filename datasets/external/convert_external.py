"""Convert the raw external datasets (``raw/``, see fetch_external.py) to labelled JSONL in ``data/``.

    python3 -I datasets/external/convert_external.py

Only prompts / user turns are kept: model responses, target completions and harmful output strings are
dropped. Rows are de-duplicated per output file (whitespace-normalised). Each output file takes its
source's licence decision (``use``) from manifest.json.

What each source becomes (and what is left out, and why):

    bipia            indirect_injection  instructions written to be planted in an email / web page / code
                     output_manipulation snippet; split by what the text alone shows (bipia_category).
                     context_only_task ``family`` is BIPIA's attack name; ``variant`` is "bare"
                                         (the instruction alone) or "embedded" (placed inside a fixed,
                                         neutral document wrapper, as a tool result would carry it).
    injecagent       indirect_injection  attacker instructions (family = attack type); ``benign`` rows are
                                         the user instructions of the benign tool tasks.
    jailbreakbench   jailbreak           attack prompts from the published artifacts (family = method:
                                         GCG, PAIR, JailbreakChat, random search, DSN); responses dropped.
                     harmful_request     the plain harmful behaviour goals (JBB-Behaviors).
                     benign_hard         JBB's benign behaviours, written to sit next to the harmful ones.
    advbench         harmful_request     harmful_behaviors.csv goals. harmful_strings.csv is *output*
                                         text (what a model must not say), not a prompt — left out.
    garak            jailbreak           DAN-family prompts, AutoDAN prompts, in-the-wild jailbreaks.
                                         agent_breaker/prompts.yaml holds garak's own attacker-LLM
                                         instructions (templates, not attacks) — left out.
    tensor-trust     direct_injection    hijacking attacks (eval_only — licence not stated).
                     prompt_extraction   extraction attacks (eval_only). The detection file is model
                                         *outputs* — left out (could test outbound checks later).
    multiturn-*      multi-turn          tom-gibbs cipher / word-mapping conversations: Harmful → attack
                                         (jailbreak), Completely- and Semi-Benign →
                                         obfuscated_benign (harmless goal, jailbreak delivery).
                                         User turns only; assistant turns ("None") dropped.
"""

from __future__ import annotations

import ast
import csv
import json
import re
import sys
from collections import Counter
from collections.abc import Iterator
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
csv.field_size_limit(sys.maxsize)

# A neutral carrier for "embedded" BIPIA rows: the injected instruction arrives inside content the
# assistant was asked to read (as a retrieved email would), not as the customer's own words.
EMBED = (
    "Here is the email I received, can you summarise it for me?\n\n"
    "Subject: Your upcoming trip\n\nHello,\n\nThank you for your booking. {attack}\n\n"
    "Kind regards,\nCustomer Service"
)
# garak DAN templates name the target model; replace the placeholder mechanically.
GARAK_PLACEHOLDER = re.compile(r"\{generator\.name\}")


def _norm(text: str) -> str:
    return " ".join(text.split()).casefold()


def _row(text: str, label: str, category: str, family: str, source: str, **extra: Any) -> dict[str, Any]:
    return {
        "text": text.strip(),
        "label": label,
        "category": category,
        "family": family,
        "lang": "en",
        "source": source,
        **extra,
    }


def _jsonl(path: Path) -> Iterator[dict[str, Any]]:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            yield json.loads(line)


def _csv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# ------------------------------------------------------------------ per source
# BIPIA instructions are attacks because of *where* they are planted (inside data the AI reads), and
# they differ in what the text alone shows:
#   indirect_injection   a harmful payload (malicious code, scam / malware / phishing links,
#                        misinformation): an attack in any context.
#   output_manipulation  orders about the assistant's reply ("encode your response in Base64", "add a
#                        sentence promoting …"): an attack inside tool data, an ordinary request in chat.
#   context_only_task    an unrelated task or question ("What is the capital of Brazil?"): only its
#                        position makes it an attack; as text it is indistinguishable from a normal
#                        question, so no model should be trained to call it one.
BIPIA_TASK_ONLY = frozenset(
    {
        "Business Intelligence",
        "Content Creation",
        "Conversational Agent",
        "Information Retrieval",
        "Learning and Tutoring",
        "Programming Help",
        "Research Assistance",
        "Sentiment Analysis",
        "Task Automation",
    }
)
BIPIA_HARMFUL = frozenset(
    {"Clickbait", "Malware Distribution", "Misinformation & Propaganda", "Scams & Fraud"}
)


def bipia_category(carrier: str, family: str) -> str:
    if carrier == "code" or family in BIPIA_HARMFUL:
        return "indirect_injection"
    return "context_only_task" if family in BIPIA_TASK_ONLY else "output_manipulation"


def bipia(raw: Path) -> Iterator[dict[str, Any]]:
    for f in sorted((raw / "benchmark").glob("*_attack_*.json")):
        kind, split = f.stem.split("_attack_")  # text|code, train|test
        for family, attacks in json.loads(f.read_text()).items():
            for a in attacks:
                for variant, text in (("bare", a), ("embedded", EMBED.format(attack=a.strip()))):
                    yield _row(
                        text,
                        "attack",
                        bipia_category(kind, family),
                        family,
                        "bipia",
                        variant=variant,
                        carrier=kind,
                        split=split,
                    )


def injecagent(raw: Path) -> Iterator[dict[str, Any]]:
    for f in ("attacker_cases_dh.jsonl", "attacker_cases_ds.jsonl"):
        for case in _jsonl(raw / "data" / f):
            yield _row(
                case["Attacker Instruction"],
                "attack",
                "indirect_injection",
                case["Attack Type"].lower().replace(" ", "_"),
                "injecagent",
                variant="bare",
                goal="direct_harm" if f.endswith("dh.jsonl") else "data_stealing",
            )
    for case in _jsonl(raw / "data" / "user_cases.jsonl"):
        yield _row(case["User Instruction"], "benign", "benign", "tool_task", "injecagent")


def jailbreakbench_artifacts(raw: Path) -> Iterator[dict[str, Any]]:
    for f in sorted((raw / "attack-artifacts").rglob("*.json")):
        if "test-artifact" in f.parts:
            continue  # JBB's own placeholder submissions
        params = json.loads(f.read_text())
        method = params["parameters"]["method"]
        for jb in params["jailbreaks"]:
            if jb.get("prompt"):
                yield _row(
                    jb["prompt"],
                    "attack",
                    "jailbreak",
                    method,
                    "jailbreakbench-artifacts",
                    harm_category=jb.get("category"),
                    target_model=params["parameters"]["model"],
                )


def jailbreakbench_behaviors(raw: Path) -> Iterator[dict[str, Any]]:
    for r in _csv(raw / "data" / "harmful-behaviors.csv"):
        yield _row(r["Goal"], "attack", "harmful_request", r["Category"], "jailbreakbench-behaviors")
    for r in _csv(raw / "data" / "benign-behaviors.csv"):
        yield _row(r["Goal"], "benign", "benign_hard", r["Category"], "jailbreakbench-behaviors")


def advbench(raw: Path) -> Iterator[dict[str, Any]]:
    for r in _csv(raw / "data" / "advbench" / "harmful_behaviors.csv"):
        yield _row(r["goal"], "attack", "harmful_request", "advbench_behavior", "advbench")


def garak(raw: Path) -> Iterator[dict[str, Any]]:
    data = raw / "garak" / "data"
    for f in sorted((data / "dan").glob("*.json")):
        for p in json.loads(f.read_text()):
            yield _row(GARAK_PLACEHOLDER.sub("ChatGPT", p), "attack", "jailbreak", f"dan:{f.stem}", "garak")
    for p in json.loads((data / "autodan" / "autodan_prompts.json").read_text()):
        yield _row(p, "attack", "jailbreak", "autodan", "garak")
    yield _row((data / "autodan" / "autodan_init.txt").read_text(), "attack", "jailbreak", "autodan", "garak")
    for p in json.loads((data / "inthewild_jailbreak_llms.json").read_text()):
        yield _row(p, "attack", "jailbreak", "in_the_wild", "garak")


def tensor_trust(raw: Path) -> Iterator[dict[str, Any]]:
    bench = raw / "benchmarks"
    for case in _jsonl(bench / "hijacking-robustness" / "v1" / "hijacking_robustness_dataset.jsonl"):
        yield _row(case["attack"], "attack", "direct_injection", "hijacking", "tensor-trust")
    for case in _jsonl(bench / "extraction-robustness" / "v1" / "extraction_robustness_dataset.jsonl"):
        yield _row(case["attack"], "attack", "prompt_extraction", "extraction", "tensor-trust")


MULTITURN_FILES = {
    "Harmful Dataset.csv": ("attack", "jailbreak"),
    # The "benign" conversations deliver a harmless request through the same cipher / word-mapping
    # machinery as the harmful ones. Blocking the decoding turn is right for a customer chat, so they are
    # their own category, reported on its own and never counted as false positives.
    "Completely-Benign Dataset.csv": ("benign", "obfuscated_benign"),
    "Semi-Benign Dataset.csv": ("benign", "obfuscated_benign"),
}


def multiturn_tomgibbs(raw: Path) -> Iterator[dict[str, Any]]:
    for name, (label, category) in MULTITURN_FILES.items():
        for i, r in enumerate(_csv(raw / name)):
            # The conversation column is a Python-literal list of {role, content}: literal_eval only
            # builds literals (never runs code).
            convo = ast.literal_eval(r["Multi-turn conversation"])
            turns = [t["content"] for t in convo if t.get("role") == "user" and str(t.get("content")).strip()]
            if not turns:
                continue
            family = "+".join(x for x in (r["Input-cipher"], r["Output-cipher"]) if x) or "plain"
            yield {
                "id": f"tomgibbs-{category}-{r['Goal ID']}-{i}",
                "turns": turns,
                "label": label,
                "category": category,
                "family": family,
                "lang": "en",
                "source": "multiturn-tomgibbs",
                "goal_id": r["Goal ID"],
            }


CONVERTERS = {
    "bipia": bipia,
    "injecagent": injecagent,
    "jailbreakbench-artifacts": jailbreakbench_artifacts,
    "jailbreakbench-behaviors": jailbreakbench_behaviors,
    "advbench": advbench,
    "garak": garak,
    "tensor-trust": tensor_trust,
    "multiturn-tomgibbs": multiturn_tomgibbs,
}


def convert_all(raw: Path, out: Path, manifest: dict[str, Any]) -> dict[str, Counter[str]]:
    out.mkdir(parents=True, exist_ok=True)
    stats: dict[str, Counter[str]] = {}
    for name, fn in CONVERTERS.items():
        meta = manifest["sources"].get(name)
        if meta is None:
            print(f"  {name:26} not downloaded — skipped")
            continue
        multi = name.startswith("multiturn-")
        seen: set[str] = set()
        rows = []
        for row in fn(raw / name):
            key = _norm(" \n ".join(row["turns"]) if multi else row["text"])
            key = f"{row.get('variant', '')}|{row['label']}|{key}"
            if not key.strip("|") or key in seen:
                continue
            seen.add(key)
            row.update(use=meta["use"], license=meta["license"], revision=meta["revision"][:12])
            rows.append(row)
        path = out / f"{name}.jsonl"
        path.write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in rows), encoding="utf-8")
        stats[name] = Counter(f"{r['label']}/{r['category']}" for r in rows)
        summary = ", ".join(f"{k} {v}" for k, v in sorted(stats[name].items()))
        print(f"  {name:26} {len(rows):5} rows  ({summary})  [{meta['use']}]")
    return stats


if __name__ == "__main__":
    convert_all(HERE / "raw", HERE / "data", json.loads((HERE / "manifest.json").read_text()))
