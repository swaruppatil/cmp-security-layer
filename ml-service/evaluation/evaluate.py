"""Evaluate the detector honestly.

    uv run python -m evaluation.evaluate                 # current model on every held-out set
    uv run python -m evaluation.evaluate --lofo          # + leave-one-family-out on the training data
    uv run python -m evaluation.evaluate --ablation      # + seed-only vs all-training-data comparison
    uv run python -m evaluation.evaluate --all

Three questions, three tests:

* **Held-out sets** (``heldout*.jsonl``, never trained on): how does the shipped model do on data it
  has not seen? Includes a public labelled test split and handwritten benign support messages.
* **Leave-one-family-out (LOFO)**: retrain without one attack family, then test on that family. This
  is the closest offline stand-in for "a new kind of attack appears tomorrow". A fixed 20% of benign
  rows is held back from every LOFO run to measure false positives at the same time.
* **Ablation**: what does each data source buy? Retrain on seed data only and compare.

Writes ``evaluation/reports/<version>-evaluation.{json,md}``.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from app.embedder import Embedder
from app.ensemble import EnsembleModel
from app.model import load_current
from app.preprocess import preprocess
from training.metrics import operating_metrics
from training.train import ROOT, SEED, build_ngram, evaluate_sets, fit_ensemble, load_heldout, load_rows

REPORTS = ROOT / "evaluation" / "reports"


class CachedEmbedder:
    """Wraps an embedder so repeated retraining never embeds the same text twice."""

    def __init__(self, inner: Embedder) -> None:
        self.inner, self.name, self.dim = inner, inner.name, inner.dim
        self._cache: dict[str, np.ndarray] = {}

    def embed(self, texts: list[str]) -> np.ndarray:
        missing = [t for t in dict.fromkeys(texts) if t not in self._cache]
        if missing:
            self._cache.update(zip(missing, self.inner.embed(missing), strict=True))
        return np.stack([self._cache[t] for t in texts]) if texts else np.zeros((0, self.dim), np.float32)


def _fit(rows: list[dict[str, Any]], emb: CachedEmbedder) -> EnsembleModel:
    model, _ = fit_ensemble(rows, emb.embed([r["text"] for r in rows]), emb.name)
    model.embedder = emb
    return model


def lofo(rows: list[dict[str, Any]], emb: CachedEmbedder) -> list[dict[str, Any]]:
    rng = np.random.default_rng(SEED)
    benign_idx = [i for i, r in enumerate(rows) if r["label"] == "benign"]
    test_benign = set(rng.choice(benign_idx, size=len(benign_idx) // 5, replace=False).tolist())
    benign_test = [rows[i] for i in sorted(test_benign)]
    families = sorted({r["family"] for r in rows if r["label"] == "attack"})
    results = []
    for fam in families:
        train_rows = [r for i, r in enumerate(rows) if r["family"] != fam and i not in test_benign]
        test_rows = [r for r in rows if r["family"] == fam] + benign_test
        model = _fit(train_rows, emb)
        scores = model.components([r["text"] for r in test_rows], emb.embed([r["text"] for r in test_rows]))
        m = operating_metrics(
            test_rows, scores["score"], model.thresholds["block"], model.thresholds["restrict"]
        )
        # Baseline for comparison: the Stage 4 model (n-grams only, threshold 0.5).
        ngram = build_ngram().fit(
            [preprocess(r["text"]) for r in train_rows], [int(r["label"] == "attack") for r in train_rows]
        )
        ng_scores = ngram.predict_proba([preprocess(r["text"]) for r in test_rows])[:, 1]
        ng = operating_metrics(test_rows, ng_scores, 0.5, 0.5)
        results.append(
            {
                "left_out": fam,
                "n": m["attacks"],
                "recall_flagged": m["recall_flagged"],
                "recall_blocked": m["recall_blocked"],
                "fpr_flagged": m["fpr_flagged"],
                "ngram_only_recall": ng["recall_flagged"],
                "ngram_only_fpr": ng["fpr_flagged"],
                "thresholds": model.thresholds,
            }
        )
        print(f"  LOFO {fam:22} recall {m['recall_flagged']} (n-gram only {ng['recall_flagged']})")
    return results


def ablation(data_dir: Path, emb: CachedEmbedder, heldout: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    out = {}
    for name, prefixes in (("seed only", ("seed",)), ("seed + train*", ("seed", "train"))):
        model = _fit(load_rows(data_dir, prefixes), emb)
        res = evaluate_sets(model, heldout)
        out[name] = {
            "thresholds": model.thresholds,
            **{s: {k: v[k] for k in ("recall_flagged", "fpr_flagged", "auc")} for s, v in res.items()},
        }
        print(
            f"  ablation {name}: " + ", ".join(f"{s} {v}" for s, v in out[name].items() if s != "thresholds")
        )
    return out


def markdown(report: dict[str, Any]) -> str:
    lines = [
        f"# Evaluation — {report['model_version']}",
        "",
        f"Generated {report['generated_at']}. Embedder `{report['embedder']}`. "
        f"Thresholds: block ≥ {report['thresholds']['block']}, restrict ≥ {report['thresholds']['restrict']}.",
        "",
        "## Held-out sets (never trained on)",
        "",
        "| set | n | attacks | recall (flag) | recall (block) | FPR (flag) | FPR (block) | AUC | AUC n-gram | AUC embedding | AUC similarity |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for name, m in report["heldout"].items():
        a = m["auc_by_component"]
        lines.append(
            f"| {name} | {m['n']} | {m['attacks']} | {m['recall_flagged']} | {m['recall_blocked']} | "
            f"{m['fpr_flagged']} | {m['fpr_blocked']} | {a['ensemble']} | {a['ngram']} | "
            f"{a['embedding']} | {a['similarity']} |"
        )
    for name, m in report["heldout"].items():
        lines += [
            "",
            f"### {name}: by language (flagged/total)",
            "",
            ", ".join(f"{k}: {v}" for k, v in m["by_lang"].items()),
        ]
        for title, key in (("False positives", "false_positives"), ("Missed attacks", "missed_attacks")):
            if m[key]:
                lines += ["", f"{title} (worst first):", ""]
                lines += [f"- `{x['score']}` {x['text'][:120]!r}" for x in m[key][:10]]
    if report.get("lofo"):
        lines += [
            "",
            "## Leave-one-family-out",
            "",
            "Retrained without the family, then tested on it (benign FPR on a fixed 20% benign hold-out).",
            "",
            "| left-out family | n | recall (flag) | recall (block) | FPR (flag) | n-gram-only recall | n-gram-only FPR |",
            "|---|---|---|---|---|---|---|",
        ]
        for r in report["lofo"]:
            lines.append(
                f"| {r['left_out']} | {r['n']} | {r['recall_flagged']} | {r['recall_blocked']} | "
                f"{r['fpr_flagged']} | {r['ngram_only_recall']} | {r['ngram_only_fpr']} |"
            )
    if report.get("ablation"):
        lines += [
            "",
            "## Ablation: training data",
            "",
            "| training data | set | recall (flag) | FPR (flag) | AUC |",
            "|---|---|---|---|---|",
        ]
        for cfg, res in report["ablation"].items():
            for s, v in res.items():
                if s != "thresholds":
                    lines.append(f"| {cfg} | {s} | {v['recall_flagged']} | {v['fpr_flagged']} | {v['auc']} |")
    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", type=Path, default=ROOT.parent / "datasets")
    p.add_argument("--model-dir", type=Path, default=ROOT / "models")
    p.add_argument("--cache-dir", default=str(ROOT / ".cache"))
    p.add_argument("--lofo", action="store_true")
    p.add_argument("--ablation", action="store_true")
    p.add_argument("--all", action="store_true")
    args = p.parse_args()

    model = load_current(args.model_dir, cache_dir=args.cache_dir, threads=4)
    assert model.embedder is not None
    emb = CachedEmbedder(model.embedder)
    model.embedder = emb
    heldout = load_heldout(args.data)
    report: dict[str, Any] = {
        "model_version": model.version,
        "generated_at": datetime.now(UTC).isoformat(),
        "embedder": model.embedder_name,
        "thresholds": model.thresholds,
        "heldout": evaluate_sets(model, heldout),
    }
    for name, m in report["heldout"].items():
        print(f"  held-out {name}: recall {m['recall_flagged']}  FPR {m['fpr_flagged']}  AUC {m['auc']}")
    if args.lofo or args.all:
        report["lofo"] = lofo(load_rows(args.data), emb)
    if args.ablation or args.all:
        report["ablation"] = ablation(args.data, emb, heldout)

    REPORTS.mkdir(parents=True, exist_ok=True)
    base = REPORTS / f"{model.version}-evaluation"
    base.with_suffix(".json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    base.with_suffix(".md").write_text(markdown(report))
    print(f"wrote {base.with_suffix('.md').relative_to(ROOT)}")


if __name__ == "__main__":
    main()
