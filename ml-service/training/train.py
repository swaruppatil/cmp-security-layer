"""Train the Stage 5 ensemble (see ``app/ensemble.py``).

    uv run python -m training.train                                   # real embeddings (downloads once)
    uv run python -m training.train --embedder hash:384               # offline, for tests
    uv run python -m training.train --data DIR --out DIR --cache-dir DIR

Data: only ``seed*.jsonl`` and ``train*.jsonl`` under ``datasets/{attacks,benign}`` are used for
fitting. ``heldout*.jsonl`` files are scored after training and never fitted on.

Steps:
1. embed every training row once;
2. 5-fold out-of-fold (OOF) predictions for each view (n-gram LR, embedding LR, similarity to the
   other folds' examples);
3. fit the stacker on the OOF features;
4. calibrate thresholds from the benign OOF scores and a false-positive budget
   (``--block-fpr`` / ``--restrict-fpr``), clamped to sane floors;
5. refit the views on all rows and save the bundle, ``current.json`` and a report.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold
from sklearn.pipeline import Pipeline

from app.embedder import DEFAULT_MODEL, get_embedder
from app.ensemble import EnsembleModel, stack_features, top_k_similarity
from app.preprocess import preprocess
from training.metrics import component_aucs, misses, operating_metrics

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261012
TRAIN_PREFIXES = ("seed", "train")
FLOORS = {"block": 0.8, "restrict": 0.5}
CAPS = {"block": 0.98, "restrict": 0.95}


# ---------------------------------------------------------------- data
def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_rows(data_dir: Path, prefixes: tuple[str, ...] = TRAIN_PREFIXES) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sub in ("attacks", "benign"):
        for path in sorted((data_dir / sub).glob("*.jsonl")):
            if path.name.startswith(prefixes):
                rows.extend(_read(path))
    if not rows:
        raise SystemExit(f"no training rows ({'/'.join(prefixes)}*.jsonl) under {data_dir}")
    return rows


def load_heldout(data_dir: Path) -> dict[str, list[dict[str, Any]]]:
    """``heldout-<name>.jsonl`` from attacks/ and benign/, grouped by name (a set may be benign-only)."""
    sets: dict[str, list[dict[str, Any]]] = {}
    for sub in ("attacks", "benign"):
        for path in sorted((data_dir / sub).glob("heldout*.jsonl")):
            sets.setdefault(path.stem.removeprefix("heldout-") or "heldout", []).extend(_read(path))
    return sets


# ---------------------------------------------------------------- model pieces
def build_ngram() -> Pipeline:
    return Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    analyzer="char_wb", ngram_range=(2, 5), min_df=2, sublinear_tf=True, max_features=200_000
                ),
            ),
            ("clf", LogisticRegression(C=4.0, class_weight="balanced", max_iter=2000, random_state=SEED)),
        ]
    )


def build_emb_clf() -> LogisticRegression:
    return LogisticRegression(C=4.0, class_weight="balanced", max_iter=2000, random_state=SEED)


def calibrate(benign_scores: np.ndarray, block_fpr: float, restrict_fpr: float) -> dict[str, float]:
    """Lowest thresholds whose benign false-positive rate stays within budget, clamped to floors/caps."""

    def at(budget: float) -> float:
        return float(np.quantile(benign_scores, 1 - budget)) + 1e-4 if len(benign_scores) else 0.0

    block = min(max(at(block_fpr), FLOORS["block"]), CAPS["block"])
    restrict = min(max(at(restrict_fpr), FLOORS["restrict"]), CAPS["restrict"], block - 0.05)
    return {"block": round(block, 4), "restrict": round(restrict, 4)}


def fit_ensemble(
    rows: list[dict[str, Any]],
    vecs: np.ndarray,
    embedder_name: str,
    *,
    folds: int = 5,
    block_fpr: float = 0.002,
    restrict_fpr: float = 0.01,
) -> tuple[EnsembleModel, dict[str, Any]]:
    texts = [preprocess(r["text"]) for r in rows]
    y = np.array([int(r["label"] == "attack") for r in rows])
    feats = np.zeros((len(rows), 4))
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED)
    for tr, te in skf.split(texts, y):
        ng = build_ngram().fit([texts[i] for i in tr], y[tr])
        em = build_emb_clf().fit(vecs[tr], y[tr])
        a_sim, _ = top_k_similarity(vecs[te], vecs[tr][y[tr] == 1])
        b_sim, _ = top_k_similarity(vecs[te], vecs[tr][y[tr] == 0])
        feats[te] = stack_features(
            ng.predict_proba([texts[i] for i in te])[:, 1], em.predict_proba(vecs[te])[:, 1], a_sim, b_sim
        )
    stacker = LogisticRegression(C=1.0, class_weight="balanced", max_iter=1000).fit(feats, y)
    oof = stacker.predict_proba(feats)[:, 1]
    thresholds = calibrate(oof[y == 0], block_fpr, restrict_fpr)

    attack_mask = y == 1
    model = EnsembleModel(
        ngram=build_ngram().fit(texts, y),
        emb_clf=build_emb_clf().fit(vecs, y),
        stacker=stacker,
        attack_vecs=vecs[attack_mask],
        attack_families=[r["family"] for r, a in zip(rows, attack_mask, strict=True) if a],
        benign_vecs=vecs[~attack_mask],
        embedder_name=embedder_name,
        thresholds=thresholds,
        version="",
    )
    weights = dict(
        zip(
            ["ngram", "embedding", "attack_similarity", "benign_similarity"],
            (round(float(w), 3) for w in stacker.coef_[0]),
            strict=True,
        )
    )
    oof_report = {
        **operating_metrics(rows, oof, thresholds["block"], thresholds["restrict"]),
        "stacker_weights": weights,
    }
    return model, oof_report


# ---------------------------------------------------------------- evaluation of a trained model
def evaluate_sets(model: EnsembleModel, sets: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    assert model.embedder is not None
    out: dict[str, Any] = {}
    for name, rows in sets.items():
        texts = [r["text"] for r in rows]
        comps = model.components(texts, model.embedder.embed(texts))
        t = model.thresholds
        out[name] = {
            **operating_metrics(rows, comps["score"], t["block"], t["restrict"]),
            "auc_by_component": component_aucs(rows, comps),
            **misses(rows, comps["score"], t["restrict"]),
        }
    return out


# ---------------------------------------------------------------- entry point
def train(
    data_dir: Path,
    out_dir: Path,
    embedder_name: str = f"fastembed:{DEFAULT_MODEL}",
    cache_dir: str | None = None,
    block_fpr: float = 0.002,
    restrict_fpr: float = 0.01,
    write_report: bool = True,
) -> dict[str, Any]:
    rows = load_rows(data_dir)
    embedder = get_embedder(embedder_name, cache_dir=cache_dir, threads=4)  # batch embedding at train time
    started = time.perf_counter()
    vecs = embedder.embed([r["text"] for r in rows])
    embed_seconds = round(time.perf_counter() - started, 2)
    model, oof_report = fit_ensemble(
        rows, vecs, embedder.name, block_fpr=block_fpr, restrict_fpr=restrict_fpr
    )
    model.embedder = embedder
    train_seconds = round(time.perf_counter() - started, 2)

    model.version = f"ensemble-{datetime.now(UTC):%Y%m%d%H%M%S}"
    labels = [r["label"] == "attack" for r in rows]
    model.metadata = {
        "trained_at": datetime.now(UTC).isoformat(),
        "embedder": embedder.name,
        "thresholds": model.thresholds,
        "calibration": {
            "block_fpr_budget": block_fpr,
            "restrict_fpr_budget": restrict_fpr,
            "floors": FLOORS,
            "caps": CAPS,
            "source": "out-of-fold benign scores",
        },
        "data": {
            "rows": len(rows),
            "attacks": sum(labels),
            "benign": len(labels) - sum(labels),
            "files": f"{'/'.join(TRAIN_PREFIXES)}*.jsonl",
            "embed_seconds": embed_seconds,
            "train_seconds": train_seconds,
        },
        "metrics": {"out_of_fold": oof_report, "heldout": evaluate_sets(model, load_heldout(data_dir))},
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    file = f"{model.version}.joblib"
    joblib.dump(model.bundle(), out_dir / file, compress=3)
    (out_dir / "current.json").write_text(json.dumps({"file": file, "version": model.version}, indent=2))
    report = {"version": model.version, **model.metadata}
    if write_report:
        reports = ROOT / "evaluation" / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / f"{model.version}.json").write_text(json.dumps(report, indent=2, ensure_ascii=False))
    return report


def summary(report: dict[str, Any]) -> str:
    lines = [
        f"trained {report['version']} ({report['embedder']}) on {report['data']['rows']} rows "
        f"in {report['data']['train_seconds']}s; thresholds {report['thresholds']}"
    ]
    rows = [("out-of-fold", report["metrics"]["out_of_fold"])] + list(report["metrics"]["heldout"].items())
    lines.append(f"{'set':28} {'n':>5} {'recall':>7} {'recall@blk':>10} {'FPR':>7} {'FPR@blk':>8} {'AUC':>6}")
    for name, m in rows:
        lines.append(
            f"{name:28} {m['n']:5} {m['recall_flagged']!s:>7} {m['recall_blocked']!s:>10} "
            f"{m['fpr_flagged']!s:>7} {m['fpr_blocked']!s:>8} {m['auc']!s:>6}"
        )
    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--data", type=Path, default=ROOT.parent / "datasets")
    p.add_argument("--out", type=Path, default=ROOT / "models")
    p.add_argument("--embedder", default=f"fastembed:{DEFAULT_MODEL}")
    p.add_argument("--cache-dir", default=str(ROOT / ".cache"))
    p.add_argument("--block-fpr", type=float, default=0.002)
    p.add_argument("--restrict-fpr", type=float, default=0.01)
    p.add_argument("--no-report", action="store_true", help="don't write evaluation/reports/<version>.json")
    args = p.parse_args()
    report = train(
        args.data,
        args.out,
        args.embedder,
        args.cache_dir,
        args.block_fpr,
        args.restrict_fpr,
        write_report=not args.no_report,
    )
    print(summary(report))


if __name__ == "__main__":
    main()
