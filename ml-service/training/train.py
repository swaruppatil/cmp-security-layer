"""Train the Stage 5 ensemble (see ``app/ensemble.py``).

    uv run python -m training.train                                   # real embeddings (downloads once)
    uv run python -m training.train --embedder hash:384               # offline, for tests
    uv run python -m training.train --data DIR --out DIR --cache-dir DIR
    uv run python -m training.train --strict                          # fail when an FPR budget is missed
    uv run python -m training.train --data ../datasets --data ../datasets/tool --out models/tool --name tool

Data under ``datasets/{attacks,benign}``:
* ``seed*.jsonl`` and ``train*.jsonl`` — fitted on;
* ``calib*.jsonl`` — never fitted on; the benign rows choose the block / restrict thresholds (realistic
  customer language, not the template data the model trained on), the airline rows choose the
  off-topic threshold;
* ``heldout*.jsonl`` — never fitted on; scored after training for the report only.

Steps:
1. embed every training row once;
2. 5-fold out-of-fold (OOF) predictions for each view (n-gram LR, embedding LR, similarity to the
   other folds' examples) plus the cheap text features;
3. fit the stacker on the OOF features;
4. calibrate thresholds from a false-positive budget (``--block-fpr`` / ``--restrict-fpr``): on the
   calib benign rows when there are enough of them, else on the benign OOF scores; the stricter of the
   two wins, clamped to sane floors and caps;
5. refit the views on all rows, pick the airline-support exemplars for the off-topic signal and its
   threshold (``--off-topic-fpr`` of airline calib rows), save the bundle, ``current.json`` and a report.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
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
from app.ensemble import EnsembleModel, extra_features, stack_features, top_k_similarity
from app.preprocess import preprocess
from app.transformer import get_transformer
from training.metrics import component_aucs, misses, operating_metrics

ROOT = Path(__file__).resolve().parents[1]
SEED = 20261012
TRAIN_PREFIXES = ("seed", "train")
CALIB_PREFIXES = ("calib",)
FLOORS = {"block": 0.8, "restrict": 0.5}
CAPS = {"block": 0.98, "restrict": 0.95}
MIN_CALIB_GROUP = 100  # a calib group (one source file) needs this many benign rows to set a threshold
SMALL_CALIB_GROUP = 300  # below this, a group must have zero flagged calib rows (see recalibrate)
# Benign families that are airline customer support (the topic the AI exists for). Everything else
# benign is "general" — fine to answer, but not what this assistant is for.
AIRLINE_FAMILIES = frozenset({"airline_support", "hard_negative", "airline_hard_negative", "short_reply"})
# Airline hard negatives are few but carry the exact words attacks use; they weigh this much more.
HARD_NEGATIVE_FAMILIES = frozenset({"airline_hard_negative", "hard_negative"})
HARD_NEGATIVE_WEIGHT = 3.0
# Held-out sets whose benign rows are realistic customer language: the FPR budget is checked on them.
BUDGET_SETS = ("handwritten", "hard", "public-bitext")


# ---------------------------------------------------------------- data
def _read(path: Path) -> list[dict[str, Any]]:
    # Split on "\n" only: str.splitlines() also breaks on U+2028 and friends, which a text may contain.
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


DataDirs = Path | list[Path]


def _dirs(data: DataDirs) -> list[Path]:
    return [data] if isinstance(data, Path) else list(data)


def load_rows(data: DataDirs, prefixes: tuple[str, ...] = TRAIN_PREFIXES) -> list[dict[str, Any]]:
    """Rows from ``<dir>/attacks`` and ``<dir>/benign`` of every directory given (not recursive: the
    tool-content data under ``datasets/tool`` is only used when that directory is passed)."""
    rows: list[dict[str, Any]] = []
    for data_dir in _dirs(data):
        for sub in ("attacks", "benign"):
            for path in sorted((data_dir / sub).glob("*.jsonl")):
                if path.name.startswith(prefixes):
                    rows.extend(_read(path))
    if not rows and prefixes == TRAIN_PREFIXES:
        raise SystemExit(f"no training rows ({'/'.join(prefixes)}*.jsonl) under {_dirs(data)}")
    return rows


def load_training(data: DataDirs) -> list[dict[str, Any]]:
    """Training rows minus any text that also appears in a held-out or calib file of the same
    directories. Public sets overlap (the same well-known jailbreak prompt sits in garak, jackhhao and
    JailbreakBench), and a held-out number is only honest when nothing in it was fitted on."""
    held_rows = [
        r
        for sets in (load_heldout(data), load_heldout(data, "calib"))
        for rows in sets.values()
        for r in rows
    ]
    reserved = {r["text"].casefold() for r in held_rows}
    # Sentence level too: a training row that contains a whole held-out sentence (six words or more)
    # has copied filler from the held-out pool, and would let the model memorise it.
    reserved_sentences = {s for r in held_rows for s in _sentences(r["text"]) if len(s.split()) >= 6}
    rows = load_rows(data)
    kept, shared = [], 0
    for r in rows:
        if r["text"].casefold() in reserved:
            continue
        if any(s in reserved_sentences for s in _sentences(r["text"])):
            shared += 1
            continue
        kept.append(r)
    if len(kept) < len(rows):
        print(
            f"dropped {len(rows) - len(kept)} training rows that also appear in held-out / calib files "
            f"({shared} shared a whole sentence)"
        )
    return kept


_SENTENCE = re.compile(r"(?<=[.!?])\s+")


def _sentences(text: str) -> list[str]:
    return [s.strip().casefold() for s in _SENTENCE.split(text) if s.strip()]


def load_heldout(data: DataDirs, prefix: str = "heldout") -> dict[str, list[dict[str, Any]]]:
    """``<prefix>-<name>.jsonl`` from attacks/ and benign/, grouped by name (a set may be benign-only)."""
    sets: dict[str, list[dict[str, Any]]] = {}
    for data_dir in _dirs(data):
        for sub in ("attacks", "benign"):
            for path in sorted((data_dir / sub).glob(f"{prefix}*.jsonl")):
                sets.setdefault(path.stem.removeprefix(f"{prefix}-") or prefix, []).extend(_read(path))
    return sets


def is_airline(row: dict[str, Any]) -> bool:
    return row["label"] == "benign" and row.get("family") in AIRLINE_FAMILIES


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
    p_transformer: np.ndarray | None = None,
    transformer_name: str | None = None,
) -> tuple[EnsembleModel, dict[str, Any]]:
    """``p_transformer``: the pretrained transformer view's P(injection) per row. It is not fitted
    here (it is pretrained), so the same values serve every fold."""
    raw_texts = [r["text"] for r in rows]
    texts = [preprocess(t) for t in raw_texts]
    y = np.array([int(r["label"] == "attack") for r in rows])
    w = np.array([HARD_NEGATIVE_WEIGHT if r.get("family") in HARD_NEGATIVE_FAMILIES else 1.0 for r in rows])
    extra = extra_features(raw_texts)
    feats = np.zeros((len(rows), 4 + extra.shape[1] + (1 if p_transformer is not None else 0)))
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED)
    for tr, te in skf.split(texts, y):
        ng = build_ngram().fit([texts[i] for i in tr], y[tr], clf__sample_weight=w[tr])
        em = build_emb_clf().fit(vecs[tr], y[tr], sample_weight=w[tr])
        a_sim, _ = top_k_similarity(vecs[te], vecs[tr][y[tr] == 1])
        b_sim, _ = top_k_similarity(vecs[te], vecs[tr][y[tr] == 0])
        feats[te] = stack_features(
            ng.predict_proba([texts[i] for i in te])[:, 1],
            em.predict_proba(vecs[te])[:, 1],
            a_sim,
            b_sim,
            extra[te],
            None if p_transformer is None else p_transformer[te],
        )
    stacker = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000).fit(feats, y, sample_weight=w)
    oof = stacker.predict_proba(feats)[:, 1]
    thresholds = calibrate(oof[y == 0], block_fpr, restrict_fpr)

    attack_mask = y == 1
    airline_mask = np.array([is_airline(r) for r in rows])
    model = EnsembleModel(
        ngram=build_ngram().fit(texts, y, clf__sample_weight=w),
        emb_clf=build_emb_clf().fit(vecs, y, sample_weight=w),
        stacker=stacker,
        attack_vecs=vecs[attack_mask],
        attack_families=[r["family"] for r, a in zip(rows, attack_mask, strict=True) if a],
        benign_vecs=vecs[~attack_mask],
        embedder_name=embedder_name,
        thresholds=thresholds,
        version="",
        topic_vecs=vecs[airline_mask] if airline_mask.any() else None,
        uses_extra=True,
        transformer_name=transformer_name if p_transformer is not None else None,
    )
    names = [
        "ngram×latin",
        "embedding",
        "attack_similarity",
        "benign_similarity",
        "latin_share",
        "second_person",
        "first_person",
        "length",
    ] + (["transformer"] if p_transformer is not None else [])
    weights = dict(zip(names, (round(float(w), 3) for w in stacker.coef_[0]), strict=True))
    oof_report = {
        **operating_metrics(rows, oof, thresholds["block"], thresholds["restrict"]),
        "stacker_weights": weights,
    }
    return model, oof_report


def recalibrate(
    model: EnsembleModel,
    calib: list[dict[str, Any]],
    *,
    block_fpr: float,
    restrict_fpr: float,
    off_topic_fpr: float,
) -> dict[str, Any]:
    """Thresholds from data the model never fitted on. Block / restrict: the stricter of the OOF
    calibration and the calib-benign calibration. Off-topic: the ``off_topic_fpr`` quantile of airline
    rows' topic similarity (so at most that share of airline messages reads as off-topic)."""
    assert model.embedder is not None
    report: dict[str, Any] = {"calib_rows": len(calib), "source": "out-of-fold benign scores"}
    if not calib:
        return report
    texts = [r["text"] for r in calib]
    comps = model.components(texts, model.embedder.embed(texts))
    y = np.array([r["label"] == "attack" for r in calib])
    benign_scores = comps["score"][~y]
    if len(benign_scores) >= MIN_CALIB_GROUP:
        # The budget must hold on every calib set on its own (grouped by source file): 800 easy
        # support messages must not dilute the quantile of 126 airline hard negatives.
        groups: dict[str, list[int]] = {}
        for i, r in enumerate(calib):
            if r["label"] == "benign":
                groups.setdefault(str(r.get("source", "?")).split(" ")[0].split(":")[0], []).append(i)

        # A small group cannot measure a 1 % rate: one row in 126 is already 0.8 %. For groups under
        # SMALL_CALIB_GROUP rows the threshold is set so that *no* calib row is flagged (the budget
        # becomes "fewer than half a row"), which is what the held-out set then tends to confirm.
        def budget_for(n: int, budget: float) -> float:
            return min(budget, 0.5 / n) if n < SMALL_CALIB_GROUP else budget

        per_group = {
            g: calibrate(
                comps["score"][idx], budget_for(len(idx), block_fpr), budget_for(len(idx), restrict_fpr)
            )
            for g, idx in groups.items()
            if len(idx) >= MIN_CALIB_GROUP
        }
        from_calib = {
            "block": max(t["block"] for t in per_group.values()),
            "restrict": max(t["restrict"] for t in per_group.values()),
        }
        before = dict(model.thresholds)
        model.thresholds["block"] = max(before["block"], from_calib["block"])
        model.thresholds["restrict"] = min(
            max(before["restrict"], from_calib["restrict"]), model.thresholds["block"] - 0.05
        )
        report.update(
            source="calib benign rows per group (stricter of each group and out-of-fold)",
            calib_benign=int((~y).sum()),
            calib_groups={g: len(idx) for g, idx in groups.items()},
            from_oof=before,
            from_calib=from_calib,
            per_group=per_group,
        )
    if "topic_similarity" in comps:
        airline = np.array([is_airline(r) for r in calib])
        if airline.sum() >= 50:
            cut = float(np.quantile(comps["topic_similarity"][airline], off_topic_fpr)) - 1e-4
            model.thresholds["off_topic"] = round(max(0.0, cut), 4)
            general = np.array([r["label"] == "benign" and not is_airline(r) for r in calib])
            report["off_topic"] = {
                "airline_rows": int(airline.sum()),
                "airline_below": round(float((comps["topic_similarity"][airline] < cut).mean()), 4),
                "general_rows": int(general.sum()),
                "general_below": (
                    round(float((comps["topic_similarity"][general] < cut).mean()), 4)
                    if general.any()
                    else None
                ),
            }
    report["thresholds"] = dict(model.thresholds)
    report["recall_at_thresholds"] = operating_metrics(
        calib, comps["score"], model.thresholds["block"], model.thresholds["restrict"]
    )
    return report


# ---------------------------------------------------------------- evaluation of a trained model
def evaluate_sets(model: EnsembleModel, sets: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
    assert model.embedder is not None
    out: dict[str, Any] = {}
    for name, rows in sets.items():
        texts = [r["text"] for r in rows]
        comps = model.components(texts, model.embedder.embed(texts))
        t = model.thresholds
        entry = {
            **operating_metrics(rows, comps["score"], t["block"], t["restrict"]),
            "auc_by_component": component_aucs(rows, comps),
            **misses(rows, comps["score"], t["restrict"]),
        }
        if "topic_similarity" in comps and "off_topic" in t:
            benign = np.array([r["label"] == "benign" for r in rows])
            if benign.any():
                entry["benign_off_topic_rate"] = round(
                    float((comps["topic_similarity"][benign] < t["off_topic"]).mean()), 4
                )
        out[name] = entry
    return out


def budget_misses(
    heldout: dict[str, Any], block_fpr: float, restrict_fpr: float, sets: tuple[str, ...] = BUDGET_SETS
) -> list[str]:
    """Held-out sets whose false-positive rate is more than twice the budget. A small set gets a
    tolerance of two rows: one blocked row in 93 is 1.1 %, which says nothing about a 0.2 % budget."""
    out = []
    for name in sets:
        m = heldout.get(name)
        if not m or m["benign"] == 0:
            continue
        slack = 2 / m["benign"]
        if (m["fpr_blocked"] or 0) > max(block_fpr * 2, slack):
            out.append(f"{name}: FPR(block) {m['fpr_blocked']} > budget {block_fpr}")
        if (m["fpr_flagged"] or 0) > max(restrict_fpr * 2, slack):
            out.append(f"{name}: FPR(flag) {m['fpr_flagged']} > budget {restrict_fpr}")
    return out


# ---------------------------------------------------------------- entry point
def train(
    data_dir: DataDirs,
    out_dir: Path,
    embedder_name: str = f"fastembed:{DEFAULT_MODEL}",
    cache_dir: str | None = None,
    block_fpr: float = 0.002,
    restrict_fpr: float = 0.01,
    off_topic_fpr: float = 0.01,
    write_report: bool = True,
    strict: bool = False,
    name: str = "ensemble",
    budget_sets: tuple[str, ...] = BUDGET_SETS,
    transformer_name: str | None = None,
) -> dict[str, Any]:
    """``data_dir`` may be several directories: the tool-content model trains on the chat data plus
    ``datasets/tool`` (``--data datasets --data datasets/tool``), so it knows both what customers write
    and what tool output looks like, and is calibrated on the tool calib rows as well."""
    rows = load_training(data_dir)
    embedder = get_embedder(embedder_name, cache_dir=cache_dir, threads=4)  # batch embedding at train time
    transformer = get_transformer(transformer_name, cache_dir=cache_dir, threads=4)
    started = time.perf_counter()
    vecs = embedder.embed([r["text"] for r in rows])
    embed_seconds = round(time.perf_counter() - started, 2)
    p_tr = transformer.predict_proba([r["text"] for r in rows]) if transformer is not None else None
    model, oof_report = fit_ensemble(
        rows,
        vecs,
        embedder.name,
        block_fpr=block_fpr,
        restrict_fpr=restrict_fpr,
        p_transformer=p_tr,
        transformer_name=transformer.name if transformer is not None else None,
    )
    model.embedder = embedder
    model.transformer = transformer
    calib_report = recalibrate(
        model,
        load_rows(data_dir, CALIB_PREFIXES),
        block_fpr=block_fpr,
        restrict_fpr=restrict_fpr,
        off_topic_fpr=off_topic_fpr,
    )
    train_seconds = round(time.perf_counter() - started, 2)

    model.version = f"{name}-{datetime.now(UTC):%Y%m%d%H%M%S}"
    labels = [r["label"] == "attack" for r in rows]
    heldout = evaluate_sets(model, load_heldout(data_dir))
    model.metadata = {
        "trained_at": datetime.now(UTC).isoformat(),
        "embedder": embedder.name,
        "transformer": transformer.name if transformer is not None else None,
        "thresholds": model.thresholds,
        "calibration": {
            "block_fpr_budget": block_fpr,
            "restrict_fpr_budget": restrict_fpr,
            "off_topic_fpr_budget": off_topic_fpr,
            "floors": FLOORS,
            "caps": CAPS,
            **calib_report,
        },
        "data": {
            "dirs": [str(d) for d in _dirs(data_dir)],
            "rows": len(rows),
            "attacks": sum(labels),
            "benign": len(labels) - sum(labels),
            "airline_topic_exemplars": int(sum(is_airline(r) for r in rows)),
            "files": f"{'/'.join(TRAIN_PREFIXES)}*.jsonl",
            "embed_seconds": embed_seconds,
            "train_seconds": train_seconds,
        },
        "metrics": {"out_of_fold": oof_report, "heldout": heldout},
        "budget_misses": budget_misses(heldout, block_fpr, restrict_fpr, budget_sets),
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
    if strict and report["budget_misses"]:
        print("FPR budget missed:\n  " + "\n  ".join(report["budget_misses"]), file=sys.stderr)
        raise SystemExit(2)
    return report


def summary(report: dict[str, Any]) -> str:
    lines = [
        f"trained {report['version']} ({report['embedder']}, transformer {report.get('transformer')}) "
        f"on {report['data']['rows']} rows "
        f"in {report['data']['train_seconds']}s; thresholds {report['thresholds']} "
        f"(calibrated on: {report['calibration'].get('source')})"
    ]
    rows = [("out-of-fold", report["metrics"]["out_of_fold"])] + list(report["metrics"]["heldout"].items())
    lines.append(
        f"{'set':28} {'n':>5} {'recall':>7} {'recall@blk':>10} {'FPR':>7} {'FPR@blk':>8} "
        f"{'AUC':>6} {'off-topic':>9}"
    )
    for name, m in rows:
        lines.append(
            f"{name:28} {m['n']:5} {m['recall_flagged']!s:>7} {m['recall_blocked']!s:>10} "
            f"{m['fpr_flagged']!s:>7} {m['fpr_blocked']!s:>8} {m['auc']!s:>6} "
            f"{m.get('benign_off_topic_rate', '')!s:>9}"
        )
    if report.get("budget_misses"):
        lines.append("FPR budget missed: " + "; ".join(report["budget_misses"]))
    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument(
        "--data",
        type=Path,
        action="append",
        help="data directory with attacks/ and benign/; repeatable (default: ../datasets)",
    )
    p.add_argument(
        "--name", default="ensemble", help="version prefix, e.g. 'tool' for the tool-content model"
    )
    p.add_argument(
        "--budget-set",
        action="append",
        help="held-out set checked against the FPR budget; repeatable (default: "
        + ", ".join(BUDGET_SETS)
        + ")",
    )
    p.add_argument("--out", type=Path, default=ROOT / "models")
    p.add_argument("--embedder", default=f"fastembed:{DEFAULT_MODEL}")
    p.add_argument(
        "--transformer",
        default="horizon-small",
        help="pretrained injection classifier as a third view: horizon-small | horizon-small-int8 | none",
    )
    p.add_argument("--cache-dir", default=str(ROOT / ".cache"))
    p.add_argument("--block-fpr", type=float, default=0.002)
    p.add_argument("--restrict-fpr", type=float, default=0.01)
    p.add_argument("--off-topic-fpr", type=float, default=0.01)
    p.add_argument("--no-report", action="store_true", help="don't write evaluation/reports/<version>.json")
    p.add_argument("--strict", action="store_true", help="exit 2 when a held-out FPR budget is missed")
    args = p.parse_args()
    report = train(
        args.data or [ROOT.parent / "datasets"],
        args.out,
        args.embedder,
        args.cache_dir,
        args.block_fpr,
        args.restrict_fpr,
        args.off_topic_fpr,
        write_report=not args.no_report,
        strict=args.strict,
        name=args.name,
        budget_sets=tuple(args.budget_set) if args.budget_set else BUDGET_SETS,
        transformer_name=None if args.transformer == "none" else args.transformer,
    )
    print(summary(report))


if __name__ == "__main__":
    main()
