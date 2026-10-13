"""Metrics shared by training and evaluation.

Two operating points per model, matching what the gateway does with a score:
* flagged = score ≥ restrict threshold (restricted or blocked);
* blocked = score ≥ block threshold.
For a benign-only set the interesting number is the false-positive rate; for a mixed set also recall
and ROC AUC (threshold-free, so components can be compared fairly).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

import numpy as np
from sklearn.metrics import roc_auc_score


def _rate(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def auc(y: np.ndarray, scores: np.ndarray) -> float | None:
    if len(set(y.tolist())) < 2:
        return None
    return round(float(roc_auc_score(y, scores)), 4)


def operating_metrics(
    rows: list[dict[str, Any]], scores: np.ndarray, block_at: float, restrict_at: float
) -> dict[str, Any]:
    y = np.array([r["label"] == "attack" for r in rows])
    flagged, blocked = scores >= restrict_at, scores >= block_at
    n_att, n_ben = int(y.sum()), int((~y).sum())
    tp, fp = int((flagged & y).sum()), int((flagged & ~y).sum())
    out: dict[str, Any] = {
        "n": len(rows),
        "attacks": n_att,
        "benign": n_ben,
        "recall_flagged": _rate(tp, n_att),
        "recall_blocked": _rate(int((blocked & y).sum()), n_att),
        "fpr_flagged": _rate(fp, n_ben),
        "fpr_blocked": _rate(int((blocked & ~y).sum()), n_ben),
        "precision_flagged": _rate(tp, tp + fp),
        "auc": auc(y.astype(int), scores),
    }
    groups: dict[str, dict[str, list[int]]] = {
        "by_family": defaultdict(lambda: [0, 0]),
        "by_lang": defaultdict(lambda: [0, 0]),
    }
    for r, f in zip(rows, flagged, strict=True):
        for key, value in (
            ("by_family", r.get("family", "?")),
            ("by_lang", f"{r['label']}:{r.get('lang', '?')}"),
        ):
            groups[key][value][0] += int(f)
            groups[key][value][1] += 1
    # by_family: flagged/total (recall for attack families, false positives for benign ones).
    out["by_family"] = {k: f"{a}/{b}" for k, (a, b) in sorted(groups["by_family"].items())}
    out["by_lang"] = {k: f"{a}/{b}" for k, (a, b) in sorted(groups["by_lang"].items())}
    return out


def component_aucs(rows: list[dict[str, Any]], comps: dict[str, np.ndarray]) -> dict[str, float | None]:
    y = np.array([int(r["label"] == "attack") for r in rows])
    return {
        "ensemble": auc(y, comps["score"]),
        "ngram": auc(y, comps["ngram"]),
        "embedding": auc(y, comps["embedding"]),
        "similarity": auc(y, comps["attack_similarity"] - comps["benign_similarity"]),
    }


def misses(
    rows: list[dict[str, Any]], scores: np.ndarray, restrict_at: float, limit: int = 15
) -> dict[str, list[dict[str, Any]]]:
    """The worst mistakes, for reading by a human: missed attacks (lowest scores) and false positives."""
    y = np.array([r["label"] == "attack" for r in rows])
    fn = [i for i in np.argsort(scores) if y[i] and scores[i] < restrict_at][:limit]
    fp = [i for i in np.argsort(-scores) if not y[i] and scores[i] >= restrict_at][:limit]

    def show(i: int) -> dict[str, Any]:
        return {
            "score": round(float(scores[i]), 4),
            "family": rows[i].get("family"),
            "text": rows[i]["text"][:200],
        }

    return {"missed_attacks": [show(i) for i in fn], "false_positives": [show(i) for i in fp]}
