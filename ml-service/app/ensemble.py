"""The Stage 5 detector: three views of a message, combined by a small learned stacker.

    text ─┬─ char n-grams → TF-IDF → logistic regression ............ p_ngram     (wording, disguises)
          └─ sentence embedding ─┬─ logistic regression ............. p_embedding (meaning)
                                 └─ cosine to known examples ........ attack_similarity, benign_similarity
                                                    │
               [logit p_ngram, logit p_embedding, attack_sim, benign_sim] → stacker → score (0..1)

* n-grams catch exact and obfuscated phrasing, and are robust to typos;
* the embedding classifier generalises to paraphrases that share no words with the training data;
* similarity to the nearest known attacks (and to the nearest normal messages) is an explainable
  signal: "this looks like that example of family X";
* the stacker is trained on *out-of-fold* predictions, so it learns how much to trust each view on
  data the views have not memorised.

``thresholds`` (block / restrict) are calibrated at training time from a false-positive budget on
benign data and travel with the model, so a retrained model brings its own operating point.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from app.embedder import Embedder
from app.preprocess import preprocess

TOP_K = 3  # similarity = mean cosine of the k nearest examples
EPS = 1e-4


def encode_vector(v: np.ndarray) -> str:
    """Unit vector → base64 of little-endian float16 (768 bytes for 384 dims). Callers use it for
    conversation analysis (similarity between turns); half precision is plenty for cosine."""
    return base64.b64encode(np.asarray(v, dtype="<f2").tobytes()).decode()


def logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, EPS, 1 - EPS)
    return np.log(p / (1 - p))


def top_k_similarity(
    queries: np.ndarray, exemplars: np.ndarray, k: int = TOP_K
) -> tuple[np.ndarray, np.ndarray]:
    """Mean cosine of the k nearest exemplars per query (vectors are unit length), and the nearest index."""
    if len(exemplars) == 0 or len(queries) == 0:
        return np.zeros(len(queries), dtype=np.float32), np.full(len(queries), -1)
    sims = queries @ exemplars.T
    k = min(k, sims.shape[1])
    top = np.partition(sims, -k, axis=1)[:, -k:]
    return top.mean(axis=1), sims.argmax(axis=1)


def stack_features(
    p_ngram: np.ndarray, p_emb: np.ndarray, attack_sim: np.ndarray, benign_sim: np.ndarray
) -> np.ndarray:
    return np.column_stack([logit(p_ngram), logit(p_emb), attack_sim, benign_sim])


@dataclass
class EnsembleModel:
    ngram: Any  # sklearn Pipeline (TF-IDF + LR) on preprocess(text)
    emb_clf: Any  # sklearn LogisticRegression on embeddings
    stacker: Any  # sklearn LogisticRegression on stack_features
    attack_vecs: np.ndarray
    attack_families: list[str]
    benign_vecs: np.ndarray
    embedder_name: str
    thresholds: dict[str, float]
    version: str
    metadata: dict[str, Any] = field(default_factory=dict)
    embedder: Embedder | None = None  # attached at load time, never pickled

    def components(self, texts: list[str], vecs: np.ndarray) -> dict[str, np.ndarray]:
        p_ngram = self.ngram.predict_proba([preprocess(t) for t in texts])[:, 1]
        p_emb = self.emb_clf.predict_proba(vecs)[:, 1]
        attack_sim, nearest = top_k_similarity(vecs, self.attack_vecs)
        benign_sim, _ = top_k_similarity(vecs, self.benign_vecs)
        score = self.stacker.predict_proba(stack_features(p_ngram, p_emb, attack_sim, benign_sim))[:, 1]
        return {
            "score": score,
            "ngram": p_ngram,
            "embedding": p_emb,
            "attack_similarity": attack_sim,
            "benign_similarity": benign_sim,
            "nearest": nearest,
        }

    def score_detailed(self, texts: list[str], return_vectors: bool = False) -> list[dict[str, Any]]:
        if not texts:
            return []
        if self.embedder is None:
            raise RuntimeError("embedder not attached")
        vecs = self.embedder.embed(texts)
        c = self.components(texts, vecs)
        out = []
        for i in range(len(texts)):
            nearest = int(c["nearest"][i])
            out.append(
                {
                    "vector": encode_vector(vecs[i]) if return_vectors else None,
                    "score": float(c["score"][i]),
                    "components": {
                        "ngram": round(float(c["ngram"][i]), 4),
                        "embedding": round(float(c["embedding"][i]), 4),
                        "attack_similarity": round(float(c["attack_similarity"][i]), 4),
                        "benign_similarity": round(float(c["benign_similarity"][i]), 4),
                        "nearest_attack_family": self.attack_families[nearest] if nearest >= 0 else None,
                    },
                }
            )
        return out

    def score(self, texts: list[str]) -> list[float]:
        return [r["score"] for r in self.score_detailed(texts)]

    def bundle(self) -> dict[str, Any]:
        """What gets pickled: everything except the embedder (re-created from ``embedder_name``)."""
        return {k: v for k, v in self.__dict__.items() if k != "embedder"}
