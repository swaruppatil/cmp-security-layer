"""The Stage 5 detector: three views of a message, combined by a small learned stacker.

    text ─┬─ char n-grams → TF-IDF → logistic regression ............ p_ngram     (wording, disguises)
          ├─ pretrained injection classifier (ONNX, optional) ....... p_transformer (outside knowledge)
          ├─ sentence embedding ─┬─ logistic regression ............. p_embedding (meaning)
          │                      ├─ cosine to known attacks / benign .. attack_sim, benign_sim
          │                      └─ cosine to airline-support examples  topic_sim   (off-topic check)
          └─ cheap text features ..................................... latin share, "you"/"my", length
                                                    │
     [logit p_ngram · latin, logit p_embedding, attack_sim, benign_sim, latin, you, my, len] → stacker → score

* n-grams catch exact and obfuscated phrasing, and are robust to typos — but only in scripts they were
  trained on, so their logit is scaled by the share of Latin letters (a Chinese message leaves the
  decision to the embedding view instead of being pulled to "benign" by an n-gram model that has
  never seen the characters);
* the embedding classifier generalises to paraphrases that share no words with the training data;
* similarity to the nearest known attacks (and to the nearest normal messages) is an explainable
  signal: "this looks like that example of family X";
* ``topic_similarity`` to airline-support exemplars is **not** part of the score. The gateway uses it
  (with ``thresholds["off_topic"]``) to notice when the AI is being used for something that is not
  customer support at all — homework, code, essays — which is abuse but not an injection;
* "you/your" (the message addresses the assistant) and "my/our" (the message is about the customer's
  own things) are the two words that separate "ignore your instructions" from "ignore my message";
* the stacker is trained on *out-of-fold* predictions, so it learns how much to trust each view on
  data the views have not memorised.

``thresholds`` (block / restrict / off_topic) are calibrated at training time from false-positive
budgets on benign data the model never fitted on, and travel with the model.
"""

from __future__ import annotations

import base64
import math
import re
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from app.embedder import Embedder
from app.preprocess import preprocess

TOP_K = 3  # similarity = mean cosine of the k nearest examples
EPS = 1e-4
N_EXTRA = 4  # latin share, second person, first person, length

SECOND_PERSON = re.compile(
    r"\b(?:you|your|yours|yourself|u|ur|tu|toi|ton|ta|tes|vous|votre|vos|du|dein|deine|usted|tú|tus|"
    r"você|seu|sua|tuo|tua)\b|[你您]",
    re.I,
)
FIRST_PERSON = re.compile(
    r"\b(?:my|mine|our|ours|mon|ma|mes|notre|nos|mi|mis|mein|meine|meu|minha|mio|mia)\b|我的", re.I
)


def encode_vector(v: np.ndarray) -> str:
    """Unit vector → base64 of little-endian float16 (768 bytes for 384 dims). Callers use it for
    conversation analysis (similarity between turns); half precision is plenty for cosine."""
    return base64.b64encode(np.asarray(v, dtype="<f2").tobytes()).decode()


def logit(p: np.ndarray) -> np.ndarray:
    p = np.clip(p, EPS, 1 - EPS)
    return np.log(p / (1 - p))


def latin_share(text: str) -> float:
    """Share of the letters that are Latin (1.0 when there are no letters)."""
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 1.0
    latin = sum(1 for c in letters if c.isascii() or "À" <= c <= "ɏ")
    return latin / len(letters)


def extra_features(texts: list[str]) -> np.ndarray:
    out = np.zeros((len(texts), N_EXTRA), dtype=np.float32)
    for i, t in enumerate(texts):
        out[i, 0] = latin_share(t)
        out[i, 1] = 1.0 if SECOND_PERSON.search(t) else 0.0
        out[i, 2] = 1.0 if FIRST_PERSON.search(t) else 0.0
        out[i, 3] = min(math.log1p(len(t)) / 8.0, 1.0)
    return out


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
    p_ngram: np.ndarray,
    p_emb: np.ndarray,
    attack_sim: np.ndarray,
    benign_sim: np.ndarray,
    extra: np.ndarray | None = None,
    p_transformer: np.ndarray | None = None,
) -> np.ndarray:
    if extra is None:  # pre-2026-10-14 bundles: four features, no extras
        return np.column_stack([logit(p_ngram), logit(p_emb), attack_sim, benign_sim])
    latin = extra[:, 0]
    cols = [logit(p_ngram) * latin, logit(p_emb), attack_sim, benign_sim, extra]
    if p_transformer is not None:
        cols.append(logit(p_transformer))
    return np.column_stack(cols)


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
    # Airline-support exemplars for the off-topic signal (None in bundles trained before 2026-10-14).
    topic_vecs: np.ndarray | None = None
    # Whether the stacker was trained with the extra features (older bundles: False).
    uses_extra: bool = False
    # Name of the pretrained transformer view the stacker was trained with (None: not used).
    transformer_name: str | None = None
    embedder: Embedder | None = None  # attached at load time, never pickled
    transformer: Any | None = None  # attached at load time, never pickled

    def components(self, texts: list[str], vecs: np.ndarray) -> dict[str, np.ndarray]:
        p_ngram = self.ngram.predict_proba([preprocess(t) for t in texts])[:, 1]
        p_emb = self.emb_clf.predict_proba(vecs)[:, 1]
        attack_sim, nearest = top_k_similarity(vecs, self.attack_vecs)
        benign_sim, _ = top_k_similarity(vecs, self.benign_vecs)
        extra = extra_features(texts) if self.uses_extra else None
        p_tr = None
        if self.transformer_name:
            if self.transformer is None:
                raise RuntimeError(f"transformer view {self.transformer_name!r} not attached")
            p_tr = self.transformer.predict_proba(texts)
        score = self.stacker.predict_proba(
            stack_features(p_ngram, p_emb, attack_sim, benign_sim, extra, p_tr)
        )[:, 1]
        out = {
            "score": score,
            "ngram": p_ngram,
            "embedding": p_emb,
            "attack_similarity": attack_sim,
            "benign_similarity": benign_sim,
            "nearest": nearest,
        }
        if p_tr is not None:
            out["transformer"] = p_tr
        if self.topic_vecs is not None and len(self.topic_vecs):
            out["topic_similarity"], _ = top_k_similarity(vecs, self.topic_vecs)
        return out

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
            components = {
                "ngram": round(float(c["ngram"][i]), 4),
                "embedding": round(float(c["embedding"][i]), 4),
                "attack_similarity": round(float(c["attack_similarity"][i]), 4),
                "benign_similarity": round(float(c["benign_similarity"][i]), 4),
                "nearest_attack_family": self.attack_families[nearest] if nearest >= 0 else None,
            }
            if "topic_similarity" in c:
                components["topic_similarity"] = round(float(c["topic_similarity"][i]), 4)
            if "transformer" in c:
                components["transformer"] = round(float(c["transformer"][i]), 4)
            out.append(
                {
                    "vector": encode_vector(vecs[i]) if return_vectors else None,
                    "score": float(c["score"][i]),
                    "components": components,
                }
            )
        return out

    def score(self, texts: list[str]) -> list[float]:
        return [r["score"] for r in self.score_detailed(texts)]

    def bundle(self) -> dict[str, Any]:
        """What gets pickled: everything except the embedder (re-created from ``embedder_name``)."""
        return {k: v for k, v in self.__dict__.items() if k not in ("embedder", "transformer")}
