"""Sentence embeddings: text → unit-length vector, so "same meaning" becomes "nearby vectors".

Two implementations behind one tiny interface (``name``, ``dim``, ``embed(texts) -> ndarray``):

* ``FastEmbedder`` — ONNX ``paraphrase-multilingual-MiniLM-L12-v2`` via fastembed (384 dims, EN/FR and
  ~50 other languages, ~4 ms per short message on one CPU core, no PyTorch). Used in the image.
* ``HashEmbedder`` — a deterministic hashed bag of words and character trigrams. No download, no
  meaning, but stable: it lets tests and offline runs exercise the whole pipeline.

Embeddings see lightly normalised text (``normalize_for_embedding``): disguises are undone, but case,
accents and digits are kept because the language model understands them.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from functools import lru_cache
from typing import Protocol

import numpy as np

from app.preprocess import CONFUSABLES, SPACED_ANY

DEFAULT_MODEL = "sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2"
WS = re.compile(r"\s+")


def normalize_for_embedding(text: str) -> str:
    t = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    t = unicodedata.normalize("NFKC", t).translate(CONFUSABLES)
    t = SPACED_ANY.sub(lambda m: re.sub(r"[\s.\-_*]", "", m.group(1)), t)
    return WS.sub(" ", t).strip()


class Embedder(Protocol):
    name: str
    dim: int

    def embed(self, texts: list[str]) -> np.ndarray: ...


def _unit(m: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    return (m / np.where(norms == 0, 1, norms)).astype(np.float32)


class FastEmbedder:
    def __init__(self, model: str = DEFAULT_MODEL, cache_dir: str | None = None, threads: int = 1) -> None:
        from fastembed import TextEmbedding

        self.name = f"fastembed:{model}"
        self._model = TextEmbedding(model_name=model, cache_dir=cache_dir, threads=threads)
        self.dim = int(self._model.embedding_size)

    def embed(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        vecs = list(self._model.embed([normalize_for_embedding(t) for t in texts], batch_size=64))
        return _unit(np.asarray(vecs, dtype=np.float32))


class HashEmbedder:
    def __init__(self, dim: int = 384) -> None:
        self.name = f"hash:{dim}"
        self.dim = dim

    def _features(self, text: str) -> list[str]:
        t = normalize_for_embedding(text).casefold()
        words = re.findall(r"\w+", t)
        return words + [t[i : i + 3] for i in range(max(len(t) - 2, 0))]

    def embed(self, texts: list[str]) -> np.ndarray:
        m = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for feat in self._features(text):
                h = int.from_bytes(hashlib.blake2b(feat.encode(), digest_size=8).digest(), "little")
                m[row, h % self.dim] += 1.0 if (h >> 63) & 1 else -1.0
        return _unit(m)


@lru_cache(maxsize=4)
def get_embedder(name: str, cache_dir: str | None = None, threads: int = 1) -> Embedder:
    """``hash:384`` or ``fastembed:<model>`` (the bundle records which one it was trained with)."""
    kind, _, arg = name.partition(":")
    if kind == "hash":
        return HashEmbedder(int(arg or 384))
    if kind == "fastembed":
        return FastEmbedder(arg or DEFAULT_MODEL, cache_dir=cache_dir, threads=threads)
    raise ValueError(f"unknown embedder {name!r}")
