"""Load the model to serve.

``models/current.json`` names a bundle (``models/<version>.joblib``) — a pickled ``EnsembleModel``
without its embedder. The embedder is re-created from the name the bundle was trained with, so the
vectors at serving time always match the vectors the classifiers were trained on.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib

from app.embedder import get_embedder
from app.ensemble import EnsembleModel

# Kept as the public name the API uses.
InjectionModel = EnsembleModel


def load_current(model_dir: str | Path, cache_dir: str | None = None, threads: int = 1) -> EnsembleModel:
    model_dir = Path(model_dir)
    pointer = json.loads((model_dir / "current.json").read_text())
    bundle = joblib.load(model_dir / pointer["file"])  # noqa: S301 - our own artifact, built in the image
    model = EnsembleModel(**bundle)
    model.embedder = get_embedder(model.embedder_name, cache_dir=cache_dir, threads=threads)
    return model
