"""Load the models to serve.

``models/current.json`` names the chat model's bundle (``models/<version>.joblib``) — a pickled
``EnsembleModel`` without its embedder. ``models/tool/current.json``, when present, names the
tool-content model (same format), used for ``POST /v1/score`` with ``"model": "tool"``. The embedder
is re-created from the name the bundle was trained with, so the vectors at serving time always match
the vectors the classifiers were trained on.
"""

from __future__ import annotations

import json
from pathlib import Path

import joblib

from app.embedder import get_embedder
from app.ensemble import EnsembleModel
from app.transformer import get_transformer

# Kept as the public name the API uses.
InjectionModel = EnsembleModel


def load_tool(
    model_dir: str | Path,
    cache_dir: str | None = None,
    threads: int = 1,
    transformer_name: str | None = None,
) -> EnsembleModel | None:
    """The tool-content model from ``<model_dir>/tool/current.json``, or None when there is none."""
    tool_dir = Path(model_dir) / "tool"
    if not (tool_dir / "current.json").exists():
        return None
    return load_current(tool_dir, cache_dir=cache_dir, threads=threads, transformer_name=transformer_name)


def load_current(
    model_dir: str | Path,
    cache_dir: str | None = None,
    threads: int = 1,
    transformer_name: str | None = None,
) -> EnsembleModel:
    """Load the bundle ``current.json`` names and attach its embedder and transformer view.

    ``transformer_name`` serves the view under another registry name (the int8 build of the same
    model, for instance); it is ignored for bundles trained without a transformer view, whose
    stacker has no input for it.
    """
    model_dir = Path(model_dir)
    pointer = json.loads((model_dir / "current.json").read_text())
    bundle = joblib.load(model_dir / pointer["file"])  # noqa: S301 - our own artifact, built in the image
    model = EnsembleModel(**bundle)
    model.embedder = get_embedder(model.embedder_name, cache_dir=cache_dir, threads=threads)
    if model.transformer_name:
        if transformer_name:
            model.transformer_name = transformer_name
        model.transformer = get_transformer(model.transformer_name, cache_dir=cache_dir, threads=threads)
    return model
