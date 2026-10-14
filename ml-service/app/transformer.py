"""A third view of the message: a small pretrained prompt-injection classifier run with ONNX Runtime.

The ensemble's other views are trained on our own data. This one brings outside knowledge: a
multilingual ModernBERT (``jhu-clsp/mmBERT-small``, 140M parameters) fine-tuned by Horizon Labs on
prompt-injection and jailbreak data in twenty languages, published under Apache-2.0 with an ONNX
export. It is **not** fine-tuned here; its probability is one more feature for the stacker, which
learns how much to trust it next to the n-gram, embedding and similarity views.

Measured on an M-series laptop with two threads: about 8 ms per short text (fp32), well inside the
gateway's 50 ms budget together with the ~5 ms embedding. Files are downloaded once into the cache
directory at a pinned revision, so a built image never needs the network.
"""

from __future__ import annotations

import logging
import time
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Any

import numpy as np

log = logging.getLogger("ml-service.transformer")

MAX_TOKENS = 256

REGISTRY: dict[str, dict[str, Any]] = {
    "horizon-small": {
        "repo": "Horizon-Labs/prompt-injection-guard-small",
        "revision": "e0e88c4e940ee7e1b52bdf943d501ec696b83b9b",
        "license": "apache-2.0",
        "files": {
            "model.onnx": "onnx/model.onnx",
            "tokenizer.json": "tokenizer.json",
            "config.json": "config.json",
        },
        "injection_label": 1,
    },
    "horizon-small-int8": {
        "repo": "Horizon-Labs/prompt-injection-guard-small",
        "revision": "e0e88c4e940ee7e1b52bdf943d501ec696b83b9b",
        "license": "apache-2.0",
        "files": {
            "model.onnx": "onnx/model_quantized.onnx",
            "tokenizer.json": "tokenizer.json",
            "config.json": "config.json",
        },
        "injection_label": 1,
    },
}


def _download(url: str, dest: Path, attempts: int = 6) -> None:
    """Download with resume: a 560 MB file over a flaky connection is retried from where it stopped."""
    part = dest.with_suffix(dest.suffix + ".part")
    for attempt in range(1, attempts + 1):
        have = part.stat().st_size if part.exists() else 0
        req = urllib.request.Request(url, headers={"Range": f"bytes={have}-"} if have else {})
        try:
            with urllib.request.urlopen(req, timeout=120) as res:  # noqa: S310 - pinned https URL
                if have and res.status != 206:  # server ignored the range: start over
                    have = 0
                    part.unlink(missing_ok=True)
                total = res.headers.get("Content-Range", "").rpartition("/")[2] or res.headers.get(
                    "Content-Length"
                )
                with part.open("ab" if have else "wb") as f:
                    while True:
                        chunk = res.read(1 << 20)
                        if not chunk:
                            break
                        f.write(chunk)
            if total and total.isdigit() and part.stat().st_size < int(total):
                raise OSError(f"short read: {part.stat().st_size} of {total} bytes")
            part.rename(dest)
            return
        except (OSError, ValueError) as exc:
            log.warning("download attempt %d/%d failed for %s: %s", attempt, attempts, url, exc)
            time.sleep(min(30, 2**attempt))
    raise OSError(f"could not download {url} after {attempts} attempts")


def ensure_files(name: str, cache_dir: str | Path) -> Path:
    spec = REGISTRY[name]
    target = Path(cache_dir) / "transformers" / name
    target.mkdir(parents=True, exist_ok=True)
    for local, remote in spec["files"].items():
        dest = target / local
        if dest.exists() and dest.stat().st_size > 1000:
            continue
        url = f"https://huggingface.co/{spec['repo']}/resolve/{spec['revision']}/{remote}"
        log.info("downloading %s", url)
        _download(url, dest)
    return target


class TransformerView:
    def __init__(self, name: str, cache_dir: str | Path, threads: int = 2) -> None:
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self.name = name
        folder = ensure_files(name, cache_dir)
        self._tok = Tokenizer.from_file(str(folder / "tokenizer.json"))
        self._tok.enable_truncation(MAX_TOKENS)
        options = ort.SessionOptions()
        options.intra_op_num_threads = threads
        options.inter_op_num_threads = 1
        self._sess = ort.InferenceSession(
            str(folder / "model.onnx"), options, providers=["CPUExecutionProvider"]
        )
        self._inputs = {i.name for i in self._sess.get_inputs()}
        self._label = int(REGISTRY[name]["injection_label"])
        pad = self._tok.token_to_id("[PAD]")
        if pad is None:
            pad = self._tok.token_to_id("<pad>")
        self._pad_id = int(pad) if pad is not None else 0

    def predict_proba(self, texts: list[str], batch_size: int = 16) -> np.ndarray:
        """P(injection) per text. Texts are padded and run in batches: one ONNX call for sixteen short
        messages costs little more than one call for one, which keeps a request with several fields
        or segments inside the gateway's budget."""
        out = np.zeros(len(texts), dtype=np.float32)
        order = sorted(range(len(texts)), key=lambda i: len(texts[i]))  # similar lengths together
        for start in range(0, len(order), batch_size):
            idx = order[start : start + batch_size]
            encs = self._tok.encode_batch([texts[i] for i in idx])
            width = max(len(e.ids) for e in encs)
            ids = np.full((len(encs), width), self._pad_id, dtype=np.int64)
            mask = np.zeros((len(encs), width), dtype=np.int64)
            for row, e in enumerate(encs):
                ids[row, : len(e.ids)] = e.ids
                mask[row, : len(e.ids)] = 1
            feeds: dict[str, np.ndarray] = {"input_ids": ids, "attention_mask": mask}
            if "token_type_ids" in self._inputs:
                feeds["token_type_ids"] = np.zeros_like(ids)
            logits = self._sess.run(None, feeds)[0]
            e = np.exp(logits - logits.max(axis=1, keepdims=True))
            probs = e / e.sum(axis=1, keepdims=True)
            for row, i in enumerate(idx):
                out[i] = float(probs[row, self._label])
        return out


@lru_cache(maxsize=2)
def get_transformer(
    name: str | None, cache_dir: str | None = None, threads: int = 2
) -> TransformerView | None:
    if not name or name == "none":
        return None
    return TransformerView(name, cache_dir or ".cache", threads=threads)
