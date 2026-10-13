"""Find the text inside a proxied request body.

AI APIs put user text in different places: ``{"message": ...}``, ``{"prompt": ...}``,
``{"messages": [{"role": "user", "content": ...}]}``, ``{"input": [...]}``,
``{"content": [{"type": "text", "text": ...}]}``. The gateway inspects all of them, so an attacker
cannot hide text in a field the checks never read.
"""

from __future__ import annotations

from typing import Any

TEXT_KEYS = frozenset({"message", "prompt", "input", "content", "text", "query", "question", "instructions"})
MAX_DEPTH = 8
MAX_FIELDS = 200


# Where AI apps put their reply in a response body (checked by the outbound pipeline in proxy mode).
RESPONSE_TEXT_KEYS = TEXT_KEYS | frozenset(
    {"reply", "output", "answer", "completion", "response", "output_text"}
)


def _walk(body: Any, keys: frozenset[str], visit: Any) -> Any:
    """Walk ``body``; for every string under one of ``keys`` call ``visit(s)`` and use its return
    value in the copy that is returned. Bounded in depth and number of strings."""
    count = 0

    def walk(node: Any, depth: int, under_text_key: bool) -> Any:
        nonlocal count
        if depth > MAX_DEPTH:
            return node
        if isinstance(node, str):
            if under_text_key and count < MAX_FIELDS:
                count += 1
                return visit(node)
            return node
        if isinstance(node, dict):
            return {k: walk(v, depth + 1, str(k).lower() in keys) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(item, depth + 1, under_text_key) for item in node]
        return node

    return walk(body, 0, False)


def extract_text_fields(body: Any, keys: frozenset[str] = TEXT_KEYS) -> list[str]:
    """Every string under a known text key (including lists of strings), bounded in depth and count."""
    found: list[str] = []

    def visit(s: str) -> str:
        found.append(s)
        return s

    _walk(body, keys, visit)
    return found


def replace_text_fields(body: Any, replacements: list[str], keys: frozenset[str] = TEXT_KEYS) -> Any:
    """A copy of ``body`` with the strings ``extract_text_fields`` finds replaced, in the same order."""
    it = iter(replacements)
    return _walk(body, keys, lambda s: next(it, s))


def combined_text(fields: list[str]) -> str:
    return "\n".join(fields)
