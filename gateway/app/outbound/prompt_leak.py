"""Protected prompts: detect a leaked system prompt by its *content*, not only by a canary.

A canary token catches a leak only when the model repeats the marker. Models coaxed into revealing
their instructions often paraphrase lightly, translate, or skip the marker line. So an admin can also
register the prompt itself (``POST /admin/protected-prompts``): the gateway folds it, cuts it into
overlapping 8-word shingles and stores only their SHA-256 hashes — the prompt text never lands in the
database. A reply whose folded text shares at least ``PROMPT_LEAK_MIN_SHINGLES`` shingles with a
registered prompt has leaked it: the reply is blocked and the leak is deterministic evidence (eight
consecutive words of a confidential prompt do not appear in a reply by chance).

Register every language variant the AI might be asked to translate into (the French prompt too) and
re-register after editing the prompt; revoking the old entry stops its shingles from matching.
"""

from __future__ import annotations

import hashlib
import re
import time
from typing import Any

from app.detectors.normalize import normalize

SHINGLE_WORDS = 8
WORD = re.compile(r"[a-z0-9]+")
# Lines that are the gateway's own marker are not part of the prompt's secret content.
CANARY_LINE = re.compile(r"cmpcanary[_\s-]?[0-9a-f]*", re.I)


def words_of(text: str) -> list[str]:
    folded = normalize(CANARY_LINE.sub(" ", text)).match
    return WORD.findall(folded)


def shingle_hashes(text: str, n: int = SHINGLE_WORDS) -> set[str]:
    """Hashes of every run of ``n`` consecutive folded words (a short prompt yields one shingle)."""
    words = words_of(text)
    if not words:
        return set()
    if len(words) <= n:
        return {hashlib.sha256(" ".join(words).encode()).hexdigest()}
    return {
        hashlib.sha256(" ".join(words[i : i + n]).encode()).hexdigest() for i in range(len(words) - n + 1)
    }


class PromptLeakService:
    """Active prompt shingles, cached for ``ttl_seconds`` (revocation takes up to that long)."""

    def __init__(self, repo: Any, ttl_seconds: float = 30.0) -> None:
        self._repo = repo
        self._ttl = ttl_seconds
        self._cache: tuple[float, dict[str, str]] | None = None  # shingle hash → prompt id

    async def active(self) -> dict[str, str]:
        now = time.monotonic()
        if self._cache is not None and self._cache[0] > now:
            return self._cache[1]
        index: dict[str, str] = {}
        for row in await self._repo.active_prompt_shingles():
            for h in row["shingles"]:
                index[h] = str(row["id"])
        self._cache = (now + self._ttl, index)
        return index

    def invalidate(self) -> None:
        self._cache = None

    async def register(self, label: str, text: str) -> dict[str, Any]:
        hashes = sorted(shingle_hashes(text))
        created = await self._repo.create_protected_prompt(label, hashes, len(words_of(text)))
        row: dict[str, Any] = dict(created)
        self.invalidate()
        return row

    async def matches(self, reply: str) -> dict[str, int]:
        """Prompt id → number of shared shingles, for every registered prompt the reply overlaps."""
        index = await self.active()
        if not index:
            return {}
        hits: dict[str, int] = {}
        for h in shingle_hashes(reply):
            pid = index.get(h)
            if pid is not None:
                hits[pid] = hits.get(pid, 0) + 1
        return hits
