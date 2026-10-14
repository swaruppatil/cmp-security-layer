"""Find and decode encoded payloads so the rules can read what they say.

Decoded: base64 (incl. URL-safe), hex, URL percent-encoding, ``\\uXXXX`` / ``\\xXX`` escapes, ROT13.
Each decoded text is decoded again (max ``MAX_DEPTH`` levels) for payloads wrapped twice.

To avoid flagging ordinary data, a candidate only counts if it decodes to mostly-printable text
with real letters. PNRs ("ABC123"), ticket numbers ("0142345678901") and flight numbers are too
short or contain no hex letters, so they are never treated as encoded.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import urllib.parse
from dataclasses import dataclass

MAX_DEPTH = 2
MAX_CANDIDATES = 20  # per text, so a pathological input cannot make decoding expensive

B64 = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
HEX = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
PERCENT = re.compile(r"(?:%[0-9a-fA-F]{2}){3,}")
ESCAPES = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}){3,}")
ROT13_HINT = re.compile(r"\brot-?13\b", re.IGNORECASE)


@dataclass(frozen=True)
class Decoded:
    technique: str
    text: str
    depth: int


def _printable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    printable = sum(ch.isprintable() or ch in "\n\t" for ch in text) / len(text)
    letters = sum(ch.isalpha() for ch in text)
    if printable < 0.9 or letters < 4 or letters / len(text) < 0.4:
        return None
    return text


def _b64(token: str) -> str | None:
    if not re.search(r"[A-Za-z]", token) or not re.search(r"[0-9+/=_-]|[A-Z].*[a-z]", token):
        return None
    padded = token + "=" * (-len(token) % 4)
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            text = _printable(decode(padded))
        except (binascii.Error, ValueError):
            continue
        if text:
            return text
    return None


def _hex(token: str) -> str | None:
    if not re.search(r"[a-fA-F]", token):  # pure digits: ticket / phone numbers, not hex text
        return None
    try:
        return _printable(bytes.fromhex(token))
    except ValueError:
        return None


def _decode_once(text: str) -> list[Decoded]:
    found: list[Decoded] = []
    for m in list(B64.finditer(text))[:MAX_CANDIDATES]:
        decoded = _b64(m.group(0))
        if decoded:
            found.append(Decoded("base64", decoded, 1))
    for m in list(HEX.finditer(text))[:MAX_CANDIDATES]:
        decoded = _hex(m.group(0))
        if decoded:
            found.append(Decoded("hex", decoded, 1))
    if PERCENT.search(text):
        unquoted = urllib.parse.unquote(text)
        if unquoted != text:
            found.append(Decoded("url_encoding", unquoted, 1))
    for m in list(ESCAPES.finditer(text))[:MAX_CANDIDATES]:
        try:
            decoded = codecs.decode(m.group(0), "unicode_escape")
        except (UnicodeDecodeError, ValueError):
            continue
        if decoded:
            found.append(Decoded("escapes", decoded, 1))
    return found


def decode_all(text: str) -> list[Decoded]:
    """Every decoded layer found in ``text`` (up to MAX_DEPTH)."""
    results: list[Decoded] = []
    frontier = [(text, 0)]
    while frontier:
        current, depth = frontier.pop()
        if depth >= MAX_DEPTH:
            continue
        for d in _decode_once(current):
            layer = Decoded(d.technique, d.text, depth + 1)
            results.append(layer)
            frontier.append((d.text, depth + 1))
        if len(results) >= MAX_CANDIDATES:
            break
    return results


def rot13(text: str) -> str:
    return codecs.encode(text, "rot13")


def reversed_text(text: str) -> str:
    """The text read backwards ("snoitcurtsni suoiverp lla erongi"); tried like ROT13, as a last resort."""
    return text[::-1]


REVERSE_HINT = re.compile(r"\b(?:backwards?|reversed?|in\s+reverse|mirror(?:ed)?)\b", re.IGNORECASE)


def mentions_reverse(text: str) -> bool:
    return bool(REVERSE_HINT.search(text))


def mentions_rot13(text: str) -> bool:
    return bool(ROT13_HINT.search(text))
