"""Text normalization: undo the disguises attackers use so the rules see what the model would see.

Produces two forms of a text:
* ``clean`` — NFKC-normalized, invisible characters removed. What a human would read.
* ``match`` — ``clean``, lower-cased, accents removed, look-alike letters folded to Latin, leetspeak
  digits folded, spaced-out words joined ("i g n o r e" → "ignore"), whitespace collapsed. Only
  used for pattern matching; never shown or stored.

It also reports what it found (invisible characters, bidi controls, mixed scripts) because the
disguise itself is a signal, and recovers text hidden in Unicode *tag characters* (U+E0000–E007F):
those render as nothing on screen but spell out ASCII that an LLM reads.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field

# Bidi controls (embedding / override / isolate) — used to reorder text so it reads differently.
BIDI = frozenset("‪‫‬‭‮⁦⁧⁨⁩‎‏؜")
# Zero-width and other invisible formatting characters.
ZERO_WIDTH = frozenset("​‌‍⁠⁡⁢⁣⁤﻿­᠎")
TAG_START, TAG_END = 0xE0000, 0xE007F

# Cyrillic / Greek letters that look like Latin ones.
CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "ԁ": "d",
        "ɡ": "g",
        "һ": "h",
        "ӏ": "l",
        "ո": "n",
        "ս": "u",
        "к": "k",
        "м": "m",
        "т": "t",
        "в": "b",
        "н": "h",
        "ѡ": "w",
        "ԛ": "q",
        "α": "a",
        "ε": "e",
        "ι": "i",
        "κ": "k",
        "ν": "v",
        "ο": "o",
        "ρ": "p",
        "τ": "t",
        "υ": "u",
        "χ": "x",
        "ω": "w",
    }
)
LEET = str.maketrans(
    {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"}
)

# Four or more single letters separated by a space/dot/dash/underscore/asterisk: "i g n o r e".
SPACED = re.compile(r"(?<![a-z])((?:[a-z][\s.\-_*]){3,}[a-z])(?![a-z])")
WS = re.compile(r"\s+")
LATIN_WORD = re.compile(r"[^\W\d_]+")


@dataclass
class Normalized:
    original: str
    clean: str
    match: str
    hidden_tag_text: str = ""
    invisible_count: int = 0
    bidi_count: int = 0
    tag_char_count: int = 0
    mixed_script_words: int = 0
    changed: bool = False
    notes: list[str] = field(default_factory=list)


def _script(ch: str) -> str:
    name = unicodedata.name(ch, "")
    for script in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(script):
            return script
    return "OTHER"


def _mixed_script_words(text: str) -> int:
    count = 0
    for word in LATIN_WORD.findall(text):
        scripts = {_script(c) for c in word if c.isalpha()} - {"OTHER"}
        if len(scripts) > 1:
            count += 1
    return count


def fold_for_matching(text: str) -> str:
    """Lowercase, strip accents, fold look-alikes and leetspeak, join spaced letters, collapse spaces."""
    t = text.casefold().translate(CONFUSABLES)
    t = "".join(c for c in unicodedata.normalize("NFD", t) if unicodedata.category(c) != "Mn")
    t = t.translate(LEET)
    t = SPACED.sub(lambda m: re.sub(r"[\s.\-_*]", "", m.group(1)), t)
    return WS.sub(" ", t).strip()


def normalize(text: str) -> Normalized:
    invisible = bidi = tags = 0
    hidden: list[str] = []
    kept: list[str] = []
    for ch in text:
        cp = ord(ch)
        if TAG_START <= cp <= TAG_END:
            tags += 1
            if 0xE0020 <= cp <= 0xE007E:  # tag versions of printable ASCII
                hidden.append(chr(cp - TAG_START))
            continue
        if ch in BIDI:
            bidi += 1
            continue
        if ch in ZERO_WIDTH or (unicodedata.category(ch) == "Cf" and ch not in "\n\t"):
            invisible += 1
            continue
        kept.append(ch)
    clean = unicodedata.normalize("NFKC", "".join(kept))
    mixed = _mixed_script_words(clean)
    result = Normalized(
        original=text,
        clean=clean,
        match=fold_for_matching(clean),
        hidden_tag_text="".join(hidden),
        invisible_count=invisible,
        bidi_count=bidi,
        tag_char_count=tags,
        mixed_script_words=mixed,
        changed=clean != text,
    )
    if tags:
        result.notes.append("tag_characters")
    if bidi:
        result.notes.append("bidi_controls")
    if invisible:
        result.notes.append("invisible_characters")
    if mixed:
        result.notes.append("mixed_script_words")
    return result
