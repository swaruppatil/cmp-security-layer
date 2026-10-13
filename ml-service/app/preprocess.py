"""Text preprocessing shared by training and serving, so the model sees text the same way in both.

Mirrors the gateway's ``fold_for_matching`` (NFKC, invisible characters removed, lower case, accents
stripped, look-alike letters and leetspeak folded, spaced-out letters joined). Keeping the two in
step matters: an attacker's disguise should look the same to the rules and to the model.
"""

from __future__ import annotations

import re
import unicodedata

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
LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
SPACED = re.compile(r"(?<![a-z])((?:[a-z][\s.\-_*]){3,}[a-z])(?![a-z])")
# Same, any case (used before lower-casing, by the embedding normaliser).
SPACED_ANY = re.compile(r"(?<![A-Za-z])((?:[A-Za-z][\s.\-_*]){3,}[A-Za-z])(?![A-Za-z])")
WS = re.compile(r"\s+")


def preprocess(text: str) -> str:
    t = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    t = unicodedata.normalize("NFKC", t).casefold().translate(CONFUSABLES)
    t = "".join(c for c in unicodedata.normalize("NFD", t) if unicodedata.category(c) != "Mn")
    t = t.translate(LEET)
    t = SPACED.sub(lambda m: re.sub(r"[\s.\-_*]", "", m.group(1)), t)
    return WS.sub(" ", t).strip()
