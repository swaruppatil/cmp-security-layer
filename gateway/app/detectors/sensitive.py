"""Sensitive-data detection and redaction: personal data (PII), payment data, secrets, identifiers.

Each finding is a span in the original text with a ``type`` and a ``category``:

| category   | types                                                                 |
|------------|-----------------------------------------------------------------------|
| pii        | email, phone, sin (Canada), ssn (US), passport, dob                   |
| payment    | card (Luhn-validated), iban (mod-97-validated)                        |
| secret     | aws_access_key, aws_secret_key, github_token, slack_token, stripe_key, google_api_key, jwt, private_key, gateway_api_key, credential_url, password_assignment |
| identifier | booking_ref, ticket, aeroplan — airline identifiers, used by the authorized-data check |

Patterns run in order and earlier ones win overlaps (secrets, then payment, then the rest).
Precision first: numbers are validated (Luhn, mod-97, SSN ranges) and weak patterns (passport, SIN
without separators, booking references, Aeroplan, date of birth) need a context word nearby
("passport", "PNR", "booking", "réservation" …). Everything is local regex work.

``redact`` replaces spans with ``[REDACTED:<type>]``; findings never carry the matched value (only a
type, the field and a short fingerprint), so decisions and logs never repeat the data they found.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

CATEGORIES = ("pii", "payment", "secret", "identifier")
CONTEXT_WINDOW = 40  # characters on either side of a match searched for a context word

# Six-letter words that look like booking references when a customer types in capitals
# ("I NEED A REFUND ON MY BOOKING, PLEASE CANCEL THE TICKET"). Only all-letter candidates are checked.
COMMON_SIX = frozenset(
    """please cancel ticket return refund number flight change search online status before
    thanks booked seated option charge credit cannot should second window middle direct
    flying travel friday sunday monday august within policy wallet points update mobile
    delete person people family mother father client coupon letter answer system prompt
    rebook resend reduce review notice choose select bought tocket urgent though toward
    canada london boston denver dallas ottawa europe mexico havana munich zurich dublin
    merci billet retour numero vol siege dossier avoir enfant client demain lundi mardi jeudi
    samedi besoin chaque encore depuis depart arrive bagage classe simple double""".split()
)
# At most this share of a message may be upper case before an all-letter token needs a digit to count.
SHOUTING_SHARE = 0.6


@dataclass(frozen=True)
class SensitiveFinding:
    type: str
    category: str
    start: int
    end: int
    field: int = 0
    value_hash: str = ""  # sha256 prefix of the normalised value: lets callers compare without seeing it

    def public(self) -> dict[str, object]:
        return {
            "type": self.type,
            "category": self.category,
            "field": self.field,
            "fingerprint": self.value_hash,
        }


# ------------------------------------------------------------------ validators
def luhn(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def iban_ok(value: str) -> bool:
    v = re.sub(r"\s", "", value).upper()
    if not 15 <= len(v) <= 34:
        return False
    rearranged = v[4:] + v[:4]
    number = "".join(str(int(c, 36)) for c in rearranged)
    return int(number) % 97 == 1


def ssn_ok(value: str) -> bool:
    area, group, serial = value[:3], value[4:6], value[7:]
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


def digits_of(value: str) -> str:
    return re.sub(r"\D", "", value)


# ------------------------------------------------------------------ patterns
@dataclass(frozen=True)
class Pattern:
    type: str
    category: str
    regex: re.Pattern[str]
    validate: Callable[[str], bool] | None = None
    context: re.Pattern[str] | None = None  # required nearby word (before or after the match)
    group: int = 0  # which regex group is the sensitive value
    flags: int = 0  # re flags the pattern was compiled with (informational)


def ctx(*words: str) -> re.Pattern[str]:
    return re.compile(r"(?:" + "|".join(words) + r")", re.I)


BOOKING_CTX = ctx(
    r"booking",
    r"reservation",
    r"r[ée]servation",
    r"\bpnr",
    r"confirmation",
    r"reference",
    r"r[ée]f[ée]rence",
    r"record locator",
    r"dossier",
    r"code de r",
)
PATTERNS: list[Pattern] = [
    # --- secrets (checked first: they win overlaps) ---
    Pattern(
        "private_key",
        "secret",
        re.compile(
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
            r"(?:-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----|$)"
        ),
    ),
    Pattern("aws_access_key", "secret", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    Pattern(
        "aws_secret_key",
        "secret",
        re.compile(r"(?i:aws_?secret_?(?:access_?)?key)[\"'\s:=]+([A-Za-z0-9/+=]{40})\b"),
        group=1,
    ),
    Pattern(
        "github_token",
        "secret",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b"),
    ),
    Pattern("slack_token", "secret", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    Pattern("stripe_key", "secret", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    Pattern("google_api_key", "secret", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    Pattern("gateway_api_key", "secret", re.compile(r"\bcmpsk_[0-9a-f]{10}_[A-Za-z0-9_\-]{20,}")),
    Pattern(
        "jwt", "secret", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
    ),
    Pattern(
        "credential_url",
        "secret",
        re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:([^\s:/@]{3,})@[^\s/]+", re.I),
        group=1,
    ),
    Pattern(
        "password_assignment",
        "secret",
        re.compile(
            r"(?i:\b(?:password|passwd|pwd|passcode|mot de passe|secret[_\-\s](?:key|token|code)|client[_\-\s]secret|api[_\-\s]?key|access[_\-\s]?token|auth[_\-\s]?token)"
            r"\s*(?:is|est|=|:)\s*)(?!(?:wrong|incorrect|invalid|expired|rejected|working|correct|missing|"
            r"blocked|locked|unknown|forgotten|required|needed|different|changed|reset|again|still|also|"
            r"always|never|probably|definitely|incorrecte?|invalide|oublie|expire)\b)[\"']?([^\s\"']{6,})"
        ),
        group=1,
    ),
    # --- payment ---
    Pattern(
        "card",
        "payment",
        re.compile(r"(?<![0-9A-Za-z-])(?:\d[ \-]?){12,18}\d(?![0-9A-Za-z-])"),
        validate=lambda v: (
            13 <= len(digits_of(v)) <= 19 and luhn(digits_of(v)) and not digits_of(v).startswith("014")
        ),
    ),  # 014… is an Air Canada ticket, not a card
    Pattern(
        "iban",
        "payment",
        re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"),
        validate=iban_ok,
    ),
    # --- personal data (an Air Canada ticket first: its 13 digits would otherwise read as a phone) ---
    Pattern("ticket", "identifier", re.compile(r"(?<!\d)014[ \-]?\d{10}(?!\d)")),
    Pattern("email", "pii", re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    Pattern("ssn", "pii", re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), validate=ssn_ok),
    Pattern(
        "sin", "pii", re.compile(r"\b\d{3}[ \-]\d{3}[ \-]\d{3}\b"), validate=lambda v: luhn(digits_of(v))
    ),
    Pattern(
        "sin",
        "pii",
        re.compile(r"\b\d{9}\b"),
        validate=lambda v: luhn(v),
        context=ctx(r"\bsin\b", r"\bnas\b", r"social insurance", r"assurance sociale"),
    ),
    Pattern(
        "phone",
        "pii",
        re.compile(
            r"(?<![\w+])(?:\+?1[ .\-]?)?\(?[2-9]\d{2}\)?[ .\-]?[2-9]\d{2}[ .\-]?\d{4}(?![\w])"
            r"|(?<![\w+])\+(?:[2-9]\d{0,2})[ .\-]?\d{1,4}(?:[ .\-]?\d{2,4}){2,4}(?!\w)"
        ),
        validate=lambda v: 10 <= len(digits_of(v)) <= 15,
    ),
    Pattern("passport", "pii", re.compile(r"\b[A-Z]{1,2}\d{6,7}\b"), context=ctx(r"passport", r"passeport")),
    Pattern(
        "dob",
        "pii",
        re.compile(r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}[/.\-]\d{1,2}[/.\-]\d{2,4})\b"),
        context=ctx(
            r"\bdob\b", r"date of birth", r"birth ?date", r"born", r"date de naissance", r"\bn[ée]e? le"
        ),
    ),
    # --- airline identifiers ---
    Pattern(
        "aeroplan",
        "identifier",
        re.compile(r"(?<!\d)\d{3}[ \-]?\d{3}[ \-]?\d{3}(?!\d)"),
        context=ctx(r"aeroplan", r"member(?:ship)? (?:number|no|#)", r"num[ée]ro de membre"),
    ),
    # Case-insensitive: customers type "abc123"; the AI replies "ABC123"; both must compare equal.
    Pattern(
        "booking_ref",
        "identifier",
        re.compile(
            r"(?<![A-Za-z0-9])(?=[A-Za-z0-9]{6}(?![A-Za-z0-9]))(?=[A-Za-z0-9]*[A-Za-z])[A-Za-z0-9]{6}(?![A-Za-z0-9])"
        ),
        validate=lambda v: not re.fullmatch(r"AC\d{1,4}", v, re.I) and v.lower() not in COMMON_SIX,
        context=BOOKING_CTX,
    ),
]


def fingerprint(type_: str, value: str) -> str:
    return hashlib.sha256(f"{type_}:{normalize_value(type_, value)}".encode()).hexdigest()[:12]


def normalize_value(type_: str, value: str) -> str:
    """Canonical form used for scope comparison (the same booking ref typed two ways compares equal)."""
    if type_ == "email":
        return value.strip().lower()
    if type_ in ("phone",):
        d = digits_of(value)
        return d[-10:] if len(d) >= 10 else d
    if type_ in ("card", "ticket", "aeroplan", "sin", "ssn"):
        return digits_of(value)
    return re.sub(r"\s", "", value).upper()


def find(text: str, field: int = 0, types: Iterable[str] | None = None) -> list[SensitiveFinding]:
    """All non-overlapping findings in ``text``. Earlier patterns (secrets) win overlaps."""
    wanted = set(types) if types is not None else None
    taken: list[tuple[int, int]] = []
    out: list[SensitiveFinding] = []
    letters = [c for c in text if c.isalpha()]
    shouting = bool(letters) and sum(c.isupper() for c in letters) / len(letters) >= SHOUTING_SHARE
    for p in PATTERNS:
        if wanted is not None and p.type not in wanted:
            continue
        for m in p.regex.finditer(text):
            start, end = m.span(p.group)
            value = m.group(p.group)
            if p.validate is not None and not p.validate(value):
                continue
            if p.type == "booking_ref" and shouting and value.isalpha():
                continue  # "PLEASE CANCEL THE TICKET": capitals, not references
            if p.context is not None and not (
                p.context.search(text[max(0, m.start() - CONTEXT_WINDOW) : m.start()])
                or p.context.search(text[m.end() : m.end() + CONTEXT_WINDOW])
            ):
                continue
            if any(start < e and s < end for s, e in taken):
                continue
            taken.append((start, end))
            out.append(SensitiveFinding(p.type, p.category, start, end, field, fingerprint(p.type, value)))
    return sorted(out, key=lambda f: f.start)


def values(text: str, findings: list[SensitiveFinding]) -> list[tuple[SensitiveFinding, str]]:
    """(finding, normalised value) pairs — for scope checks only; never logged or returned."""
    return [(f, normalize_value(f.type, text[f.start : f.end])) for f in findings]


def redact(
    text: str, findings: list[SensitiveFinding], only: Callable[[SensitiveFinding], bool] | None = None
) -> str:
    """Replace each selected finding with ``[REDACTED:<type>]``."""
    chosen = [f for f in findings if only is None or only(f)]
    out, last = [], 0
    for f in sorted(chosen, key=lambda x: x.start):
        out.append(text[last : f.start])
        out.append(f"[REDACTED:{f.type}]")
        last = f.end
    out.append(text[last:])
    return "".join(out)


def parse_types(spec: str) -> frozenset[str]:
    """``"card,secret,sin"`` → types; a category name expands to every type in it."""
    names = {s.strip().lower() for s in spec.split(",") if s.strip()}
    out: set[str] = set()
    for p in PATTERNS:
        if p.type in names or p.category in names:
            out.add(p.type)
    return frozenset(out)
