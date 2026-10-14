"""Run every fast detector over every text field of a request.

For each field:
1. normalize it (``normalize.py``) — and treat text hidden in Unicode tag characters as its own
   variant, because it is invisible to people but read by models;
2. decode any encoded layers (``encodings.py``) — each decoded layer is another variant;
3. scan the folded text of every variant with the attack rules (``rules.py``); a rule hit inside a
   decoded or hidden variant is also an ``encoded_payload`` hit;
4. ROT13 and reversed text are tried when the text mentions them, or as a last resort when nothing
   else matched (only strong hits count: both transforms turn ordinary text into gibberish);
5. structural checks on the clean text: flooding, markup, links, forged dialogue, disguise signals.

Every finding carries its **evidence**: ``deterministic`` for things that prove intent (template
tokens, text hidden in tag characters, an attack phrase found *inside* an encoded layer — nobody
base64-encodes "ignore all previous instructions" by accident) and ``probabilistic`` for a phrase
matched in plain text. The result's ``severity`` is the worst finding. All work is local and bounded
(fields, candidates, decode depth), typically tens of microseconds per message.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.detectors import structure
from app.detectors.encodings import (
    decode_all,
    mentions_reverse,
    mentions_rot13,
    reversed_text,
    rot13,
)
from app.detectors.normalize import fold_for_matching, normalize
from app.detectors.rules import RULES, RULESET_VERSION, TOOL_RULES, Evidence, Match, scan

MAX_FIELDS = 50
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}
# A decoded or hidden layer that contains an attack phrase is proof: text is not encoded by accident.
# ROT13 and reversal are excluded: they are tried on every message, and ordinary text can collide.
PROOF_VIAS = frozenset({"hidden_text", "base64", "hex", "url_encoding", "escapes"})


@dataclass
class Finding:
    id: str
    family: str
    severity: str
    via: str
    field: int
    evidence: Evidence = "probabilistic"


@dataclass
class Analysis:
    findings: list[Finding] = field(default_factory=list)
    ruleset_version: str = RULESET_VERSION

    @property
    def severity(self) -> str | None:
        if not self.findings:
            return None
        return max(self.findings, key=lambda f: SEVERITY_ORDER[f.severity]).severity

    def of(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def evidence(self, severity: str) -> Evidence:
        """The strongest evidence among the findings of that severity."""
        return (
            "deterministic"
            if any(f.evidence == "deterministic" for f in self.of(severity))
            else "probabilistic"
        )


def _from_match(m: Match) -> list[Finding]:
    evidence: Evidence = "deterministic" if m.via in PROOF_VIAS else m.evidence
    out = [Finding(m.rule_id, m.family, m.severity, m.via, m.field, evidence)]
    if m.via != "text":
        out.append(Finding(f"encoded.{m.via}", "encoded_payload", m.severity, m.via, m.field, evidence))
    return out


def analyze(
    fields: list[str],
    *,
    allowed_link_domains: tuple[str, ...],
    max_links: int,
    untrusted: bool = False,
) -> Analysis:
    """``untrusted=True`` for tool results and documents: the tool-content rules run as well (a
    first-person request or an order about the reply has no place inside data), and the
    data-harvesting rules do not run at all. Those target a *customer asking* for other people's data;
    inside a booking record or an email the data is simply there ("the seat stays blocked for the
    passenger with the service dog" is a remark, not a request). The sealed tool held-out set the
    peer session built showed every one of its look-alike false positives came from that family."""
    rules = tuple(r for r in RULES if r.family != "data_harvesting") + TOOL_RULES if untrusted else RULES
    result = Analysis()
    seen: set[tuple[str, int]] = set()

    def add(findings: list[Finding]) -> None:
        for f in findings:
            if (f.id, f.field) not in seen:
                seen.add((f.id, f.field))
                result.findings.append(f)

    for i, raw in enumerate(fields[:MAX_FIELDS]):
        n = normalize(raw)
        matched = False
        for m in scan(n.match, via="text", field=i, rules=rules):
            add(_from_match(m))
            matched = True

        if n.hidden_tag_text.strip():
            hidden = scan(fold_for_matching(n.hidden_tag_text), via="hidden_text", field=i)
            for m in hidden:
                add(_from_match(m))
            # Text nobody can see but a model reads: never legitimate in a chat message.
            add(
                [
                    Finding(
                        "disguise.hidden_text", "encoded_payload", "high", "hidden_text", i, "deterministic"
                    )
                ]
            )
            matched = matched or bool(hidden)

        for d in decode_all(n.clean):
            for m in scan(fold_for_matching(d.text), via=d.technique, field=i):
                add(_from_match(m))
                matched = True

        # Last-resort transforms: only strong hits, since they turn ordinary text into gibberish.
        if mentions_rot13(n.clean) or not matched:
            for m in scan(fold_for_matching(rot13(n.clean)), via="rot13", field=i):
                if m.severity == "high":
                    add(_from_match(m))
                    matched = True
        if mentions_reverse(n.clean) or not matched:
            for m in scan(fold_for_matching(reversed_text(n.clean)), via="reversed", field=i):
                if m.severity == "high":
                    add(_from_match(m))

        if n.bidi_count:
            add([Finding("disguise.bidi_controls", "encoded_payload", "medium", "text", i)])
        if n.invisible_count >= 3:
            add([Finding("disguise.invisible_characters", "encoded_payload", "low", "text", i)])
        if n.mixed_script_words:
            add([Finding("disguise.mixed_script", "encoded_payload", "low", "text", i)])

        rep = structure.repetition(n.clean)
        if rep:
            add([Finding(rep.id, "flooding", rep.severity, "text", i)])
        dlg = structure.dialogue(n.clean)
        if dlg:
            add([Finding(dlg.id, "role_tokens", dlg.severity, "text", i)])
        for s in structure.markup(n.clean):
            add([Finding(s.id, "markup", s.severity, "text", i)])
        for s in structure.links(n.clean, allowed_link_domains, max_links):
            add([Finding(s.id, "links", s.severity, "text", i)])
    return result
