"""Attack rules: high-precision patterns over the *folded* text (see ``normalize.fold_for_matching``).

Patterns are written against folded text: lower case, no accents, look-alikes and leetspeak already
undone, so one pattern covers "Ignore", "ＩＧＮＯＲＥ", "1gn0r3", "i g n o r e" and "іgnоrе".

Severity → action (applied by the rules check):
* high   — block, and a **deterministic** strike (feeds ban escalation)
* medium — restrict (the protected app should switch off sensitive actions)
* low    — no action on its own; raises risk and is visible to the ML tier and policies

Precision over recall: a pattern only goes in if real customers would almost never write it.
"Ignore my previous booking" must not match; "ignore all previous instructions" must. The ML tier
exists for everything these patterns miss.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

RULESET_VERSION = "2026-10-12.1"
Severity = Literal["high", "medium", "low"]

# Reusable fragments (folded text: no accents, lower case).
_PRIOR = r"(?:all |any |the |your |my |these |those |every )*(?:previous|prior|above|earlier|preceding|original|initial|system|existing)"
_INSTR = r"(?:instructions?|rules?|directions?|directives?|guidelines?|prompts?|commands?|constraints?|polic(?:y|ies)|programming|context)"
_SYS = r"(?:system|initial|hidden|original|secret|internal|developer|base|first)"
_PROMPT = r"(?:prompt|instructions?|message|rules|configuration|guidelines)"


@dataclass(frozen=True)
class Rule:
    id: str
    family: str
    severity: Severity
    pattern: re.Pattern[str]
    lang: str = "en"


def _r(rule_id: str, family: str, severity: Severity, pattern: str, lang: str = "en") -> Rule:
    return Rule(rule_id, family, severity, re.compile(pattern), lang)


RULES: tuple[Rule, ...] = (
    # ----------------------------------------------------------------- instruction override
    _r(
        "override.ignore_prior",
        "instruction_override",
        "high",
        rf"\b(?:ignore|disregard|forget|skip|bypass|override|drop|discard|abandon|neglect)\s+{_PRIOR}\s+{_INSTR}",
    ),
    _r(
        "override.ignore_everything",
        "instruction_override",
        "high",
        r"\b(?:ignore|disregard|forget|drop|discard|skip|bypass)\s+(?:everything|all)\s+(?:you\s+(?:were|have\s+been)\s+told|(?:said|written)\s+(?:above|before))",
    ),
    _r(
        "override.ignore_your",
        "instruction_override",
        "high",
        r"\b(?:ignore|disregard|forget|bypass|override|drop|discard|skip)\s+(?:all\s+(?:of\s+)?)?your\s+(?:instructions|rules|guidelines|directives|programming|system\s+prompt|prompt|polic(?:y|ies)|constraints|restrictions|training)",
    ),
    _r(
        "override.instructions_above",
        "instruction_override",
        "high",
        r"\b(?:ignore|disregard|forget|bypass|override|drop|discard|skip)\s+(?:all\s+)?(?:the|these|those)\s+(?:instructions|rules|guidelines|directives|prompts?)\s+(?:above|you\s+(?:were|have\s+been)\s+given|before|so\s+far|earlier)",
    ),
    _r(
        "override.new_instructions",
        "instruction_override",
        "high",
        r"\b(?:your|the)\s+new\s+(?:instructions|rules|task|directive)s?\s+(?:are|is)\b",
    ),
    _r(
        "override.from_now_on",
        "instruction_override",
        "medium",
        r"\bfrom\s+now\s+on,?\s+(?:you\s+(?:will|must|are|shall)|ignore|always|never)\b",
    ),
    _r(
        "override.fr_ignore",
        "instruction_override",
        "high",
        r"\b(?:ignore[rsz]?|oublie[rsz]?|ne\s+tiens?\s+pas\s+compte\s+d|ne\s+tenez\s+pas\s+compte\s+d)\w*\s+(?:de\s+|des\s+)?(?:toutes?\s+)?(?:tes|vos|les|ces)\s+(?:instructions|regles|consignes|directives)",
        "fr",
    ),
    _r(
        "override.fr_previous",
        "instruction_override",
        "high",
        r"\b(?:instructions|regles|consignes)\s+(?:precedentes|anterieures|ci-dessus|initiales)\b",
        "fr",
    ),
    # ----------------------------------------------------------------- prompt exfiltration
    _r(
        "exfil.reveal_prompt",
        "prompt_exfiltration",
        "high",
        rf"\b(?:reveal|show|print|repeat|output|display|dump|leak|share|copy|tell\s+me|give\s+me|write\s+out)\s+(?:me\s+)?(?:your|the)\s+(?:{_SYS}\s+)?{_PROMPT}\b"
        rf"(?:(?<=prompt)|(?<=configuration)|\s+(?:verbatim|word\s+for\s+word|you\s+were\s+given|above|in\s+a\s+code\s+block))",
    ),
    # Only "… prompt" and "hidden/secret instructions": customers do say "system message" / "first message".
    _r(
        "exfil.system_prompt",
        "prompt_exfiltration",
        "high",
        r"\b(?:system|hidden|secret|developer|initial|original|internal)\s+prompt\b|\b(?:hidden|secret)\s+(?:instructions|rules)\b",
    ),
    _r(
        "exfil.what_are_your_instructions",
        "prompt_exfiltration",
        "high",
        r"\bwhat\s+(?:are|were|is)\s+your\s+(?:system\s+|initial\s+|original\s+|hidden\s+)?(?:instructions|rules|prompt|directives)\b",
    ),
    _r(
        "exfil.repeat_above",
        "prompt_exfiltration",
        "high",
        r"\brepeat\s+(?:the\s+)?(?:text|words|everything)\s+(?:above|before)|starting\s+with\s+['\"]?you\s+are",
    ),
    _r(
        "exfil.developer_told",
        "prompt_exfiltration",
        "medium",
        r"\bwhat\s+did\s+(?:the\s+)?(?:developers?|creators?|admins?)\s+tell\s+you",
    ),
    _r(
        "exfil.fr_reveal",
        "prompt_exfiltration",
        "high",
        r"\b(?:revele|montre|affiche|donne)[rsz]?(?:-moi)?\s+(?:moi\s+)?(?:ton|tes|votre|vos)\s+(?:prompt|instructions|consignes|regles)(?:\s+(?:systeme|initial|initiales|cachees|cache))?",
        "fr",
    ),
    # ----------------------------------------------------------------- jailbreak / role-play
    _r(
        "jailbreak.dan",
        "jailbreak_roleplay",
        "high",
        r"\bdo\s+anything\s+now\b|\byou\s+are\s+(?:now\s+)?dan\b",
    ),
    _r(
        "jailbreak.developer_mode",
        "jailbreak_roleplay",
        "high",
        r"\b(?:developer|maintenance|debug|god|admin|sudo|jailbreak|unrestricted)\s+mode\b|\bmode\s+(?:developpeur|administrateur)\b",
    ),
    # Tied to the assistant's own behaviour, so "no restrictions on my ticket, can you check" never matches.
    _r(
        "jailbreak.no_restrictions",
        "jailbreak_roleplay",
        "high",
        r"\b(?:answer|respond|reply|act|behave|operate|talk|repond\w*)\s+(?:\w+\s+){0,3}(?:without|with\s+no|sans)\s+(?:any\s+|aucune?\s+)?(?:restrictions?|filters?|limitations?|limits|rules|censorship)"
        r"|\b(?:ai|assistant|bot|model|version\s+of\s+yourself)\s+(?:with\s+no|without|that\s+has\s+no|sans)\s+(?:any\s+)?(?:restrictions?|filters?|limitations?|rules|censorship|content\s+restrictions)"
        r"|\b(?:unrestricted|unfiltered|uncensored|jailbroken)\s+(?:ai|assistant|bot|model|version|persona)"
        r"|\bsans\s+aucune\s+restriction",
    ),
    _r(
        "jailbreak.persona",
        "jailbreak_roleplay",
        "high",
        r"\b(?:pretend|act|roleplay|role-play|behave|imagine)\s+(?:to\s+be\s+|as\s+(?:if\s+you\s+(?:were|are)\s+)?|you\s+are\s+|that\s+you\s+are\s+)(?:an?\s+)?(?:\w+\s+){0,3}(?:ai|assistant|bot|model)\s+(?:with(?:out)?|that|who)\b",
    ),
    _r(
        "jailbreak.employee_admin",
        "jailbreak_roleplay",
        "high",
        r"\b(?:pretend|act|imagine|fais\s+comme\s+si)\b.{0,40}\b(?:employee|employe|staff|agent|admin\w*)\b.{0,30}\b(?:admin\w*|access|acces|override|privileges?)",
    ),
    _r(
        "jailbreak.evil_twin",
        "jailbreak_roleplay",
        "medium",
        r"\b(?:two|2)\s+(?:personas|personalities|responses)\b|\bevil\s*bot\b|\bnever\s+refuses?\b",
    ),
    _r(
        "jailbreak.safety_disabled",
        "jailbreak_roleplay",
        "high",
        r"\b(?:safety|security|content)\s+(?:checks?|filters?|guidelines|policies)\s+(?:are\s+)?(?:disabled|off|removed|lifted)",
    ),
    # ----------------------------------------------------------------- role / template tokens
    _r(
        "tokens.chatml",
        "role_tokens",
        "high",
        r"<\|\s*(?:im_start|im_end|system|user|assistant|endoftext)\s*\|>",
    ),
    _r("tokens.llama", "role_tokens", "high", r"\[/?inst\]|<<\s*/?sys\s*>>|</s>\s*<s>"),
    _r("tokens.xml_role", "role_tokens", "high", r"</?\s*(?:system|assistant|im_start)\s*>"),
    _r(
        "tokens.markdown_role",
        "role_tokens",
        "high",
        r"(?:^|\n)\s*#{2,}\s*(?:system|assistant|instruction)s?\s*:",
    ),
    _r(
        "tokens.fake_turn",
        "role_tokens",
        "medium",
        r"(?:^|\n)\s*(?:system|assistant)\s*:\s*(?:you|the\s+user|sure|ok|new|skip|grant|ignore|override|here\s+is)",
    ),
    # ----------------------------------------------------------------- tool / action manipulation
    _r(
        "tool.call_function",
        "tool_manipulation",
        "high",
        r"\b(?:call|invoke|run|execute|trigger|use)\s+(?:the\s+)?(?:function|tool|api|endpoint)\s+\w*|\b(?:call|invoke|run|execute|trigger)\s+(?:the\s+)?\w+_\w+\s+(?:tool|function)?",
    ),
    _r(
        "tool.set_flag",
        "tool_manipulation",
        "high",
        r"\b(?:set|make|mark)\s+(?:handoff|verified|is_?admin|authenticated|identity_?verified|role)\s*(?:=|to)\s*(?:true|yes|1|admin)",
    ),
    _r(
        "tool.via_api",
        "tool_manipulation",
        "medium",
        r"\b(?:use|via)\s+(?:your|the)\s+(?:api|tools?|backend|database)\s+to\b",
    ),
    # ----------------------------------------------------------------- data harvesting
    _r(
        "harvest.bulk_passengers",
        "data_harvesting",
        "high",
        r"\b(?:list|show|give|dump|export|tell)\s+(?:me\s+)?(?:all|every)\s+(?:the\s+)?(?:other\s+)?(?:passengers?|customers?|travell?ers?|bookings?|pnrs?|reservations?)\b(?!\s+(?:on\s+)?my\b)",
    ),
    _r(
        "harvest.others_contact",
        "data_harvesting",
        "high",
        r"\b(?:email|e-mail|phone\s+numbers?|contact\s+(?:info|details)|addresses?)\s+(?:addresses\s+)?of\s+(?:the\s+)?(?:passengers?|customers?|people|person|everyone)",
    ),
    _r(
        "harvest.export_db",
        "data_harvesting",
        "high",
        r"\b(?:export|dump|download)\s+(?:the\s+)?(?:customer|passenger|user|booking)s?\s+(?:database|db|table|list|data)",
    ),
    _r(
        "harvest.anyone_named",
        "data_harvesting",
        "medium",
        r"\b(?:bookings?|reservations?|pnrs?)\s+(?:for|of|under)\s+(?:anyone|everyone|all\s+passengers|people)\s+(?:named|called|with)",
    ),
    _r(
        "harvest.fr_passengers",
        "data_harvesting",
        "high",
        r"\b(?:liste|affiche|donne|montre)[rsz]?\s+(?:moi\s+)?(?:tous\s+)?(?:les\s+)?(?:passagers|clients|courriels|reservations)\b",
        "fr",
    ),
    # ----------------------------------------------------------------- indirect injection markers
    _r(
        "indirect.note_to_ai",
        "indirect_injection",
        "high",
        r"\b(?:note|message|instruction)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|bot|model|llm)\b",
    ),
    _r(
        "indirect.system_override",
        "indirect_injection",
        "high",
        r"\bsystem\s+override\b|\b(?:assistant|bot|ai)\s+(?:must|shall|is\s+authorized\s+to|is\s+allowed\s+to)\s+(?:approve|share|reveal|grant|waive|comply)",
    ),
    _r(
        "indirect.comply_all",
        "indirect_injection",
        "medium",
        r"\bcomply\s+with\s+(?:all|any|every)\s+requests?\b|\bis\s+an?\s+administrator\b",
    ),
)


@dataclass(frozen=True)
class Match:
    rule_id: str
    family: str
    severity: Severity
    via: str  # "text", "hidden_text", "base64", "hex", "url_encoding", "escapes", "rot13"
    field: int


def scan(folded: str, *, via: str, field: int) -> list[Match]:
    out: list[Match] = []
    for rule in RULES:
        if rule.pattern.search(folded) is not None:
            # No excerpt is kept: matched text may contain personal data and decisions are logged.
            out.append(Match(rule.id, rule.family, rule.severity, via, field))
    return out
