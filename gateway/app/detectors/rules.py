"""Attack rules: high-precision patterns over the *folded* text (see ``normalize.fold_for_matching``).

Patterns are written against folded text: lower case, no accents, look-alikes and leetspeak already
undone, so one pattern covers "Ignore", "ＩＧＮＯＲＥ", "1gn0r3", "i g n o r e" and "іgnоrе".

Severity → action (applied by the rules check):
* high   — block; a strike whose kind is the rule's **evidence**
* medium — restrict (the protected app should switch off sensitive actions)
* low    — no action on its own; raises risk and is visible to the ML tier and policies

Evidence. A rule is **deterministic** only when matching it proves intent beyond doubt: model
template tokens, a role object in JSON. Every *phrase* rule is **probabilistic**: a regex over customer
language is strong evidence, not proof, so a phrase match blocks the message but counts as a strike
only when the ML tier agrees (see ``pipeline/checks.py``), and never leads to a permanent ban on its own.

Precision over recall: a pattern only goes in if real customers would almost never write it. Every
pattern that names the assistant's instructions, rules or data must say *whose*: "ignore all previous
instructions" matches, "ignore my previous message" and "what are your rules for pets" must not. The
hard-negative corpus in ``tests/unit/test_hard_negatives.py`` is the contract; add a line there before
loosening a rule. The ML tier exists for everything these patterns miss.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

RULESET_VERSION = "2026-10-14.2"
Severity = Literal["high", "medium", "low"]
Evidence = Literal["deterministic", "probabilistic"]

# Reusable fragments (folded text: no accents, lower case). "my"/"our" is deliberately absent from the
# possessives: the assistant's instructions, never the customer's own.
_PRIOR = r"(?:all |any |the |your |these |those |every |its |of )*(?:previous|prior|above|earlier|preceding|original|initial|system|existing|current|standing)"
_INSTR = r"(?:instructions?|rules?|directions?|directives?|guidelines?|guidance|prompts?|commands?|constraints?|polic(?:y|ies)|programming|context|configuration)"
_SYS = r"(?:system|initial|hidden|original|secret|internal|developer|base|first|meta|master)"
# "for/on/about …" after the noun means a topic ("rules for pets"), not the assistant's own rules.
_NOT_TOPIC = (
    r"(?!\s+(?:for|on|about|regarding|concerning|around|when|if|with|as|at|during|in)\b(?!\s+(?:me|us)\b))"
)
# A flight number *after folding*: the leetspeak fold turns digits 0/1/3/4/5/7 into o/i/e/a/s/t.
_FLIGHT = r"ac\s?[0-9ioeast]{1,4}\b"
# Nothing in the rest of the sentence says it is the customer's own thing.
_NOT_MINE = r"(?![^.?!\n]{0,40}\b(?:my|our|mine|ours)\b)"


@dataclass(frozen=True)
class Rule:
    id: str
    family: str
    severity: Severity
    pattern: re.Pattern[str]
    lang: str = "en"
    evidence: Evidence = "probabilistic"


def _r(
    rule_id: str,
    family: str,
    severity: Severity,
    pattern: str,
    lang: str = "en",
    evidence: Evidence = "probabilistic",
) -> Rule:
    return Rule(rule_id, family, severity, re.compile(pattern), lang, evidence)


def _det(rule_id: str, family: str, severity: Severity, pattern: str, lang: str = "en") -> Rule:
    return _r(rule_id, family, severity, pattern, lang, "deterministic")


RULES: tuple[Rule, ...] = (
    # ----------------------------------------------------------------- instruction override
    _r(
        "override.ignore_prior",
        "instruction_override",
        "high",
        rf"\b(?:ignore|disregard|forget|skip|bypass|override|drop|discard|abandon|neglect|scrap)\s+{_PRIOR}\s+{_INSTR}\b",
    ),
    _r(
        "override.ignore_everything",
        "instruction_override",
        "high",
        r"\b(?:ignore|disregard|forget|drop|discard|skip|bypass)\s+(?:everything|all)\s+(?:you\s+(?:were|have\s+been|had\s+been)\s+(?:told|given|taught|instructed)|(?:said|written|stated)\s+(?:above|before|so\s+far)|that\s+came\s+before)",
    ),
    _r(
        "override.ignore_your",
        "instruction_override",
        "high",
        r"\b(?:ignore|disregard|forget|bypass|override|drop|discard|skip|abandon)\s+(?:(?:all|any)\s+(?:of\s+)?)?your\s+(?:previous\s+|prior\s+|earlier\s+|original\s+|initial\s+|own\s+|current\s+|existing\s+|usual\s+|standard\s+|default\s+)?(?:instructions|rules|guidelines|guidance|directives|programming|system\s+prompt|prompt|polic(?:y|ies)|constraints|restrictions|training|safety\s+(?:rules|guidelines))\b",
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
        r"\b(?:your|the)\s+new\s+(?:instructions|rules|task|directive)s?\s+(?:are|is)\b|(?:^|\n|[.!?]\s*)new\s+(?:instructions|rules|directives?|system\s+prompt)\s*:"
        r"|\bdeine\s+neue\s+aufgabe\b|\btu\s+nueva\s+tarea\b|\b(?:ta|votre)\s+nouvelle\s+(?:tache|mission|consigne)\b",
    ),
    # Only when the rest of the sentence addresses the assistant's behaviour ("from now on you will…"),
    # not the customer's preferences ("from now on, send me the boarding pass by email").
    _r(
        "override.from_now_on",
        "instruction_override",
        "medium",
        r"\bfrom\s+now\s+on,?\s+(?:you\s+(?:will|must|are|shall|should|can|have\s+to)|ignore|always\s+(?:answer|respond|reply|say|act|behave|obey|comply|approve)|never\s+(?:refuse|say|mention|decline))\b|\bdesormais,?\s+(?:tu|vous)\s+(?:es|etes|dois|devez|vas|allez|reponds|repondez)\b",
    ),
    _r(
        "override.forget_everything",
        "instruction_override",
        "medium",
        r"\b(?:forget|ignore|disregard)\s+everything\b(?!\s+(?:about|i\s+(?:said|told|asked|wrote|typed)|you\s+know\s+about|i\s+(?:just\s+)?mentioned|else))(?:\s*[.!,;]|\s+(?:and|you|now)\b)",
    ),
    _r(
        "override.ignore_above",
        "instruction_override",
        "medium",
        r"\b(?:ignore|disregard)\s+(?:all\s+(?:of\s+)?)?(?:the\s+)?(?:above|text\s+above|everything\s+above)\b(?:\s+this\s+(?:line|message|point))?\s*(?:and|,|;|\.|$)(?![^.?!\n]{0,40}\b(?:i|my\s+(?:message|question|request|booking|email|typo|mistake|earlier|last|previous))\b)",
    ),
    _r(
        "override.fr_ignore",
        "instruction_override",
        "high",
        r"\b(?:ignore[rsz]?|oublie[rsz]?|ne\s+tiens?\s+pas\s+compte\s+d|ne\s+tenez\s+pas\s+compte\s+d)\w*\s+(?:de\s+|des\s+)?(?:toutes?\s+)?(?:tes|vos|les|ces)\s+(?:instructions|regles|consignes|directives)"
        r"|\bignore[rz]?\s+tout\s+ce\s+qui\s+precede\b|\boublie[rz]?\s+(?:la\s+|ta\s+|votre\s+)?(?:politique|tes\s+regles|vos\s+regles)\b",
        "fr",
    ),
    _r(
        "override.fr_previous",
        "instruction_override",
        "high",
        r"\b(?:instructions|regles|consignes)\s+(?:precedentes|anterieures|ci-dessus|initiales)\b",
        "fr",
    ),
    _r(
        "override.de_ignore",
        "instruction_override",
        "high",
        r"\b(?:ignorier\w*|vergiss|vergessen\s+sie|missachte\w*|uberspring\w*|verwirf)\s+(?:alle\s+|deine\s+|die\s+|ihre\s+|samtliche\s+|bitte\s+)*(?:bisherigen\s+|vorherigen\s+|fruheren\s+|obigen\s+|vorigen\s+|alten\s+)?(?:anweisungen|regeln|instruktionen|vorgaben|richtlinien|system[\s-]?prompt)\b",
        "de",
    ),
    _r(
        "override.es_ignore",
        "instruction_override",
        "high",
        r"\b(?:ignora|ignore|ignorar|olvida|olvide|olvidar|omite|descarta|haz\s+caso\s+omiso\s+de)\s+(?:todas?\s+|tus\s+|las\s+|sus\s+|cualquier\s+|por\s+favor\s+)*(?:instrucciones|reglas|indicaciones|directrices|prompt\s+del\s+sistema)\b",
        "es",
    ),
    _r(
        "override.pt_ignore",
        "instruction_override",
        "high",
        r"\b(?:ignore|ignora|ignorar|esqueca|esquece|esquecer|desconsidere|desconsidera)\s+(?:todas?\s+|as\s+|suas\s+|tuas\s+|quaisquer\s+)*(?:instrucoes|regras|diretrizes|prompt\s+do\s+sistema)\b",
        "pt",
    ),
    _r(
        "override.it_ignore",
        "instruction_override",
        "high",
        r"\b(?:ignora|ignorare|dimentica|dimenticare|trascura)\s+(?:tutte\s+|le\s+|tue\s+|qualsiasi\s+)*(?:istruzioni|regole|direttive|prompt\s+di\s+sistema)\b",
        "it",
    ),
    _r(
        "override.zh_ignore",
        "instruction_override",
        "high",
        r"(?:忽略|无视|忘记|忘掉|不要理会)(?:之前|以上|上面|先前|所有|全部|你的|您的)*的?(?:所有|全部)?(?:指令|指示|规则|規則|提示|设定|設定)",
        "zh",
    ),
    _r(
        "override.ar_ignore",
        "instruction_override",
        "high",
        r"(?:تجاهل|انسى|انس|اهمل)\s+(?:جميع\s+|كل\s+)?(?:التعليمات|القواعد|الأوامر|الاوامر)",
        "ar",
    ),
    # ----------------------------------------------------------------- prompt exfiltration
    # The assistant's *own* configuration: "prompt"/"configuration" always; "instructions/rules" only
    # with a system word before or a verbatim-style qualifier after. "Show me the rules above about
    # baggage" and "repeat the fare rules" do not match.
    _r(
        "exfil.reveal_prompt",
        "prompt_exfiltration",
        "high",
        rf"\b(?:reveal|show|print|repeat|output|display|dump|leak|share|copy|tell\s+me|give\s+me|write\s+out|recite|read\s+out|paste|summari[sz]e|paraphrase|translate|encode|list)\s+(?:me\s+)?(?:all\s+(?:of\s+)?)?(?:your|the)\s+"
        rf"(?:(?:{_SYS}\s+)?(?:prompt|configuration|directives|system\s+message)\b"
        rf"|{_SYS}\s+(?:instructions|rules|guidelines)\b"
        rf"|(?:system|hidden|secret|internal|developer|master|meta)\s+(?:message|text)\b"
        rf"|(?:instructions|rules|guidelines)\s+(?:verbatim|word\s+for\s+word|you\s+(?:were|have\s+been)\s+given|you\s+follow|exactly|in\s+full|in\s+a\s+code\s+block|from\s+the\s+start|you\s+were\s+configured\s+with|as\s+written|into\s+(?:french|english|spanish|german)|in\s+base64))",
    ),
    _r(
        "exfil.your_instructions",
        "prompt_exfiltration",
        "medium",
        rf"\b(?:reveal|show|print|output|display|dump|leak|share|recite|summari[sz]e|paraphrase|list|repeat|describe|explain)\s+(?:me\s+)?(?:all\s+(?:of\s+)?)?your\s+(?:own\s+|full\s+|exact\s+|complete\s+)?(?:instructions|rules|guidelines|directives|configuration)\b{_NOT_TOPIC}",
    ),
    # Only "… prompt" and "hidden/secret instructions": customers do say "system message" / "first message".
    _r(
        "exfil.system_prompt",
        "prompt_exfiltration",
        "high",
        r"\b(?:system|hidden|secret|developer|initial|original|internal|master|meta)\s+prompt\b|\b(?:hidden|secret)\s+(?:instructions|rules|directives)\b",
    ),
    _r(
        "exfil.what_are_your_instructions",
        "prompt_exfiltration",
        "high",
        rf"\bwhat\s+(?:are|were|is|was)\s+(?:all\s+)?your\s+(?:system\s+|initial\s+|original\s+|hidden\s+|exact\s+|full\s+)?(?:instructions|rules|prompt|directives|configuration)\b{_NOT_TOPIC}(?!\?\s*(?:i\s+mean|like))",
    ),
    _r(
        "exfil.told_to",
        "prompt_exfiltration",
        "medium",
        r"\bwhat\s+(?:were|are|have)\s+you\s+(?:been\s+)?(?:told|instructed|programmed|configured|trained|asked|forbidden|prohibited)\s+(?:not\s+)?to\b|\b(?:what|which)\s+(?:topics?|things?|subjects?|questions?)\s+(?:are|were)\s+you\s+(?:forbidden|not\s+allowed|prohibited|banned|restricted|told\s+not)\b",
    ),
    _r(
        "exfil.repeat_above",
        "prompt_exfiltration",
        "high",
        r"\brepeat\s+(?:the\s+)?(?:text|words|everything)\s+(?:above|before)\s+(?:verbatim|word\s+for\s+word|exactly|in\s+full|starting\s+with)|\bstarting\s+with\s+['\"]?you\s+are\b|\b(?:print|output|repeat|show)\s+everything\s+(?:above|before)\s+(?:this\s+(?:line|message|point)|here|the\s+word)|\b(?:output|print|show)\s+(?:all\s+)?(?:the\s+)?text\s+(?:before|above|preceding)\s+(?:the\s+word|this|user)",
    ),
    _r(
        "exfil.repeat_above_soft",
        "prompt_exfiltration",
        "low",
        r"\brepeat\s+(?:the\s+)?(?:text|words|everything)\s+(?:above|before)\b",
    ),
    _r(
        "exfil.complete_prefix",
        "prompt_exfiltration",
        "high",
        r"\b(?:complete|finish|continue)\s+(?:the|this)\s+(?:sentence|text|phrase|line)\b.{0,30}['\"]?(?:you\s+are|the\s+assistant\s+must)\b|\bwhat\s+comes\s+(?:right\s+)?(?:after|before|next)\b.{0,30}['\"](?:you\s+are|user)['\"]|\b(?:first|opening)\s+(?:sentence|line|words?|paragraph)\s+(?:you\s+were\s+given|of\s+your\s+(?:prompt|instructions|configuration)|before\s+this\s+chat)",
    ),
    _r(
        "exfil.fiction_framing",
        "prompt_exfiltration",
        "medium",
        r"\b(?:hypothetically|in\s+a\s+(?:story|novel|screenplay|play|movie|script|scene)|for\s+(?:a|my)\s+(?:story|novel|screenplay|script|book)|imagine\s+(?:that\s+)?you\s+(?:could|had\s+to|were\s+allowed|were\s+free)|my\s+(?:late\s+)?grand(?:mother|father|ma|pa)|pretend\s+(?:that\s+)?(?:you|the\s+(?:ai|assistant|bot))|if\s+you\s+(?:were|could|had)\s+(?:to\s+)?)\b.{0,80}\b(?:reveal|read(?:s|ing)?(?:\s+(?:out|me))?|print|recite|describe|explain|share|leak|recites?|reads?\s+out|tell)\b.{0,40}\b(?:instructions|configuration|prompt|rules|guidelines)\b",
    ),
    _r(
        "exfil.opening_message",
        "prompt_exfiltration",
        "medium",
        r"\b(?:reply\s+with|repeat|show|send|print|paste)\s+(?:me\s+)?(?:your|the)\s+(?:opening|very\s+first|first|initial)\s+(?:message|text|words|lines?)\b\s*(?:,\s*)?(?:the\s+one\s+before|you\s+(?:were\s+given|got|received)|before\s+(?:this\s+)?(?:chat|conversation|we)|that\s+set\s+you\s+up)|\b(?:message|text)\s+(?:you\s+(?:got|received|were\s+given)\s+)?before\s+i\s+(?:said|typed|wrote)\s+(?:hello|hi|anything)\b"
        r"|\bwhat\s+(?:were|are)\s+you\s+(?:asked|told|instructed)\s+(?:never\s+)?(?:not\s+)?to\s+(?:tell|say|mention|reveal|share)\b(?:\s+(?:to\s+)?(?:customers|users|people|me))?"
        r"|\bce\s+qu'?on\s+t'?a\s+(?:demande|dit|interdit)\s+de\s+(?:ne\s+)?(?:jamais\s+)?(?:pas\s+)?(?:dire|reveler|mentionner)|\b(?:ton|votre)\s+(?:premier|tout\s+premier)\s+message\b",
    ),
    _r(
        "exfil.developer_told",
        "prompt_exfiltration",
        "medium",
        r"\bwhat\s+did\s+(?:the\s+)?(?:developers?|creators?|admins?|programmers?)\s+tell\s+you",
    ),
    _r(
        "exfil.fr_reveal",
        "prompt_exfiltration",
        "high",
        r"\b(?:revele|montre|affiche|donne)[rsz]?(?:-moi)?\s+(?:moi\s+)?(?:ton|tes|votre|vos)\s+(?:prompt|instructions|consignes|regles)(?:\s+(?:systeme|initial|initiales|cachees|cache))?",
        "fr",
    ),
    _r(
        "exfil.multi_reveal",
        "prompt_exfiltration",
        "high",
        r"\b(?:zeig|zeige|zeigen\s+sie)\s+(?:mir\s+)?(?:deinen|ihren|den)\s+system[\s-]?prompt|\bmuestra(?:me)?\s+(?:tus\s+instrucciones|tu\s+prompt)|\bmostr[ae]\s+(?:suas\s+instrucoes|seu\s+prompt)|(?:显示|告诉我|输出)(?:你的|您的)?(?:系统提示|隐藏指令|隱藏指令|系統提示|初始指令)",
        "multi",
    ),
    # ----------------------------------------------------------------- jailbreak / role-play
    _r(
        "jailbreak.dan",
        "jailbreak_roleplay",
        "high",
        r"\bdo\s+anything\s+now\b|\byou\s+are\s+(?:now\s+)?dan\b|\b(?:enable|activate|enter|turn\s+on|switch\s+to|start|engage)\s+dan\b|\bdan\s+mode\b",
    ),
    # Only when the assistant is told to *enter* the mode: a customer's phone can be in developer mode.
    _r(
        "jailbreak.developer_mode",
        "jailbreak_roleplay",
        "high",
        r"\b(?:enable|enter|activate|switch\s+(?:in)?to|turn\s+on|go\s+into|unlock|start|engage|you\s+are\s+(?:now\s+)?in|you\s+are\s+now|you're\s+(?:now\s+)?in|we\s+are\s+(?:now\s+)?in|put\s+yourself\s+in(?:to)?|boot\s+into)\s+(?:the\s+|a\s+|your\s+)?(?:developer|maintenance|debug|god|admin|sudo|jailbreak|unrestricted|unfiltered|dev|uncensored|root)\s+mode\b|\b(?:developer|unrestricted|jailbreak|god)\s+mode\s+(?:is\s+)?(?:enabled|activated|on|unlocked)\b|\b(?:active|activer|passe\s+en)\s+(?:le\s+)?mode\s+(?:developpeur|administrateur|debug)\b",
    ),
    # Tied to the assistant's own behaviour, so "no restrictions on my ticket, can you check" never matches.
    _r(
        "jailbreak.no_restrictions",
        "jailbreak_roleplay",
        "high",
        r"\b(?:answer|respond|reply|act|behave|operate|talk|repond\w*)\s+(?:\w+\s+){0,3}(?:without|with\s+no|sans)\s+(?:any\s+|aucune?\s+)?(?:restrictions?|filters?|limitations?|limits|rules|censorship)"
        r"|\b(?:ai|assistant|bot|model|version\s+of\s+yourself)\s+(?:with\s+no|without|that\s+has\s+no|sans)\s+(?:any\s+)?(?:restrictions?|filters?|limitations?|rules|censorship|content\s+restrictions|polic(?:y|ies))"
        r"|\b(?:unrestricted|unfiltered|uncensored|jailbroken)\s+(?:ai|assistant|bot|model|version|persona|mode)"
        r"|\bsans\s+aucune\s+restriction|\byour\s+restrictions\s+(?:are|were|have\s+been)\s+(?:lifted|removed|disabled|off)",
    ),
    _r(
        "jailbreak.persona",
        "jailbreak_roleplay",
        "high",
        r"\b(?:pretend|act|roleplay|role-play|behave|imagine)\s+(?:to\s+be\s+|as\s+(?:if\s+you\s+(?:were|are)\s+)?|you\s+are\s+|that\s+you\s+are\s+)(?:an?\s+)?(?:\w+\s+){0,3}(?:ai|assistant|bot|model)\s+(?:with(?:out)?|that|who)\b",
    ),
    # The assistant playing staff with power; never "can I act as the agent for my mother's booking".
    _r(
        "jailbreak.employee_admin",
        "jailbreak_roleplay",
        "high",
        r"\b(?:pretend|act|imagine|behave|roleplay|role-play|you\s+are\s+now|be|fais\s+comme\s+si)\s+(?:to\s+be\s+|as\s+(?:if\s+you\s+(?:were|are)\s+)?|you\s+are\s+|that\s+you\s+are\s+|you're\s+|like\s+|que\s+tu\s+es\s+|comme\s+)?(?:an?\s+|the\s+|un\s+|une\s+)?(?:\w+\s+){0,3}(?:employee|employe|staff|supervisor|superviseur|manager|gestionnaire|station\s+manager|admin\w*|agent\s+with|team\s+lead|fraud\s+team)\b"
        r"(?![^.?!\n]{0,40}\b(?:for\s+my|on\s+behalf|my\s+(?:mother|father|wife|husband|son|daughter|parents|company|boss|friend))\b)"
        r".{0,40}\b(?:admin\w*|access|acces|override|privileges?|authority|authori[sz]e\w*|approve|waive|refund|cancel|read\s+me|details)",
    ),
    _r(
        "jailbreak.you_are_now",
        "jailbreak_roleplay",
        "medium",
        r"\byou\s+are\s+(?:now|no\s+longer)\s+(?:an?\s+)?(?!(?:talking|speaking|chatting|connected|helping|the\s+(?:only|first|second|third|fourth|fifth|last|next|same|\d+\w*)|on\s|in\s+(?:the\s+)?(?:queue|line)|able|free\s+to\s+go|booked|checked|confirmed|eligible|entitled|registered|all\s+set))(?:\w+\s+){0,2}(?:ai|assistant|bot|model|persona|character|pirate|expert|manager|supervisor|agent|employee|chatgpt|gpt|claude|gemini|llama)\b|\byou\s+are\s+(?:chatgpt|gpt-?\d|claude|gemini|llama|not\s+(?:an?\s+)?(?:airline|air\s+canada|customer\s+service)\s+(?:bot|assistant))\b",
    ),
    _r(
        "jailbreak.evil_twin",
        "jailbreak_roleplay",
        "medium",
        r"\b(?:answer|respond|reply|give(?:\s+me)?|write)\s+(?:in|with|as|using)\s+(?:two|2)\s+(?:different\s+)?(?:personas|personalities|responses|ways|modes|voices)\b|\bevil\s*bot\b|\b(?:who|that|which)\s+never\s+refuses?\b|\bnever\s+refuses?\s+(?:any|a)\s+request|\balways\s+says?\s+yes\b",
    ),
    _r(
        "jailbreak.opposite",
        "jailbreak_roleplay",
        "medium",
        r"\b(?:answer|do|say|respond\s+with)\s+the\s+opposite\s+of\s+(?:what\s+)?your\s+(?:rules|instructions|guidelines|training)\b",
    ),
    _r(
        "jailbreak.safety_disabled",
        "jailbreak_roleplay",
        "high",
        r"\b(?:safety|security|content)\s+(?:checks?|filters?|guidelines|policies)\s+(?:are\s+|have\s+been\s+)?(?:disabled|off|removed|lifted|suspended|don't\s+apply|do\s+not\s+apply)",
    ),
    # ----------------------------------------------------------------- role / template tokens
    _det(
        "tokens.chatml",
        "role_tokens",
        "high",
        r"<\|\s*(?:im_start|im_end|system|user|assistant|endoftext|start_header_id|end_header_id|eot_id|begin_of_text|end_of_text|end|eos|bos|pad)\s*\|>|<\|\s*(?:begin|end)▁of▁sentence\s*\|>",
    ),
    _det("tokens.llama", "role_tokens", "high", r"\[/?inst\]|<<\s*/?sys\s*>>|</s>\s*<s>"),
    _det(
        "tokens.xml_role",
        "role_tokens",
        "high",
        r"</?\s*(?:system|assistant|im_start|start_of_turn|end_of_turn)\s*>",
    ),
    _det(
        "tokens.markdown_role",
        "role_tokens",
        "high",
        # Folding collapses newlines, so the header is followed by a colon or straight by an order.
        r"(?:^|\n)\s*#{2,}\s*(?:system|assistant|instruction|response|admin|developer)s?\s*(?::|\s+(?:approve|ignore|disregard|you\s+are|grant|waive|reveal|set|mark|override|refund|new\s+rules?))",
    ),
    _det(
        "tokens.json_role",
        "role_tokens",
        "high",
        r"\\?[\"']role\\?[\"']\s*:\s*\\?[\"'](?:system|assistant|developer)\\?[\"']|(?:^|\n)\s*role\s*:\s*(?:system|assistant|developer)\s*(?:\n|$)",
    ),
    _r(
        "tokens.fake_turn",
        "role_tokens",
        "medium",
        r"(?:^|\n)\s*(?:system|assistant|ai|human|user)\s*:\s*(?:you|the\s+user|the\s+customer|sure|ok|okay|new|skip|grant|ignore|override|here\s+is|certainly|of\s+course|understood|done|approved|policy)",
    ),
    # ----------------------------------------------------------------- tool / action manipulation
    _r(
        "tool.call_function",
        "tool_manipulation",
        "high",
        r"\b(?:call|invoke|run|execute|trigger|use)\s+(?:the\s+)?(?:function|tool)\s+(?:called\s+|named\s+)?[a-z]+_[a-z0-9_]+"
        r"|\b(?:call|invoke|run|execute|trigger)\s+(?:the\s+)?[a-z]+_[a-z0-9_]+(?:\s+(?:tool|function))?\b"
        r"|\b(?:call|invoke|run|execute|trigger)\s+(?:the\s+)?(?:function|tool)\s+(?:called|named)\s+\w+"
        r"|\b(?:call|invoke|run|execute)\s+[a-z_]+\([^)]*\)",
    ),
    _r(
        "tool.set_flag",
        "tool_manipulation",
        "high",
        r"\b(?:set|make|mark|flip|update|change|switch|flag|record)\s+(?:the\s+|my\s+|this\s+)?(?:handoff|verified|is_?admin|authenticated|identity(?:[_\s])?verified|role|verification\s+(?:flag|status)|session|identity|contact|booking\s+owner|me|my\s+identity|my\s+session|my\s+account)\s*(?:=|to|as)\s*(?:a\s+)?(?:true|yes|1|admin|verified|approved|paid|super\s+elite|me\b|mine\b)",
    ),
    _r(
        "tool.skip_check",
        "tool_manipulation",
        "medium",
        r"\b(?:skip|bypass|without|disable|ignore)\s+(?:the\s+|any\s+)?(?:eligibility|identity|id|verification|authorization|authentication|validation|fraud|kyc)\s+(?:checks?|step|process|requirement)\b|\bwithout\s+(?:any\s+|the\s+)?(?:identity\s+)?verification\b",
    ),
    _r(
        "tool.via_api",
        "tool_manipulation",
        "medium",
        r"\b(?:use|via|through)\s+(?:your|the)\s+(?:internal\s+|backend\s+|admin\s+)?(?:api|tools?|backend|database|crm|system)\s+to\s+(?:approve|grant|change|override|issue|refund|waive|look\s*up|pull|fetch|list|export|update|set|cancel|transfer)",
    ),
    # ----------------------------------------------------------------- data harvesting
    # Other people's records in bulk. Every alternative excludes the customer's own booking.
    _r(
        "harvest.bulk_passengers",
        "data_harvesting",
        "high",
        r"\b(?:list|show|give|dump|export|tell|pull\s+up|read\s+out|send|print)\s+(?:me\s+)?(?:all|every|each)\s+(?:the\s+)?(?:other\s+)?(?:passengers?|customers?|travell?ers?|bookings?|pnrs?|reservations?|names?)\b"
        r"(?!\s*(?:on|in|under|of|for|from|with|at)?\s*(?:my|our|me|i\b|the\s+same|this\s+booking|this\s+reservation))"
        rf"(?!\s+on\s+(?:booking|reservation|pnr)\b)(?!\s+on\s+(?!{_FLIGHT}|flight\b)[a-z0-9]{{6}}\b)"
        r"(?![^.?!\n]{0,40}\b(?:my|our)\s+(?:booking|reservation|itinerary|name|account|pnr|trip|flight|family|party|group))",
    ),
    _r(
        "harvest.manifest",
        "data_harvesting",
        "high",
        rf"\b(?:names?|passengers?|manifest|people|who\s+else|everyone)\s+(?:is\s+|are\s+|that\s+(?:is|are)\s+)?(?:on|aboard|booked\s+on|flying\s+on|travell?ing\s+on|in)\s+(?:flight\s+|the\s+flight\s+)?{_FLIGHT}(?![^.?!\n]{{0,30}}\b(?:my|our|with\s+me|with\s+us)\b)|\bwho\s+(?:is|'s|sits?|is\s+sitting|is\s+booked)\s+(?:in|at)\s+seat\s+[0-9ioeast]{{1,2}}[a-k]\b",
    ),
    _r(
        "harvest.others_contact",
        "data_harvesting",
        "high",
        r"\b(?:email|e-mail|phone\s+numbers?|contact\s+(?:info|details)|addresses?|passport\s+numbers?|dates?\s+of\s+birth)\s+(?:addresses?\s+)?(?:of|for|on)\s+(?:the\s+|all\s+|every\s+)?(?:other\s+)?(?:passengers?|customers?|people|person|everyone|travell?ers?)\b"
        + _NOT_MINE,
    ),
    # One other person's data, named by booking, title or role. Restrict: the AI may still answer
    # policy questions but must not look anything up.
    _r(
        "harvest.targeted",
        "data_harvesting",
        "medium",
        r"\b(?:phone(?:\s+number)?|email(?:\s+address)?|home\s+address|address|passport(?:\s+number)?|date\s+of\s+birth|dob|payment\s+card|card\s+(?:number|used)|credit\s+card|itinerary|seat|contact\s+details|travel\s+dates|last\s+four|frequent\s+flyer\s+number|aeroplan\s+number)\b[^.?!\n]{0,25}\b(?:on|for|of|used\s+for|registered\s+(?:on|to)|belonging\s+to)\s+(?:the\s+)?(?:booking|reservation|pnr|passenger|person\s+who\s+booked|mr|mrs|ms|dr)\b"
        + _NOT_MINE,
    ),
    _r(
        "harvest.act_on_other",
        "data_harvesting",
        "medium",
        r"\b(?:cancel|change|modify|move|rebook|refund|update|transfer)\s+(?:the\s+)?(?:booking|reservation|flight|ticket|seat)\s+(?:of|for|belonging\s+to)\s+(?:passenger|mr|mrs|ms|dr|the\s+person|someone)\b"
        + _NOT_MINE,
    ),
    _r(
        "harvest.by_name",
        "data_harvesting",
        "medium",
        r"\b(?:every|all|any)\s+(?:the\s+)?(?:reservations?|bookings?|pnrs?)\s+(?:under|for|with|belonging\s+to)\s+(?:the\s+)?(?:last\s+)?(?:name|surname|family\s+name)\b"
        + _NOT_MINE,
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
        r"\b(?:liste|affiche|donne|montre)[rsz]?\s+(?:moi\s+)?(?:tous\s+)?(?:les\s+)?(?:passagers|clients|courriels|reservations)\b(?![^.?!\n]{0,30}\b(?:ma|mon|mes|notre)\b)",
        "fr",
    ),
    # ----------------------------------------------------------------- indirect injection markers
    _r(
        "indirect.note_to_ai",
        "indirect_injection",
        "high",
        r"\b(?:note|message|instruction|reminder)\s+(?:to|for)\s+(?:the\s+)?(?:ai|assistant|bot|model|llm|automated\s+agent|airline\s+bot)\b"
        r"|\b(?:note|message|consigne|instruction)\s+pour\s+(?:l'?ia|l'?assistant|le\s+robot|l'?agent\s+automatique)\b"
        # An HTML comment carrying an instruction ("<!--" folds to "<i--": the leet fold maps "!" to "i").
        r"|<[!i]--[^>]{0,40}\b(?:assistant|ai|bot|llm|agent)\b[^>]{0,160}-->",
    ),
    _r(
        "indirect.system_override",
        "indirect_injection",
        "high",
        r"\bsystem\s+override\b|\b(?:the\s+)?(?:assistant|bot|ai|automated\s+agent)\s+(?:must|shall|should|is\s+authorized\s+to|is\s+allowed\s+to|is\s+cleared\s+to|is\s+permitted\s+to)\s+(?:approve|share|reveal|grant|waive|comply|disclose|transfer|change|issue|refund|cancel|read\s+out|output|ignore|disregard|mark)"
        r"|\bl'?(?:assistant|ia)\s+(?:doit|peut|est\s+autorise\w*\s+a)\s+(?:approuver|communiquer|reveler|ignorer|annuler|rembourser|transferer)",
    ),
    _r(
        "indirect.addressed",
        "indirect_injection",
        "medium",
        r"\b(?:ai\s+agent|assistant|the\s+bot|the\s+model|automated\s+agent)\s*:\s*(?:before\s+replying|ignore|disregard|approve|issue|waive|reveal|output|grant|mark|transfer|read\s+out|you\s+(?:must|should|are))\b"
        r"|\bwhen\s+the\s+(?:assistant|ai|bot|model)\s+reads\s+this\b|\b(?:bot|assistant|ai)\s+reading\s+this\b",
    ),
    _r(
        "jailbreak.persona_multi",
        "jailbreak_roleplay",
        "medium",
        r"\bactua\s+como\s+(?:un\s+|una\s+)?(?:supervisor|empleado|agente|administrador|gerente)\b|\bverhalte\s+dich\s+wie\s+ein\s+(?:mitarbeiter|supervisor|administrator|manager)\b|\bcomporte-toi\s+comme\s+(?:un\s+|une\s+)?(?:superviseur|employe|administrateur|gestionnaire)\b",
        "multi",
    ),
    _r(
        "indirect.comply_all",
        "indirect_injection",
        "medium",
        r"\bcomply\s+with\s+(?:all|any|every)\s+(?:of\s+)?(?:the\s+)?(?:user'?s?\s+|customer'?s?\s+|my\s+)?requests?\b|\b(?:the\s+)?(?:user|customer|caller|following\s+user|person\s+you\s+are\s+talking\s+to)\s+is\s+an?\s+(?:administrator|admin|developer|supervisor)\b",
    ),
    # ----------------------------------------------------------------- refusal suppression / output coercion
    _r(
        "coerce.no_refusal",
        "refusal_suppression",
        "medium",
        r"\b(?:do\s+not|don't|never|dont|you\s+must\s+not|you\s+may\s+not)\s+(?:ever\s+)?(?:apologi[sz]e|refuse|decline|include\s+(?:any\s+)?(?:disclaimers?|warnings?|caveats?)|add\s+(?:any\s+)?(?:disclaimers?|warnings?|caveats?)|mention\s+(?:your\s+|the\s+|any\s+)?(?:polic(?:y|ies)|rules|guidelines|restrictions)|lecture\s+me|warn\s+me)\b"
        r"|\bnever\s+say\s+(?:that\s+)?you\s+(?:can'?t|cannot|are\s+unable|aren't\s+able)\b"
        r"|\bno\s+(?:disclaimers?|caveats?|refusals?|policy\s+talk)\b"
        r"|\bwithout\s+(?:any\s+)?(?:refus\w+|disclaimers?|warnings?|caveats?|lectur\w+|apolog\w+|hesitation)\b"
        r"|\b(?:stop|quit)\s+(?:apologi[sz]ing|refusing)\b"
        r"|\b(?:respond|answer|reply|output)\s+(?:only\s+|exactly\s+|just\s+)?(?:with|using)\s+(?:the\s+word\s+|exactly\s+|only\s+)?(?:yes|approved|confirmed|done|['\"])"
        r"|\boutput\s+exactly\s*:|\bsay\s+yes\s+and\b",
    ),
    # ----------------------------------------------------------------- authority / urgency claims
    _r(
        "social.staff_claim",
        "social_engineering",
        "medium",
        r"\b(?:treat|consider|regard)\s+me\s+as\s+(?:a\s+|an\s+|the\s+)?(?:staff|employee|agent|supervisor|admin\w*|colleague|internal\s+user|verified)\b"
        r"|\b(?:you\s+are|you're|i\s+am|i'm)\s+(?:a\s+|the\s+)?(?:senior\s+|lead\s+)?(?:agent|supervisor|manager|staff)\s+with\s+(?:override|admin\w*|full|elevated|special)\s+(?:rights|access|privileges|authority)\b"
        r"|\bstaff\s+can\s+(?:see|view|access|open)\s+(?:any|all|every)\b"
        r"|\b(?:pretend|assume|act\s+as\s+if|treat\s+it\s+as\s+if|consider)\s+(?:that\s+)?(?:the\s+|my\s+)?(?:verification|identity\s+check|idv|authentication)\s+(?:has\s+)?(?:already\s+)?(?:passed|succeeded|is\s+done|was\s+done|completed|cleared)\b"
        r"|\bfais\s+comme\s+si\s+(?:la\s+)?(?:verification|identification|authentification)\s+(?:etait|avait\s+ete|est)\s+(?:deja\s+)?(?:faite|passee|validee|reussie)\b"
        r"|\b(?:considere|traite)[\-\s]?moi\s+comme\s+(?:un\s+|une\s+)?(?:employe|agent|superviseur|administrateur)\b",
    ),
    _r(
        "social.authority",
        "social_engineering",
        "medium",
        r"\b(?:i\s+am|i'm|this\s+is|we\s+are|we're|speaking\s+from|calling\s+from|here\s+from|i\s+work\s+(?:at|for|in))\s+(?:from\s+|at\s+|in\s+)?(?:the\s+)?(?:air\s+canada\s+)?(?:it|security|cyber\s*security|engineering|dev(?:eloper)?|fraud|trust\s+and\s+safety|compliance|red[\s-]?team|qa|hq)\s*(?:team|department|dept|division|squad|speaking)?\b.{0,60}\b(?:authori[sz]ed|authori[sz]e|authori[sz]ing|approved|cleared|test|exercise|audit|override|exception)"
        r"|\b(?:authori[sz]ed|internal|official|sanctioned)\s+(?:test|audit|exercise|override|red[\s-]?team(?:ing)?|penetration\s+test)\b"
        r"|\b(?:test|maintenance|audit|qa)\s+mode\s+(?:is\s+)?(?:enabled|on|active|activated)\b"
        r"|\bas\s+your\s+(?:developer|creator|admin(?:istrator)?|operator|owner)\b"
        r"|\b(?:you\s+are|the\s+assistant\s+is|you're)\s+(?:cleared|authori[sz]ed|permitted)\s+to\s+(?:share|approve|reveal|waive|disclose|ignore|bypass)\b"
        r"|\b(?:compliance|legal|trust\s+and\s+safety|the\s+supervisor|my\s+manager|management)\s+(?:has|have)\s+(?:signed\s+off|approved\s+an\s+exception|cleared\s+this)\b",
    ),
)


# Rules for *untrusted content only* (tool results, retrieved documents). Tool output is data about
# the customer, not the customer talking: a first-person request for an action ("please transfer $3,000
# from my account", "unlock my front door") or an order about the reply ("translate your message") has
# no business inside a booking record or an email body. In customer chat the same sentences are normal,
# so these never run on customer text.
TOOL_RULES: tuple[Rule, ...] = (
    _r(
        "indirect.request_in_data",
        "indirect_injection",
        "medium",
        r"\b(?:please\s+|kindly\s+|could\s+you\s+|can\s+you\s+)?(?:transfer|send|deposit|wire|pay|unlock|open|schedule|book|cancel|delete|forward|email|e-mail|post|share|buy|purchase|order|leave|withdraw|move|reset|change|update|grant|add|remove|invite|publish|upload|download|export|get|fetch|retrieve|pull|collect|gather|look\s+up)\b[^.?!\n]{0,70}\b(?:my\s+(?!booking\b|reservation\b|flight\b|seat\b|bag\b|baggage\b|luggage\b|ticket\b|itinerary\b|aeroplan\b|points\b|boarding\b|meal\b|wheelchair\b|child\b|son\b|daughter\b)\w+|for\s+me\b|to\s+me\b|on\s+my\s+behalf)"
        # Amounts are leet-folded in matching text ("$3,000" reads as letters), so key on the destination.
        r"|\b(?:please\s+)?(?:transfer|send|deposit|wire|pay|move)\b[^.?!\n]{0,60}\b(?:to\s+)?(?:account(?:\s+(?:number|id|no))?|wallet|iban|binance|coinbase|paypal|venmo|bank\s+account|crypto)\b",
    ),
    _r(
        "indirect.output_manipulation",
        "indirect_injection",
        "medium",
        r"\b(?:translate|rewrite|rephrase|repeat|start|begin|end|finish|prefix|suffix|augment|enhance|extend|invert|reverse|scramble|capitali[sz]e|shorten|format)\s+(?:your|the)\s+(?:message|reply|response|answer|summary|output)\b"
        r"|\b(?:invert|reverse|scramble|shuffle)\s+(?:the\s+)?(?:order\s+of\s+)?(?:letters|words|characters)\b[^.?!\n]{0,30}\b(?:your|the)\s+(?:message|reply|response|answer)\b"
        r"|\b(?:respond|answer|reply)\s+(?:only\s+)?(?:in|with|using)\s+(?:all\s+caps|capital\s+letters|emojis?|italian|german|french|spanish|pirate|rhymes?|a\s+poem|one\s+word|json)\b"
        r"|\b(?:include|add|append|insert)\s+(?:the\s+(?:word|phrase|link|url|text)|this\s+(?:link|url|text|sentence))\b[^.?!\n]{0,40}\b(?:in|to)\s+(?:your|the)\s+(?:reply|response|answer|message|summary)\b",
    ),
)


@dataclass(frozen=True)
class Match:
    rule_id: str
    family: str
    severity: Severity
    via: str  # "text", "hidden_text", "base64", "hex", "url_encoding", "escapes", "rot13", "reversed"
    field: int
    evidence: Evidence = "probabilistic"


def scan(folded: str, *, via: str, field: int, rules: tuple[Rule, ...] = RULES) -> list[Match]:
    out: list[Match] = []
    for rule in rules:
        if rule.pattern.search(folded) is not None:
            # No excerpt is kept: matched text may contain personal data and decisions are logged.
            out.append(Match(rule.id, rule.family, rule.severity, via, field, rule.evidence))
    return out
