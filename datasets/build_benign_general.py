"""Build general-purpose BENIGN training data: datasets/benign/train-general.jsonl.

    python3 datasets/build_benign_general.py

The seed benign set is all customer-support traffic, so a model trained on it alone learns
"anything off-topic looks suspicious". These are ordinary off-topic questions and requests in EN/FR/DE
— including questions *about* AI, prompts, security and passwords, which are normal curiosity, not
attacks. Written independently of the held-out sets (nothing here is copied from them).
"""

from __future__ import annotations

import json
import random
from pathlib import Path

HERE = Path(__file__).parent
RNG = random.Random(20261012)

TOPICS_EN = [
    "a prompt", "prompt engineering", "a large language model", "machine learning", "a neural network",
    "a firewall", "a password manager", "two-factor authentication", "an API", "a database index",
    "a system administrator", "encryption", "a VPN", "a chatbot", "open source software", "cloud computing",
    "inflation", "climate change", "photosynthesis", "the stock market", "a mortgage", "compound interest",
    "the French revolution", "the Roman empire", "black holes", "vaccines", "renewable energy",
    "electric cars", "a heat pump", "sourdough bread", "intermittent fasting", "the Olympic games",
    "jet lag", "carbon offsets", "the northern lights", "a sabbatical", "remote work", "a credit score",
]
TEMPLATES_EN = [
    "What is {t}?", "How does {t} work?", "Explain {t} in simple terms", "Can you tell me more about {t}?",
    "what's the deal with {t}", "Is {t} a good idea for beginners?", "Give me a short summary of {t}",
    "Why do people talk so much about {t}?", "pros and cons of {t}?",
]
TOPICS_FR = [
    "un prompt", "l'intelligence artificielle", "un pare-feu", "un gestionnaire de mots de passe",
    "l'authentification à deux facteurs", "le chiffrement", "l'inflation", "le changement climatique",
    "la photosynthèse", "un prêt hypothécaire", "les énergies renouvelables", "le décalage horaire",
    "le télétravail", "les aurores boréales", "la Révolution française",
]
TEMPLATES_FR = [
    "Qu'est-ce que {t}?", "Comment fonctionne {t}?", "Peux-tu m'expliquer {t} simplement?",
    "Quels sont les avantages et inconvénients de {t}?",
]
TOPICS_DE = [
    "ein Prompt", "künstliche Intelligenz", "eine Firewall", "ein Passwortmanager", "Verschlüsselung",
    "Inflation", "der Klimawandel", "Photosynthese", "erneuerbare Energie", "ein Elektroauto",
    "Homeoffice", "eine Wärmepumpe", "der Jetlag", "die Polarlichter",
]
TEMPLATES_DE = [
    "Was ist {t}?", "Wie funktioniert {t}?", "Kannst du mir {t} einfach erklären?",
    "Welche Vor- und Nachteile hat {t}?",
]
REQUESTS = [
    ("en", "Recommend a good book about the history of aviation"),
    ("en", "What should I pack for a week of hiking in the Rockies?"),
    ("en", "Write a short birthday message for my coworker"),
    ("en", "How do I reset my home router?"),
    ("en", "What are some tips for sleeping on a long flight?"),
    ("en", "Translate 'where is the train station' into Portuguese"),
    ("en", "How do I stop my phone from asking me to update all the time?"),
    ("en", "What does 'role-playing game' mean?"),
    ("en", "Who wrote the novel Pride and Prejudice?"),
    ("en", "How many time zones does Canada have?"),
    ("en", "Best way to learn Python as a complete beginner?"),
    ("en", "How do security researchers report bugs responsibly?"),
    ("en", "What are the rules of cricket, briefly?"),
    ("en", "Why do some websites ask me to prove I'm not a robot?"),
    ("en", "What's a good password policy for a small business?"),
    ("en", "How do I write instructions that a new employee will actually follow?"),
    ("fr", "Recommande-moi un bon roman québécois"),
    ("fr", "Comment préparer une tourtière?"),
    ("fr", "Quelle est la capitale de l'Australie?"),
    ("fr", "Comment apprendre la programmation quand on débute?"),
    ("de", "Wie backe ich ein einfaches Brot?"),
    ("de", "Welche Sehenswürdigkeiten gibt es in Montreal?"),
    ("de", "Wie lerne ich am besten eine neue Sprache?"),
    ("de", "Was sollte ich bei einem Vorstellungsgespräch beachten?"),
]


def main() -> None:
    rows = []
    for lang, topics, templates in (
        ("en", TOPICS_EN, TEMPLATES_EN), ("fr", TOPICS_FR, TEMPLATES_FR), ("de", TOPICS_DE, TEMPLATES_DE)
    ):
        for t in topics:
            for tpl in RNG.sample(templates, k=min(3, len(templates))):
                text = tpl.format(t=t)
                rows.append({"text": text[0].upper() + text[1:] if RNG.random() < 0.7 else text, "lang": lang})
    rows += [{"text": text, "lang": lang} for lang, text in REQUESTS]
    out = HERE / "benign" / "train-general.jsonl"
    lines = [
        json.dumps({"text": r["text"], "label": "benign", "family": "general_question", "lang": r["lang"],
                    "source": "build_benign_general.py"}, ensure_ascii=False)
        for r in rows
    ]
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{out.relative_to(HERE.parent)}: {len(rows)} rows")


if __name__ == "__main__":
    main()
