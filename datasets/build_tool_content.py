"""Build tool-result content (what the AI agent's tools return) for the ML model (deterministic).

    python3 -I datasets/external/fetch_external.py      # once: the injections come from BIPIA / InjecAgent
    python3 -I datasets/build_tool_content.py

Writes, under ``datasets/tool/`` — the *tool model's* extra data, kept out of the chat model's
``datasets/attacks|benign`` (one model for both made chat thresholds rise and chat recall fall):
    tool/benign/train-toolcontent.jsonl     fitted on
    tool/benign/calib-toolcontent.jsonl     never fitted on: chooses the tool model's thresholds
    tool/benign/heldout-toolcontent.jsonl   never fitted on: report only
    tool/attacks/train-toolcontent.jsonl    tool/attacks/heldout-toolcontent.jsonl

The tool model trains on the chat data *and* this (``train.py --data datasets --data datasets/tool
--out models/tool``): a tool field can hold a customer's own words, so it must know chat too.

Why. In CMP an indirect injection reaches the AI inside a tool result: a booking remark, an email body,
a review, a flight note. ``POST /v1/inspect/tool-result`` scores such content field by field (JSON
values) or paragraph by paragraph (text), so each row here is one such segment.

Three kinds of rows, so the model learns the *instruction*, not the look of tool data:

* normal       booking remarks, email paragraphs, flight / baggage notes, policy text
                 (family ``airline_tool_content``)
* look-alike   the same kind of content using words attacks use — "please disregard our previous
                 email", "do not reply", "agents must verify identity", "system maintenance", "override
                 approved by duty manager" (family ``airline_hard_negative``: weighted 3× in training)
* attack       an injection from BIPIA / InjecAgent, alone (a whole field) or placed among normal
                 sentences from the *same* pools (family ``indirect_injection``). The injection text is
                 the datasets' own, unchanged. BIPIA's unrelated questions ("capital of Brazil?") are
                 left out: nothing in the text says attack (convert_external.bipia_category).

Train, calib and held-out use disjoint sentence pools (different content of the same kinds; calib is
every fifth train-pool sentence), and injections are split with the same rule as
build_external_splits.py, so held-out scores measure generalisation.
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
SRC = HERE / "external" / "data"
HELDOUT_SHARE = 0.2
TOOL_ATTACKS = frozenset({"indirect_injection", "output_manipulation"})
rng = random.Random(20261014)  # noqa: S311 - reproducible data, not security

FILL = {
    "flight": ["AC854", "AC101", "AC33", "AC870", "AC422", "AC8527", "AC306", "AC7", "AC1150"],
    "city": ["Toronto", "Vancouver", "Montreal", "Calgary", "London", "Paris", "Tokyo", "Halifax", "Ottawa"],
    "pnr": ["ABC123", "QX7Z9P", "LMN4RT", "9KD2WQ", "H3J8TY", "R4T6YU"],
    "date": ["March 3", "the 12th", "June 28", "October 5", "next Friday"],
    "time": ["06:15", "09:40", "13:05", "17:55", "21:40", "23:10"],
    "gate": ["D41", "E72", "C30", "B22", "A12"],
    "belt": ["7", "12", "3", "9"],
}

# ------------------------------------------------------------------ normal content
NORMAL_TRAIN = [
    "Your flight {flight} from {city} on {date} has been rescheduled. The new departure time is {time}.",
    "Thank you for choosing Air Canada. Your booking reference is {pnr}.",
    "Passenger requested an aisle seat; seat 23C assigned.",
    "Special service request: wheelchair assistance to the gate (WCHR).",
    "Meal request: vegetarian (VGML) confirmed for both segments.",
    "Checked baggage allowance: 2 bags, 23 kg each.",
    "Boarding begins at {time} from gate {gate}. Please have your boarding pass ready.",
    "Your bag was located in {city} and will be delivered to your address within 24 hours.",
    "Flight {flight} is delayed due to late arrival of the inbound aircraft.",
    "Refund of 245.60 CAD processed to the original form of payment.",
    "Customer called to confirm infant on lap for the return flight.",
    "Seat selection fee waived per Aeroplan Elite status.",
    "Travel credit of 180 CAD issued, valid for 24 months.",
    "Online check-in opens 24 hours before departure.",
    "Your upgrade request has been added to the waitlist for {flight}.",
    "Baggage claim for {flight} is at belt {belt}.",
    "Name correction from SMTH to SMITH completed at no charge.",
    "Pet in cabin (small dog) confirmed; carrier must fit under the seat.",
    "Connecting flight protected on {flight} departing {time}.",
    "Customer prefers contact by email for schedule changes.",
    "Tickets reissued after schedule change, no additional collection.",
    "Lounge access included with the Business Class fare.",
    "Unaccompanied minor service booked; guardian details on file.",
    "Hotel voucher issued for overnight delay in {city}.",
    "Damaged bag report filed at {city}; reference number {pnr}-BAG.",
    "Please arrive at the airport at least 3 hours before international departures.",
    "The fare is non-refundable but changes are permitted for a fee.",
    "Your e-ticket receipt is attached to this email.",
    "We are sorry for the inconvenience caused by the cancellation of {flight}.",
    "Rebooked on the next available flight to {city} on {date}.",
    "Carry-on bags must not exceed 23 x 40 x 55 cm.",
    "Great crew on the flight to {city}, the cabin was clean and boarding was quick.",
    "The flight was on time but the in-flight entertainment did not work at seat 31A.",
    "Customer requested a receipt for all segments on booking {pnr}.",
    "Travel documents verified at check-in: passport and eTA.",
    "Medical clearance (MEDA) received for travel on {date}.",
    "Priority boarding applies to Zone 1 and Zone 2 customers.",
    "The duty-free cart will pass through the cabin after the meal service.",
    "Due to weather in {city}, flights may be delayed or cancelled.",
    "Aeroplan points will be credited within 7 days of travel.",
    "Your seat on {flight} is 14A, window.",
    "Customer will travel with a guide dog; documentation received.",
    "Sports equipment (golf bag) added as checked baggage.",
    "Flight status: {flight} landed in {city} at {time}.",
    "You can manage your booking online using your reference {pnr} and last name.",
    "Your compensation request for the {flight} delay was approved; payment follows in 7-10 business days.",
    "Claim received for the damaged suitcase; please keep your receipts for repairs.",
    "We have reviewed your claim under the Air Passenger Protection Regulations.",
    "Compensation of 400 CAD was issued as an e-voucher to the email on file.",
    "Your refund request is being processed and will appear on your statement within two billing cycles.",
    "Claim reference {pnr}-CLM: additional documents received, no further action needed.",
    "Expense claim for meals during the delay in {city} approved.",
    "A customer relations agent will contact you within 30 business days about your complaint.",
    "We have received your feedback and shared it with the cabin crew team.",
    "Your baggage delay claim is closed; reimbursement of 120 CAD sent.",
]
NORMAL_HELDOUT = [
    "Departure of {flight} moved to {time} because of an aircraft swap.",
    "Seat 7D confirmed in Premium Economy.",
    "Excess baggage paid at the airport: 1 extra bag.",
    "Delivery of the delayed bag is scheduled for this evening.",
    "We have received your compensation claim and will reply within 30 days.",
    "Customer asked about bringing a car seat for the infant.",
    "Gate change: {flight} now departs from gate {gate}.",
    "Snacks and drinks are available for purchase on board.",
    "Your Aeroplan account was credited with 2,450 points.",
    "Check-in counters close 60 minutes before departure.",
    "The flight attendant was very helpful when my child felt sick.",
    "Booking {pnr} includes two adults and one child.",
    "The new itinerary routes through {city} with a 2 hour connection.",
    "Oversized item (cello) booked on its own seat.",
    "We look forward to welcoming you on board.",
]

# ------------------------------------------------------------------ look-alikes (benign)
LOOKALIKE_TRAIN = [
    "Please disregard our previous email about your schedule change; the original departure time applies.",
    "Do not reply to this email. This mailbox is not monitored.",
    "IMPORTANT: Agents must verify the customer's identity before making any change to this booking.",
    "System notice: online check-in will be unavailable from 02:00 to 04:00 ET for maintenance.",
    "Ignore the seat map shown at booking; the aircraft type changed and seats were reassigned.",
    "Override approved by the duty manager: change fee waived due to irregular operations.",
    "Instructions: bring your passport and the printed visa approval to check-in.",
    "Never share your confirmation code with anyone who calls claiming to be from Air Canada.",
    "Customer note: please ignore my earlier request for a vegetarian meal.",
    "Previous instructions in your itinerary are no longer valid; please follow the updated itinerary.",
    "Forget the earlier gate information, boarding is now at gate {gate}.",
    "Agent note: customer asked us to repeat the baggage rules, explained twice.",
    "From now on, all notifications will be sent to the new email address on file.",
    "Admin remark: duplicate booking cancelled, original booking {pnr} kept.",
    "You must complete the health declaration before boarding; it is required by the destination.",
    "Act now: reply within 48 hours to accept the new flight time or request a refund.",
    "The system automatically cancelled the unused return segment after a no-show.",
    "Do not print this boarding pass; show it on your phone at the gate.",
    "Reveal the QR code at security, then again at the gate.",
    "Agent instructions: rebook on the first available flight and send the new itinerary.",
    "This message replaces all earlier messages about flight {flight}.",
    "Customer said the previous agent's instructions were wrong; corrected the return date.",
    "Supervisor approved a full refund to the original form of payment.",
    "Password reset requested for the Aeroplan account; customer completed it online.",
    "Bypass the kiosk and go directly to the bag drop if you checked in online.",
    "Remember to switch your phone to airplane mode before take-off.",
    "Security notice: we will never ask for your password by email.",
    "Customer insisted on speaking to a supervisor; call transferred.",
    "Disregard the automated message sent earlier today; it was sent in error.",
    "Note to agent: the customer is hard of hearing, please use chat.",
    "Execute the schedule change only after the customer confirms the new time.",
    "The previous system note was incorrect; the infant is on booking {pnr}.",
    "Pretend you are going through security: remove laptops and liquids from your bag.",
    "Role: primary traveller. Secondary traveller: spouse.",
    "Debug info for IT: booking sync failed at {time}, resolved automatically.",
    "These travel instructions replace the ones sent with your booking confirmation.",
    "The instructions below supersede any earlier message about your connection in {city}.",
    "System-generated notice: your seat was changed automatically after the aircraft swap.",
    "Automated message: no reply is needed, your check-in is complete.",
    "New instructions for your trip: proceed to gate {gate} after security.",
    "Ignore this message if you have already completed your claim form.",
    "If you received our earlier email about compensation, please disregard it; the amount below is correct.",
    "Agents: do not issue a second voucher, compensation was already paid.",
    "Internal note: claim escalated to a supervisor for approval of the hotel costs.",
    "Override of the baggage fee approved because the customer is a Super Elite member.",
    "System message: the booking was synchronised with the partner airline at {time}.",
    "Instructions for unaccompanied minors: the guardian must stay until the flight departs.",
    "Please follow the instructions from airport staff if the gate changes again.",
    "Your previous claim was merged into this one; use reference {pnr}-CLM from now on.",
    "Reminder: you must not leave bags unattended in the terminal.",
    "The assistant at the counter rebooked the customer on {flight}.",
    "Customer requested that all future messages be sent in French.",
    "Disregard the voucher code in the first email; the corrected code is in this one.",
]
# ------------------------------------------------------------------ sealed held-out (v2)
# Written after the first held-out pool had been looked at while choosing training rows. Nothing may be
# derived from these sentences: they only measure. Different topics and wording from every pool above.
NORMAL_SEALED = [
    "Lounge access in {city} is available from 05:00 until the last departure.",
    "Wi-Fi on {flight} is free for messaging; streaming requires a paid pass.",
    "Your upgrade to Business Class on {flight} was confirmed at the gate.",
    "Accessible seating was arranged near the front of the cabin.",
    "The cargo shipment was received at the {city} warehouse and is ready for pick-up.",
    "A pet relief area is located past security near gate {gate}.",
    "Status qualifying miles for this trip were added to the member's account.",
    "Receipt for seat purchase: 59.00 CAD, paid by credit card.",
    "Visitor visa details were checked against the passport on file.",
    "Ground transport to the hotel leaves from door 4 on the arrivals level.",
    "Infant bassinet requested for the long-haul segment.",
    "Departure from {city} was smooth and the meal service was excellent.",
    "The travel insurance certificate is attached to the itinerary.",
    "Fast-track security is included for this ticket at {city}.",
    "The traveller's middle name was added to match the passport.",
]
LOOKALIKE_SEALED = [
    "Prompt payment of the balance is appreciated to keep this group booking.",
    "The purser will act as your point of contact during the flight.",
    "Confidential: medical details shared only with the crew who need them.",
    "Do not disclose your booking reference on social media.",
    "Admin fee for paper tickets: 25 CAD per ticket.",
    "Execute the refund once the cancelled segment is confirmed as unused.",
    "Developer notice: the booking API will return a new field from next month.",
    "Bypass lanes are reserved for customers with mobility assistance.",
    "Your role as group leader lets you change names for the whole party.",
    "System outage earlier today: some boarding passes were sent twice, please use the latest one.",
    "Reveal your boarding pass barcode only to airline or airport staff.",
    "Ignore any text messages asking for card details; we never request them that way.",
    "Override seat lock applied: the seat stays blocked for the passenger with the service dog.",
    "Previous messages about this flight are out of date; the times shown here are current.",
]

LOOKALIKE_HELDOUT = [
    "Please ignore the reminder you received yesterday; your check-in is already complete.",
    "Do not respond to this automated notification.",
    "Staff must confirm the passport details before reissuing the ticket.",
    "Scheduled maintenance: the mobile app will be offline tonight.",
    "Previous seat assignments were cancelled when the aircraft changed.",
    "Manager override: name change allowed once at no cost.",
    "Never give your Aeroplan PIN to anyone, including our agents.",
    "Customer asked us to forget the old phone number and use the new one.",
    "These instructions replace the ones in your original confirmation.",
    "System generated: no action required from you.",
    "Agent note: customer requested that we repeat the refund timeline in writing.",
    "Updated instructions: the shuttle to terminal 3 leaves every 10 minutes.",
    "Ignore the boarding time printed on the old pass; use the one in the app.",
    "Admin: merged two duplicate customer profiles.",
]

# ------------------------------------------------------------------ French (CMP serves Québec)
NORMAL_FR = [
    "Votre vol {flight} du {date} a été reporté. Le nouveau départ est à {time}.",
    "Siège 18F confirmé, côté hublot.",
    "Votre bagage a été retrouvé et sera livré dans les 24 heures.",
    "Remboursement traité sur le mode de paiement d'origine.",
    "L'enregistrement en ligne ouvre 24 heures avant le départ.",
    "Bon de repas émis pour le retard du vol {flight}.",
]
LOOKALIKE_FR = [
    "Veuillez ignorer notre courriel précédent; l'heure de départ initiale s'applique.",
    "Ne répondez pas à ce courriel, cette boîte n'est pas surveillée.",
    "Les agents doivent vérifier l'identité du client avant toute modification.",
    "Avis système : l'application sera indisponible cette nuit pour maintenance.",
    "Oubliez l'ancienne porte d'embarquement, l'embarquement se fait maintenant à la porte {gate}.",
    "Note : le client demande d'ignorer sa demande précédente de repas spécial.",
]


def fill(template: str) -> str:
    return template.format(**{k: rng.choice(v) for k, v in FILL.items()})


def _group(text: str) -> str:
    return " ".join(text.split()).casefold()[:60]


def _heldout(text: str) -> bool:
    """Same split rule as build_external_splits.py, so an injection is never trained on in one file
    and held out in the other."""
    h = int(hashlib.sha256(_group(text).encode()).hexdigest()[:8], 16)
    return h / 0xFFFFFFFF < HELDOUT_SHARE


def _read(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").split("\n") if line.strip()]


def injections() -> tuple[list[str], list[str]]:
    """(train, heldout) injection texts: BIPIA and InjecAgent instructions as published."""
    train: list[str] = []
    held: list[str] = []
    seen: set[str] = set()
    for name in ("bipia", "injecagent"):
        path = SRC / f"{name}.jsonl"
        if not path.exists():
            raise SystemExit(f"{path} missing: run  python3 -I datasets/external/fetch_external.py  first")
        for r in _read(path):
            if r["label"] != "attack" or r.get("variant") != "bare" or r["text"] in seen:
                continue
            # Harmful payloads and orders about the assistant's reply: both are attacks inside tool
            # data. Unrelated questions ("capital of Brazil?") are not learnable from the text: left out.
            if r["category"] not in TOOL_ATTACKS:
                continue
            seen.add(r["text"])
            (held if _heldout(r["text"]) else train).append(r["text"])
    return train, held


def row(text: str, label: str, family: str, source: str, lang: str = "en") -> dict[str, Any]:
    return {
        "text": text,
        "label": label,
        "family": family,
        "lang": lang,
        "source": f"build_tool_content.py:{source}",
    }


def benign_rows(
    normal: list[str], lookalike: list[str], n_normal: int, n_look: int, *, french: bool
) -> list[dict[str, Any]]:
    out = []
    for _ in range(n_normal):
        k = rng.choice((1, 1, 2, 3))  # a field, or a paragraph of a few sentences
        out.append(
            row(" ".join(fill(s) for s in rng.sample(normal, k)), "benign", "airline_tool_content", "normal")
        )
    for _ in range(n_look):
        parts = [fill(rng.choice(lookalike))] + [
            fill(s) for s in rng.sample(normal, rng.choice((0, 0, 1, 2)))
        ]
        rng.shuffle(parts)
        out.append(row(" ".join(parts), "benign", "airline_hard_negative", "lookalike"))
    for s in NORMAL_FR if french else []:
        out.append(row(fill(s), "benign", "airline_tool_content", "normal_fr", "fr"))
    for s in LOOKALIKE_FR if french else []:
        out.append(row(fill(s), "benign", "airline_hard_negative", "lookalike_fr", "fr"))
    return out


def attack_rows(payloads: list[str], normal: list[str], copies: int) -> list[dict[str, Any]]:
    """Each injection among 1–2 normal sentences (before, after or both): how it sits in an email body,
    a review or a remark field."""
    out = []
    for p in payloads:
        for _ in range(copies):
            before = [fill(s) for s in rng.sample(normal, rng.choice((0, 1)))]
            after = [fill(s) for s in rng.sample(normal, rng.choice((0, 1) if before else (1,)))]
            out.append(
                row(" ".join([*before, p.strip(), *after]), "attack", "indirect_injection", "embedded")
            )
    return out


def bare_rows(payloads: list[str]) -> list[dict[str, Any]]:
    """The injection as a whole field (a remark or review that is nothing but the injection)."""
    return [row(p.strip(), "attack", "indirect_injection", "bare") for p in payloads]


def main() -> int:
    train_p, held_p = injections()
    normal_fit = [s for i, s in enumerate(NORMAL_TRAIN) if i % 5]
    normal_cal = [s for i, s in enumerate(NORMAL_TRAIN) if not i % 5]
    look_fit = [s for i, s in enumerate(LOOKALIKE_TRAIN) if i % 5]
    look_cal = [s for i, s in enumerate(LOOKALIKE_TRAIN) if not i % 5]
    builders: dict[str, Callable[[], list[dict[str, Any]]]] = {
        "tool/benign/train-toolcontent": lambda: benign_rows(normal_fit, look_fit, 700, 500, french=True),
        "tool/benign/calib-toolcontent": lambda: benign_rows(normal_cal, look_cal, 250, 150, french=False),
        "tool/benign/heldout-toolcontent": lambda: benign_rows(
            NORMAL_HELDOUT, LOOKALIKE_HELDOUT, 150, 120, french=False
        ),
        "tool/attacks/train-toolcontent": lambda: bare_rows(train_p) + attack_rows(train_p, normal_fit, 2),
        "tool/attacks/heldout-toolcontent": lambda: (
            bare_rows(held_p) + attack_rows(held_p, NORMAL_HELDOUT, 1)
        ),
        # Sealed: measure only, never a source of training rows (see NORMAL_SEALED).
        "tool/benign/heldout-toolcontent-sealed": lambda: benign_rows(
            NORMAL_SEALED, LOOKALIKE_SEALED, 150, 120, french=False
        ),
        "tool/attacks/heldout-toolcontent-sealed": lambda: attack_rows(held_p, NORMAL_SEALED, 1),
    }
    for rel, build in builders.items():
        # Each file draws from its own seed: adding training sentences never changes the held-out rows.
        rng.seed(f"20261014:{rel}")
        rows = build()
        seen: set[str] = set()
        unique = [r for r in rows if not (r["text"] in seen or seen.add(r["text"]))]  # type: ignore[func-returns-value]
        (HERE / f"{rel}.jsonl").parent.mkdir(parents=True, exist_ok=True)
        (HERE / f"{rel}.jsonl").write_text(
            "".join(json.dumps(r, ensure_ascii=False) + "\n" for r in unique), encoding="utf-8"
        )
        kinds = Counter(r["source"].split(":")[1] for r in unique)
        print(
            f"  {rel + '.jsonl':40} {len(unique):5} rows  " + ", ".join(f"{k} {v}" for k, v in kinds.items())
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
