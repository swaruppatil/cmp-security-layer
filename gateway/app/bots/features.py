"""Bot features: pure functions over one identity's recent events (no I/O, easy to test).

An *event* is one request: ``(timestamp_ms, message_length, simhash | None)``. From the last
``BOT_WINDOW_EVENTS`` events of an identity we compute:

* **rate** — requests in the last 60 s. People don't send 30 a minute.
* **regularity** — coefficient of variation (stdev / mean) of the gaps between requests. Scripts
  send on a timer (CV ≈ 0); people are irregular (CV ≳ 0.5).
* **typing speed** — characters per second since the previous message. People type ~3–8 chars/s;
  a 300-character message one second after the last one was pasted or generated.
* **duplicates** — earlier messages within a few bits of this one (SimHash). Scripts repeat a template.

SimHash (64-bit, over word pairs of the folded text) maps near-identical messages to fingerprints a
few bits apart: "send me ABC123's ticket" and "send me XYZ789's ticket" are near-duplicates.
"""

from __future__ import annotations

import hashlib
import statistics
from dataclasses import dataclass, field

from app.detectors.normalize import normalize

MASK64 = (1 << 64) - 1


def simhash(text: str) -> int | None:
    """64-bit SimHash of the folded text's word pairs; None for texts too short to fingerprint."""
    words = normalize(text).match.split()
    if len(words) < 3:
        return None
    shingles = [f"{a} {b}" for a, b in zip(words, words[1:], strict=False)]
    acc = [0] * 64
    for sh in shingles:
        h = int.from_bytes(hashlib.blake2b(sh.encode(), digest_size=8).digest(), "big")
        for bit in range(64):
            acc[bit] += 1 if (h >> bit) & 1 else -1
    return sum(1 << bit for bit in range(64) if acc[bit] > 0) & MASK64


def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()


def bands(h: int) -> list[str]:
    """Four 16-bit bands: two fingerprints within 3 bits share at least one band exactly."""
    return [f"{i}:{(h >> (16 * i)) & 0xFFFF:04x}" for i in range(4)]


@dataclass(frozen=True)
class Event:
    ts_ms: int
    length: int
    simhash: int | None

    def encode(self) -> str:
        return (
            f"{self.ts_ms}|{self.length}|{self.simhash:016x}"
            if self.simhash is not None
            else f"{self.ts_ms}|{self.length}|-"
        )

    @classmethod
    def decode(cls, raw: str | bytes) -> Event | None:
        try:
            s = raw.decode() if isinstance(raw, bytes) else raw
            ts, length, sh = s.split("|")
            return cls(int(ts), int(length), None if sh == "-" else int(sh, 16))
        except (ValueError, UnicodeDecodeError):
            return None


@dataclass
class Features:
    events: int  # including the current one
    rate_per_min: int
    gap_cv: float | None  # None when there are too few gaps
    mean_gap_s: float | None
    fast_share: float  # share of recent long messages typed faster than a person can
    judged: int  # how many recent messages were long enough to judge typing speed
    duplicates: int  # earlier messages that are near-duplicates of this one
    detail: dict[str, float | int | None] = field(default_factory=dict)


def compute(
    history: list[Event],
    current: Event,
    *,
    min_gaps: int,
    fast_cps: float,
    fast_min_chars: int,
    dup_distance: int,
) -> Features:
    events = sorted([*history, current], key=lambda e: e.ts_ms)
    now = current.ts_ms
    rate = sum(1 for e in events if now - e.ts_ms <= 60_000)
    gaps = [(b.ts_ms - a.ts_ms) / 1000 for a, b in zip(events, events[1:], strict=False)]
    cv = mean_gap = None
    if len(gaps) >= min_gaps:
        recent = gaps[-min_gaps * 2 :]
        mean_gap = statistics.fmean(recent)
        cv = statistics.pstdev(recent) / mean_gap if mean_gap > 0 else 0.0
    # Typing speed of each long message: its length over the time since the previous request.
    speeds = [
        b.length / max(gap, 0.05)
        for (a, b), gap in zip(zip(events, events[1:], strict=False), gaps, strict=True)
        if b.length >= fast_min_chars
    ][-10:]
    fast_share = sum(1 for v in speeds if v > fast_cps) / len(speeds) if speeds else 0.0
    dups = 0
    if current.simhash is not None:
        dups = sum(
            1
            for e in history
            if e.simhash is not None and hamming(e.simhash, current.simhash) <= dup_distance
        )
    return Features(
        events=len(events),
        rate_per_min=rate,
        gap_cv=None if cv is None else round(cv, 4),
        mean_gap_s=None if mean_gap is None else round(mean_gap, 3),
        fast_share=round(fast_share, 3),
        judged=len(speeds),
        duplicates=dups,
    )
