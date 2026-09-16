"""
A recorded card — APDU responses served from a capture file.

Emulation needs something to relay *to*. Until now that meant a real card, in a
local reader or behind the remote proxy, which is a hard requirement when all
you want to do is see what a terminal asks. This transport answers from a file
instead, so a capture taken once can be presented to a terminal again.

What a replayed card cannot do
------------------------------
**It cannot answer a challenge it has never seen.** A terminal picks its own
unpredictable number and amount, and the cryptogram the recorded card returned
was computed over the *previous* terminal's values. GENERATE AC replies are
therefore stale by construction: they will be rejected by any issuer that checks
them, and by most terminals doing offline data authentication.

What it is good for is everything before that — which AIDs a terminal selects,
what it puts in the PDOL, which records it reads, how it reacts to a given
response — and for driving the emulator without hardware in the loop.

Matching is deliberately layered, and every fallback is logged, because a
response served by a looser rule than exact match is a weaker claim about what
the card would really have said.
"""
from __future__ import annotations

import json
import logging
import re
from collections import deque
from pathlib import Path

from transport.base import CardTransport

logger = logging.getLogger(__name__)

SW_INS_NOT_SUPPORTED = bytes([0x6D, 0x00])

_TERMINAL_TO_CARD = "terminal→card"


class RecordedCardError(ValueError):
    """The capture could not be read, or holds no APDU pairs. User-facing."""


def _hex(text: str) -> bytes:
    """Hex with any spacing, or a clear complaint."""
    cleaned = re.sub(r"[\s:]", "", text)
    if not cleaned:
        return b""
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise RecordedCardError(f"{text[:40]!r} is not hex: {exc}") from exc


# ── readers for the shapes a capture arrives in ──────────────────────────────

def _pairs_from_records(records) -> list[tuple[bytes, bytes]]:
    """
    Pair each command with the response that followed it.

    A capture is a flat stream of directed records; a command with no response
    after it is dropped rather than paired with the next command, which would
    silently attribute one card's answer to a different question.
    """
    pairs: list[tuple[bytes, bytes]] = []
    pending: bytes | None = None
    for direction, raw in records:
        if direction == _TERMINAL_TO_CARD:
            pending = raw
        elif pending is not None:
            pairs.append((pending, raw))
            pending = None
    return pairs


def _read_hexlog(text: str) -> list[tuple[bytes, bytes]]:
    """ATRIUM's own hexlog: ``<ts>  C|R  [sid]  00 A4 04 00 …``."""
    records = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = re.match(r"^\s*\d+\s+([CR])\s+\[[^\]]*\]\s+(.+)$", line)
        if not m:
            continue
        tag, body = m.groups()
        records.append((_TERMINAL_TO_CARD if tag == "C" else "card→terminal", _hex(body)))
    return _pairs_from_records(records)


def _read_json(text: str) -> tuple[list[tuple[bytes, bytes]], bytes]:
    """A session JSON from JSONHandler, or a list of {cmd, resp} objects."""
    doc = json.loads(text)
    atr = b""

    if isinstance(doc, dict) and "apdus" in doc:
        atr = _hex(doc.get("atr") or "")
        records = [(r.get("direction", ""), _hex(r.get("raw_hex", "")))
                   for r in doc["apdus"]]
        return _pairs_from_records(records), atr

    if isinstance(doc, dict):
        doc = doc.get("data") or doc.get("entries") or doc.get("apdus") or []

    pairs = []
    for entry in doc:
        if not isinstance(entry, dict):
            continue
        cmd = entry.get("cmd") or entry.get("command") or entry.get("c")
        resp = entry.get("resp") or entry.get("response") or entry.get("r")
        if cmd and resp:
            pairs.append((_hex(cmd), _hex(resp)))
    return pairs, atr


def _read_jsonl(text: str) -> list[tuple[bytes, bytes]]:
    pairs = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        cmd = entry.get("cmd") or entry.get("command")
        resp = entry.get("resp") or entry.get("response")
        if cmd and resp:
            pairs.append((_hex(cmd), _hex(resp)))
    return pairs


def _read_plain(text: str) -> list[tuple[bytes, bytes]]:
    """
    A hand-written file — the format to reach for when writing one by hand.

    Either direction-marked lines::

        > 00A4040007A0000000031010
        < 6F1A840E325041592E5359532E4444463031 9000

    or one pair per line::

        00A4040007A0000000031010  6F1A840E325041592E5359532E4444463031 9000

    ``#`` starts a comment.
    """
    pairs: list[tuple[bytes, bytes]] = []
    pending: bytes | None = None

    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue

        if line.startswith((">", "<")):
            marker, body = line[0], line[1:]
            if marker == ">":
                pending = _hex(body)
            elif pending is not None:
                pairs.append((pending, _hex(body)))
                pending = None
            continue

        # One pair per line: two hex blobs separated by whitespace, tab or comma.
        parts = [p for p in re.split(r"[,\t]|\s{2,}", line) if p.strip()]
        if len(parts) < 2:
            parts = line.split(None, 1)
        if len(parts) >= 2:
            pairs.append((_hex(parts[0]), _hex(parts[1])))

    return pairs


def load_pairs(path: str | Path) -> tuple[list[tuple[bytes, bytes]], bytes]:
    """Read a capture in whichever of the supported shapes it is in."""
    p = Path(path)
    try:
        text = p.read_text()
    except OSError as exc:
        raise RecordedCardError(f"Could not read {p}: {exc}") from exc

    suffix = p.suffix.lower()
    atr = b""
    if suffix == ".json":
        pairs, atr = _read_json(text)
    elif suffix == ".jsonl":
        pairs = _read_jsonl(text)
    elif suffix in (".hexlog", ".log"):
        pairs = _read_hexlog(text)
    else:
        # Sniff, so a capture keeps working when it is renamed.
        stripped = text.lstrip()
        if stripped.startswith(("{", "[")):
            pairs, atr = _read_json(text)
        elif re.search(r"^\s*\d+\s+[CR]\s+\[", text, re.M):
            pairs = _read_hexlog(text)
        else:
            pairs = _read_plain(text)

    if not pairs:
        raise RecordedCardError(
            f"{p} holds no command/response pairs. Supported: ATRIUM hexlogs "
            f"and session JSON, JSONL of {{cmd, resp}}, or lines of "
            f"'> command' / '< response'.")
    return pairs, atr


# ── the transport ────────────────────────────────────────────────────────────

class RecordedCardTransport(CardTransport):
    """A card that answers from a capture rather than from hardware."""

    def __init__(self, path: str | Path, strict: bool = False) -> None:
        self.path = Path(path)
        # strict answers 6D00 rather than serving a loosely-matched response,
        # which is the honest setting when the point is to find out what the
        # recorded card actually covered.
        self.strict = strict
        self._pairs: list[tuple[bytes, bytes]] = []
        self._atr = b""
        self._exact: dict[bytes, deque] = {}
        self._header: dict[bytes, deque] = {}
        self._by_ins: dict[int, deque] = {}
        self.misses: list[bytes] = []

    # ── lifecycle ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        self._pairs, self._atr = load_pairs(self.path)
        self._index()
        logger.info("Recorded card: %d pair(s) from %s", len(self._pairs), self.path)

    def disconnect(self) -> None:
        if self.misses:
            logger.warning("Recorded card had no answer for %d command(s); "
                           "first was %s", len(self.misses),
                           self.misses[0].hex().upper())

    def get_atr(self) -> bytes:
        return self._atr

    def _index(self) -> None:
        """
        Build the three lookups, each keeping duplicates in recorded order.

        A command asked twice usually has two different answers — READ RECORD
        walks a file, GET DATA counters move — so repeats are served in the
        order they were captured rather than collapsed to the first.
        """
        self._exact, self._header, self._by_ins = {}, {}, {}
        for cmd, resp in self._pairs:
            self._exact.setdefault(cmd, deque()).append(resp)
            if len(cmd) >= 4:
                self._header.setdefault(bytes(cmd[:4]), deque()).append(resp)
                self._by_ins.setdefault(cmd[1], deque()).append(resp)

    # ── serving ──────────────────────────────────────────────────────────────

    def transmit(self, apdu: bytes) -> bytes:
        hit = self._take(self._exact, bytes(apdu))
        if hit is not None:
            return hit

        if self.strict:
            return self._miss(apdu, "no exact match and strict mode is on")

        if len(apdu) >= 4:
            hit = self._take(self._header, bytes(apdu[:4]))
            if hit is not None:
                logger.info("Recorded card: %s answered from a CLA/INS/P1/P2 match — "
                            "the recorded response was to different data",
                            apdu[:4].hex().upper())
                return hit

            hit = self._take(self._by_ins, apdu[1])
            if hit is not None:
                logger.warning("Recorded card: %s answered from an INS-only match — "
                               "this is a guess, not the card's answer to this command",
                               apdu[:4].hex().upper())
                return hit

        return self._miss(apdu, "the capture has nothing like it")

    @staticmethod
    def _take(index, key):
        queue = index.get(key)
        if not queue:
            return None
        return queue.popleft()

    def _miss(self, apdu: bytes, why: str) -> bytes:
        self.misses.append(bytes(apdu))
        logger.warning("Recorded card: no answer for %s (%s) — replying 6D00",
                       apdu[:8].hex().upper(), why)
        return SW_INS_NOT_SUPPORTED
