"""
Capture — what the passive proxy records, and how requests pair with responses.

One JSON object per message, appended to a JSONL file.  Two properties matter:

* **Raw bytes are kept.**  A capture is the corpus everything later depends on:
  re-running detection with a better dialect, replaying in phase 4, diffing what
  a gateway forwarded against what it received.  A decoded-only capture is
  worth much less, because it is only as good as the dialect you had at the
  time.
* **Cardholder data is masked in the decoded view.**  DE2 and track data never
  reach the decoded ``fields`` in full.

Be clear about what that second point does *not* cover: ``raw`` is the wire
bytes, and the wire carries the PAN in the clear.  A capture file is therefore
cardholder data and must be handled as such — it is gitignored, and
``include_raw=False`` drops it entirely at the cost of everything downstream
that needs to replay or re-decode.  Masking protects the at-a-glance view, not
the file.

Correlation is by STAN, not arrival order: several authorisations are in flight
at once on a real link, and pairing them positionally mis-attributes responses
the moment the host answers out of order.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import threading
import time
from pathlib import Path

from host.iso8583.codec import Message
from host.iso8583.dialect import Dialect
from host.scoping import mask_pan, mask_track2

log = logging.getLogger(__name__)

DE_PAN = 2
DE_STAN = 11
DE_TRACK2 = 35
DE_TRACK3 = 36
DE_RRN = 37
DE_RESPONSE_CODE = 39

# Fields whose value must never be written out in full.
SENSITIVE_FIELDS = {DE_PAN: mask_pan, DE_TRACK2: mask_track2, DE_TRACK3: mask_track2}

ACQUIRER_TO_ISSUER = "acquirer->issuer"
ISSUER_TO_ACQUIRER = "issuer->acquirer"


def masked_fields(msg: Message) -> dict:
    """The decoded fields with cardholder data reduced to a safe rendering."""
    out: dict[str, str] = {}
    for number, value in sorted(msg.fields.items()):
        if isinstance(value, (bytes, bytearray)):
            out[str(number)] = value.hex().upper()
            continue
        masker = SENSITIVE_FIELDS.get(number)
        out[str(number)] = masker(value) if masker else value
    return out


def is_response(mti: str) -> bool:
    """0110 answers 0100, 0210 answers 0200 — the third digit carries it."""
    return len(mti) == 4 and mti[2] in ("1", "3")


def request_mti_for(mti: str) -> str:
    """The request MTI a given response MTI answers."""
    return mti[:2] + str(int(mti[2]) - 1) + mti[3] if is_response(mti) else mti


@dataclasses.dataclass
class Record:
    """One observed message."""
    ts: float
    conn: str
    leg: str
    seq: int
    raw: str
    mti: str = ""
    fields: dict = dataclasses.field(default_factory=dict)
    tpdu: str = ""
    de55: dict = dataclasses.field(default_factory=dict)
    discrepancies: list = dataclasses.field(default_factory=list)
    problems: list = dataclasses.field(default_factory=list)
    warnings: list = dataclasses.field(default_factory=list)
    rtt_ms: float | None = None
    # Mutation provenance. `raw` is always what arrived; `sent` appears only
    # when what left differed, so a capture stays a faithful record of the wire
    # in both directions even while rules are firing.
    mutations: list = dataclasses.field(default_factory=list)
    sent: str = ""
    note: str = ""

    def to_json(self) -> str:
        d = {k: v for k, v in dataclasses.asdict(self).items() if v not in ({}, [], "", None)}
        d["ts"] = self.ts          # keep even at 0
        d["seq"] = self.seq
        return json.dumps(d, separators=(",", ":"))


class Correlator:
    """
    Pairs responses with their requests by STAN, with a bounded memory.

    Matching is by STAN rather than arrival order, so a host answering several
    in-flight authorisations out of order still pairs correctly.

    Round-trip times are best-effort, for a reason that is a feature elsewhere:
    the proxy forwards bytes before decoding them, so on a very fast link the
    response can be observed and recorded before the request that provoked it
    has finished being decoded. When that happens the response simply carries
    no rtt_ms — and the capture may list the two legs in the other order. The
    pairing logic itself is exact; only the derived timing is opportunistic.
    """

    def __init__(self, max_pending: int = 512) -> None:
        self._pending: dict[tuple[str, str], float] = {}
        self._max = max_pending
        self._lock = threading.Lock()

    @staticmethod
    def _key(msg: Message) -> tuple[str, str] | None:
        stan = msg.fields.get(DE_STAN)
        if not isinstance(stan, str) or not stan:
            return None
        return (request_mti_for(msg.mti), stan)

    def note_request(self, msg: Message, ts: float) -> None:
        key = self._key(msg)
        if key is None:
            return
        with self._lock:
            if len(self._pending) >= self._max:
                # Drop the oldest rather than grow without bound: a host that
                # never answers should not become a memory leak.
                oldest = min(self._pending, key=self._pending.get)
                self._pending.pop(oldest, None)
            self._pending[key] = ts

    def match_response(self, msg: Message, ts: float) -> float | None:
        """Round-trip time in milliseconds, or None when nothing matched."""
        key = self._key(msg)
        if key is None:
            return None
        with self._lock:
            started = self._pending.pop(key, None)
        return None if started is None else round((ts - started) * 1000, 2)

    @property
    def outstanding(self) -> int:
        with self._lock:
            return len(self._pending)


class CaptureLog:
    """Append-only JSONL capture, safe to write from both relay threads."""

    def __init__(self, path: str | Path | None, include_raw: bool = True) -> None:
        self.path = Path(path) if path else None
        self.include_raw = include_raw
        self.records: list[Record] = []
        self._lock = threading.Lock()
        self._fh = None
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open("a", encoding="utf-8")

    def close(self) -> None:
        with self._lock:
            if self._fh:
                self._fh.close()
                self._fh = None

    def __enter__(self) -> "CaptureLog":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def write(self, record: Record) -> Record:
        if not self.include_raw:
            record.raw = ""
        with self._lock:
            self.records.append(record)
            if self._fh:
                self._fh.write(record.to_json() + "\n")
                self._fh.flush()      # a capture that dies with the process is no capture
        return record


def observe(dialect: Dialect, body: bytes, raw: bytes, *, conn: str, leg: str,
            seq: int, tpdu: bytes = b"", correlator: Correlator | None = None,
            scope=None, ts: float | None = None) -> Record:
    """
    Decode one observed message into a Record.

    Never raises on bad input: decoding is observation, and a proxy that dies
    because a message did not parse has failed at the one job it has.
    """
    ts = time.time() if ts is None else ts
    record = Record(ts=ts, conn=conn, leg=leg, seq=seq, raw=raw.hex().upper())

    try:
        from host.iso8583.codec import unpack_body
        from host.iso8583 import de55 as de55_mod

        msg = unpack_body(dialect, body)
        msg.tpdu = tpdu
        record.mti = msg.mti
        record.fields = masked_fields(msg)
        record.tpdu = tpdu.hex().upper()
        record.problems = list(msg.problems)
        if msg.trailing:
            record.problems.append(f"{len(msg.trailing)} trailing bytes")

        nodes = de55_mod.from_message(msg)
        if nodes:
            record.de55 = de55_mod.summary(nodes)
            record.discrepancies = [str(d) for d in de55_mod.cross_check(msg, nodes)]

        if correlator is not None and msg.mti:
            if is_response(msg.mti):
                record.rtt_ms = correlator.match_response(msg, ts)
            else:
                correlator.note_request(msg, ts)

        if scope is not None:
            pan = msg.fields.get(DE_PAN)
            if isinstance(pan, str) and pan:
                warning = scope.check_pan(pan)      # may raise ScopeError
                if warning:
                    record.warnings.append(warning)

    except Exception as exc:                        # noqa: BLE001
        from host.scoping import ScopeError
        if isinstance(exc, ScopeError):
            raise
        log.debug("Could not decode observed message: %s", exc)
        record.problems.append(f"decode failed: {exc}")

    return record


def load_capture(path: str | Path) -> list[dict]:
    """Read a JSONL capture back. Malformed lines are skipped, not fatal."""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def summarise(records: list[dict]) -> str:
    """A human summary of a capture file."""
    if not records:
        return "Capture is empty."

    by_mti: dict[str, int] = {}
    problems = discrepancies = warnings = mutations = mutated_msgs = 0
    rtts: list[float] = []
    for r in records:
        by_mti[r.get("mti", "?")] = by_mti.get(r.get("mti", "?"), 0) + 1
        problems += len(r.get("problems", []))
        discrepancies += len(r.get("discrepancies", []))
        warnings += len(r.get("warnings", []))
        if r.get("mutations"):
            mutated_msgs += 1
            mutations += len(r["mutations"])
        if r.get("rtt_ms") is not None:
            rtts.append(r["rtt_ms"])

    lines = [f"{len(records)} messages captured."]
    lines.append("  by MTI: " + ", ".join(f"{m}×{n}" for m, n in sorted(by_mti.items())))
    if mutations:
        lines.append(f"  ** {mutations} mutation(s) applied across "
                     f"{mutated_msgs} message(s) — this capture is not a "
                     f"record of untouched traffic")
    if rtts:
        lines.append(f"  round trips: {len(rtts)} matched, "
                     f"median {sorted(rtts)[len(rtts) // 2]:.1f} ms")
    if discrepancies:
        lines.append(f"  ** {discrepancies} DE55 discrepancies — see 'discrepancies' fields")
    if warnings:
        lines.append(f"  ** {warnings} scope warnings")
    if problems:
        lines.append(f"  {problems} decode problems (dialect may be wrong)")
    return "\n".join(lines)
