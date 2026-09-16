"""
NFCGate's wire format, encoded by hand.

Two protobuf messages carry the whole relay, and both are about as small as
protobuf gets — two varint enums, one length-delimited ``bytes`` field, one
varint ``int64``::

    // c2s.proto — client ⇄ server
    message ServerData {
      enum Opcode { OP_PSH = 0; OP_SYN = 1; OP_ACK = 2; OP_FIN = 3; }
      Opcode opcode = 1;
      bytes  data   = 2;
    }

    // c2c.proto — client ⇄ client, inside ServerData.data on OP_PSH
    message NFCData {
      enum DataSource { READER = 0; CARD = 1; }
      enum DataType   { INITIAL = 0; CONTINUATION = 1; }
      DataSource data_source = 1;
      DataType   data_type   = 2;
      bytes      data        = 3;
      int64      timestamp   = 4;   // unix millis
    }

Why not import ``protobuf``
---------------------------
NFCGate's own generated ``_pb2.py`` files were built against protobuf 3.x's
C++ descriptor API and raise ``Descriptors cannot be created directly`` on any
current runtime, so "just import theirs" was never on the table.  That leaves
regenerating with ``protoc`` or encoding these two messages directly — and at
this size, direct encoding costs about forty lines and no dependency at all,
which is what the rest of this project does for its own wire formats
(``card_proxy``, ``secure_link``, ``host/iso8583``).

``doc/verify_proto.py`` checks this codec byte-for-byte against the real
protobuf runtime, in both directions, for every enum combination in both
messages.

Reading, not just writing
-------------------------
Decoding is deliberately tolerant of fields it does not know: proto3 omits
zero-valued fields, and a future NFCGate may add ones this does not.  Unknown
field numbers are skipped rather than rejected, so a newer peer does not become
an error.
"""
from __future__ import annotations

import dataclasses

# NFCData.DataSource — which end of the RF link the bytes came from.
READER = 0
CARD = 1

# NFCData.DataType — the tag's configuration, or traffic.
INITIAL = 0
CONTINUATION = 1

# ServerData.Opcode
OP_PSH = 0
OP_SYN = 1
OP_ACK = 2
OP_FIN = 3

_OPCODE_NAMES = {OP_PSH: "OP_PSH", OP_SYN: "OP_SYN", OP_ACK: "OP_ACK", OP_FIN: "OP_FIN"}

# Protobuf wire types, of which only these two appear in either message.
_WIRE_VARINT = 0
_WIRE_BYTES = 2

# A frame this side will not try to hold in memory. NFCGate's own client caps
# receives at 100 MiB; an APDU relay has no business near either number, and an
# unbounded length prefix off a socket is how a peer turns into an allocator.
MAX_MESSAGE = 1 << 20


class NFCGateProtocolError(ValueError):
    """A frame did not decode. User-facing: it usually means the wrong port."""


def opcode_name(opcode: int) -> str:
    return _OPCODE_NAMES.get(opcode, f"opcode {opcode}")


# ── varint and field primitives ──────────────────────────────────────────────

def _varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("negative varints are not used by either message")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if i >= len(buf):
            raise NFCGateProtocolError("truncated varint")
        if shift > 63:
            raise NFCGateProtocolError("varint too long")
        byte = buf[i]
        i += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, i
        shift += 7


def _field(number: int, wire: int, payload: bytes) -> bytes:
    return _varint((number << 3) | wire) + payload


def _bytes_field(number: int, data: bytes) -> bytes:
    return _field(number, _WIRE_BYTES, _varint(len(data)) + bytes(data))


def _scan(buf: bytes) -> dict[int, int | bytes]:
    """
    Decode a flat proto3 message to ``{field_number: value}``.

    Later occurrences win, which is what proto3 says to do for a repeated
    scalar on the wire.  Unknown *field numbers* are kept; unknown *wire types*
    are the only thing that fails, because skipping one needs a length this
    cannot know.
    """
    out: dict[int, int | bytes] = {}
    i = 0
    while i < len(buf):
        key, i = _read_varint(buf, i)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise NFCGateProtocolError("field number 0 is not valid")
        if wire == _WIRE_VARINT:
            out[number], i = _read_varint(buf, i)
        elif wire == _WIRE_BYTES:
            length, i = _read_varint(buf, i)
            if length > len(buf) - i:
                raise NFCGateProtocolError("length-delimited field runs past the message")
            out[number], i = buf[i:i + length], i + length
        elif wire == 5:                                # fixed32
            out[number], i = buf[i:i + 4], i + 4
        elif wire == 1:                                # fixed64
            out[number], i = buf[i:i + 8], i + 8
        else:
            raise NFCGateProtocolError(
                f"wire type {wire} in field {number} — this is not an NFCGate message")
    return out


def _as_int(value: int | bytes | None, field: str) -> int:
    if value is None:
        return 0                                       # proto3 omits zeros
    if isinstance(value, int):
        return value
    raise NFCGateProtocolError(f"{field} arrived length-delimited, expected a varint")


def _as_bytes(value: int | bytes | None, field: str) -> bytes:
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    raise NFCGateProtocolError(f"{field} arrived as a varint, expected bytes")


# ── ServerData ───────────────────────────────────────────────────────────────

def encode_serverdata(opcode: int, data: bytes = b"") -> bytes:
    out = b""
    if opcode:                                         # proto3: 0 is the default
        out += _field(1, _WIRE_VARINT, _varint(opcode))
    if data:
        out += _bytes_field(2, data)
    return out


def decode_serverdata(buf: bytes) -> tuple[int, bytes]:
    """Return ``(opcode, data)``."""
    fields = _scan(buf)
    return _as_int(fields.get(1), "ServerData.opcode"), _as_bytes(fields.get(2), "ServerData.data")


# ── NFCData ──────────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class NFCData:
    """One message between the two peers of a relay."""

    data_source: int = READER
    data_type: int = CONTINUATION
    data: bytes = b""
    timestamp: int = 0

    @property
    def from_card(self) -> bool:
        return self.data_source == CARD

    @property
    def is_initial(self) -> bool:
        """True when ``data`` is the tag's configuration rather than an APDU."""
        return self.data_type == INITIAL

    def __str__(self) -> str:
        side = "C" if self.from_card else "R"
        kind = "(initial) " if self.is_initial else ""
        return f"{side}: {kind}{self.data.hex().upper()}"


def encode_nfcdata(
    data: bytes,
    *,
    data_source: int = READER,
    data_type: int = CONTINUATION,
    timestamp: int = 0,
) -> bytes:
    out = b""
    if data_source:
        out += _field(1, _WIRE_VARINT, _varint(data_source))
    if data_type:
        out += _field(2, _WIRE_VARINT, _varint(data_type))
    if data:
        out += _bytes_field(3, data)
    if timestamp:
        out += _field(4, _WIRE_VARINT, _varint(timestamp))
    return out


def decode_nfcdata(buf: bytes) -> NFCData:
    fields = _scan(buf)
    return NFCData(
        data_source=_as_int(fields.get(1), "NFCData.data_source"),
        data_type=_as_int(fields.get(2), "NFCData.data_type"),
        data=_as_bytes(fields.get(3), "NFCData.data"),
        timestamp=_as_int(fields.get(4), "NFCData.timestamp"),
    )


# ── the tag's configuration ──────────────────────────────────────────────────
#
# An INITIAL message from the reader-side peer carries an NCI config stream,
# not an APDU: a flat run of [type:1][len:1][value:len] records built by
# NFCGate's ConfigBuilder from whatever the phone learned during anticollision.
# The type bytes are NCI listen-mode parameter IDs (OptionType.java).

LA_BIT_FRAME_SDD = 0x30      # ATQA[0]
LA_PLATFORM_CONFIG = 0x31    # ATQA[1]
LA_SEL_INFO = 0x32           # SAK
LA_NFCID1 = 0x33             # UID
LB_SENSB_INFO = 0x38
LB_NFCID0 = 0x39             # PUPI
LB_APPLICATION_DATA = 0x3A
LB_SFGI = 0x3B
LB_FWI_ADC_FO = 0x3C
LB_BIT_RATE = 0x3E
LF_T3T_IDENTIFIERS_1 = 0x40
LF_T3T_PMM = 0x51
LF_T3T_FLAGS = 0x53
LI_A_RATS_TB1 = 0x58         # FWI / SFGI
LI_A_HIST_BY = 0x59          # ATS historical bytes
LI_B_H_INFO_RSP = 0x5A       # Type B higher-layer response
LI_A_BIT_RATE = 0x5B         # a *derived* max-bitrate code, not TA(1)
LI_A_RATS_TC1 = 0x5C         # NAD / CID support

_OPTION_NAMES = {
    LA_BIT_FRAME_SDD: "LA_BIT_FRAME_SDD", LA_PLATFORM_CONFIG: "LA_PLATFORM_CONFIG",
    LA_SEL_INFO: "LA_SEL_INFO", LA_NFCID1: "LA_NFCID1",
    LB_SENSB_INFO: "LB_SENSB_INFO", LB_NFCID0: "LB_NFCID0",
    LB_APPLICATION_DATA: "LB_APPLICATION_DATA", LB_SFGI: "LB_SFGI",
    LB_FWI_ADC_FO: "LB_FWI_ADC_FO", LB_BIT_RATE: "LB_BIT_RATE",
    LF_T3T_IDENTIFIERS_1: "LF_T3T_IDENTIFIERS_1", LF_T3T_PMM: "LF_T3T_PMM",
    LF_T3T_FLAGS: "LF_T3T_FLAGS",
    LI_A_RATS_TB1: "LI_A_RATS_TB1", LI_A_HIST_BY: "LI_A_HIST_BY",
    LI_B_H_INFO_RSP: "LI_B_H_INFO_RSP", LI_A_BIT_RATE: "LI_A_BIT_RATE",
    LI_A_RATS_TC1: "LI_A_RATS_TC1",
}

# T0 presence bits in an ATS (ISO/IEC 14443-4 §5.2.2).
_TA1_PRESENT = 0x10
_TB1_PRESENT = 0x20
_TC1_PRESENT = 0x40

# FSCI is not carried anywhere in the config stream — the phone never forwards
# it — so a reconstructed ATS has to put *something* in T0's low nibble. 8 is
# FSC 256, the common case for an ISO 14443-4 card. It is a stand-in, which is
# why `ats_is_partial` exists and why the transport says so out loud.
DEFAULT_FSCI = 0x08


def option_name(option: int) -> str:
    return _OPTION_NAMES.get(option, f"0x{option:02X}")


def parse_config_stream(data: bytes) -> dict[int, bytes]:
    """
    Split an NCI config stream into ``{option_type: value}``.

    Mirrors ``ConfigBuilder.parse``, including its bound: a record whose length
    byte overruns the buffer ends the walk rather than raising, because a
    truncated tail is a partial read, not a different protocol.
    """
    out: dict[int, bytes] = {}
    i = 0
    while i + 2 <= len(data):
        option, length = data[i], data[i + 1]
        if i + 2 + length > len(data):
            break
        out[option] = bytes(data[i + 2:i + 2 + length])
        i += 2 + length
    return out


@dataclasses.dataclass(frozen=True)
class TagConfig:
    """
    What the phone learned about the tag, as far as it travels.

    Richer than the ACR122U gives us on the same job — UID, SAK and ATQA arrive
    named rather than having to be asked for — but not complete. See ``ats``.
    """

    options: dict[int, bytes] = dataclasses.field(default_factory=dict)

    @classmethod
    def from_stream(cls, data: bytes) -> TagConfig:
        return cls(parse_config_stream(data))

    # ── Type A anticollision ────────────────────────────────────────────────

    @property
    def uid(self) -> bytes:
        return self.options.get(LA_NFCID1, b"")

    @property
    def sak(self) -> int | None:
        raw = self.options.get(LA_SEL_INFO, b"")
        return raw[0] if raw else None

    @property
    def atqa(self) -> bytes:
        """ATQA in reading order, from the two halves NCI keeps apart."""
        low = self.options.get(LA_BIT_FRAME_SDD, b"")
        high = self.options.get(LA_PLATFORM_CONFIG, b"")
        if not low and not high:
            return b""
        return bytes([low[0] if low else 0, high[0] if high else 0])

    @property
    def historical_bytes(self) -> bytes:
        return self.options.get(LI_A_HIST_BY, b"")

    # ── Type B ──────────────────────────────────────────────────────────────

    @property
    def pupi(self) -> bytes:
        return self.options.get(LB_NFCID0, b"")

    @property
    def is_type_b(self) -> bool:
        return bool(self.options.keys() & {LB_NFCID0, LB_SENSB_INFO, LI_B_H_INFO_RSP})

    # ── the ATS, and what is missing from it ────────────────────────────────

    @property
    def ats_is_partial(self) -> bool:
        """
        True when ``ats`` had to invent part of itself.

        Two things never make the trip. **FSCI** is not in the stream at all,
        so T0's low nibble is ``DEFAULT_FSCI`` rather than the card's. **TA(1)**
        is destroyed in transit: NFCGate sends ``findMaxNCIBitRate(TA1)``, a
        lossy code, so the byte cannot be put back and is omitted — meaning a
        reconstructed ATS never advertises a higher bit rate even when the card
        did.

        Everything else — TB(1), TC(1), the historical bytes — is the card's.
        """
        return bool(self.historical_bytes)

    @property
    def ats(self) -> bytes:
        """
        The ATS rebuilt from what survived, or empty if there is nothing to build.

        Callers that print this as an ATR are printing an ATS, the same caveat
        the ACR122U path carries — and here it is a *partial* ATS besides.
        Empty rather than a bare ``TL T0`` when the tag contributed no
        historical bytes: two invented bytes are not an answer.
        """
        hist = self.historical_bytes
        if not hist:
            return b""

        tb1 = self.options.get(LI_A_RATS_TB1, b"")
        tc1 = self.options.get(LI_A_RATS_TC1, b"")

        t0 = DEFAULT_FSCI & 0x0F
        interface = b""
        # TA(1) is deliberately absent — see ats_is_partial.
        if tb1:
            t0 |= _TB1_PRESENT
            interface += tb1[:1]
        if tc1:
            t0 |= _TC1_PRESENT
            interface += tc1[:1]

        body = bytes([t0]) + interface + hist
        return bytes([len(body) + 1]) + body

    # ── for logs and the dashboard ──────────────────────────────────────────

    def describe(self) -> str:
        """One line naming what the phone actually reported."""
        parts = []
        if self.uid:
            parts.append(f"UID {self.uid.hex().upper()}")
        if self.sak is not None:
            parts.append(f"SAK {self.sak:02X}")
        if self.atqa:
            parts.append(f"ATQA {self.atqa.hex().upper()}")
        if self.pupi:
            parts.append(f"PUPI {self.pupi.hex().upper()}")
        if self.historical_bytes:
            parts.append(f"historical bytes {self.historical_bytes.hex().upper()}")
        return ", ".join(parts) or "no recognised tag fields"

    def __bool__(self) -> bool:
        return bool(self.options)
