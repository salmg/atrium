"""
ISO/IEC 14443-4 (ISO-DEP), from the card's side.

The PN532 will do this layer itself — that is what ``PTM_ISO14443_4_PICC_ONLY``
and ``SetParameters`` bit ``0x20`` buy, and it is why ``TgGetData``/``TgSetData``
deal in whole APDUs.  Convenient, and it costs three things the emulator wants:

* **The ATS is the chip's, not ours.**  ``TgInitAsTarget`` takes historical
  bytes and nothing else, so **FWI** — the frame waiting time every terminal
  honours — is decided by firmware.
* **No S(WTX).**  A card that needs longer than FWT is supposed to *ask*.  The
  firmware never asks on our behalf, so a relay that outruns the budget is
  simply dropped.
* **No chaining.**  One response has to fit one frame, which is where the
  262-byte ceiling in ``emulator.py`` comes from.

All three are the same purchase: own the block layer and you set FWI, you can
send S(WTX), and a long response becomes several blocks instead of an error.

This module is that layer and nothing else — no hardware, no sockets, no
threads.  It parses and builds blocks and does the arithmetic; the driver in
``nfc/emulator.py`` moves the bytes.  That split is deliberate: the RF
behaviour cannot be tested from here, but every byte this decides can be.

Bit layouts follow ISO/IEC 14443-4 §7.1, cross-checked against nfcpy's
``IsoDepInitiator`` — chaining is bit 5 (``0x10``), which is easy to
misremember as bit 4.

    I-block   0 0 0 c a d 1 n     c=chaining(0x10) a=CID(0x08) d=NAD(0x04)
    R-block   1 0 1 k a 0 1 n     k=0 ACK / 1 NAK (0x10), a=CID(0x08)
    S-block   1 1 t t a 0 1 0     tt=00 DESELECT, 11 WTX, a=CID(0x08)
"""
from __future__ import annotations

import dataclasses
import enum

# ── carrier arithmetic ───────────────────────────────────────────────────────
#
# fc is 13.56 MHz. Every timing below is a count of carrier cycles turned into
# seconds, which is why the constants look arbitrary.

FC_HZ = 13_560_000

# FWT = (256 * 16 / fc) * 2^FWI  — ISO/IEC 14443-4 §7.2
_FWT_UNIT = 256 * 16 / FC_HZ                    # 302.065 µs

# The tolerance a PCD must add on top of FWT before it may call a timeout.
DELTA_FWT = 49_152 / FC_HZ                      # 3.625 ms

# FSDI/FSCI → frame size in bytes. Index is the nibble; 9..15 are RFU and are
# treated as 256, which is what every reader in practice does.
_FRAME_SIZES = (16, 24, 32, 40, 48, 64, 96, 128, 256)

FWI_MAX = 14            # FWI 15 is RFU; 14 is ~4.9 s, the largest legal FWT
WTXM_MAX = 59           # ISO/IEC 14443-4 §7.3 — WTXM is 6 bits, 1..59

# How long the reader waits for the ATS after sending RATS.
#
# This one is not negotiable and not ours to choose: before the ATS exists
# there is no FWI to read out of it, so §7.2 fixes the budget at FWI 4 plus the
# reader's tolerance. Roughly 8.5 ms, and every other timing on this card is
# generous by comparison — FWI 12 is a hundred and forty times longer.
#
# It is the deadline a host-side implementation is least able to meet, because
# answering RATS costs a USB round trip through the CCID bridge and the driver
# stack, and that is the same order of magnitude. Worth naming so the code can
# check itself against it rather than leaving it to be inferred from a reader
# that quietly asks again.
ATS_DEADLINE = _FWT_UNIT * (2 ** 4) + DELTA_FWT


def fwt_seconds(fwi: int) -> float:
    """Frame waiting time for an FWI, in seconds."""
    if not 0 <= fwi <= 15:
        raise ValueError(f"FWI is 4 bits: 0–15, not {fwi}")
    return _FWT_UNIT * (2 ** fwi)


def frame_size(index: int) -> int:
    """FSDI or FSCI to a byte count."""
    if not 0 <= index <= 15:
        raise ValueError(f"FSDI/FSCI is 4 bits: 0–15, not {index}")
    return _FRAME_SIZES[index] if index < len(_FRAME_SIZES) else 256


def frame_size_index(size: int) -> int:
    """The largest FSCI whose frame fits in `size`."""
    best = 0
    for i, value in enumerate(_FRAME_SIZES):
        if value <= size:
            best = i
    return best


# ── PCB bits ─────────────────────────────────────────────────────────────────

PCB_BLOCK_NUMBER = 0x01
PCB_NAD = 0x04
PCB_CID = 0x08
PCB_CHAINING = 0x10          # I-block only
PCB_NAK = 0x10               # R-block only — same bit, different meaning

_I_BLOCK_BASE = 0x02
_R_BLOCK_BASE = 0xA2
_S_DESELECT_BASE = 0xC2
_S_WTX_BASE = 0xF2

# RATS and PPS are activation frames, not blocks.
RATS_HEAD = 0xE0
PPS_MASK = 0xF0
PPS_HEAD = 0xD0


class BlockType(enum.Enum):
    I = "I"
    R = "R"
    S = "S"


class SType(enum.Enum):
    DESELECT = "DESELECT"
    WTX = "WTX"


class IsoDepError(ValueError):
    """A frame that is not a block this layer understands."""


@dataclasses.dataclass(frozen=True)
class Block:
    """One decoded ISO-DEP block."""

    type: BlockType
    pcb: int
    inf: bytes = b""
    block_number: int = 0
    cid: int | None = None
    nad: int | None = None
    chaining: bool = False
    nak: bool = False
    s_type: SType | None = None

    @property
    def wtxm(self) -> int:
        """The multiplier in an S(WTX), or 0 if this is not one."""
        if self.s_type is not SType.WTX or not self.inf:
            return 0
        return self.inf[0] & 0x3F


def parse_block(raw: bytes) -> Block:
    """
    Decode one block. Raises ``IsoDepError`` on anything that is not one.

    The optional CID and NAD bytes sit between the PCB and INF, in that order,
    and only when their PCB bits say so — read them in the wrong order and the
    first INF byte quietly becomes a NAD.
    """
    if not raw:
        raise IsoDepError("empty frame")

    pcb = raw[0]
    body = raw[1:]

    cid = nad = None
    if pcb & PCB_CID:
        if not body:
            raise IsoDepError("PCB says a CID follows, but the frame ends")
        cid, body = body[0] & 0x0F, body[1:]

    top = pcb & 0xC0
    if top == 0x00:                              # I-block
        if pcb & PCB_NAD:
            if not body:
                raise IsoDepError("PCB says a NAD follows, but the frame ends")
            nad, body = body[0], body[1:]
        if pcb & 0x02 != 0x02:
            raise IsoDepError(f"I-block PCB {pcb:02X} has bit 2 clear")
        return Block(BlockType.I, pcb, bytes(body), pcb & PCB_BLOCK_NUMBER,
                     cid, nad, chaining=bool(pcb & PCB_CHAINING))

    if top == 0x80:                              # R-block
        if pcb & 0xE0 != 0xA0:
            raise IsoDepError(f"{pcb:02X} is not a valid R-block")
        return Block(BlockType.R, pcb, bytes(body), pcb & PCB_BLOCK_NUMBER,
                     cid, None, nak=bool(pcb & PCB_NAK))

    if top == 0xC0:                              # S-block
        kind = pcb & 0x30
        if kind == 0x00:
            s_type = SType.DESELECT
        elif kind == 0x30:
            s_type = SType.WTX
        else:
            raise IsoDepError(f"S-block {pcb:02X} is neither DESELECT nor WTX")
        return Block(BlockType.S, pcb, bytes(body), 0, cid, None, s_type=s_type)

    raise IsoDepError(f"{pcb:02X} is not an ISO-DEP PCB")


def _with_cid(pcb: int, cid: int | None) -> tuple[int, bytes]:
    if cid is None:
        return pcb, b""
    return pcb | PCB_CID, bytes([cid & 0x0F])


def i_block(block_number: int, inf: bytes = b"", *, chaining: bool = False,
            cid: int | None = None) -> bytes:
    pcb = _I_BLOCK_BASE | (block_number & 1) | (PCB_CHAINING if chaining else 0)
    pcb, extra = _with_cid(pcb, cid)
    return bytes([pcb]) + extra + bytes(inf)


def r_block(block_number: int, *, nak: bool = False,
            cid: int | None = None) -> bytes:
    pcb = _R_BLOCK_BASE | (block_number & 1) | (PCB_NAK if nak else 0)
    pcb, extra = _with_cid(pcb, cid)
    return bytes([pcb]) + extra


def s_wtx(wtxm: int, *, cid: int | None = None) -> bytes:
    """
    Ask the terminal for `wtxm` more frame waiting times.

    Both the request and the reader's grant use this shape; the reader may come
    back with a smaller multiplier, and that smaller one is what applies.
    """
    if not 1 <= wtxm <= WTXM_MAX:
        raise ValueError(f"WTXM is 1–{WTXM_MAX}, not {wtxm}")
    pcb, extra = _with_cid(_S_WTX_BASE, cid)
    return bytes([pcb]) + extra + bytes([wtxm & 0x3F])


def s_deselect(*, cid: int | None = None) -> bytes:
    pcb, extra = _with_cid(_S_DESELECT_BASE, cid)
    return bytes([pcb]) + extra


# ── activation ───────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class Rats:
    """A decoded RATS: how big a frame the reader will accept, and its CID."""

    fsdi: int
    cid: int

    @property
    def fsd(self) -> int:
        return frame_size(self.fsdi)


def parse_rats(raw: bytes) -> Rats:
    if len(raw) < 2 or raw[0] != RATS_HEAD:
        raise IsoDepError(
            f"{raw[:2].hex().upper() or '(empty)'} is not a RATS (E0 xx)")
    param = raw[1]
    return Rats(fsdi=(param >> 4) & 0x0F, cid=param & 0x0F)


def is_rats(raw: bytes) -> bool:
    return len(raw) >= 2 and raw[0] == RATS_HEAD


def is_pps(raw: bytes) -> bool:
    return bool(raw) and (raw[0] & PPS_MASK) == PPS_HEAD


def pps_response(raw: bytes) -> bytes:
    """
    Accept a PPS by echoing its first byte.

    Accepting without changing the bit rate is the honest answer here: the
    relay has no reason to want 424 kbps and every reason to keep the timing
    it already reasoned about.
    """
    if not is_pps(raw):
        raise IsoDepError(f"{raw[:1].hex().upper() or '(empty)'} is not a PPS")
    return raw[:1]


@dataclasses.dataclass
class Ats:
    """
    The ATS this card answers a RATS with.

    Every field here is one the PN532's own PICC mode decides for us. ``fwi``
    is the reason this module exists.
    """

    # FSCI 8 is a 256-byte frame — the largest, and what a relay wants.
    fsci: int = 8
    # FWI 12 is ~1.24 s. Comfortably more than a USB round trip to the relayed
    # card, which a card-like 7 or 8 (≈39/77 ms) is not, and still well inside
    # what readers accept. S(WTX) extends from here rather than replacing it.
    fwi: int = 12
    # SFGI is the *start-up* frame guard time: how long the reader must wait
    # after the ATS before sending its first command. It is not FWI, and it is
    # the one field a host-side implementation cannot leave at zero.
    #
    # Zero means the default 302 µs, and the reader takes that literally: one
    # run lost the first command outright and sat in TgGetInitiatorCommand for
    # twenty seconds, the next came back mid-frame to a run of CRC errors. A
    # real card answers SFGI 1 because a real card is ready in microseconds.
    # This is a Python process behind a CCID bridge.
    #
    # The gap it has to cover was 127 ms when this was written, on code that
    # slept between reads; with that removed it is nearer 8 ms. Ten is kept
    # anyway — 309 ms — because it is spent once, after the ATS and never per
    # exchange, and because this bridge's variance is real and large: a plain
    # firmware query with no RF in it has been measured at 108 ms on a link
    # whose median is 2.8 ms. Margin here costs nothing and its absence cost
    # two whole runs.
    sfgi: int = 10
    # TA(1) is omitted rather than invented: it advertises bit rates, and
    # claiming one the relay cannot sustain is worse than staying at 106 kbps.
    ta1: int | None = None
    supports_cid: bool = True
    supports_nad: bool = False
    historical: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.fwi <= FWI_MAX:
            raise ValueError(f"FWI is 0–{FWI_MAX} (15 is RFU), not {self.fwi}")
        if not 0 <= self.fsci <= 15:
            raise ValueError(f"FSCI is 4 bits: 0–15, not {self.fsci}")
        if not 0 <= self.sfgi <= 15:
            raise ValueError(f"SFGI is 4 bits: 0–15, not {self.sfgi}")

    @property
    def fwt(self) -> float:
        return fwt_seconds(self.fwi)

    @property
    def fsc(self) -> int:
        return frame_size(self.fsci)

    def build(self) -> bytes:
        """
        The ATS bytes: TL, T0, the interface bytes present, then Tk.

        T0's high nibble says which of TA(1)/TB(1)/TC(1) follow; TB(1) carries
        FWI and SFGI, which is the whole point.
        """
        t0 = self.fsci & 0x0F
        interface = bytearray()

        if self.ta1 is not None:
            t0 |= 0x10
            interface.append(self.ta1 & 0xFF)

        # TB(1) always: without it the reader assumes FWI 4 (~4.8 ms), which
        # no relay survives.
        t0 |= 0x20
        interface.append(((self.fwi & 0x0F) << 4) | (self.sfgi & 0x0F))

        tc1 = (0x02 if self.supports_cid else 0) | (0x01 if self.supports_nad else 0)
        if tc1:
            t0 |= 0x40
            interface.append(tc1)

        body = bytes([t0]) + bytes(interface) + bytes(self.historical)
        return bytes([len(body) + 1]) + body


def parse_ats(raw: bytes) -> Ats:
    """
    Read an ATS back — for copying a relayed card's own timing onto the
    emulated one, which is the most faithful FWI available.
    """
    if len(raw) < 2:
        raise IsoDepError("an ATS is at least TL and T0")
    length = raw[0]
    if length < 2 or length > len(raw):
        raise IsoDepError(f"ATS says {length} bytes, frame holds {len(raw)}")

    t0 = raw[1]
    pos = 2
    ta1 = tb1 = tc1 = None
    if t0 & 0x10:
        ta1, pos = raw[pos], pos + 1
    if t0 & 0x20:
        tb1, pos = raw[pos], pos + 1
    if t0 & 0x40:
        tc1, pos = raw[pos], pos + 1

    return Ats(
        fsci=t0 & 0x0F,
        fwi=(tb1 >> 4) & 0x0F if tb1 is not None else 4,
        sfgi=tb1 & 0x0F if tb1 is not None else 0,
        ta1=ta1,
        supports_cid=bool(tc1 & 0x02) if tc1 is not None else False,
        supports_nad=bool(tc1 & 0x01) if tc1 is not None else False,
        historical=bytes(raw[pos:length]),
    )


def with_length_byte(ats: bytes) -> bytes:
    """
    An ATS in its on-the-wire shape, whichever shape it arrived in.

    TL counts itself, and the PN532 strips it from ``InListPassiveTarget``
    results — so a card's ATS reaches us starting at T0 while one we built
    ourselves starts at TL. ``parse_ats`` wants the wire shape; this supplies
    it, using the same test ``historical_bytes`` uses, so the two cannot
    disagree about which form they are looking at.
    """
    if not ats:
        return ats
    return ats if ats[0] == len(ats) else bytes([len(ats) + 1]) + ats


def historical_bytes(ats: bytes) -> bytes:
    """
    The historical bytes out of an ATS, whichever shape it arrives in.

    An ATS on the wire starts with TL, which counts itself. The PN532 strips
    that byte from ``InListPassiveTarget`` results, so a card's ATS reaches us
    starting at T0 — and reading one form as the other silently yields nonsense
    rather than an error. TL is recognisable because it equals the length.

    Empty when the tag offered none, which is a legal thing for it to do.
    """
    if len(ats) < 1:
        return b""
    body = ats[1:] if ats[0] == len(ats) else ats
    if not body:
        return b""

    t0 = body[0]
    pos = 1
    for present in (0x10, 0x20, 0x40):          # TA(1), TB(1), TC(1)
        if t0 & present:
            pos += 1
    return bytes(body[pos:]) if pos <= len(body) else b""


def chain(payload: bytes, block_number: int, max_inf: int,
          *, cid: int | None = None) -> list[bytes]:
    """
    Split a response into I-blocks, marking every one but the last as chaining.

    ``max_inf`` is how much INF fits one frame: FSD less the PCB, the CID and
    NAD bytes if present, and the two CRC bytes the chip appends. Getting that
    subtraction wrong is how a response that *looks* like it fits gets
    truncated on the air.

    The block number alternates per block, and an empty payload still sends one
    block — a zero-length response is a legal answer.
    """
    if max_inf < 1:
        raise ValueError(f"no room for INF in a {max_inf}-byte budget")

    pieces = [payload[i:i + max_inf] for i in range(0, len(payload), max_inf)] or [b""]
    out = []
    number = block_number
    for index, piece in enumerate(pieces):
        out.append(i_block(number, piece, chaining=index < len(pieces) - 1, cid=cid))
        number ^= 1
    return out


def max_inf_size(fsd: int, *, cid: bool = False, nad: bool = False) -> int:
    """How many INF bytes fit a frame of `fsd` bytes."""
    # PCB (1) + CID? + NAD? + CRC (2)
    return max(1, fsd - 1 - (1 if cid else 0) - (1 if nad else 0) - 2)
