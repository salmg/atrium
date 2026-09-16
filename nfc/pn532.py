"""
PN532 host protocol.

The ACR122U is a PN532 behind a CCID bridge, so everything the chip can do is
reachable over USB through PC/SC — including the parts the CCID layer does not
expose as ordinary card commands.  This module speaks the chip's own protocol
and knows nothing about how the bytes get there; ``nfc.acr122`` supplies the
link.

Frame format (PN532 User Manual §6.2.1.1):

    00 00 FF  LEN  LCS  TFI  <data…>  DCS  00
              │    │    │              └─ 0x100 - (TFI + sum(data)) & 0xFF
              │    │    └─ 0xD4 host→chip, 0xD5 chip→host
              │    └─ 0x100 - LEN & 0xFF
              └─ TFI + data length

The chip answers a command with an ACK frame (00 00 FF 00 FF 00) and then the
response frame.  Some links hand back both in one read and some do not, so the
parser here takes a buffer and reports what it found rather than assuming a
particular arrangement.
"""
from __future__ import annotations

import dataclasses
import logging
import time

logger = logging.getLogger(__name__)

PREAMBLE = b"\x00\x00\xFF"
ACK = b"\x00\x00\xFF\x00\xFF\x00"
NACK = b"\x00\x00\xFF\xFF\x00\x00"

HOST_TO_PN532 = 0xD4
PN532_TO_HOST = 0xD5

# Commands used here. The chip has many more; these are the ones that matter
# for reading a card and for pretending to be one.
CMD_GET_FIRMWARE_VERSION = 0x02
CMD_SAM_CONFIGURATION = 0x14
CMD_RF_CONFIGURATION = 0x32
CMD_IN_LIST_PASSIVE_TARGET = 0x4A
CMD_IN_DATA_EXCHANGE = 0x40
CMD_IN_RELEASE = 0x52
CMD_SET_PARAMETERS = 0x12
CMD_TG_INIT_AS_TARGET = 0x8C
CMD_TG_GET_DATA = 0x86
CMD_TG_SET_DATA = 0x8E
# The chip's own answer to a response that will not fit one command. Each piece
# goes out with the ISO-DEP chaining bit set and the chip waits for the
# reader's acknowledgement; the last piece goes as an ordinary TgSetData, which
# clears chaining. Without this a target on this bridge cannot answer a READ
# RECORD carrying a certificate — see CardEmulator.set_data.
CMD_TG_SET_META_DATA = 0x94
# The raw target pair. TgGetData/TgSetData carry whole APDUs because the chip
# is doing ISO-DEP; these two carry the blocks themselves, which is what owning
# that layer requires. See nfc/isodep.py.
CMD_TG_GET_INITIATOR_COMMAND = 0x88
CMD_TG_RESPONSE_TO_INITIATOR = 0x90

# SetParameters flags (UM0701-02 §7.2.9). Only the last one matters here.
PARAM_NAD_USED = 0x01
PARAM_DID_USED = 0x02
PARAM_AUTO_ATR_RES = 0x04
PARAM_AUTO_RATS = 0x10
# Off means the chip stops answering RATS and stops framing ISO-DEP, and the
# blocks arrive here instead. PN532 only.
PARAM_14443_4_PICC = 0x20

# What a chip should be holding when nobody has asked for anything unusual.
# There is no ReadParameters command, so the last value written is the only
# record of it — which is why every flag has to be changed by read-modify-write
# on that record rather than by writing a whole byte. Clearing the lot leaves
# AUTO_RATS off, and a chip that no longer sends RATS stops producing an ATS,
# so its *next* use as a reader quietly fails to activate 14443-4 cards.
DEFAULT_PARAMETERS = PARAM_AUTO_ATR_RES | PARAM_AUTO_RATS

# Names, so a failure says which command drew it rather than a bare number.
_COMMAND_NAMES = {
    CMD_GET_FIRMWARE_VERSION: "GetFirmwareVersion",
    CMD_SET_PARAMETERS: "SetParameters",
    CMD_SAM_CONFIGURATION: "SAMConfiguration",
    CMD_RF_CONFIGURATION: "RFConfiguration",
    CMD_IN_DATA_EXCHANGE: "InDataExchange",
    CMD_IN_LIST_PASSIVE_TARGET: "InListPassiveTarget",
    CMD_IN_RELEASE: "InRelease",
    CMD_TG_GET_DATA: "TgGetData",
    CMD_TG_GET_INITIATOR_COMMAND: "TgGetInitiatorCommand",
    CMD_TG_INIT_AS_TARGET: "TgInitAsTarget",
    CMD_TG_SET_DATA: "TgSetData",
    CMD_TG_SET_META_DATA: "TgSetMetaData",
    CMD_TG_RESPONSE_TO_INITIATOR: "TgResponseToInitiator",
}


def command_name(command: int) -> str:
    """"TgInitAsTarget (D4 8C)", or just the bytes when it is not one we know."""
    name = _COMMAND_NAMES.get(command)
    code = f"D4 {command:02X}"
    return f"{name} ({code})" if name else f"command {code}"


# How long to keep asking for an answer, and what to do when none comes.
#
# Most commands are the chip talking to itself and answer within milliseconds.
# The three below wait on the outside world: TgInitAsTarget does not return
# until a terminal is presented, and the two receive commands not until one
# sends something. That wait is longer than a bridged reader will hold a USB
# transaction open, so it has to be handled rather than merely waited out.
#
# On an ACR122U the bridge gives up at about five seconds and **discards the
# command**. Measured, not assumed:
#
#     → FF0000002BD48C…      TgInitAsTarget, no terminal present
#     ← (nothing)            5015 ms later
#     → FFC0000000  ×30      GET RESPONSE, every 250 ms
#     ← (nothing)            on all thirty
#     → FF00000003D41214     SetParameters — answered in 131 ms
#
# Two things follow. There is nothing to collect afterwards, so polling for a
# deferred answer is wasted traffic; and the chip is not wedged by the timeout,
# so the command can simply be sent again. Re-issuing is what these three want:
# TgInitAsTarget re-arms target mode, and the two receive commands are reads
# with no side effect. Nothing else may be re-sent — TgSetData twice would put
# a response on the air twice.
DEFAULT_TIMEOUT = 1.0
RECEIVE_TIMEOUT = 20.0
ARM_TIMEOUT = 60.0

# Between a discarded command and its replacement. Only a guard against a link
# that fails instantly rather than blocking; the reader's own five seconds is
# what actually paces this.
RETRY_PAUSE = 0.05

REISSUABLE = frozenset({
    CMD_TG_INIT_AS_TARGET,
    CMD_TG_GET_DATA,
    CMD_TG_GET_INITIATOR_COMMAND,
})


def default_timeout(command: int) -> float:
    """How long ``call`` waits when the caller did not say."""
    if command == CMD_TG_INIT_AS_TARGET:
        return ARM_TIMEOUT
    if command in REISSUABLE:
        # A terminal mid-session that has said nothing for this long has gone.
        return RECEIVE_TIMEOUT
    return DEFAULT_TIMEOUT


# The other shape: a link that hands over the ACK and the response separately,
# which a directly-attached PN532 does. There the answer *is* coming, so it is
# collected by reading again rather than by re-sending.
POLL_INTERVAL = 0.02
IDLE_POLL_INTERVAL = 0.25
BACKOFF_AFTER = 1.0


def _poll_interval(command: int, waited: float) -> float:
    """
    How long to leave between reads while collecting an acknowledged answer.

    It eases off only for TgInitAsTarget, and only once the wait has clearly
    become a human-scale one. It must not ease off for the two receive
    commands: by the time either is waiting the target is selected and the
    terminal is timing us against the frame waiting time, so a quarter-second
    spent not asking is a quarter-second of a budget measured in milliseconds.
    """
    if command == CMD_TG_INIT_AS_TARGET and waited >= BACKOFF_AFTER:
        return IDLE_POLL_INTERVAL
    return POLL_INTERVAL


# TgInitAsTarget's *reply* mode byte, which is not the layout of the mode
# *parameter* the command takes — and reading one as the other is what rejected
# a perfectly good activation here:
#
#   b2 b1 b0   baud rate   000 = 106 kbps, 001 = 212, 010 = 424
#   b3         activated as an ISO/IEC 14443-4 PICC
#   b4         activated in DEP mode
#   b6 b5      framing     00 = Mifare, 01 = Active, 10 = FeliCa
#
# The parameter's "PICC only" bit is 0x04; the reply's "is a PICC" bit is 0x08.
# A reply of 08 to a command that asked for PICC-only was read as DEP, which
# that command forbids — so the impossibility was the tell.
TARGET_MODE_BAUD = 0x07
TARGET_MODE_PICC = 0x08
TARGET_MODE_DEP = 0x10
TARGET_MODE_FRAMING = 0x60

_BAUD_NAMES = {0: "106 kbps", 1: "212 kbps", 2: "424 kbps"}
_FRAMING_NAMES = {0: "Mifare", 1: "Active", 2: "FeliCa"}


def describe_target_mode(mode: int) -> dict:
    """
    What TgInitAsTarget's reply says the chip actually activated as.

    One decoder, because two of them drifted: the emulator tested one bit and
    the probe printed another, and both were wrong in different ways.
    """
    return {
        "baud": _BAUD_NAMES.get(mode & TARGET_MODE_BAUD, "?"),
        "framing": _FRAMING_NAMES.get((mode & TARGET_MODE_FRAMING) >> 5, "?"),
        "picc": bool(mode & TARGET_MODE_PICC),
        "dep": bool(mode & TARGET_MODE_DEP),
    }


def summarise_target_mode(mode: int) -> str:
    """"106 kbps, Mifare framing, ISO-DEP on" — for a log line."""
    seen = describe_target_mode(mode)
    return (f"{seen['baud']}, {seen['framing']} framing, "
            f"ISO-DEP {'on' if seen['picc'] else 'off'}"
            + (", DEP" if seen["dep"] else ""))


# 106 kbps ISO/IEC 14443 type A — what a contactless EMV card answers on.
BAUD_106A = 0x00

# The chip's own buffer caps a single exchange. Longer APDUs need chaining,
# which this does not implement — it reports the limit instead of truncating.
MAX_FRAME_DATA = 262

# A normal information frame carries a one-byte length, so TFI plus body cannot
# exceed 255 — and that, not the 262-byte buffer, is what actually binds. The
# two are close enough that using the wrong one is easy and the symptom is
# misleading: a payload in the gap passes the buffer check and then dies deep in
# build_frame talking about extended frames, which is not the operator's problem
# and says nothing about chaining.
MAX_NORMAL_FRAME = 255

# LEN=FF LCS=FF where a normal frame's length byte would be. Not confusable
# with a NACK (FF 00) or with a 255-byte normal frame, whose LCS is 01.
EXTENDED_MARKER = b"\xFF\xFF"
MAX_EXTENDED_FRAME = 0xFFFF


def max_payload(header_bytes: int) -> int:
    """
    How many payload bytes fit after a command's own header.

    ``header_bytes`` counts everything build_frame will see before the payload:
    the TFI and the command byte always, plus any fixed arguments the command
    carries ahead of it.
    """
    return MAX_NORMAL_FRAME - header_bytes


class PN532Error(RuntimeError):
    """The chip refused a command or answered something unusable."""


class NoAnswer(PN532Error):
    """
    A command ran out of time without the chip ever framing a reply.

    Its own class because for most commands this is a fault, and for the two
    that wait on somebody else — a terminal arriving, a terminal speaking — it
    is an ordinary outcome the caller wants to handle rather than report.
    """


class Cancelled(PN532Error):
    """
    The caller asked to stop while a command was still being waited on.

    Not a failure. Waiting for a terminal is the one thing here that can take
    minutes, and an operator who presses Ctrl-C during it should get a relay
    that ends rather than a traceback about the chip.
    """


# ── Framing ───────────────────────────────────────────────────────────────────

def build_frame(data: bytes) -> bytes:
    """
    Wrap a command (TFI + body) in an information frame, normal or extended.

    Extended frames are not a nicety. A contactless EMV READ RECORD carrying an
    ICC public key certificate answers 254 bytes, and the chip hands that back
    as ``D5 41 <status>`` plus the lot — 259 bytes, four past what a normal
    frame's single length byte can describe. This function used to refuse, so
    the reader's own answer was thrown away on the doorstep and the terminal
    got 6F00 to the one command every real transaction depends on.

    A normal frame carries the length in one byte; an extended frame announces
    itself with ``FF FF`` where that byte would be and carries it in two. The
    marker cannot be mistaken for a NACK (``FF 00``) or for a normal frame of
    255 bytes, whose LCS would have to be ``01``.
    """
    if not data:
        raise PN532Error("Cannot frame an empty command")
    dcs = (0x100 - sum(data)) & 0xFF
    length = len(data)
    if length <= MAX_NORMAL_FRAME:
        lcs = (0x100 - length) & 0xFF
        return PREAMBLE + bytes([length, lcs]) + data + bytes([dcs, 0x00])
    if length > MAX_EXTENDED_FRAME:
        raise PN532Error(
            f"{length} bytes exceeds the {MAX_EXTENDED_FRAME} an extended "
            f"frame can describe")
    high, low = length >> 8, length & 0xFF
    lcs = (0x100 - ((high + low) & 0xFF)) & 0xFF
    return (PREAMBLE + EXTENDED_MARKER + bytes([high, low, lcs])
            + data + bytes([dcs, 0x00]))


def _frame_body_span(rest: bytes) -> tuple[int, int] | None:
    """
    Where an information frame's TFI-and-payload sits, and how long it is.

    ``(start, length)``, or None when the header is not all there yet. The one
    place that knows how the two frame shapes differ, so the parser and the
    unframer cannot come to different conclusions about the same bytes.
    """
    if len(rest) < 5:
        return None
    if rest[3:5] == EXTENDED_MARKER:
        if len(rest) < 8:
            return None
        high, low, lcs = rest[5], rest[6], rest[7]
        if (high + low + lcs) & 0xFF:
            raise PN532Error(
                f"Extended frame length checksum failed "
                f"(LEN={high:02X}{low:02X} LCS={lcs:02X})")
        return 8, (high << 8) | low
    length, lcs = rest[3], rest[4]
    if (length + lcs) & 0xFF:
        raise PN532Error(
            f"Frame length checksum failed (LEN={length:02X} LCS={lcs:02X})")
    return 5, length


def build_command(command: int, body: bytes = b"") -> bytes:
    return build_frame(bytes([HOST_TO_PN532, command]) + body)


def unframe(frame: bytes) -> bytes:
    """
    The payload out of a normal information frame — the inverse of build_frame.

    Some links carry whole frames and some carry only the payload, because
    their own microcontroller does the framing. The ACR122U is the second kind,
    so its link has to undo this before sending. Keeping the inverse next to
    build_frame is what stops the two drifting apart.
    """
    start = frame.find(PREAMBLE)
    if start < 0 or len(frame) - start < 7:
        raise PN532Error(
            f"Not an information frame: {frame[:8].hex().upper() or '(empty)'}")
    rest = frame[start:]
    span = _frame_body_span(rest)
    if span is None:
        raise PN532Error(
            f"Frame header is incomplete: {rest[:8].hex().upper()}")
    body_at, length = span
    if len(rest) < body_at + length + 1:
        raise PN532Error(
            f"Frame says {length} bytes, only {len(rest) - body_at - 1} present")
    return rest[body_at:body_at + length]


@dataclasses.dataclass
class ParsedFrame:
    kind: str            # ack | nack | error | data | incomplete
    data: bytes = b""    # TFI-stripped payload, for kind == data
    consumed: int = 0

    @property
    def is_data(self) -> bool:
        return self.kind == "data"


def parse_frame(buf: bytes) -> ParsedFrame:
    """
    Read the first frame out of a buffer.

    Reports rather than raises for a short buffer, because a link that returns
    the ACK and the response in separate reads is normal, not an error.
    """
    if len(buf) < 6:
        return ParsedFrame("incomplete")

    start = buf.find(PREAMBLE)
    if start < 0:
        return ParsedFrame("incomplete")
    rest = buf[start:]
    if len(rest) < 6:
        return ParsedFrame("incomplete")

    if rest.startswith(ACK):
        return ParsedFrame("ack", consumed=start + len(ACK))
    if rest.startswith(NACK):
        return ParsedFrame("nack", consumed=start + len(NACK))

    try:
        span = _frame_body_span(rest)
    except PN532Error as exc:
        raise PN532Error(
            f"{exc} — the link is out of sync or this is not a PN532 response"
        ) from exc
    if span is None:
        return ParsedFrame("incomplete")
    body_at, length = span
    if length == 0:
        return ParsedFrame("error", consumed=start + 6)

    end = body_at + length
    if len(rest) < end + 1:
        return ParsedFrame("incomplete")

    body = rest[body_at:end]
    dcs = rest[end]
    if (sum(body) + dcs) & 0xFF:
        raise PN532Error("Frame data checksum failed — the response is corrupt")

    if body[0] != PN532_TO_HOST:
        raise PN532Error(
            f"Expected a chip-to-host frame (TFI D5), got {body[0]:02X}")

    # +1 for DCS, +1 for the postamble when the link included it.
    consumed = start + end + 1 + (1 if len(rest) > end + 1 else 0)
    return ParsedFrame("data", data=body[1:], consumed=consumed)


# ── Chip ──────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class Target:
    """One contactless card the chip found in the field."""
    number: int
    atqa: bytes
    sak: int
    uid: bytes
    ats: bytes = b""

    @property
    def is_iso14443_4(self) -> bool:
        """Bit 5 of SAK means the card speaks ISO 14443-4 — i.e. APDUs."""
        return bool(self.sak & 0x20)

    def __str__(self) -> str:
        return (f"UID {self.uid.hex().upper()} "
                f"ATQA {self.atqa.hex().upper()} SAK {self.sak:02X}"
                + (f" ATS {self.ats.hex().upper()}" if self.ats else ""))


class PN532:
    """
    The chip, over whatever link it is behind.

    ``link`` needs one method: ``exchange(frame: bytes) -> bytes``, sending a
    built frame and returning whatever came back.
    """

    def __init__(self, link) -> None:
        self.link = link
        # The chip cannot be asked what its parameters are, so this is the
        # record. open_pn532 writes the default at connect so it is true.
        self.parameters = DEFAULT_PARAMETERS
        # How the last target-mode read ended: 0x29 for a deliberate release
        # by the initiator, 0x2B for the field going away. Both hand the
        # caller None, and the difference between "the terminal decided to
        # stop" and "the card left the antenna" is the whole diagnosis.
        self.release_status: int | None = None

    # ── plumbing ─────────────────────────────────────────────────────────────

    def call(self, command: int, body: bytes = b"",
             timeout: float | None = None, keep_waiting=None,
             on_retry=None) -> bytes:
        """
        Send a command and return the response body, without the 0xD5 or the
        echoed command byte.

        The answer does not always come back with the send, and the two reasons
        it might not want opposite responses:

        * **The chip acknowledged and is working on it.** The answer is
          genuinely coming, so it is collected by reading again.
        * **Nothing came back at all.** On a bridged reader that is the
          bridge's own timeout expiring, which discards the command with it —
          so there is nothing to collect, and the thing to do is send it again.

        Telling them apart is what the ACK is for, and it is sticky: once the
        chip has acknowledged, a quiet read means "not finished", never "start
        over". Only the commands in ``REISSUABLE`` are ever re-sent.

        ``timeout`` is how long to keep trying; omitted, it comes from
        ``default_timeout`` — commands that wait on something outside the chip
        get a deadline measured in the units their wait actually takes.

        ``keep_waiting`` is consulted between attempts and stops the wait when
        it returns false. A command that can block for minutes has to be
        interruptible, or ``stop()`` means nothing until the deadline.

        ``on_retry(attempt, waited)`` is called before each re-send. Re-arming
        happens every five seconds or so and is otherwise completely silent,
        which leaves an operator with a working relay and a broken one looking
        identical — so the caller gets told, and decides what to say.
        """
        if timeout is None:
            timeout = default_timeout(command)
        began = time.monotonic()
        deadline = began + timeout
        request = build_command(command, body)

        raw = self.link.exchange(request)
        acknowledged = False
        attempts = 1

        while True:
            frame = parse_frame(raw)
            # An ACK is only an acknowledgement; the answer is in what follows.
            if frame.kind in ("ack", "nack"):
                acknowledged = True
                remainder = raw[frame.consumed:]
                frame = (parse_frame(remainder) if remainder
                         else ParsedFrame("incomplete"))
            if frame.kind != "incomplete":
                break

            now = time.monotonic()
            if now >= deadline:
                break
            if keep_waiting is not None and not keep_waiting():
                raise Cancelled(
                    f"Stopped while waiting for {command_name(command)}")

            if acknowledged:
                # Read first, pace afterwards. Sleeping before the first
                # collection spent a whole poll interval — 20 ms, half a real
                # card's entire frame waiting time — on an answer the chip may
                # already have had ready.
                raw = self.link.exchange(b"")           # collect the answer
                if not raw:
                    time.sleep(min(_poll_interval(command, now - began),
                                   max(0.0, deadline - time.monotonic())))
            elif command in REISSUABLE:
                time.sleep(min(RETRY_PAUSE, deadline - now))
                attempts += 1
                logger.debug("%s went unanswered; sending it again (%d)",
                             command_name(command), attempts)
                if on_retry is not None:
                    on_retry(attempts, now - began)
                raw = self.link.exchange(request)       # the reader dropped it
            else:
                break

        if frame.kind == "error":
            raise PN532Error(
                f"The chip reported an error for {command_name(command)}")
        if not frame.is_data:
            raise NoAnswer(self._silence(command, timeout, raw, attempts))

        data = frame.data
        expected = (command + 1) & 0xFF
        if data and data[0] == expected:
            return data[1:]
        raise PN532Error(
            f"Response was for command {data[0]:02X} rather than {expected:02X}")

    def _silence(self, command: int, waited: float, last: bytes,
                 attempts: int = 1) -> str:
        """
        What to say when a command never produced a frame.

        The link knows things the chip layer cannot — which reader this is and
        what its bridge will carry — so it gets to add to the message if it has
        anything to add.
        """
        seen = (f"last reply {len(last)} bytes: {last[:16].hex().upper()}"
                if last else "the reader answered nothing at all")
        tries = f", {attempts} attempts" if attempts > 1 else ""
        message = (f"{command_name(command)} produced no response in "
                   f"{waited:.1f}s{tries} ({seen}).")
        hint = getattr(self.link, "silence_hint", None)
        if hint is not None:
            try:
                extra = hint(command)
            except Exception:                          # noqa: BLE001
                extra = ""
            if extra:
                message += "\n" + extra
        return message

    # ── identity and setup ───────────────────────────────────────────────────

    def firmware_version(self) -> dict:
        data = self.call(CMD_GET_FIRMWARE_VERSION)
        if len(data) < 4:
            raise PN532Error("Short firmware response")
        chip = {0x32: "PN532"}.get(data[0], f"0x{data[0]:02X}")
        return {"chip": chip, "version": f"{data[1]}.{data[2]}",
                "support": data[3]}

    def sam_configuration(self, mode: int = 0x01, timeout: int = 0x14,
                          use_irq: bool = False) -> None:
        """
        Put the security access module in normal mode.

        Mode 0x01 is 'normal' — no SAM, the chip acts alone. The ACR122U needs
        this before it will do anything useful in raw mode.
        """
        self.call(CMD_SAM_CONFIGURATION,
                  bytes([mode, timeout, 0x01 if use_irq else 0x00]))

    def set_parameters(self, flags: int) -> None:
        """
        Write the chip's behaviour flags outright.

        Prefer ``update_parameters``: this byte holds several unrelated
        settings, and writing it whole silently reverts whichever ones the
        caller was not thinking about.
        """
        flags &= 0xFF
        self.call(CMD_SET_PARAMETERS, bytes([flags]))
        self.parameters = flags

    def update_parameters(self, *, set_bits: int = 0, clear_bits: int = 0) -> int:
        """
        Change only the flags named, leaving the others as they are.

        Chiefly ``PARAM_14443_4_PICC``: with it on, the PN532 answers RATS and
        frames ISO-DEP itself and ``TgGetData`` yields APDUs; with it off, the
        blocks come through ``TgGetInitiatorCommand`` and framing is ours.
        ``PARAM_AUTO_RATS`` is the one that must survive that change — without
        it the chip stops activating 14443-4 cards when it is next a reader.
        """
        wanted = (self.parameters | set_bits) & ~clear_bits & 0xFF
        if wanted != self.parameters:
            self.set_parameters(wanted)
        return wanted

    def set_retries(self, passive: int = 0xFF) -> None:
        """
        How hard to try when looking for a card. 0xFF is 'forever', which is
        wrong for an interactive scan — the caller usually wants a small number
        so a missing card returns rather than hangs.
        """
        self.call(CMD_RF_CONFIGURATION, bytes([0x05, 0xFF, 0x01, passive]))

    # ── initiator (reader) mode ──────────────────────────────────────────────

    def list_passive_targets(self, limit: int = 1,
                             baud: int = BAUD_106A) -> list[Target]:
        """Look for cards in the field. Empty list when there are none."""
        data = self.call(CMD_IN_LIST_PASSIVE_TARGET, bytes([limit, baud]))
        if not data:
            return []

        count = data[0]
        targets: list[Target] = []
        pos = 1
        for _ in range(count):
            if pos + 5 > len(data):
                break
            number = data[pos]
            atqa = data[pos + 1:pos + 3]
            sak = data[pos + 3]
            uid_len = data[pos + 4]
            pos += 5
            uid = data[pos:pos + uid_len]
            pos += uid_len

            ats = b""
            if pos < len(data):
                ats_len = data[pos]
                if ats_len:
                    # The length byte counts itself.
                    ats = data[pos + 1:pos + ats_len]
                    pos += ats_len
                else:
                    pos += 1
            targets.append(Target(number=number, atqa=atqa, sak=sak,
                                  uid=uid, ats=ats))
        return targets

    def data_exchange(self, apdu: bytes, target: int = 1) -> bytes:
        """Send one APDU to a selected card and return its response."""
        # TFI + InDataExchange + target byte precede the APDU in the frame.
        limit = max_payload(3)
        if len(apdu) > limit:
            raise PN532Error(
                f"{len(apdu)}-byte APDU exceeds what one exchange carries "
                f"({limit}); command chaining is not implemented")
        data = self.call(CMD_IN_DATA_EXCHANGE, bytes([target]) + apdu)
        if not data:
            raise PN532Error("Empty response to InDataExchange")

        status = status_of(data[0])
        if status == STATUS_NO_CONTEXT:
            raise TargetLost(
                f"InDataExchange failed: {describe_status(status)} — the chip "
                f"has no activated target to talk to")
        if status != 0x00:
            raise PN532Error(f"InDataExchange failed: {describe_status(status)}")
        return data[1:]

    # ── target (card) mode, raw ───────────────────────────────────────────────

    def get_initiator_command(self) -> bytes | None:
        """
        One raw frame from the terminal, or None when it has gone away.

        The counterpart of ``TgGetData`` for a target that is doing its own
        ISO-DEP: what comes back is the block — PCB and all — not an APDU.
        """
        data = self.call(CMD_TG_GET_INITIATOR_COMMAND)
        if not data:
            raise PN532Error("TgGetInitiatorCommand returned nothing")
        status = status_of(data[0])
        if status != 0x00:
            if status in (STATUS_RELEASED, STATUS_FIELD_OFF):
                # Both end the session and both come back as None, but they
                # are opposite diagnoses — see release_status.
                self.release_status = status
                return None
            if status in RECOVERABLE_RF:
                raise RFError(
                    f"TgGetInitiatorCommand: {describe_status(status)}", status)
            raise PN532Error(
                f"TgGetInitiatorCommand failed: {describe_status(status)}")
        return data[1:]

    def response_to_initiator(self, frame: bytes) -> None:
        """Send one raw frame back. The chip appends the CRC."""
        limit = max_payload(2)
        if len(frame) > limit:
            raise PN532Error(
                f"{len(frame)}-byte frame exceeds what one exchange carries "
                f"({limit})")
        data = self.call(CMD_TG_RESPONSE_TO_INITIATOR, bytes(frame))
        if not data:
            raise PN532Error(
                "TgResponseToInitiator came back without a status byte, so "
                "whether the frame reached the reader is unknown")
        if status_of(data[0]) != 0x00:
            raise PN532Error(
                f"TgResponseToInitiator failed: {describe_status(status_of(data[0]))}")

    def release(self, target: int = 1) -> None:
        try:
            self.call(CMD_IN_RELEASE, bytes([target]))
        except PN532Error:
            pass          # releasing a target that already went away is fine


# Statuses that mean a frame was mangled on the air rather than that anything
# is wrong with the link. ISO/IEC 14443-4 expects the peer to retry — a PCD
# re-sends, a PICC stays silent and waits — so tearing the session down on one
# of these throws away a transaction that was about to recover on its own.
# Bits 6 and 7 of a PN532 status byte are flags, not part of the error code —
# libnfc's pn53x_transceive stores `abtRx[0] & 0x3f` for exactly this reason.
# Comparing the whole byte turns a success carrying a flag into an unknown
# status and a hard failure.
STATUS_CODE = 0x3F


def status_of(byte: int) -> int:
    """The error code out of a status byte, with the flag bits masked off."""
    return byte & STATUS_CODE


# The two ways a target-mode read ends the session. Both hand the caller None
# and they are opposite diagnoses, so the code that ends a relay needs to say
# which — see _RelayCore._why_it_ended.
STATUS_RELEASED = 0x29    # the initiator deselected us: a decision it made
STATUS_FIELD_OFF = 0x2B   # the RF field went away: it lost us

# Reader mode's counterpart: the chip was asked to talk to a target it does not
# have. The one chip failure a caller can actually do something about.
STATUS_NO_CONTEXT = 0x27

RECOVERABLE_RF = frozenset({
    0x02,   # CRC error
    0x03,   # parity error
    0x04,   # bit-count error during anticollision
    0x05,   # framing error
    0x06,   # abnormal bit collision
    0x09,   # RF buffer overflow
    0x0B,   # RF protocol error
})


class TargetLost(PN532Error):
    """
    The card the chip had activated is no longer activated.

    Distinct from PN532Error because it is the one failure a caller can fix.
    On an ACR122U it usually is not the card leaving the field: the reader's
    own polling loop runs independently of the escape channel and redoes
    anticollision underneath whoever is using it. Activating again recovers,
    at the cost of resetting the card to the master file.
    """


class RFError(PN532Error):
    """One frame did not survive the air. The peer will try again."""

    def __init__(self, message: str, status: int) -> None:
        super().__init__(message)
        self.status = status


# ── Status codes ──────────────────────────────────────────────────────────────

_STATUS = {
    0x00: "success",
    0x01: "timeout — the card did not answer in time",
    0x02: "CRC error",
    0x03: "parity error",
    0x04: "bit-count error during anticollision",
    0x05: "framing error",
    0x06: "abnormal bit collision",
    0x07: "buffer too small",
    0x09: "RF buffer overflow",
    0x0A: "the card did not enter the field in time",
    0x0B: "RF protocol error",
    0x0D: "overheated",
    0x0E: "internal buffer overflow",
    0x10: "invalid parameter",
    0x12: "the chip does not support that command",
    0x13: "the card answered with bad data",
    0x14: "authentication failed",
    0x23: "wrong UID check byte",
    0x25: "invalid device state",
    0x26: "the operation is not allowed in this configuration",
    0x27: "the command makes no sense in the current context",
    0x29: "the emulated target was released by the initiator",
    0x2A: "the card is no longer the one that was selected",
    0x2B: "the card left the field",
    0x2C: "mismatched NFCID3 during initiator/target negotiation",
    0x2D: "over-current detected",
    0x2E: "missing NAD",
}


def describe_status(code: int) -> str:
    return _STATUS.get(code, f"unknown status 0x{code:02X}")
