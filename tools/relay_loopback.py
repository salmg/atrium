#!/usr/bin/env python3
"""
The whole contactless relay, end to end, with no hardware in it.

    terminal (this file)  ──►  CardEmulator  ──►  CardTransport  ──►  card
                                (the real one)                     (this file)

``atrium.py nfc emulate`` needs two ACR122U readers, a real card and a real
terminal, and when it ends after one exchange there is no way to tell a relay
bug from a terminal that simply decided to stop.  This runs the *same*
``CardEmulator`` against a terminal and a card that are both in this process,
so the relay can be exercised, stepped through and regression-tested on a
laptop with nothing plugged in.

What is real here: ``nfc.emulator.CardEmulator``, ``nfc.pn532.PN532`` and its
framing, the mutation hooks, the session/re-arm loop and every diagnostic the
live command prints.  What is simulated: the link under the PN532 (which
answers as a terminal instead of as a chip) and the card at the far end.

The terminal is *reactive*, not scripted.  It reads the PPSE answer, picks an
AID out of it, builds GET PROCESSING OPTIONS from the card's own PDOL and
reads the records the AFL points at.  So if the relay corrupts a byte, the
terminal notices in the same way a real one would, rather than marching
through a fixed script.

    python3 tools/relay_loopback.py                 # a full transaction
    python3 tools/relay_loopback.py --stop-after 1  # the PPSE-then-deselect trace
    python3 tools/relay_loopback.py --card-delay 200 --verbose   # blow the budget

Authorised testing only.  The card here is synthetic and the PAN is a publicly
published Mastercard test number.
"""
from __future__ import annotations

import argparse
import logging
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nfc.emulator import CardEmulator, EmulatedCard          # noqa: E402
from nfc.pn532 import (                                       # noqa: E402
    ACK,
    CMD_GET_FIRMWARE_VERSION,
    CMD_RF_CONFIGURATION,
    CMD_SAM_CONFIGURATION,
    CMD_SET_PARAMETERS,
    CMD_TG_GET_DATA,
    CMD_TG_INIT_AS_TARGET,
    CMD_TG_SET_DATA,
    PN532,
    PN532_TO_HOST,
    STATUS_RELEASED,
    build_frame,
    unframe,
)
from transport.base import CardTransport                      # noqa: E402

logger = logging.getLogger("relay.loopback")

# The mode byte a real TgInitAsTarget answers with when a terminal activates
# the target at 106 kbps with Mifare framing and ISO-DEP on. The same value
# the live run reports as "mode byte 08".
ACTIVATED_AS_PICC = b"\x08"


# ── BER-TLV, only as much as a terminal needs ────────────────────────────────

def tlv_walk(data: bytes):
    """Yield (tag, value) for one level of a BER-TLV blob, skipping padding."""
    i = 0
    while i < len(data):
        if data[i] in (0x00, 0xFF):
            i += 1
            continue
        start = i
        first = data[i]
        i += 1
        if first & 0x1F == 0x1F:                    # multi-byte tag
            while i < len(data) and data[i] & 0x80:
                i += 1
            i += 1
        tag = data[start:i]
        if i >= len(data):
            return
        length = data[i]
        i += 1
        if length & 0x80:                           # multi-byte length
            n = length & 0x7F
            length = int.from_bytes(data[i:i + n], "big")
            i += n
        value = data[i:i + length]
        i += length
        yield tag, value


def tlv_find(data: bytes, tag: bytes) -> bytes | None:
    """The first value carrying `tag`, at any depth."""
    for found, value in tlv_walk(data):
        if found == tag:
            return value
        if found[0] & 0x20:                         # constructed — go in
            deeper = tlv_find(value, tag)
            if deeper is not None:
                return deeper
    return None


def dol_pairs(dol: bytes):
    """Yield (tag, length) from a DOL, which carries no values."""
    i = 0
    while i < len(dol):
        start = i
        first = dol[i]
        i += 1
        if first & 0x1F == 0x1F:
            while i < len(dol) and dol[i] & 0x80:
                i += 1
            i += 1
        tag = dol[start:i]
        if i >= len(dol):
            return
        yield tag, dol[i]
        i += 1


# ── the card at the far end ──────────────────────────────────────────────────

class ScriptedCard(CardTransport):
    """
    A card that answers by lookup, so the terminal may ask in any order.

    A recorded capture replays in sequence and desynchronises the moment a
    reactive terminal asks something the recording did not contain.  Keying on
    the command instead means the terminal drives and the card just answers,
    which is what a card does.
    """

    def __init__(self, responses: dict[str, str], atr: bytes = b"",
                 uid: bytes = b"", delay: float = 0.0) -> None:
        self.responses = {bytes.fromhex(k.replace(" ", "")):
                          bytes.fromhex(v.replace(" ", ""))
                          for k, v in responses.items()}
        self._atr = atr
        self.uid = uid
        self.delay = delay
        self.received: list[bytes] = []
        self.answered: list[bytes] = []
        self.unknown: list[bytes] = []
        self.connected = False

    def connect(self) -> None:
        self.connected = True

    def get_atr(self) -> bytes:
        return self._atr

    def transmit(self, apdu: bytes) -> bytes:
        if self.delay:
            time.sleep(self.delay)
        apdu = bytes(apdu)
        self.received.append(apdu)
        response = self.responses.get(apdu)
        if response is None:
            self.unknown.append(apdu)
            response = b"\x6A\x82"                  # file or application not found
        self.answered.append(response)
        return response

    def disconnect(self) -> None:
        self.connected = False


# The card the trace in the bug report came from: a contactless Debit
# Mastercard. The identity is that card's, read off the rig; the PPSE answer is
# byte for byte what it gave. The rest is a plausible, well-formed continuation
# with a published test PAN, so a whole transaction can run.
MASTERCARD = {
    # SELECT 2PAY.SYS.DDF01
    "00A404000E325041592E5359532E444446303100":
        "6F35840E325041592E5359532E4444463031A523BF0C20611E4F07A0000000041010"
        "50104465626974204D6173746572636172648701019000",
    # SELECT A0000000041010
    "00A4040007A000000004101000":
        "6F268407A0000000041010A51B50104465626974204D61737465726361726487"
        "01019F38039F66049000",
    # GET PROCESSING OPTIONS, with TTQ 36000000 in the PDOL
    "80A8000006830436000000 00".replace(" ", ""):
        "770A8202198094040801010090 00".replace(" ", ""),
    # READ RECORD, SFI 1 record 1
    "00B2010C00":
        "7014 5A08 5413339000001513 5F2403 291231 5F3401 00 9000".replace(" ", ""),
}

MASTERCARD_ATS = bytes.fromhex("78007002534C4A0130502310")
MASTERCARD_UID = bytes.fromhex("0586CC7A956300")


# ── the terminal ─────────────────────────────────────────────────────────────

class ContactlessKernel:
    """
    A payment terminal, reduced to the decisions that matter to a relay.

    It does what an EMV contactless kernel does in the order it does it, and
    stops for the reasons a real one stops: a status word that is not 9000, a
    PPSE with no application it recognises, or a deliberate end once it has
    what it came for.  ``stop_after`` forces the third one early, which is how
    the "read the PPSE and deselect" trace is reproduced on demand.
    """

    PPSE = bytes.fromhex("00A404000E325041592E5359532E444446303100")

    def __init__(self, stop_after: int | None = None,
                 ttq: bytes = b"\x36\x00\x00\x00") -> None:
        self.stop_after = stop_after
        self.ttq = ttq
        self.sent: list[bytes] = []
        self.received: list[bytes] = []
        self.notes: list[str] = []
        self._queue: list[bytes] = [self.PPSE]
        self._done = False

    # what the emulator pulls out of TgGetData
    def next_command(self) -> bytes | None:
        if self._done:
            return None
        if self.stop_after is not None and len(self.sent) >= self.stop_after:
            self.notes.append(
                f"deselecting after {len(self.sent)} exchange(s) — asked to, "
                f"which is the shape a kernel makes when it is only looking")
            self._done = True
            return None
        if not self._queue:
            self.notes.append("nothing left to ask — deselecting")
            self._done = True
            return None
        command = self._queue.pop(0)
        self.sent.append(command)
        return command

    # what the emulator pushes in through TgSetData
    def give_response(self, response: bytes) -> None:
        self.received.append(response)
        previous = self.sent[-1]
        if len(response) < 2:
            self.notes.append("response too short to carry a status word")
            self._done = True
            return
        sw, body = response[-2:], response[:-2]
        if sw != b"\x90\x00":
            self.notes.append(
                f"stopping: {previous[:4].hex().upper()} answered "
                f"{sw.hex().upper()}")
            self._done = True
            return
        if previous == self.PPSE:
            self._after_ppse(body)
        elif previous[1] == 0xA4:
            self._after_select_aid(body)
        elif previous[:2] == b"\x80\xA8":
            self._after_gpo(body)
        elif previous[:2] == b"\x00\xB2":
            pass                                    # records just accumulate

    def _after_ppse(self, body: bytes) -> None:
        aid = tlv_find(body, b"\x4F")
        if not aid:
            self.notes.append(
                "the PPSE carried no application identifier (tag 4F) — "
                "nothing to select, so the terminal stops here")
            self._done = True
            return
        label = tlv_find(body, b"\x50")
        self.notes.append(
            f"chose AID {aid.hex().upper()}"
            + (f" ({label.decode('ascii', 'replace')})" if label else ""))
        self._queue.append(bytes([0x00, 0xA4, 0x04, 0x00, len(aid)]) + aid
                           + b"\x00")

    def _after_select_aid(self, body: bytes) -> None:
        pdol = tlv_find(body, b"\x9F\x38") or b""
        data = b""
        for tag, length in dol_pairs(pdol):
            if tag == b"\x9F\x66":                  # terminal transaction qualifiers
                value = self.ttq[:length].ljust(length, b"\x00")
            else:
                value = bytes(length)
            data += value
        field = b"\x83" + bytes([len(data)]) + data
        self.notes.append(
            f"built GPO from a {len(pdol)}-byte PDOL"
            if pdol else "no PDOL — sending an empty GPO")
        self._queue.append(b"\x80\xA8\x00\x00" + bytes([len(field)]) + field
                           + b"\x00")

    def _after_gpo(self, body: bytes) -> None:
        afl = tlv_find(body, b"\x94")
        if afl is None and body[:1] == b"\x80":     # format 1
            afl = body[2 + 2:] if len(body) > 4 else b""
        if not afl:
            self.notes.append("no application file locator — nothing to read")
            self._done = True
            return
        for i in range(0, len(afl) - 3, 4):
            sfi = afl[i] >> 3
            first, last = afl[i + 1], afl[i + 2]
            for record in range(first, last + 1):
                self._queue.append(
                    bytes([0x00, 0xB2, record, (sfi << 3) | 0x04, 0x00]))
        self.notes.append(
            f"AFL {afl.hex().upper()} — reading "
            f"{len(self._queue)} record(s)")


# ── the link, which is really the terminal ───────────────────────────────────

class LoopbackLink:
    """
    Answers PN532 frames the way a chip would, out of a terminal's decisions.

    ``PN532`` talks to this exactly as it talks to an ACR122U over the vendor
    escape: it hands over a framed command and reads a framed reply.  Target
    mode is where the substitution shows — TgGetData hands back whatever the
    terminal wants to ask next, and TgSetData gives the terminal its answer.
    """

    _ACKNOWLEDGED = {CMD_SET_PARAMETERS, CMD_SAM_CONFIGURATION,
                     CMD_RF_CONFIGURATION}

    def __init__(self, kernels: list[ContactlessKernel],
                 bridge_delay: float = 0.0) -> None:
        self.kernels = kernels
        self.bridge_delay = bridge_delay
        self.index = 0
        self.polls = 0
        self.sent: list[bytes] = []
        self.init_bodies: list[bytes] = []

    # ACR122Link's shape, for anything that pokes the reader directly
    def peripheral(self, apdu: bytes):
        return b"", 0x90, 0x00

    def close(self) -> None:
        pass

    def _current(self) -> ContactlessKernel | None:
        if self.index >= len(self.kernels):
            return None
        return self.kernels[self.index]

    def exchange(self, frame: bytes) -> bytes:
        if self.bridge_delay:
            time.sleep(self.bridge_delay)
        if not frame:
            self.polls += 1
            return b""
        self.sent.append(frame)
        payload = unframe(frame)
        command, body = payload[1], payload[2:]
        if command in self._ACKNOWLEDGED:
            out = b""
        elif command == CMD_GET_FIRMWARE_VERSION:
            out = b"\x32\x01\x06\x07"
        elif command == CMD_TG_INIT_AS_TARGET:
            self.init_bodies.append(body)
            out = ACTIVATED_AS_PICC
        elif command == CMD_TG_GET_DATA:
            out = self._tg_get_data()
        elif command == CMD_TG_SET_DATA:
            out = self._tg_set_data(body)
        else:
            out = b"\x00"
        return ACK + build_frame(
            bytes([PN532_TO_HOST, (command + 1) & 0xFF]) + out)

    def _tg_get_data(self) -> bytes:
        kernel = self._current()
        if kernel is None:
            return bytes([STATUS_RELEASED])
        command = kernel.next_command()
        if command is None:
            self.index += 1                         # this terminal is finished
            return bytes([STATUS_RELEASED])
        return b"\x00" + command

    def _tg_set_data(self, body: bytes) -> bytes:
        kernel = self._current()
        if kernel is not None:
            kernel.give_response(body)
        return b"\x00"


# ── running one ─────────────────────────────────────────────────────────────

def build(args) -> tuple[CardEmulator, ScriptedCard, list[ContactlessKernel]]:
    if args.from_file:
        from transport.recorded import RecordedCardTransport

        card = RecordedCardTransport(args.from_file, strict=False)
    else:
        card = ScriptedCard(MASTERCARD, atr=MASTERCARD_ATS,
                            uid=MASTERCARD_UID,
                            delay=args.card_delay / 1000.0)

    kernels = [ContactlessKernel(stop_after=args.stop_after)
               for _ in range(args.sessions)]
    link = LoopbackLink(kernels, bridge_delay=args.bridge_delay / 1000.0)
    chip = PN532(link)

    def log(command: bytes, response: bytes) -> None:
        logging.getLogger("atrium").info(
            "%s -> %s", command.hex().upper(), response.hex().upper())

    emulator = CardEmulator(chip, card, card=EmulatedCard(), on_apdu=log,
                            alert=False)
    return emulator, card, kernels


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Run the contactless relay with no hardware attached.")
    parser.add_argument("--stop-after", type=int, metavar="N", default=None,
                        help="terminal deselects after N exchanges — "
                             "N=1 reproduces the PPSE-then-deselect trace")
    parser.add_argument("--sessions", type=int, default=2, metavar="N",
                        help="how many terminal passes to simulate "
                             "(default 2: read the card, come back)")
    parser.add_argument("--card-delay", type=float, default=0.0, metavar="MS",
                        help="how long the relayed card takes per APDU")
    parser.add_argument("--bridge-delay", type=float, default=0.0, metavar="MS",
                        help="how long one command to the chip takes")
    parser.add_argument("--from-file", metavar="PATH",
                        help="relay to a recorded capture instead of the "
                             "built-in card")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show the emulator's debug lines too")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s  %(levelname)-8s %(name)s — %(message)s")

    emulator, card, kernels = build(args)
    print(f"\n  ** RELAY LOOPBACK — no hardware. **\n\n"
          f"  Terminal:    simulated EMV contactless kernel\n"
          f"  Card:        {args.from_file or 'built-in Debit Mastercard'}\n"
          f"  Sessions:    {args.sessions}\n"
          f"  Card delay:  {args.card_delay:.0f} ms per APDU\n",
          flush=True)

    emulator.run()

    print("\n  ── what the terminal decided ──")
    for i, kernel in enumerate(kernels, 1):
        if not kernel.sent:
            continue
        print(f"\n  session {i}: {len(kernel.sent)} command(s)")
        for note in kernel.notes:
            print(f"    · {note}")

    # The relay's one job is to be transparent. Anything the terminal received
    # that is not what the card said is a relay bug, and saying so here is the
    # whole reason this harness exists.
    got = [r for k in kernels for r in k.received]
    said = list(card.answered) if isinstance(card, ScriptedCard) else []
    if said and got != said:
        print("\n  !! the terminal did not receive what the card said:")
        for i, (a, b) in enumerate(zip(said, got)):
            if a != b:
                print(f"     #{i}: card {a.hex().upper()}")
                print(f"          term {b.hex().upper()}")
        return 1
    if said:
        print(f"\n  Relay was byte-transparent over {len(got)} exchange(s).")
    unknown = getattr(card, "unknown", [])
    if unknown:
        print(f"\n  The card had no answer for {len(unknown)} command(s) "
              f"(answered 6A82):")
        for apdu in unknown:
            print(f"     {apdu.hex().upper()}")
    print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
