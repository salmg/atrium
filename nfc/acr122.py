"""
ACR122U link — PN532 frames tunnelled over PC/SC.

The ACR122U is a PN532 behind a CCID bridge.  Ordinary contactless work goes
through PC/SC as normal APDUs, but the chip's own commands — the ones that put
it into card emulation — are not exposed that way.  They travel inside a
vendor pseudo-APDU instead:

    FF 00 00 00 <Lc> <PN532 frame>

The reader answers with the chip's reply wrapped in a response that usually
carries a ``61 xx`` "more data" status, so a GET RESPONSE follows.  Some
firmware answers directly.  Both shapes are handled here.

Two ways in, because the ACR122U presents differently depending on whether a
card is in the field:

* **A connected card.**  ``T=1`` protocol, the ordinary case: the pseudo-APDU
  travels over ``SCardTransmit`` like any other.
* **No card at all.**  A direct connection to the reader itself, which PC/SC
  exposes with ``SCARD_SHARE_DIRECT``.  This is what card emulation needs —
  there is no card to connect to, the reader *is* the target.

A direct connection has **no negotiated protocol**, and ``SCardTransmit`` needs
one.  pyscard rejects the call before it reaches the driver ("Invalid protocol
in transmit"), which is what a direct-mode session used to die on.  The escape
channel — ``SCardControl`` with the CCID escape IOCTL — is the way in, and it is
the path libnfc takes for the same reason.  Some stacks accept a ``RAW``
transmit instead, so that is tried as a fallback.

Everything here needs real hardware to exercise; the tests drive a fake
connection so the protocol handling is covered without one.
"""
from __future__ import annotations

import logging
import sys
import time

from nfc.pn532 import build_frame, unframe

logger = logging.getLogger(__name__)

# Every byte in and out of the reader, when somebody asks for it. Its own
# logger rather than a debug level on the one above, because turning that on
# buys a great deal of noise and not this: this is the only record of what the
# hardware was actually told, as opposed to what a layer above made of it.
# `atrium.py nfc emulate --trace-chip` is what switches it on.
wire = logging.getLogger("nfc.wire")
wire.setLevel(logging.WARNING)

# The ACR122U's "direct transmit" pseudo-APDU:
#
#     FF 00 00 00 <Lc> D4 <command> <parameters…>
#
# Lc counts the D4 as well. What travels is the *bare* command, not a framed
# one: the reader's own microcontroller builds the normal information frame,
# and answers with a bare response plus a status word:
#
#     D5 <command+1> <data…> 90 00
#
# Handing it a framed command instead gets nothing back at all — no error, an
# empty reply — which is why this is worth spelling out. libnfc's
# acr122_pcsc.c does the same thing (ACR122_PCSC_WRAP_LEN is 6: the four
# prefix bytes, Lc, and D4).
PSEUDO_APDU_PREFIX = bytes([0xFF, 0x00, 0x00, 0x00])
GET_RESPONSE = bytes([0xFF, 0xC0, 0x00, 0x00])

SW_MORE_DATA = 0x61
SW_OK = (0x90, 0x00)

# ── Finding the escape channel ───────────────────────────────────────────────
#
# The control code that carries a vendor escape is *not* the same number on
# every stack, which is the trap here:
#
#     Windows        SCARD_CTL_CODE(3500)
#     macOS, BSD     ((0x31) << 16) | (3500 << 2)
#     Linux/libccid  SCARD_CTL_CODE(1)          ← IOCTL_SMARTCARD_VENDOR_IFD_EXCHANGE
#
# Sending 3500 to libccid does not fail as "not authorised" — it falls through
# every branch of IFDHControl and returns its default, IFD_ERROR_NOT_SUPPORTED
# (606), which surfaces as "Feature not supported" and reads exactly like the
# authorisation problem it is not. libnfc carries the same three-way split.
#
# Rather than guess from the platform, ask: PC/SC part 10 defines a feature
# query, and libccid answers it with the control code to use. It only lists
# FEATURE_CCID_ESC_COMMAND when escape is authorised, so one query settles both
# questions — which code, and whether we are allowed to use it at all.

CM_IOCTL_GET_FEATURE_REQUEST = 3400
FEATURE_CCID_ESC_COMMAND = 0x13

# Tried in order when the feature query itself is unavailable.
_ESCAPE_FALLBACKS = ("linux", "other")


def _ctl_code(value: int) -> int:
    from smartcard.scard import SCARD_CTL_CODE
    return SCARD_CTL_CODE(value)


def _fallback_ioctls() -> list[int]:
    """Best guesses, most likely first for this platform."""
    mac_bsd = ((0x31) << 16) | (3500 << 2)
    if sys.platform.startswith("linux"):
        return [_ctl_code(1), _ctl_code(3500), mac_bsd]
    if sys.platform == "win32":
        return [_ctl_code(3500), _ctl_code(1)]
    return [mac_bsd, _ctl_code(1), _ctl_code(3500)]


def _parse_feature_tlv(reply) -> dict[int, int]:
    """
    Decode a CM_IOCTL_GET_FEATURE_REQUEST answer.

    A flat run of ``tag(1) length(1) value(length)``; the values that name a
    control code are 4 bytes big-endian.
    """
    out: dict[int, int] = {}
    data = bytes(reply)
    i = 0
    while i + 2 <= len(data):
        tag, length = data[i], data[i + 1]
        if i + 2 + length > len(data):
            break
        if length == 4:
            out[tag] = int.from_bytes(data[i + 2:i + 6], "big")
        i += 2 + length
    return out


# The plist lives in a different place on every distribution — /etc on
# Debian and Ubuntu, inside the driver bundle on Fedora and Arch — so the fix
# has to find it rather than assume it. The sed anchors on the key and edits
# the line after it, which keeps it correct when the value is already
# something other than 0x0000 (a global 0x0000 → 0x0001 silently does nothing
# in that case, and looks like the fix failed).
# libccid only lists the escape feature once ifdDriverOptions authorises it, so
# "the query answered and the feature was absent" is a definite answer rather
# than a guess — and it is a different problem from "no escape code worked",
# which is usually the wrong control code for the stack. Saying the same thing
# for both is what makes this error hard to act on.
NOT_AUTHORISED_HELP = (
    "The driver answered, and it does not offer an escape channel — which on "
    "libccid means escape commands are not authorised yet. Enable them once:\n\n"
    "    plist=$(ls /etc/libccid_Info.plist \\\n"
    "               /usr/lib*/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist \\\n"
    "               /usr/local/lib*/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist \\\n"
    "            2>/dev/null | head -1)\n"
    "    grep -A1 ifdDriverOptions \"$plist\"          # what it is now\n"
    "    sudo sed -i '/ifdDriverOptions/{n;s|<string>0x[0-9A-Fa-f]*</string>"
    "|<string>0x0001</string>|}' \"$plist\"\n"
    "    sudo systemctl restart pcscd.socket pcscd.service\n\n"
    "0x0001 is DRIVER_OPTION_CCID_EXCHANGE_AUTHORIZED."
)

NO_ESCAPE_HELP = (
    "No control code reached the chip, and the driver would not say which one "
    "to use.\n"
    "The escape code differs by stack — SCARD_CTL_CODE(1) on Linux/libccid, "
    "3500 on Windows, ((0x31)<<16)|(3500<<2) on macOS and BSD — and every one "
    "of them was tried.\n"
    "If pcscd logs 'Card not transacted: 606' the code was not recognised; "
    "612 means it was recognised and refused, which is the authorisation "
    "problem instead — and on libccid that is fixed with:\n\n"
    "    plist=$(ls /etc/libccid_Info.plist \\\n"
    "               /usr/lib*/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist \\\n"
    "               /usr/local/lib*/pcsc/drivers/ifd-ccid.bundle/Contents/Info.plist \\\n"
    "            2>/dev/null | head -1)\n"
    "    sudo sed -i '/ifdDriverOptions/{n;s|<string>0x[0-9A-Fa-f]*</string>"
    "|<string>0x0001</string>|}' \"$plist\"\n"
    "    sudo systemctl restart pcscd.socket pcscd.service"
)

# Why a given command might never answer. Keyed by the chip's command byte,
# because that is what the caller can act on: which half of the system to look
# at. Naming a command the caller never sent would point them at the wrong one.
_SILENCE_HINTS = {
    0x40: ("The card is probably not activated — check the log line where it "
           "was selected: one with no ATS never completed RATS."),
    0x8C: ("Target mode would not start. The chip has to have automatic "
           "ATR_RES switched off before TgInitAsTarget, and it is persistent, "
           "so a session that left it on breaks the next one. Re-running "
           "reopens the reader and resets it; if it persists, unplug it.\n"
           "'python3 atrium.py nfc probe' shows the raw reader traffic for "
           "exactly this command, which is the way to tell a chip that "
           "refused from a bridge that will not carry the answer."),
    0x88: ("Target mode is armed but the chip is not passing raw frames. This "
           "reader's bridge may not carry TgGetInitiatorCommand at all — try "
           "without --own-isodep to see whether the chip's own ISO-DEP works."),
}


class ACR122Error(RuntimeError):
    """The reader refused a pseudo-APDU, or is not an ACR122. User-facing."""


# How much of a chip frame one Direct Transmit may carry.
#
# Not 255, which is what a single Lc byte can express and what ACS document.
# The reader itself will not take that much, and it does not say so — it
# answers nothing in a dozen milliseconds and is then damaged: the next run
# gets empty replies to a 57-byte TgSetData that worked a minute earlier, and
# a second oversized send failed its PC/SC control transfer after **thirty
# seconds**. Three runs' worth of "the chip refuses TgSetData" turned out to be
# one wedged reader carrying the fault across process boundaries.
#
# What is known from the wire trace, and it is only a bracket:
#
#   Lc AA (175-byte APDU)   answered, repeatedly, over days
#   Lc FF (260-byte APDU)   nothing back, then a wedged reader
#
# 192 sits well inside the half that works. It is chosen to be safe rather than
# tight, because the cost of being wrong is a reader that needs unplugging and
# a diagnosis that survives into the next session pretending to be something
# else. ISO 7816-4's extended form is deliberately *not* used: at 265 bytes it
# is further past the boundary, not around it.
MAX_PSEUDO_APDU_PAYLOAD = 192


def pseudo_apdu(payload: bytes) -> bytes:
    """
    Wrap a chip frame's payload in the reader's Direct Transmit pseudo-APDU.

    Refuses rather than truncating or going extended — callers with more to say
    than this carries have to split it, because there is no length this reader
    will accept that holds an EMV certificate record whole.
    """
    if len(payload) > MAX_PSEUDO_APDU_PAYLOAD:
        raise ACR122Error(
            f"{len(payload)} bytes is past the {MAX_PSEUDO_APDU_PAYLOAD} this "
            f"reader takes in one Direct Transmit; send it in pieces")
    return PSEUDO_APDU_PREFIX + bytes([len(payload)]) + payload


class ACR122Link:
    """
    Carries PN532 frames to an ACR122U over PC/SC.

    Satisfies the one method ``nfc.pn532.PN532`` needs: ``exchange(frame)``.
    """

    def __init__(self, reader_name: str, direct: bool = False) -> None:
        self.reader_name = reader_name
        self.direct = direct
        self._connection = None
        # Which way out works on this stack: "control", "raw", or None until
        # the first send has settled it. Remembered so the fallback is probed
        # once rather than on every frame.
        self._path: str | None = None
        # The control code that carries an escape here, once the driver has
        # been asked. None until connect() has tried.
        self._escape_code: int | None = None
        # True/False once the feature query has answered; None if it could not
        # be asked at all. The difference decides what the failure says.
        self._escape_authorised: bool | None = None

    # ── lifecycle ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """
        Open the reader.

        ``direct=True`` connects to the reader rather than to a card, which is
        the only way in when the field is empty — and card emulation, by
        definition, starts with an empty field.
        """
        try:
            from smartcard.System import readers as list_readers
        except ImportError as exc:
            raise ACR122Error(
                "pyscard is required to talk to an ACR122U: pip install pyscard"
            ) from exc

        target = None
        for reader in list_readers():
            if str(reader) == self.reader_name:
                target = reader
                break
        if target is None:
            raise ACR122Error(f"Reader '{self.reader_name}' is not connected")

        connection = target.createConnection()
        if self.direct:
            try:
                from smartcard.scard import SCARD_PROTOCOL_UNDEFINED, SCARD_SHARE_DIRECT
                connection.connect(mode=SCARD_SHARE_DIRECT,
                                   protocol=SCARD_PROTOCOL_UNDEFINED)
            except Exception as exc:                   # noqa: BLE001
                raise ACR122Error(
                    f"Could not open '{self.reader_name}' directly ({exc}). "
                    "Direct access is needed with no card in the field; on "
                    "Linux this usually means pcscd has the reader open — stop "
                    "any other process using it."
                ) from exc
        else:
            try:
                connection.connect()
            except Exception as exc:                   # noqa: BLE001
                raise ACR122Error(
                    f"Could not connect through '{self.reader_name}' ({exc}). "
                    "Is a card in the field? Use direct mode if not."
                ) from exc

        self._connection = connection
        self._discover_escape()
        logger.debug("ACR122 link open on %s (direct=%s)",
                     self.reader_name, self.direct)

    def _discover_escape(self) -> None:
        """
        Ask the driver which control code carries an escape, and whether we may.

        Best-effort: a driver that does not answer the feature query leaves
        both answers unknown and the fallbacks are tried instead.
        """
        try:
            reply = self._connection.control(_ctl_code(CM_IOCTL_GET_FEATURE_REQUEST), [])
        except Exception as exc:                       # noqa: BLE001
            logger.debug("Feature query unavailable on %s (%s); falling back to "
                         "platform guesses", self.reader_name, exc)
            return

        features = _parse_feature_tlv(reply)
        code = features.get(FEATURE_CCID_ESC_COMMAND)
        self._escape_authorised = code is not None
        if code is None:
            # libccid lists this feature only when escape is authorised, so its
            # absence is the authorisation answer rather than a missing driver.
            logger.debug("Driver on %s lists no escape feature (%d others)",
                         self.reader_name, len(features))
            return
        self._escape_code = code
        logger.debug("Escape on %s uses control code 0x%08X",
                     self.reader_name, code)

    def close(self) -> None:
        connection, self._connection = self._connection, None
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:                          # noqa: BLE001
                pass

    def __enter__(self) -> "ACR122Link":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── the one method PN532 needs ───────────────────────────────────────────

    def exchange(self, frame: bytes) -> bytes:
        """
        Send a PN532 frame and return whatever the chip answered.

        An empty frame means "just poll for more" — ``PN532.call`` uses it when
        a link delivered the ACK and the response separately.
        """
        if self._connection is None:
            raise ACR122Error("Link is not connected")

        if not frame:
            # "Ask again" — the chip layer polling for an answer the reader
            # deferred. It has to come back framed like any other, or the
            # parser above sees a bare response, calls it incomplete, and polls
            # until its deadline for something it has already been handed.
            return self._frame_or_nothing(self._get_response())

        # The reader wants the bare command; its MCU does the framing.
        payload = unframe(frame)
        apdu = pseudo_apdu(payload)
        data, sw1, sw2 = self._transmit(apdu)

        if sw1 == SW_MORE_DATA:
            data += self._get_response(sw2)
        elif (sw1, sw2) != SW_OK and not data:
            raise ACR122Error(
                f"The reader rejected the pseudo-APDU (SW {sw1:02X}{sw2:02X}). "
                "This escape is ACR122-specific — check the reader is one.")

        return self._frame_or_nothing(data)

    def _frame_or_nothing(self, data: bytes) -> bytes:
        """
        Re-frame a bare PN532 response, or report that none arrived yet.

        Re-framing keeps the link's contract with ``PN532`` — whole frames in,
        whole frames out — so the frame parser and every test around it stay as
        they are, and only this reader's peculiarity lives here.

        An empty body is not an error. The reader takes a pseudo-APDU and
        answers as soon as its own microcontroller is satisfied, which for a
        command that waits on the outside world is *before* the chip has
        anything to say. Reporting nothing lets ``PN532.call`` keep asking
        until its deadline; raising here would turn every blocking command into
        an instant failure, which is what it used to do.

        The trailing status word only comes off on the escape path, for the
        same reason ``peripheral`` only puts it back there: escape hands over
        one undivided reply, while a transmit has already had its status word
        separated. Stripping unconditionally would take the 90 00 off the end
        of any relayed response that happened to succeed — which is most of
        them.
        """
        body = bytes(data)
        if (self._path == "control" and len(body) >= 2
                and (body[-2], body[-1]) == SW_OK):
            body = body[:-2]
        return build_frame(body) if body else b""

    @staticmethod
    def silence_hint(command: int) -> str:
        """
        Why this particular command might never have answered.

        ``PN532.call`` asks when its deadline runs out. The knowledge is
        reader-specific — what the ACR122U's bridge will and will not carry —
        so it lives here, and the chip layer simply passes on whatever the link
        knows.
        """
        if command in _SILENCE_HINTS:
            return (_SILENCE_HINTS[command]
                    + "\nOtherwise the chip is wedged; unplug the reader "
                      "and try again.")
        return "The chip may be wedged; unplug the reader and try again."

    def peripheral(self, apdu: bytes, split_status: bool = True
                   ) -> tuple[bytes, int, int]:
        """
        Send a reader command verbatim, without the PN532 wrapper.

        ``exchange`` is for chip frames and wraps them in FF 00 00 00; the
        reader's own commands — LED, buzzer, firmware — already are APDUs and
        must not be wrapped.

        The escape path hands back the whole reply with a synthetic 9000,
        because splitting a PN532 frame on its last two bytes would break its
        checksum. A peripheral command is the opposite case: its status word
        *is* the answer, and leaving it buried in the data would report every
        refusal as a success. So it is recovered here — except for the commands
        that answer with data in place of a status word entirely, which pass
        ``split_status=False`` and reassemble it themselves.
        """
        if self._connection is None:
            raise ACR122Error("Link is not connected")

        data, sw1, sw2 = self._transmit(apdu)
        if split_status and self._path == "control" and len(data) >= 2:
            return bytes(data[:-2]), data[-2], data[-1]
        return data, sw1, sw2

    def raw(self, apdu) -> bytes:
        """
        Every byte the reader answered, status word and all.

        ``exchange`` interprets and ``peripheral`` splits; this does neither.
        It exists for the probe, whose whole job is to show what actually came
        back rather than what a layer above made of it — the difference between
        "the chip refused" and "the bridge answered before the chip had
        anything to say" is invisible once either of those has had a turn.
        """
        data, sw1, sw2 = self._transmit(apdu)
        if self._path == "control":
            # The escape channel hands back the whole reply; the 90 00 in the
            # tuple is synthetic and appending it would invent two bytes.
            return bytes(data)
        return bytes(data) + bytes([sw1, sw2])

    def _escape_help(self) -> str:
        """Whichever of the two causes the feature query actually pointed at."""
        head = ("The reader is open, but neither the CCID escape channel nor a "
                "raw transmit reached the PN532.\n\n")
        tail = ("\n\nThen re-run 'python3 atrium.py nfc info' — a firmware version "
                "coming back means the escape path works and everything after it "
                "is RF behaviour.")
        if self._escape_authorised is False:
            return head + NOT_AUTHORISED_HELP + tail
        return head + NO_ESCAPE_HELP + tail

    def _get_response(self, length: int = 0x00) -> bytes:
        data, sw1, sw2 = self._transmit(list(GET_RESPONSE) + [length])
        if sw1 == SW_MORE_DATA:
            data += self._get_response(sw2)
        return data

    def _transmit(self, apdu) -> tuple[bytes, int, int]:
        if self._connection is None:
            raise ACR122Error("Link is not connected")
        if wire.isEnabledFor(logging.INFO):
            return self._traced_transmit(apdu)
        return self._untraced_transmit(apdu)

    def _traced_transmit(self, apdu) -> tuple[bytes, int, int]:
        """
        The same send, with both directions and the wall clock written down.

        Every question this project has spent a day on — is the chip being
        asked, did the reader answer, did it answer *nothing*, how long did it
        hold the command — is answered by these two lines and nothing above
        them. The layers in between interpret, and interpretation is what has
        repeatedly been wrong.
        """
        out = bytes(apdu)
        wire.info("→ %s", out.hex().upper())
        began = time.monotonic()
        try:
            data, sw1, sw2 = self._untraced_transmit(apdu)
        except Exception as exc:                       # noqa: BLE001
            wire.info("✗ %s after %.1f ms", exc, (time.monotonic() - began) * 1000)
            raise
        took = (time.monotonic() - began) * 1000
        # On the escape path the (sw1, sw2) tuple is synthetic — the reader's
        # real status word is the last two bytes of the reply — so printing
        # both showed the status twice and, next to a card response that ends
        # in its own 9000, three 9000s in a row. Enough to stop an operator
        # mid-diagnosis and ask what was wrong, which is the opposite of what
        # a wire trace is for.
        body, status = bytes(data), f"{sw1:02X}{sw2:02X}"
        if self._path == "control" and len(body) >= 2:
            body, status = body[:-2], body[-2:].hex().upper()
        wire.info("← %s %s   %.1f ms%s",
                  body.hex().upper() or "(no data)", status, took,
                  "   ← the reader answered with nothing" if not data else "")
        return data, sw1, sw2

    def _untraced_transmit(self, apdu) -> tuple[bytes, int, int]:
        if not self.direct:
            return self._plain_transmit(apdu)

        if self._path == "control":
            return self._escape(apdu)
        if self._path == "raw":
            return self._raw_transmit(apdu)

        # First send on a direct connection: find out which way this stack
        # takes. Escape first — it is the one that works on pcsc-lite, where a
        # direct connection has no protocol for SCardTransmit to use.
        try:
            out = self._escape(apdu)
            self._path = "control"
            return out
        except ACR122Error as escape_failed:
            try:
                out = self._raw_transmit(apdu)
            except ACR122Error as raw_failed:
                raise ACR122Error(
                    f"{self._escape_help()}\n\nEscape said: {escape_failed}\n"
                    f"Raw transmit said: {raw_failed}") from escape_failed
            self._path = "raw"
            logger.debug("Direct link on %s is using a raw transmit", self.reader_name)
            return out

    def _plain_transmit(self, apdu) -> tuple[bytes, int, int]:
        try:
            response, sw1, sw2 = self._connection.transmit(list(apdu))
        except Exception as exc:                       # noqa: BLE001
            raise ACR122Error(f"Transmit failed: {exc}") from exc
        return bytes(response), sw1, sw2

    def _raw_transmit(self, apdu) -> tuple[bytes, int, int]:
        """``SCardTransmit`` with an explicit RAW protocol."""
        try:
            from smartcard.CardConnection import CardConnection
            response, sw1, sw2 = self._connection.transmit(
                list(apdu), protocol=CardConnection.RAW_protocol)
        except IndexError as exc:
            # pyscard reads the status word off the end of the reply, so an
            # empty one surfaces as "list index out of range" — which says
            # nothing about what happened. On pcsc-lite a direct connection
            # has no negotiated protocol, so this is the expected outcome and
            # the escape channel is the real path.
            raise ACR122Error(
                "the reader accepted the transmit but answered nothing, which "
                "is what a direct connection does when it has no protocol to "
                "transmit over") from exc
        except Exception as exc:                       # noqa: BLE001
            raise ACR122Error(str(exc)) from exc
        return bytes(response), sw1, sw2

    def _escape(self, apdu) -> tuple[bytes, int, int]:
        """
        ``SCardControl`` with the CCID escape IOCTL.

        The whole reply is handed back as data with a synthetic 9000 rather than
        having its last two bytes read as a status word: the escape channel
        answers in one go, and a PN532 frame that happened to end 90 00 would
        otherwise be truncated into a checksum failure. The frame parser finds
        the frame by its own length field, so trailing bytes cost nothing.
        """
        codes = [self._escape_code] if self._escape_code else _fallback_ioctls()
        last: Exception | None = None
        for code in codes:
            try:
                reply = self._connection.control(code, list(apdu))
            except Exception as exc:                   # noqa: BLE001
                last = exc
                continue
            if self._escape_code != code:
                logger.debug("Escape on %s settled on control code 0x%08X",
                             self.reader_name, code)
                self._escape_code = code
            return bytes(reply), 0x90, 0x00

        tried = ", ".join(f"0x{c:08X}" for c in codes)
        raise ACR122Error(f"{last} (tried {tried})") from last


# ── Peripheral commands: the reader itself, not the chip ─────────────────────
#
# These are ACR122U commands rather than PN532 frames, so they travel as plain
# pseudo-APDUs and are *not* wrapped in FF 00 00 00. The LED one is here for one
# reason: with two identical ACR122Us on a desk, no amount of naming answers
# which is which. Making one of them blink does.

LED_CONTROL = bytes([0xFF, 0x00, 0x40])
FIRMWARE_QUERY = bytes([0xFF, 0x00, 0x48, 0x00, 0x00])

# Set PICC Operating Parameter: FF 00 51 <param> 00, answered 90 <param>.
#
# The reader runs its own contactless polling loop whenever it is not holding a
# card connection, and a direct connection does not stop it. Every escape we
# send therefore queues behind whatever poll cycle is in flight on the same
# antenna and the same PN532 — which is a candidate for the tens of
# milliseconds an escape costs on this bridge, and one the probe can measure
# rather than assume.
#
# Bit 7 is Auto PICC Polling. 0xFF is the factory default, everything on.
PICC_OPERATING_PARAMETER = bytes([0xFF, 0x00, 0x51])
PICC_POLLING_ON = 0xFF
PICC_POLLING_OFF = 0x7F


def set_picc_polling(link, param: int) -> int | None:
    """
    Turn the reader's own card polling on or off. Returns what it reports back.

    Volatile as far as the vendor documentation goes — a power cycle restores
    the default — but the probe restores it anyway, because this project has
    twice shipped a reader left in a state that broke the next session.
    """
    try:
        _, sw1, sw2 = link.peripheral(
            PICC_OPERATING_PARAMETER + bytes([param, 0x00]))
    except Exception:                                  # noqa: BLE001
        logger.debug("Reader would not take a PICC operating parameter",
                     exc_info=True)
        return None
    return sw2 if sw1 == 0x90 else None

# LED State Control bits, from the ACR122U API. The mask bits say "act on this
# LED"; without them the state bits are ignored.
_LED_RED_FINAL      = 0x01
_LED_GREEN_FINAL    = 0x02
_LED_RED_MASK       = 0x04
_LED_GREEN_MASK     = 0x08
_LED_RED_INITIAL    = 0x10
_LED_GREEN_INITIAL  = 0x20
_LED_RED_BLINK      = 0x40
_LED_GREEN_BLINK    = 0x80

BUZZER_OFF = 0x00
BUZZER_T1 = 0x01


def build_led_command(green: bool = True, red: bool = False,
                      t1: int = 2, t2: int = 2, repeat: int = 3,
                      buzzer: int = BUZZER_OFF) -> bytes:
    """
    An ACR122U blink, as a pseudo-APDU.

    ``t1``/``t2`` are in units of 100 ms — the reader's own granularity, kept
    rather than converted so the numbers match the vendor documentation.

    The final-state bits are deliberately left clear while the mask bits are
    set, so the LED returns to off when the blinking stops. An identify that
    leaves a reader lit would be worse than none: the next one would be
    ambiguous.
    """
    if not (green or red):
        raise ACR122Error("Nothing to blink — ask for green, red, or both")
    for label, value in (("t1", t1), ("t2", t2), ("repeat", repeat)):
        if not 0 <= value <= 255:
            raise ACR122Error(f"{label}={value} does not fit in a byte")
    if buzzer not in (0x00, 0x01, 0x02, 0x03):
        raise ACR122Error(f"Buzzer link {buzzer:#04x} is not one of 00/01/02/03")

    state = 0
    if green:
        state |= _LED_GREEN_MASK | _LED_GREEN_INITIAL | _LED_GREEN_BLINK
    if red:
        state |= _LED_RED_MASK | _LED_RED_INITIAL | _LED_RED_BLINK

    return LED_CONTROL + bytes([state, 0x04, t1, t2, repeat, buzzer])


def announce_armed(link, *, buzzer: bool = True) -> bool:
    """
    Blink and beep: target mode is about to open, present the terminal now.

    Worth doing because the window is not obvious from outside. The reader is
    armed for about five seconds at a time — that is the ACR122U's own bridge
    timeout — and re-arms until a terminal turns up, so what looks from the
    desk like a continuous wait is really a series of short ones. A cue at the
    start of the first is the difference between presenting the terminal at the
    right moment and wondering why nothing happened.

    Takes an already-open link rather than a reader name, because the caller is
    holding the reader and opening a second connection to it would fail.

    Best-effort and deliberately so: a reader that is not an ACR122U, or one
    that refuses the command, must not stop a relay from arming. Returns
    whether the cue actually went out.
    """
    if not hasattr(link, "peripheral"):
        return False
    try:
        # Two slow blinks, ~800 ms in total. The reader holds the command open
        # while it blinks, so this is time the relay is not yet armed — long
        # enough to notice, short enough not to be in the way.
        apdu = build_led_command(green=True, t1=2, t2=2, repeat=2,
                                 buzzer=BUZZER_T1 if buzzer else BUZZER_OFF)
        link.peripheral(apdu)
        return True
    except Exception:                                  # noqa: BLE001
        logger.debug("Reader would not sound the ready cue", exc_info=True)
        return False


def identify(reader_name: str, *, green: bool = True, red: bool = False,
             repeat: int = 3, buzzer: bool = False) -> dict:
    """
    Blink one reader so a human can see which physical device it is.

    Answers the question two identical ACR122Us actually pose. PC/SC names them
    apart — pcsc-lite appends an index — but a name does not tell you which of
    the two on the desk it belongs to, and a USB bus address only moves the
    problem to which port is which.

    Returns the LED state the reader reports back.
    """
    link = ACR122Link(reader_name, direct=True)
    link.connect()
    try:
        apdu = build_led_command(green=green, red=red, repeat=repeat,
                                 buzzer=BUZZER_T1 if buzzer else BUZZER_OFF)
        # The reply is 90 <LED state>, so SW2 is data rather than a status —
        # checking it against 9000 would report every success as a failure.
        _, sw1, sw2 = link.peripheral(apdu)
        if sw1 != 0x90:
            raise ACR122Error(
                f"The reader refused the LED command (SW {sw1:02X}{sw2:02X}). "
                "This is an ACR122-specific command — check the reader is one.")
        return {"reader": reader_name, "led_state": sw2}
    finally:
        link.close()


def firmware_string(reader_name: str) -> str:
    """
    The reader's own firmware string, e.g. ``ACR122U214``.

    Confirms the device is an ACR122 without going near the PN532, which makes
    it a useful second opinion when the chip is not answering. It is the same
    for every unit of a model, so it identifies the *kind* of reader, never
    which one.
    """
    link = ACR122Link(reader_name, direct=True)
    link.connect()
    try:
        # Answers with the string in place of a status word, so nothing may be
        # split off the end — the last two bytes are the version, not a status.
        data, sw1, sw2 = link.peripheral(FIRMWARE_QUERY, split_status=False)
        raw = bytes(data)
        if link._path != "control":
            # A plain transmit really did parse a status word off the end.
            raw += bytes([sw1, sw2])
        # Drivers pad the reply buffer, so stop at the first NUL rather than
        # decoding the padding into the version string.
        return raw.split(b"\x00")[0].decode("ascii", "replace").strip()
    finally:
        link.close()


def open_pn532(reader_name: str, direct: bool = False):
    """
    Open an ACR122U and hand back a configured PN532 plus its link.

    Returns (pn532, link); the caller closes the link. SAM configuration runs
    here because the chip ignores most commands until it has been done.
    """
    from nfc.pn532 import DEFAULT_PARAMETERS, PN532

    link = ACR122Link(reader_name, direct=direct)
    link.connect()
    chip = PN532(link)
    try:
        chip.sam_configuration()
        # A known baseline every time. The chip keeps its parameter byte until
        # something changes it, so a session that left AUTO_RATS off would
        # otherwise poison every later use of that reader — including as the
        # card side of a relay, where the symptom is a card that activates but
        # produces no ATS and then answers nothing.
        chip.set_parameters(DEFAULT_PARAMETERS)
    except Exception:                                  # noqa: BLE001
        link.close()
        raise
    return chip, link
