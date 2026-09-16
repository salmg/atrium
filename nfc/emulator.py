"""
Card emulation — the ACR122U pretending to be a contactless card.

``TgInitAsTarget`` puts the PN532 into target mode: it stops looking for cards
and starts answering as one.  A terminal in whose field it sits will select it
and send APDUs, which this forwards to a real card over any ``CardTransport``
— giving the contactless counterpart of what SimTrace2 does on the contact
side.

    terminal  ──RF──►  [ACR122U as target]  ──►  CardTransport  ──►  real card
              ◄──RF──                       ◄──                 ◄──

What this hardware can and cannot do
------------------------------------
Worth knowing before trusting a result:

* **The UID is not fully yours.** In target mode the PN532 answers with a
  4-byte NFCID1 whose first byte the chip forces to 0x08, the "random UID"
  marker. A terminal that pins a specific UID will not see the card's own.
* **One frame per exchange.** A normal information frame carries 255 bytes of
  TFI plus body, so a relayed response has 253 to itself. Longer needs ISO
  14443-4 chaining, which this does not implement; it reports the limit rather
  than truncating.
* **Timing is not transparent.** Every APDU makes a USB round trip to the
  relayed card. Terminals that enforce contactless timing budgets — and EMV
  contactless kernels generally do — may abandon the transaction. That is a
  property of relaying over USB, not a bug to be fixed here. Mutation rules
  that *inject* extra commands spend that budget twice over, which is why an
  injection that is free on contact can time a contactless tap out.

None of this has been exercised against real hardware from the machine it was
written on. The framing, the command construction and the relay loop are
covered by tests against a fake chip; the RF behaviour is not, and cannot be.
"""
from __future__ import annotations

import dataclasses
import logging
import threading
import time

from nfc.acr122 import MAX_PSEUDO_APDU_PAYLOAD
from nfc.isodep import (
    ATS_DEADLINE,
    WTXM_MAX,
    Ats,
    historical_bytes,
    BlockType,
    IsoDepError,
    SType,
    chain,
    is_pps,
    is_rats,
    max_inf_size,
    parse_ats,
    parse_block,
    parse_rats,
    pps_response,
    r_block,
    s_deselect,
    s_wtx,
    with_length_byte,
)
from nfc.pn532 import (
    CMD_TG_GET_DATA,
    CMD_TG_INIT_AS_TARGET,
    CMD_TG_SET_DATA,
    CMD_TG_SET_META_DATA,
    NoAnswer,
    PARAM_14443_4_PICC,
    PARAM_AUTO_ATR_RES,
    RECOVERABLE_RF,
    STATUS_FIELD_OFF,
    STATUS_RELEASED,
    TARGET_MODE_PICC,
    status_of,
    Cancelled,
    PN532Error,
    RFError,
    command_name,
    describe_status,
    summarise_target_mode,
)

# What one TgSetData carries: TFI + the command byte precede the response
# inside a pseudo-APDU the reader will actually accept. Not the 253 a single Lc
# byte allows — the reader is damaged by a send that big, and three runs of
# "the chip refuses TgSetData" were one wedged reader carrying the fault from
# the run before. See nfc.acr122.MAX_PSEUDO_APDU_PAYLOAD for the bracket.
MAX_RESPONSE = MAX_PSEUDO_APDU_PAYLOAD - 2

# What a *chained* response carries. TgSetMetaData exists precisely so a target
# can answer with more than one command holds, so this is a sanity bound rather
# than a hardware one — a response past it is a mutation that has run away, not
# a card. Ten blocks is far more than any EMV record.
MAX_CHAINED_RESPONSE = MAX_RESPONSE * 10

# How long to keep target mode open waiting for a terminal. The chip's own
# default is a minute, which is the right length for "is this reader broken?"
# and the wrong one for a person carrying a reader to a till. This is the
# second question, so it gets a person's answer — and stop() is honoured
# throughout, so the wait is long without being a trap.
TERMINAL_WAIT = 300.0

logger = logging.getLogger(__name__)

# Mode byte for TgInitAsTarget: accept ISO/IEC 14443-4 (PICC) only, and refuse
# to act as a DEP target. Passive-only, because an active target is a
# peer-to-peer thing and not what a payment terminal is looking for.
MODE_PICC_ONLY_PASSIVE = 0x05

# The same, minus the ISO14443-4-PICC restriction. That bit asks the chip to do
# ISO-DEP; raw mode is asking it not to, so the restriction comes off with it —
# the pairing libnfc uses when it is not relying on the chip's PICC support.
MODE_PASSIVE_ONLY = 0x01



# The ATS the PN532's own PICC mode answers RATS with, measured on this rig
# with `atrium.py nfc measure-ats`: T0 TA(1) TB(1) TC(1), no TL — the shape
# InListPassiveTarget hands back. It is firmware's and cannot be set from here,
# which is the point of recording it: the differences between this and the
# relayed card's ATS are the ones no amount of code will close on this path.
# Other firmware may differ; measure-ats is how to find out.
CHIP_ATS = bytes.fromhex("75339203")


class CannotChain(PN532Error):
    """
    A response is too big for one Direct Transmit and the chip will not split
    it. Its own class because it is the one send failure with something better
    to do than propagate: the terminal can still be told the card failed.
    """


@dataclasses.dataclass
class EmulatedCard:
    """
    What the emulated card looks like on the air.

    Defaults describe a generic ISO 14443-4 Type A card. SAK 0x20 is the bit a
    terminal checks to decide the target speaks APDUs at all, so changing it
    without reason will simply stop terminals talking.
    """
    # SENS_RES (ATQA), little-endian on the wire as the chip wants it.
    atqa: bytes = b"\x04\x00"
    # NFCID1, 3 bytes — the chip prepends 0x08 itself.
    nfcid1: bytes = b"\x01\x02\x03"
    sak: int = 0x20
    # The **historical bytes** — Tk, the tail of the ATS. Not the whole ATS:
    # TgInitAsTarget takes only these, and the chip supplies TL and the
    # interface bytes itself from its own firmware.
    #
    # This default is libnfc's, and libnfc took it from the PN532's own ATS,
    # which is why an emulated card reads back as 75339203 twice over — once
    # as the chip's interface bytes and once as these. Harmless, and baffling
    # until you know. A relay overwrites them with the real card's.
    historical: bytes = b"\x75\x33\x92\x03"

    def mifare_params(self) -> bytes:
        """The 6-byte MIFARE parameter block TgInitAsTarget expects."""
        if len(self.atqa) != 2:
            raise PN532Error("ATQA must be 2 bytes")
        if len(self.nfcid1) != 3:
            raise PN532Error(
                "NFCID1 must be 3 bytes — the chip supplies the leading 0x08")
        return bytes(self.atqa) + bytes(self.nfcid1) + bytes([self.sak])

    def init_body(self, mode: int = MODE_PICC_ONLY_PASSIVE) -> bytes:
        """
        The TgInitAsTarget argument block.

        Layout: mode, MIFARE params (6), FeliCa params (18), NFCID3 (10),
        general bytes (length-prefixed), historical bytes (length-prefixed).
        FeliCa and NFCID3 are zero-filled: they matter for the modes this
        deliberately refuses.

        ``mode`` differs between the two drivers: the chip is asked to restrict
        itself to ISO14443-4 PICC when it is doing that layer, and not when the
        emulator is.
        """
        return (
            bytes([mode])
            + self.mifare_params()
            + bytes(18)                      # FeliCa params, unused
            + bytes(10)                      # NFCID3t, unused
            + bytes([0])                     # no general bytes
            + bytes([len(self.historical)]) + bytes(self.historical)
        )


class _RelayCore:
    """
    What both emulators do with an APDU once they have one.

    The two drivers differ only in how bytes reach the air — the chip's own
    ISO-DEP, or ours. Mutation, observation and the counters are the same job
    either way, and a second copy of them is a second place for the two paths
    to drift apart.
    """

    def __init__(self, chip, transport, card: EmulatedCard | None = None,
                 on_apdu=None, mutations=None, alert: bool = True,
                 split_responses: bool = False) -> None:
        # Whether a response too big for one exchange is offered to the
        # terminal as 61 XX and collected with GET RESPONSE. Off by default:
        # it changes what the card appears to have said. See
        # CardEmulator._split_for_terminal.
        self.split_responses = split_responses
        self.split_responses_used = 0
        # What is left of a response the terminal has been told to collect,
        # and the card's own status word to finish it with.
        self._held: bytes | None = None
        self._held_sw = b"\x90\x00"
        self.chip = chip
        self.transport = transport
        self.card = card or EmulatedCard()
        # Blink and beep the reader when target mode opens. On by default: the
        # window is a few seconds long and invisible from the desk, and an
        # operator who misses it has no way to tell that from a relay that is
        # not working.
        self.alert = alert
        # Called with (command, response) for every relayed pair. An observer:
        # it sees what crossed, it does not get to change it.
        self.on_apdu = on_apdu
        # A MutationEngine, or None. This one *is* in the path — the same two
        # hooks the contact relay uses, so a playbook written for one interface
        # runs on the other.
        self.mutations = mutations
        self._stop = False
        # What the chip's parameters were before target mode borrowed it.
        self._saved_parameters: int | None = None
        self.exchanges = 0
        # Time the relayed card spent answering, in total and at its worst.
        # The terminal is timing the same waits against its frame waiting time,
        # so this is what decides whether a relay is survivable at all.
        self.card_seconds = 0.0
        self.slowest_card = 0.0
        # The whole span the terminal waited: the card plus our own overhead
        # plus the bridge. This is the number FWT is actually measured against.
        self.slowest_turnaround = 0.0
        # The same two, for the session in progress only. A verdict on how a
        # session ended has to be measured against what *that* session waited.
        # The run-wide maxima stay high once anything has been slow, so reading
        # them in a later session hands it a timeout verdict for latency it
        # never spent — and a session with no exchanges at all, which cannot
        # have expired anything, got told to go and fix its timing.
        self.session_slowest_card = 0.0
        self.session_slowest_turnaround = 0.0
        # STATUS_RELEASED if the terminal deselected deliberately,
        # STATUS_FIELD_OFF if the field went away, None if neither happened.
        self.ended_status: int | None = None
        # A terminal may select this card, finish with it and come back —
        # discovery and transaction are separate passes on some kernels. So a
        # run is several sessions, and the counters that answer "why did that
        # one end" have to be per session rather than per run.
        self.sessions = 0
        self.session_exchanges = 0
        self.session_silent = False
        # The status word of the last answer the terminal got. A deliberate
        # deselect is a decision about *something*, and this is the something.
        self.last_sw: bytes | None = None
        # What one command to the chip costs, measured before the relay starts.
        # Both drivers need it, because both time their turnaround from a clock
        # that starts too late — see _note_turnaround.
        self.link_round_trip = 0.0
        # How many times target mode has been re-armed waiting for a terminal.
        # Reported, because "nothing is happening" and "listening, nobody has
        # come" are the same picture from the outside and very different
        # problems.
        self.arm_attempts = 0
        # Responses a mutation grew past what one exchange carries. Counted
        # rather than raised: see _fit.
        self.oversize = 0
        # Frames the air mangled. Counted rather than fatal — see _receive.
        self.rf_errors = 0
        # Blocks a response had to be split into. Both drivers chain, for the
        # same reason: an EMV record carrying a certificate does not fit one.
        self.chained_out = 0
        # Card responses too big for one Direct Transmit on a chip that will
        # not split them. The terminal gets 6F00 and the relay carries on,
        # because the alternative is a traceback where a trace should be.
        self.undeliverable = 0
        # Terminals that activated this card and then asked nothing at all.
        # Distinct from a deselect after an exchange: nothing we answered can
        # explain it, so the objection is to the activation — the UID, the
        # ATQA, the ATS — or the terminal was only looking.
        self.silent_activations = 0

    def stop(self) -> None:
        self._stop = True

    def _still_wanted(self) -> bool:
        """Passed to the chip so a long wait can be called off part way."""
        return not self._stop

    def _card_historical(self) -> bytes:
        """
        The relayed card's historical bytes, or empty if it offered none.

        They are the most recognisable thing in an ATS — this rig's card says
        "KONA" — and a terminal that reads them off the real card and then off
        the emulated one should get the same answer either way. Both drivers
        want that; they differ only in where the bytes end up.
        """
        try:
            their_ats = self.transport.get_atr()
        except Exception:                              # noqa: BLE001
            logger.debug("Relayed card offered no ATS to copy", exc_info=True)
            return b""
        return historical_bytes(bytes(their_ats or b""))

    def _note_ending(self, status: int | None) -> None:
        """
        Record *how* the terminal finished, because the two ways differ.

        STATUS_RELEASED is a deliberate S(DESELECT): the terminal chose to end,
        having decided something about this card. STATUS_FIELD_OFF is the field
        going away —
        the card moved, or the terminal stopped driving. Merging them into
        "the terminal ended the transaction" throws away the only evidence
        there is about which happened, and they call for opposite next steps.
        """
        self.ended_status = status
        if status == STATUS_RELEASED:
            logger.info("The terminal deselected us deliberately — it decided "
                        "to end, rather than losing us")
        elif status == STATUS_FIELD_OFF:
            logger.info("The RF field went away — the reader was moved, or the "
                        "terminal stopped driving it")
        else:
            logger.info("Terminal ended the transaction")

    def _note_turnaround(self, took: float) -> None:
        """
        Record how long the terminal waited for one answer, end to end.

        The clock here starts after the command has already been handed over,
        but the terminal starts counting FWT the instant it stops
        transmitting — and between those sits the whole inbound leg: the chip
        receiving the frame, the reader's MCU marshalling it, and the escape
        carrying it back. That is a bridge round trip's worth of the
        terminal's wait that this process cannot see, exactly as with the ATS
        deadline, so it is added rather than quietly dropped.
        """
        whole = took + self.link_round_trip / 2
        self.slowest_turnaround = max(self.slowest_turnaround, whole)
        self.session_slowest_turnaround = max(
            self.session_slowest_turnaround, whole)
        logger.debug("Answered in %.0f ms measured, ~%.0f ms as the terminal "
                     "counts it", took * 1000, whole * 1000)

    def _measure_link(self) -> None:
        """
        Time one trivial command, to learn what a round trip to the chip costs.

        GetFirmwareVersion is the cheapest thing the chip answers and touches
        no RF state, so half its round trip is a fair estimate for each of the
        legs that cannot be timed from inside the relay loop.

        Once per run. It was once per arming, which put an extra command to
        the chip between every session and the next — and measured the
        reader's recovery from the previous session rather than the link,
        which is why a re-arm after an abandoned TgGetData reported 110 ms
        against the same link's 6 ms.
        """
        if self.link_round_trip:
            return
        try:
            began = time.monotonic()
            self.chip.firmware_version()
            self.link_round_trip = time.monotonic() - began
            logger.info("A round trip to the chip costs %.1f ms on this link",
                        self.link_round_trip * 1000)
        except Exception:                              # noqa: BLE001
            logger.debug("Could not time the link", exc_info=True)
            self.link_round_trip = 0.0

    def _rearmed(self, attempt: int, waited: float) -> None:
        """
        Say that we are still listening, each time the reader drops the command.

        The ACR122U holds target mode open for about five seconds and then
        discards it, so this is roughly one line every five seconds. That is
        the right amount: an operator who has walked to a terminal needs to see
        that the relay is alive, and a silent five minutes looks like a hang.
        """
        self.arm_attempts = attempt
        logger.info("Still waiting for a terminal — target mode re-armed "
                    "(attempt %d, %.0fs). Present the reader now.",
                    attempt, waited)

    def _announce(self) -> None:
        """
        Cue the operator that the reader is about to start listening.

        Only while nobody has turned up. The reader holds the LED command open
        while it blinks — about 800 ms — and that is 800 ms in which target
        mode is *not* armed. Before the first terminal that is a good trade:
        the operator cannot otherwise tell when to present it. Once a terminal
        has been seen it is a hole punched in the card's availability every
        session, cueing someone who is already standing at the reader.
        """
        if not self.alert or self.sessions:
            return
        from nfc.acr122 import announce_armed

        link = getattr(self.chip, "link", None)
        if link is not None:
            announce_armed(link)

    # ── borrowing the chip for target mode ───────────────────────────────────
    #
    # Either driver has to turn some flags off before TgInitAsTarget, and both
    # have to put them back: the byte is persistent, and a reader left changed
    # misbehaves in whatever it is used for next. libnfc clears AUTO_ATR_RES
    # for every ISO14443-A target — it belongs to DEP, and leaving it on stops
    # the chip entering target mode at all.

    def _borrow_chip(self, *, set_bits: int = 0, clear_bits: int = 0) -> None:
        # Only the first borrow records the original. Re-arming borrows again,
        # and saving then would record the borrowed byte as the baseline — the
        # chip would be "restored" to target-mode parameters and stop
        # activating cards as a reader.
        if self._saved_parameters is None:
            self._saved_parameters = self.chip.parameters
        self.chip.update_parameters(set_bits=set_bits, clear_bits=clear_bits)

    def _return_chip(self) -> None:
        """Hand the chip back the way it was found."""
        if self._saved_parameters is None:
            return
        try:
            self.chip.set_parameters(self._saved_parameters)
        except Exception:                              # noqa: BLE001
            logger.warning(
                "Could not put the chip's parameters back to %02X. Unplug the "
                "reader before using it as a card reader, or it may not "
                "activate 14443-4 cards.", self._saved_parameters, exc_info=True)
        finally:
            self._saved_parameters = None

    # ── one APDU, there and back ─────────────────────────────────────────────

    # The frame waiting time the PN532's own PICC mode advertises, measured
    # rather than assumed: `atrium.py nfc measure-ats` arms one reader as a
    # card, reads it with another, and this rig's chip answered TB1 92 —
    # FWI 9, which is 154.7 ms.
    #
    # It was 0.039 here for a long while, on the reasoning that the firmware
    # would advertise something card-like (a real card in front of this one
    # answers FWI 7). That was four times too strict, and the cost of the
    # guess was not academic: every relay that ended early got a timeout
    # verdict, which sent the work at latency for days when the terminal had
    # been inside its budget the whole time and was ending for a reason the
    # trace could have shown.
    #
    # Different PN532 firmware may well advertise a different FWI. measure-ats
    # is how to find out rather than assume, which is the whole point of it.
    CHIP_FWT = 0.155

    def _budget_seconds(self) -> float:
        """
        The frame waiting time the terminal is holding this relay to.

        The firmware path cannot choose it and will not report it, so this is
        the measured one. A driver that advertised its own FWI knows the true
        number first-hand and says so instead.
        """
        return self.CHIP_FWT

    def _timeout_advice(self) -> str:
        """What to do about an expiry, which differs by who owns the ATS."""
        return ("The chip picks its own FWI on this path and cannot ask for "
                "more time. --own-isodep sets FWI itself and sends S(WTX) "
                "while the card is answering, which is the mechanism for "
                "exactly this.")

    def _why_it_ended(self) -> str | None:
        """
        Whether the terminal finishing looks like finishing or like giving up.

        Three short endings need telling apart and the chip offers one bit of
        help: STATUS_RELEASED is a deliberate S(DESELECT), STATUS_FIELD_OFF is
        the field going away.
        Neither says *why*, so the timing has to supply the rest.

        * Waited longer than a card would take, then ended — a frame waiting
          time expiry. The terminal gave up mid-fetch; a release appears here
          too, because giving up is done by deselecting.
        * Ended **inside** the budget — not a timeout at all. The terminal read
          an answer and chose to stop, which is a decision about what it was
          told and puts the answer in the trace rather than on the clock.
        * The field went away — neither of the above. The card left the
          antenna or the terminal stopped driving.

        Calling the second one a timeout is what sent this rig chasing latency
        it had already fixed, so the distinction is worth the branch.
        """
        if self.session_exchanges > 3:
            return None
        if self.ended_status is None:
            # Nobody said the terminal ended this. An operator's Ctrl-C during
            # a slow exchange looks exactly like a timeout from the counters,
            # and blaming the terminal for it would be a fabricated verdict.
            return None
        waited = max(self.session_slowest_turnaround, self.session_slowest_card)
        budget = self._budget_seconds()

        if self.ended_status == STATUS_FIELD_OFF:
            return (
                f"The RF field went away after {self.session_exchanges} "
                f"exchange(s). "
                "That is the reader losing us rather than the terminal "
                "deciding anything: the card was lifted off the antenna, or "
                "the terminal stopped driving its field. Nothing in this "
                "points at the relay's timing.")

        if waited >= budget:
            return (
                f"The terminal let go after {self.session_exchanges} exchange(s) having "
                f"waited {waited * 1000:.0f} ms for one — "
                f"{self.session_slowest_card * 1000:.0f} ms "
                f"of that the card, the rest this process and the USB bridge. "
                f"The frame waiting time allows {budget * 1000:.0f} ms. That "
                f"reads as the terminal timing out, not finishing.\n"
                + self._timeout_advice())

        if self.ended_status != STATUS_RELEASED:
            return None

        if not self.session_exchanges:
            return (
                "The terminal activated us and then deselected without asking "
                "anything at all. It read the ATS and declined to go on, so "
                "whatever it objected to is in what we advertised — historical "
                "bytes, UID, or the ATS itself — not in how fast we answered.")

        answer = (f"{self.last_sw.hex().upper()} to the last command"
                  if self.last_sw else "the last answer")
        return (
            f"The terminal deselected deliberately after {self.session_exchanges} "
            f"exchange(s), having waited {waited * 1000:.0f} ms at worst against "
            f"a frame waiting time of {budget * 1000:.0f} ms. That is inside "
            f"the budget, so this is not a timeout: the terminal got {answer} "
            f"and chose to stop.\n"
            "Look at the last exchange in the trace rather than at the clock. A "
            "terminal ends this way when it dislikes what it was told — an "
            "unexpected status word, a missing application, an ATS or UID it "
            "will not transact with.")

    def _relay(self, command: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Mutate the command, put it to the card, mutate the answer.

        Returns ``(command, card_response, response)`` — the card's own bytes
        come back alongside the mutated ones because a driver that has to
        reject an oversized mutation needs something to fall back to.

        A failure to reach the relayed card is answered with 6F 00 rather than
        by dropping the RF link: the terminal then reports a card error, which
        is a legible outcome, instead of a mystery timeout.
        """
        command = self._mutate("on_command", command, command)
        began = time.monotonic()
        try:
            card_response = self.transport.transmit(command)
        except Exception as exc:                       # noqa: BLE001
            logger.error("Relayed card failed on %s: %s",
                         command[:8].hex().upper(), exc)
            card_response = b"\x6F\x00"
        # How long the card took is the number every timing question turns on,
        # and it is the one thing no layer above can observe. The terminal is
        # counting the same milliseconds against the frame waiting time.
        took = time.monotonic() - began
        self.card_seconds += took
        self.slowest_card = max(self.slowest_card, took)
        self.session_slowest_card = max(self.session_slowest_card, took)
        logger.debug("Card answered %s in %.0f ms",
                     command[:8].hex().upper(), took * 1000)
        response = self._mutate("on_response", card_response,
                                command, card_response)
        return command, card_response, response

    def _observe(self, command: bytes, response: bytes) -> None:
        self.exchanges += 1
        self.session_exchanges += 1
        if len(response) >= 2:
            self.last_sw = bytes(response[-2:])
        if self.on_apdu is not None:
            try:
                self.on_apdu(command, response)
            except Exception:                          # noqa: BLE001
                logger.exception("APDU observer raised; continuing the relay")

    # ── mutation ─────────────────────────────────────────────────────────────

    def _mutate(self, hook: str, fallback: bytes, *args) -> bytes:
        """
        Run one mutation hook, or return what was going to happen anyway.

        A rule that raises must not take the RF link down with it. The terminal
        is holding a transaction open and the operator is standing at it; an
        unmutated exchange they can see in the trace is a far better outcome
        than a dropped field they have to diagnose.
        """
        if self.mutations is None:
            return fallback
        try:
            out = getattr(self.mutations, hook)(*args)
        except Exception:                              # noqa: BLE001
            logger.exception("Mutation %s raised; relaying the original bytes", hook)
            return fallback
        return bytes(out) if out is not None else fallback


class CardEmulator(_RelayCore):
    """
    Drives a PN532 in target mode and relays what the terminal sends.

    ``transport`` is anything satisfying ``transport.base.CardTransport``, so
    the card being relayed can be in a local reader, behind the remote card
    proxy, or in another ACR122U.

    The chip does ISO-DEP here, which is why this deals in whole APDUs and why
    a response has to fit one frame. ``IsoDepEmulator`` is the other trade.
    """

    # No __init__ of its own. It had one that forwarded every argument
    # unchanged, which bought nothing and cost a signature to keep in step —
    # and duly fell out of step the moment _RelayCore gained one.

    # ── target mode ──────────────────────────────────────────────────────────

    def wait_for_terminal(self) -> bytes:
        """
        Enter target mode and block until a terminal selects us.

        Returns the PN532 manual's ``InitiatorCommand``: the first frame the
        chip received once it was a target. That is not decoration — see
        ``_command_in_activation``, which is where a whole session used to go
        missing.
        """
        logger.info("Entering target mode — present the reader to a terminal")
        # PARAM_14443_4_PICC is what makes the chip run the ISO-DEP state
        # machine as a PICC, and it is the whole premise of this driver:
        # TgGetData and TgSetData carry APDUs only while it is on. It is not in
        # the reader baseline — a reader has no use for it — so it has to be
        # set here rather than assumed, and it goes back with everything else.
        # AUTO_ATR_RES still has to go, or TgInitAsTarget answers nothing.
        self._borrow_chip(set_bits=PARAM_14443_4_PICC,
                          clear_bits=PARAM_AUTO_ATR_RES)
        if not self.sessions:
            self._wear_card_historical()
            self._report_identity()
        self._measure_link()
        self._announce()
        data = self.chip.call(CMD_TG_INIT_AS_TARGET, self.card.init_body(),
                              timeout=TERMINAL_WAIT,
                              keep_waiting=self._still_wanted,
                              on_retry=self._rearmed)
        if not data:
            raise PN532Error("TgInitAsTarget returned nothing")
        mode = data[0]
        logger.info("Selected by a terminal — %s (mode byte %02X)",
                    summarise_target_mode(mode), mode)
        if not mode & TARGET_MODE_PICC:
            # The chip is not running ISO-DEP, so TgGetData has nothing to
            # hand over and the relay would stall with no explanation. Say it
            # here, where the cause is still in view.
            raise PN532Error(
                f"The chip activated with ISO-DEP off (mode {mode:02X} — "
                f"{summarise_target_mode(mode)}), so it will not carry APDUs. "
                "PARAM_14443_4_PICC did not take — try again on a freshly "
                "plugged-in reader, or use --own-isodep, which does the layer "
                "here and wants that bit off anyway.")
        return data[1:]

    def _report_identity(self) -> None:
        """
        Put the emulated card and the relayed one side by side, once.

        A terminal that reads a valid PPSE and deselects anyway has decided
        something, and everything it could have decided on other than the
        answer itself is in these rows. The firmware builds the ATS, so all but
        the last of them are the chip's and not ours to change — which is
        exactly why they are worth stating rather than leaving to be guessed
        at from a log that shows only APDUs.
        """
        theirs = b""
        try:
            theirs = bytes(self.transport.get_atr() or b"")
        except Exception:                              # noqa: BLE001
            logger.debug("Relayed card offered no ATS to compare", exc_info=True)

        uid = getattr(self.transport, "uid", b"")
        ours_uid = b"\x08" + bytes(self.card.nfcid1)
        logger.info("Presenting  UID %s (%d bytes, random ID)  ATQA %s  SAK %02X",
                    ours_uid.hex().upper(), len(ours_uid),
                    bytes(self.card.atqa).hex().upper(), self.card.sak)
        if uid:
            logger.info("Relaying    UID %s (%d bytes)",
                        bytes(uid).hex().upper(), len(bytes(uid)))

        if not theirs:
            return
        try:
            card_ats = parse_ats(with_length_byte(theirs))
        except IsoDepError:
            logger.debug("Relayed card's ATS did not parse: %s", theirs.hex())
            return

        chip = parse_ats(with_length_byte(CHIP_ATS))
        logger.info("ATS  ours (the chip's): FSCI %d (%d-byte frames), FWI %d, "
                    "TA1 %s", chip.fsci, chip.fsc, chip.fwi,
                    "--" if chip.ta1 is None else f"{chip.ta1:02X}")
        logger.info("ATS  the card's:        FSCI %d (%d-byte frames), FWI %d, "
                    "TA1 %s", card_ats.fsci, card_ats.fsc, card_ats.fwi,
                    "--" if card_ats.ta1 is None else f"{card_ats.ta1:02X}")
        differences = [name for name, mine, theirs_ in
                       (("frame size", chip.fsci, card_ats.fsci),
                        ("FWI", chip.fwi, card_ats.fwi),
                        ("bit rates", chip.ta1 or 0, card_ats.ta1 or 0))
                       if mine != theirs_]
        if differences:
            logger.info("The two differ on %s. The chip builds this ATS in "
                        "firmware, so none of it is ours to match — if a "
                        "terminal takes the real card and refuses this one, "
                        "these rows are where to look.",
                        ", ".join(differences))

    def _wear_card_historical(self) -> None:
        """
        Put the relayed card's historical bytes into the activation block.

        On this path the chip builds the ATS, and the only part of it we get a
        say in is the Tk field of TgInitAsTarget. Everything else — FWI
        included — is the firmware's, which is the trade this driver makes.
        """
        theirs = self._card_historical()
        if not theirs or theirs == bytes(self.card.historical):
            return
        logger.info("Wearing the relayed card's historical bytes: %s",
                    theirs.hex().upper())
        self.card.historical = theirs

    # How long to wait for a terminal's *first* command after it activates us.
    # TgGetData's own deadline is twenty seconds, which is right for a
    # conversation in progress and wrong here: a terminal that selects a card
    # and then says nothing has decided something about the activation itself,
    # and waiting out twenty silent seconds for it — then raising — hides both
    # the decision and every session that would have followed.
    #
    # It cannot cut a wait short, and the number is chosen knowing that. The
    # escape is a blocking PC/SC transmit: once TgGetData is with the reader,
    # the reader holds it until its own bridge timeout — about five seconds —
    # and nothing on this side gets a say until it comes back. A deadline
    # under that expires while the command is still in flight, which is why
    # "asked nothing for 4 s" was printed 5.6 seconds after activation and why
    # the next command to the reader then cost 110 ms instead of 6: it was
    # queued behind the tail of a command we had already given up on.
    #
    # So it sits just past the bridge's own timeout. One TgGetData is issued,
    # allowed to run its course, and the verdict is passed on what it returned.
    FIRST_COMMAND_WAIT = 5.5

    def get_data(self, timeout: float | None = None) -> bytes | None:
        """
        One APDU from the terminal, or None when it has gone away.

        A released target is an ordinary end to a transaction, not a failure,
        so it comes back as None rather than an exception.
        """
        data = self.chip.call(CMD_TG_GET_DATA, timeout=timeout)
        if not data:
            raise PN532Error("TgGetData returned nothing")
        status = status_of(data[0])
        if status != 0x00:
            if status in (STATUS_RELEASED, STATUS_FIELD_OFF):
                self._note_ending(status)
                return None
            if status in RECOVERABLE_RF:
                raise RFError(f"TgGetData: {describe_status(status)}", status)
            raise PN532Error(f"TgGetData failed: {describe_status(status)}")
        return data[1:]

    def set_data(self, response: bytes) -> None:
        """
        Hand a response back to the terminal.

        One TgSetData is all there is on this path, and it carries less than
        the reader's Lc byte can express — see MAX_PSEUDO_APDU_PAYLOAD. The two
        other ways of getting a longer response out are both closed:
        TgSetMetaData is not answered by this chip, and a Direct Transmit big
        enough to hold the whole thing damages the reader.

        So a response that does not fit is not sent at all from here. Splitting
        it is the *terminal's* problem to be told about, not the chip's — see
        _split_for_terminal.
        """
        if len(response) > MAX_RESPONSE:
            raise CannotChain(
                f"{len(response)} bytes will not fit the {MAX_RESPONSE} one "
                f"TgSetData carries on this reader, and this chip offers no "
                f"way to split it below the APDU layer")
        self._send_piece(CMD_TG_SET_DATA, response)

    def _send_piece(self, command: int, piece: bytes) -> None:
        try:
            data = self.chip.call(command, piece)
        except NoAnswer as exc:
            if command == CMD_TG_SET_META_DATA:
                raise CannotChain(
                    self._why_the_send_went_unanswered(command, piece)) from exc
            raise PN532Error(
                self._why_the_send_went_unanswered(command, piece)) from exc
        if not data:
            # An answer with no status byte is an outcome nobody saw, and
            # calling that success is how a response that never reached the
            # terminal becomes a mystery two layers up: the relay carries on,
            # asks for the next command, and waits out the reader on a
            # terminal that is still expecting the last one.
            raise PN532Error(
                f"{command_name(command)} came back without a status byte, so "
                f"whether the terminal got the response is unknown")
        if status_of(data[0]) != 0x00:
            raise PN532Error(
                f"{command_name(command)} failed: "
                f"{describe_status(status_of(data[0]))}")

    def _split_for_terminal(self, response: bytes) -> bytes:
        """
        Keep a response that will not fit, and tell the terminal to come back
        for it.

        This is the last mechanism available on this hardware, and it is one
        layer up from every other thing tried. Below the APDU layer everything
        is closed: one TgSetData carries less than a certificate record, the
        chip does not answer TgSetMetaData, and a Direct Transmit big enough
        for the whole response damages the reader. Above it, ISO 7816-4 has an
        answer that has been there all along — ``61 XX``, "there are XX more
        bytes, ask for them" — and the terminal collects them with GET
        RESPONSE, at a size we choose.

        So a 256-byte record leaves as ``61 BC``, then 188 bytes and ``61 42``,
        then 66 bytes and the card's own ``9000``. Three exchanges, none of
        them near anything that has ever hurt this reader, each with its own
        frame waiting time.

        **It changes what the card says.** The card answered in one APDU and
        the terminal is told it answered in three, so it is off unless asked
        for: a trace with this on is a trace of a conversation ATRIUM shaped.
        Whether a contactless kernel will do GET RESPONSE at all is the open
        question — it is mandatory over T=0 and unusual over the air, where
        ISO-DEP normally makes it unnecessary. The log says plainly when it is
        used, and the terminal's next command answers it.
        """
        if not self.split_responses or len(response) <= MAX_RESPONSE:
            return response
        if len(response) < 2:
            return response

        self._held, self._held_sw = bytes(response[:-2]), bytes(response[-2:])
        self.split_responses_used += 1
        logger.warning(
            "The card answered %d bytes, which will not fit one exchange on "
            "this reader. Telling the terminal 61 XX and holding the rest for "
            "GET RESPONSE — the card said this in one APDU and the terminal is "
            "being told it said it in several.", len(response))
        return self._more_to_come()

    def _more_to_come(self) -> bytes:
        """``61 XX`` for as much as the next GET RESPONSE should ask for."""
        return b"\x61" + bytes([min(len(self._held), self.SPLIT_CHUNK)])

    def _serve_held(self, command: bytes) -> bytes | None:
        """
        The next slice of a held response, if this is the terminal collecting.

        None when it is not, which is every command on an ordinary run. A GET
        RESPONSE with nothing held is a real command for the card — some cards
        implement it — so it is only intercepted while something is waiting.
        """
        if self._held is None:
            return None
        if len(command) < 4 or command[:4] != self.GET_RESPONSE:
            # The terminal moved on without collecting. Its choice; drop the
            # held bytes rather than serving them out of order later.
            logger.info("Terminal did not collect the held response; dropping it")
            self._held = None
            return None

        wanted = command[4] if len(command) > 4 and command[4] else 256
        wanted = min(wanted, self.SPLIT_CHUNK, len(self._held))
        slice_, self._held = self._held[:wanted], self._held[wanted:]
        if self._held:
            tail = self._more_to_come()
        else:
            tail, self._held = self._held_sw, None
        logger.info("Served %d held byte(s) to GET RESPONSE, %d still to go",
                    len(slice_), len(self._held or b""))
        return slice_ + tail

    def _why_the_send_went_unanswered(self, command: int, piece: bytes) -> str:
        """
        What an unanswered send means, which now differs by command.

        TgSetMetaData is settled: on a freshly plugged reader, at 190 bytes,
        two hundred milliseconds after a 173-byte TgSetData had been answered
        normally, it returned nothing. Size and wedging were the two confounds
        and both were ruled out by that run, so this chip does not implement
        it. Saying "maybe unplug the reader" there would send the operator
        after a fault that has already been eliminated.

        TgSetData is the opposite: it works, so silence from it is the reader,
        and the reader is worth power-cycling before concluding anything.
        """
        if command == CMD_TG_SET_META_DATA:
            return (
                f"This chip does not answer {command_name(command)}, which is "
                f"measured rather than suspected: {len(piece)} bytes on a "
                f"freshly plugged reader, moments after a 173-byte TgSetData "
                f"went through.\n"
                f"So a response cannot be split on the firmware ISO-DEP path, "
                f"and one that will not fit a single Direct Transmit cannot be "
                f"delivered at all. `atrium.py nfc transmit-limit` measures how "
                f"much this reader carries; a certificate record needs 258.")
        return (
            f"{command_name(command)} went unanswered with {len(piece)} bytes "
            f"to carry, inside the {MAX_PSEUDO_APDU_PAYLOAD - 2} this reader "
            f"has been answering. So it is not the size, and this is a command "
            f"the chip does implement.\n"
            f"The reader is wedged. An oversized Direct Transmit damages an "
            f"ACR122U until it is power-cycled, and the damage outlives the "
            f"process — three runs of exactly this symptom, on a command that "
            f"had worked a minute earlier, were one reader carrying a fault "
            f"from the run before.\n"
            f"Unplug the reader, plug it back in, and try once more."
        )

    # ── the relay ────────────────────────────────────────────────────────────

    def relay_once(self) -> bool:
        """Move one APDU each way. False when the terminal has finished."""
        first = not self.session_exchanges
        began = time.monotonic()
        try:
            command = self.get_data(
                timeout=self.FIRST_COMMAND_WAIT if first else None)
        except NoAnswer:
            if not first:
                raise
            waited = time.monotonic() - began
            # Activated, then nothing. Worth naming: it is a different
            # animal from a deselect, and it is the shape a terminal makes
            # when it objects to the activation rather than to an answer.
            logger.info("The terminal selected us and then asked nothing for "
                        "%.1f s — the reader held one TgGetData open for that "
                        "whole time and handed back nothing. Arming again.",
                        waited)
            self.silent_activations += 1
            self.session_silent = True
            return False
        except RFError as exc:
            # The terminal will send it again; answering nothing is what the
            # standard asks of a card that did not hear the question.
            self.rf_errors += 1
            logger.info("%s — staying silent; the terminal will retry", exc)
            return True
        if command is None:
            return False
        self._exchange(command)
        return True

    # ── answering more than one exchange carries ─────────────────────────────

    GET_RESPONSE = b"\x00\xC0\x00\x00"

    # How much to hand over per GET RESPONSE. Two bytes short of a full
    # exchange, because every slice but the last is followed by another
    # 61 XX and the two have to travel together.
    SPLIT_CHUNK = MAX_RESPONSE - 2

    def _exchange(self, command: bytes) -> None:
        """Put one command to the card and hand the answer back to the terminal."""
        held = self._serve_held(command)
        if held is not None:
            self.set_data(held)
            self._observe(command, held)
            return
        # The terminal starts counting against FWT the moment it finishes
        # sending, so what matters to it is this whole span — the card's share
        # plus everything this process and the USB bridge add. Measuring only
        # the card understates it, and the difference is the part we control.
        began = time.monotonic()
        command, card_response, response = self._relay(command)
        response = self._fit(card_response, response)

        response = self._split_for_terminal(response)
        try:
            self.set_data(response)
        except CannotChain as exc:
            # The card answered, and the answer cannot be delivered. Telling
            # the terminal so is far better than raising: it gets a legible
            # card error, the session stays up, and the trace goes on to show
            # what it does next — which is the thing worth knowing and the
            # thing a traceback here destroys.
            logger.error("%s", exc)
            logger.error("Answering the terminal 6F00 for a %d-byte response "
                         "that cannot be delivered. --split-responses offers "
                         "it as 61 XX for the terminal to collect, which is "
                         "the only route left on this reader.", len(response))
            self.undeliverable += 1
            response = b"\x6F\x00"
            self.set_data(response)
        self._note_turnaround(time.monotonic() - began)
        self._observe(command, response)

    def _command_in_activation(self, activation: bytes) -> bytes | None:
        """
        The terminal's first APDU, when it arrived with the activation.

        ``TgInitAsTarget`` answers with the mode byte followed by
        ``InitiatorCommand`` — "the first valid frame received by the PN532
        once configured as target". Where the terminal's opening SELECT lands
        is a race: if it reaches the chip before the host has collected the
        activation it rides along inside that reply, and if it arrives after,
        the following ``TgGetData`` collects it. libnfc's emulation examples
        treat what ``nfc_target_init`` returns as the first APDU for exactly
        this reason.

        This driver dropped it, and the cost was a whole session each time it
        happened: the terminal sat waiting for an answer to a command nobody
        had seen, while ``TgGetData`` waited for a second command the terminal
        was never going to send. On this rig it was every other session,
        alternating — one relayed exchange, one four-second silence, one
        relayed exchange.

        A RATS here is activation rather than an APDU, and anything shorter
        than a header is not a command; both come back as None.
        """
        # Said every time, including when it is empty. Which of the two places
        # the terminal's opening command lands in is the difference between a
        # session that relays and one that sits silent, and a log that only
        # speaks up in one of the two cases cannot settle which happened.
        logger.info("Activation carried %d byte(s)%s", len(activation),
                    f": {activation[:32].hex().upper()}" if activation else "")
        if len(activation) < 4 or is_rats(activation):
            return None
        logger.info("The activation carried the terminal's first command "
                    "(%d bytes) — relaying it rather than waiting for a "
                    "second that is not coming", len(activation))
        return bytes(activation)

    def _fit(self, original: bytes, mutated: bytes) -> bytes:
        """
        Keep a grown response inside what one exchange carries.

        This is the contactless-specific hazard, and it has no contact
        equivalent: a mutation that lengthens a response — a replaced tag with a
        longer value, an append, a splice — can push a READ RECORD or GPO past
        the chip's 262-byte frame. set_data would raise, the link would drop,
        and the operator would be looking at a timeout with nothing to read.

        Serving the card's own bytes instead is the lesser wrong: the trace
        shows the exchange unmutated and the count says how often it happened,
        so the answer is "that rule does not fit contactless" rather than
        "the reader stopped working".
        """
        if mutated is original or len(mutated) <= MAX_CHAINED_RESPONSE:
            return mutated
        self.oversize += 1
        logger.error(
            "A mutation grew the response to %d bytes; one exchange carries %d. "
            "Relaying the card's own %d bytes instead — shorten the rule, or use "
            "a mode that does not lengthen the value.",
            len(mutated), MAX_CHAINED_RESPONSE, len(original))
        return original

    def run(self) -> int:
        """
        Present a card for as long as the operator wants one. Returns the
        total number of exchanges across every session.

        A terminal ending a session is not a reason to stop presenting a card.
        Several kernels look at a card once — read the PPSE, see what
        applications it offers — deselect, and come back to transact; a phone
        does the same on every tag it discovers. An emulator that exits on the
        first S(DESELECT) never sees the second pass, and every run looks like
        "one exchange and it gave up" no matter what the terminal was actually
        doing. That is precisely what this rig kept reporting.

        So the loop re-arms: a session ends, and unless the operator has said
        stop, the chip goes straight back into target mode. Ctrl-C is what
        finishes a run.

        The transport is connected here rather than by the caller so a card
        that is not present fails before the RF side is armed, when the error
        can still say something useful.
        """
        self.transport.connect()
        try:
            while not self._stop:
                self._start_session()
                try:
                    activation = self.wait_for_terminal()
                except NoAnswer:
                    # Nobody came in the whole arming window. Ordinary, and
                    # scoped tightly to the arming: wrapped around the session
                    # as well, it reported a failed TgSetData as "no terminal
                    # turned up" and buried the thing that actually broke.
                    logger.info("No terminal turned up while the card was "
                                "presented")
                    break
                # Counted here rather than at arming: a session is a terminal
                # that turned up, and reporting "3 sessions" for two terminals
                # and a timeout would be a small lie in the one number an
                # operator reads to decide whether anything happened.
                self.sessions += 1
                opening = self._command_in_activation(activation)
                if opening is not None:
                    self._exchange(opening)
                while not self._stop:
                    if not self.relay_once():
                        break
                self._finish_session()
                if not self._should_stay_armed():
                    break
        except Cancelled as exc:
            logger.info("%s", exc)
        finally:
            self._return_chip()
            self.transport.disconnect()
        logger.info("Finished after %d session(s) and %d exchange(s); the card "
                    "took %.0f ms in total, %.0f ms at its slowest, and the "
                    "terminal waited %.0f ms at worst",
                    self.sessions, self.exchanges, self.card_seconds * 1000,
                    self.slowest_card * 1000, self.slowest_turnaround * 1000)
        return self.exchanges

    def _should_stay_armed(self) -> bool:
        """
        Whether to present the card again after the session that just ended.

        Yes if the terminal engaged at all: it asked something, or it activated
        us and then went quiet, which is still a terminal that is present and
        deciding — and the quiet one is worth watching repeat, because nothing
        we answered can explain it.

        No if it activated and deselected without a word. That is a stray poll,
        and re-arming for it leaves the reader beeping at an empty room.
        """
        return bool(self.session_exchanges or self.session_silent)

    def _start_session(self) -> None:
        self.session_exchanges = 0
        self._held = None
        self.session_silent = False
        self.session_slowest_card = 0.0
        self.session_slowest_turnaround = 0.0
        self.ended_status = None
        self.last_sw = None
        if self.sessions:
            logger.info("Session %d — arming again; the terminal may be back",
                        self.sessions + 1)

    def _finish_session(self) -> None:
        """Say how the session that just ended went, while it is still one."""
        logger.info("Session %d ended after %d exchange(s)",
                    self.sessions, self.session_exchanges)
        if self.session_exchanges:
            logger.info("Staying armed — a terminal that read this card once "
                        "may come back to transact. Ctrl-C to stop.")
        verdict = self._why_it_ended()
        if verdict:
            logger.warning("%s", verdict)


# ── Owning ISO-DEP, so the card can ask for more time ────────────────────────

class Deselected(Exception):
    """The terminal ended the session. An ordinary outcome, not a failure."""


class IsoDepEmulator(_RelayCore):
    """
    Card emulation with the block layer in our hands rather than the chip's.

    ``CardEmulator`` lets the PN532 do ISO-DEP and deals in whole APDUs. That
    is the proven path and stays the default. It also means the chip decides
    FWI, never sends S(WTX), and cannot chain — so a relay slower than the
    firmware's frame waiting time is dropped by the terminal with nothing said.

    This driver turns the chip's PICC handling off and does the layer itself,
    which buys exactly three things:

    * **FWI is ours.** ``ats.fwi`` goes into the ATS we answer RATS with, so
      the terminal's budget is one we chose. 12 is ~1.24 s against the
      firmware's card-like tens of milliseconds.
    * **S(WTX).** While the relayed card is being waited on, this asks the
      terminal for more time — repeatedly, for as long as the answer takes.
      That is the mechanism ISO 14443-4 provides for precisely this, and it is
      the only one that survives a genuinely slow relay.
    * **Chaining.** A response longer than one frame goes out as several
      blocks instead of being refused, which retires the 262-byte ceiling.

    What it costs is that the ISO-DEP layer is now ours to get right. The block
    handling is covered by tests against a fake chip; the RF behaviour is not,
    and cannot be. The ACR122U's CCID bridge does pass the raw target commands
    — a terminal has selected a card emulated this way and the RATS came back
    in the activation data — so what is left unproven is a granted extension
    rather than the path itself.
    """

    # Ask for time when this much of the budget is gone. The rest is headroom
    # for the round trip that carrying the S(WTX) itself costs — over USB and
    # a scheduler, not free. Lower it on a slow link.
    WTX_AT = 0.6

    def __init__(self, chip, transport, card: EmulatedCard | None = None,
                 on_apdu=None, mutations=None, ats: Ats | None = None,
                 wtxm: int = 16, wtx_at: float | None = None,
                 alert: bool = True) -> None:
        super().__init__(chip, transport, card, on_apdu, mutations, alert)
        # Everything in the ATS but the historical bytes is this driver's to
        # choose. The bytes themselves are the card's identity, so a caller
        # that pinned none has not asked for none — it has said nothing, and
        # run() fills them from the card actually being relayed.
        self.ats = ats or Ats()
        if not self.ats.historical:
            self.ats.historical = bytes(self.card.historical)
            self._historical_pinned = False
        else:
            self._historical_pinned = True
        if not 1 <= wtxm <= WTXM_MAX:
            raise ValueError(f"WTXM is 1–{WTXM_MAX}, not {wtxm}")
        self.wtxm = wtxm
        self.wtx_at = self.WTX_AT if wtx_at is None else wtx_at
        if not 0 < self.wtx_at < 1:
            raise ValueError(f"wtx_at is a fraction of the budget, not {self.wtx_at}")

        self.cid: int | None = None
        self.fsd = 256
        self.wtx_requests = 0
        # How many times the reader asked for an ATS, and how long the answer
        # took. More than one RATS means the first answer did not arrive in
        # time, which no later fix can undo.
        self.rats_seen = 0
        self.ats_seconds = 0.0
        self._inbound = bytearray()
        self._last_sent: bytes | None = None
        self._activated = False

    # ── the wire ─────────────────────────────────────────────────────────────

    # The smallest gap between two reads. Not a pacing device — a floor, so a
    # link that fails instantly cannot spin the CPU for the whole budget. On
    # real hardware a read costs ~9 ms, well over this, so nothing is ever
    # slept and the chip listens continuously; only a link answering in
    # microseconds ever touches it.
    MIN_READ_INTERVAL = 0.002

    # How long to keep trying past mangled frames before calling it.
    #
    # This is a *duration*, not a pause between attempts, and the difference
    # was a bug. The count alone was wrong — eight reads inside 40 ms declared
    # the air unusable before the terminal could retransmit — but the fix for
    # it, sleeping a share of FWT between reads, was worse. The chip only
    # receives while TgGetInitiatorCommand is outstanding: it sits inside the
    # command until the bridge's own ~5 s discard, which is why an idle run
    # shows the command re-armed four times in twenty seconds rather than
    # returning at once. Sleeping between reads is therefore not patience, it
    # is deafness — at 177 ms of sleep per 9 ms read the relay was listening
    # under 5% of the time and would miss a retransmission that arrived
    # perfectly.
    #
    # So: no sleeping. Re-enter the read immediately, keep the chip listening
    # as near to continuously as this transport allows, and bound the whole
    # thing by wall clock instead.
    RF_RETRY_SECONDS = 1.5

    def _receive(self) -> bytes | None:
        """
        The next frame from the terminal, past anything the air mangled.

        A CRC or framing error is not the end of a session — ISO/IEC 14443-4
        expects the card to stay silent so the reader retries, which is exactly
        what reading again does. Treating one as fatal drops a transaction that
        was about to recover by itself, and that is what a terminal shows as a
        dead card.

        Reading again *at once* is the whole point: the chip hears nothing while
        no read is outstanding, so any gap is a window in which the terminal's
        retransmission is lost. The budget is spent on wall clock rather than
        on a count, so a fast-failing link still gets a fair hearing without
        the relay going deaf between attempts.
        """
        deadline = time.monotonic() + self.RF_RETRY_SECONDS
        consecutive = 0
        while True:
            began = time.monotonic()
            try:
                frame = self.chip.get_initiator_command()
            except RFError as exc:
                self.rf_errors += 1
                consecutive += 1
                if time.monotonic() >= deadline:
                    raise PN532Error(self._rf_failure(consecutive, exc)) from exc
                if consecutive <= 3 or consecutive % 25 == 0:
                    logger.info("%s — reading again straight away, so the chip "
                                "keeps listening (%d)", exc, consecutive)
                floor = self.MIN_READ_INTERVAL - (time.monotonic() - began)
                if floor > 0:
                    time.sleep(floor)
                continue
            if frame is None:
                # get_initiator_command answers None for both a deliberate
                # release and a lost field; the chip kept which it was.
                self._note_ending(self.chip.release_status)
            return frame

    def _rf_failure(self, consecutive: int, exc: Exception) -> str:
        """
        Why a run of receive errors happened — the honest version.

        "Move the readers apart" is the right advice for genuine interference
        and the wrong advice here, where a reader that relays fine under other
        software rules interference out. On a bridged reader the more likely
        cause is structural: every frame the terminal sends has to be collected
        across a USB round trip through the CCID bridge, and if that misses the
        RF reception window the frame comes back parity- or CRC-garbled no
        matter how clean the air is. Before any command has been exchanged,
        that is the same round-trip ceiling that the ATS deadline is about,
        one frame later.
        """
        over = self.RF_RETRY_SECONDS
        head = (f"{consecutive} frames from the terminal arrived garbled over "
                f"{over:.1f}s ({exc})")

        # A late ATS explains this whether or not an exchange slipped through.
        # The reader gave up waiting and restarted activation, so the chip is
        # reading fragments of an activation it is no longer part of — and one
        # exchange getting through in the middle of that is luck, not health.
        if self.ats_seconds > ATS_DEADLINE:
            return (
                f"{head}, after an ATS that went out {self.ats_seconds * 1000:.1f} ms "
                f"late.\n"
                "That is the cause, not the air: the reader stops waiting for "
                f"an ATS after {ATS_DEADLINE * 1000:.1f} ms and restarts "
                "activation, so what is being read here is fragments of an "
                "activation this chip is no longer part of. Answering RATS "
                "from the host costs a USB round trip, and the deadline is "
                "shorter than one. The chip's own ISO-DEP — the default, "
                "without --own-isodep — answers it in firmware.")

        if self.exchanges == 0:
            return (
                f"{head}, before a single command completed.\n"
                "Activation finished but nothing legible followed, which on "
                "this path usually means the chip and the reader are out of "
                "step rather than that the air is bad. Try the default path "
                "(without --own-isodep), which does the block layer in "
                "firmware; if that relays, the air is fine.")

        return (
            f"{head}, after {self.exchanges} clean exchange(s). Activation was "
            "sound and a command did get through, so this really may be the "
            "air — move the reader and the terminal a little apart, or closer.")

    def _send(self, frame: bytes) -> None:
        self._last_sent = frame
        self.chip.response_to_initiator(frame)

    @property
    def max_inf(self) -> int:
        return max_inf_size(self.fsd, cid=self.cid is not None)

    # ── activation ───────────────────────────────────────────────────────────

    def arm(self) -> bytes:
        """
        Put the chip in target mode with its own ISO-DEP switched off.

        The order matters: the parameter has to be clear before the target is
        initialised, or the chip arms itself to answer RATS and the first
        block never reaches us.

        Only the two flags this mode is about are touched. Writing the whole
        byte would also clear AUTO_RATS, which has nothing to do with target
        mode and everything to do with whether this reader can still activate a
        card afterwards.
        """
        self._borrow_chip(clear_bits=PARAM_14443_4_PICC | PARAM_AUTO_ATR_RES)
        logger.info("ISO-DEP is ours: PN532 PICC handling off, FWI %d (FWT %.0f ms)",
                    self.ats.fwi, self.ats.fwt * 1000)
        self._measure_link()
        self._announce()
        data = self.chip.call(CMD_TG_INIT_AS_TARGET,
                              self.card.init_body(mode=MODE_PASSIVE_ONLY),
                              timeout=TERMINAL_WAIT,
                              keep_waiting=self._still_wanted,
                              on_retry=self._rearmed)
        if not data:
            raise PN532Error("TgInitAsTarget returned nothing")
        logger.info("Selected by a terminal — %s (mode byte %02X)",
                    summarise_target_mode(data[0]), data[0])
        if data[0] & TARGET_MODE_PICC:
            # This driver asked the chip *not* to do ISO-DEP; if it did anyway,
            # every block below is about to be fought over by two state
            # machines. Better to say so than to debug it from the air.
            logger.warning(
                "The chip activated as an ISO-DEP PICC even though PICC "
                "handling was switched off. It will answer RATS itself and "
                "this driver's blocks will collide with the chip's — drop "
                "--own-isodep, or re-plug the reader and try again.")
        return data[1:]

    def _handle_rats(self, raw: bytes) -> None:
        rats = parse_rats(raw)
        self.cid = rats.cid or None
        self.fsd = rats.fsd
        ats = self.ats.build()

        self.rats_seen += 1
        if self._activated:
            # The reader is asking again, which it only does when no valid ATS
            # reached it in time. That is the clearest signal there is that the
            # answer below is late, and it arrives before any CRC error does.
            logger.warning(
                "The reader sent RATS again — it did not get our ATS within "
                "the %.1f ms ISO 14443-4 allows for it. Answering once more, "
                "but a repeat here means the answer is not arriving in time "
                "rather than arriving wrong.", ATS_DEADLINE * 1000)
        self._activated = True

        logger.info("RATS: reader takes %d-byte frames, CID %d — answering ATS %s "
                    "(FWT %.0f ms)", rats.fsd, rats.cid, ats.hex().upper(),
                    self.ats.fwt * 1000)

        # Timed, because this is the one deadline on the card that is not ours
        # to choose and the one this stack is least able to meet.
        began = time.monotonic()
        self._send(ats)
        took = time.monotonic() - began

        # The reader's clock started when it *sent* RATS. Ours cannot: by the
        # time this code runs, the RATS has already crossed USB inside
        # TgInitAsTarget's reply, and that leg is invisible from here. Counting
        # only from where we can see reports a missed deadline as met — which
        # it did, at "8.2 ms, inside the 8.5 ms deadline", on a run whose next
        # eight reads were all CRC errors. Half a measured round trip is the
        # honest estimate for the part we cannot time.
        unseen = self.link_round_trip / 2
        self.ats_seconds = took + unseen

        detail = (f"{took * 1000:.1f} ms measured from when the RATS reached "
                  f"this process, plus about {unseen * 1000:.1f} ms for the "
                  f"leg before that which cannot be timed from here"
                  if unseen else
                  f"{took * 1000:.1f} ms measured, with the leg before it "
                  f"unmeasured")

        if self.ats_seconds > ATS_DEADLINE:
            logger.warning(
                "The ATS went out roughly %.1f ms after the reader asked for "
                "it — %s. The reader stops waiting after %.1f ms. It has "
                "already restarted activation by then, so anything read next "
                "is fragments of that, which is what a run of CRC errors here "
                "really is. This is the limit of doing ISO-DEP from the host "
                "through a CCID bridge, not a fixable timing detail.",
                self.ats_seconds * 1000, detail, ATS_DEADLINE * 1000)
        else:
            logger.info("ATS answered in roughly %.1f ms (%s), inside the "
                        "%.1f ms deadline",
                        self.ats_seconds * 1000, detail, ATS_DEADLINE * 1000)

    # ── waiting, out loud ────────────────────────────────────────────────────

    def _request_wtx(self) -> int:
        """
        Ask for more time and return the multiplier actually granted.

        The reader is entitled to grant less than was asked for, and the
        smaller number is the one that counts — taking our own would be
        assuming a budget the reader never agreed to.
        """
        self._send(s_wtx(self.wtxm, cid=self.cid))
        self.wtx_requests += 1

        raw = self._receive()
        if raw is None:
            raise Deselected("the terminal left while we were asking for time")

        block = parse_block(raw)
        if block.type is BlockType.S and block.s_type is SType.DESELECT:
            self.ended_status = STATUS_RELEASED
            self._send(s_deselect(cid=self.cid))
            raise Deselected("the terminal deselected us instead of granting time")
        if block.type is not BlockType.S or block.s_type is not SType.WTX:
            # Not a refusal in the protocol's terms, but not a grant either.
            logger.warning("Asked for time and got %s back; carrying on with our "
                           "own multiplier", raw[:2].hex().upper())
            return self.wtxm

        granted = block.wtxm or self.wtxm
        if granted < self.wtxm:
            logger.info("Asked for %d frame waiting times, granted %d",
                        self.wtxm, granted)
        return granted

    def _relay_with_wtx(self, command: bytes) -> tuple[bytes, bytes, bytes]:
        """
        Relay one APDU, asking the terminal for more time as often as it takes.

        The transport call goes to a worker so this thread stays free to talk
        to the terminal. That is the whole trick: a relay is slow because of
        something happening elsewhere, and the RF link has to keep answering
        while it happens.
        """
        box: dict[str, object] = {}

        def work() -> None:
            try:
                box["out"] = self._relay(command)
            except BaseException as exc:               # noqa: BLE001
                box["exc"] = exc

        worker = threading.Thread(target=work, daemon=True, name="isodep-relay")
        worker.start()

        budget = self.ats.fwt * self.wtx_at
        while True:
            worker.join(budget)
            if not worker.is_alive():
                break
            granted = self._request_wtx()
            budget = self.ats.fwt * granted * self.wtx_at

        if "exc" in box:
            raise box["exc"]                           # type: ignore[misc]
        return box["out"]                              # type: ignore[return-value]

    # ── sending a response, in as many blocks as it takes ────────────────────

    def _send_response(self, response: bytes, block_number: int) -> None:
        blocks = chain(response, block_number, self.max_inf, cid=self.cid)
        if len(blocks) > 1:
            self.chained_out += 1
            logger.info("Response is %d bytes; sending %d chained blocks",
                        len(response), len(blocks))

        self._send(blocks[0])
        for index, block in enumerate(blocks[1:], start=1):
            # Every further block waits for the reader to ack the one before.
            if not self._await_ack_for(block):
                logger.warning("Chained response abandoned after %d of %d blocks",
                               index, len(blocks))
                return
            self._send(block)

    def _await_ack_for(self, pending: bytes) -> bool:
        """Wait for the R(ACK) that releases `pending`. False if we should stop."""
        expected = parse_block(pending).block_number
        while True:
            raw = self._receive()
            if raw is None:
                return False
            block = parse_block(raw)

            if block.type is BlockType.S and block.s_type is SType.DESELECT:
                self.ended_status = STATUS_RELEASED
                self._send(s_deselect(cid=self.cid))
                raise Deselected("the terminal deselected us mid-response")

            if block.type is BlockType.R:
                if block.nak:
                    # A NAK asks for the block before this one again.
                    logger.info("Reader NAKed; resending the previous block")
                    if self._last_sent is not None:
                        self.chip.response_to_initiator(self._last_sent)
                    continue
                if block.block_number == expected:
                    return True
                logger.warning("R(ACK) for block %d while %d was pending",
                               block.block_number, expected)
                continue

            logger.warning("Expected an ack mid-chain, got %s — dropping it",
                           raw[:2].hex().upper())

    # ── the loop ─────────────────────────────────────────────────────────────

    def relay_once(self) -> bool:
        """Handle one frame from the terminal. False when it has finished."""
        raw = self._receive()
        if raw is None:
            return False

        if is_rats(raw):
            self._handle_rats(raw)
            return True

        if is_pps(raw):
            logger.info("PPS %s — accepting without changing the bit rate",
                        raw.hex().upper())
            self._send(pps_response(raw))
            return True

        try:
            block = parse_block(raw)
        except IsoDepError as exc:
            logger.warning("Not an ISO-DEP block (%s): %s", exc, raw[:8].hex().upper())
            return True

        if block.type is BlockType.S:
            if block.s_type is SType.DESELECT:
                # Seen as a block rather than inferred from a status byte, but
                # the same ending, and _why_it_ended needs to know which it was.
                self.ended_status = STATUS_RELEASED
                logger.info("Terminal deselected us — ending the transaction")
                self._send(s_deselect(cid=self.cid))
                return False
            # An unprompted S(WTX) from the reader is not a thing we asked for.
            logger.warning("Unprompted S(WTX) from the reader; ignoring")
            return True

        if block.type is BlockType.R:
            if block.nak and self._last_sent is not None:
                logger.info("Reader NAKed; resending")
                self.chip.response_to_initiator(self._last_sent)
            return True

        # An I-block. Chained ones are acknowledged and accumulated; the last
        # completes the command.
        self._inbound.extend(block.inf)
        if block.chaining:
            self._send(r_block(block.block_number, cid=self.cid))
            return True

        command = bytes(self._inbound)
        self._inbound.clear()

        began = time.monotonic()
        try:
            command, _card_response, response = self._relay_with_wtx(command)
        except Deselected as exc:
            logger.info("%s", exc)
            return False

        self._send_response(response, block.block_number)
        self._note_turnaround(time.monotonic() - began)
        self._observe(command, response)
        return True

    def _adopt_card_identity(self) -> None:
        """
        Wear the relayed card's historical bytes.

        They are the most recognisable thing in an ATS — this card's say
        "KONA" — and a terminal that reads them off the real card and then off
        ours should see the same answer. FWI is deliberately *not* copied: the
        real card's is sized for a card, and a relay needs the longer budget
        this driver exists to choose.
        """
        if self._historical_pinned:
            return
        theirs = self._card_historical()
        if not theirs or theirs == self.ats.historical:
            return
        logger.info("Adopting the relayed card's historical bytes: %s",
                    theirs.hex().upper())
        self.ats.historical = theirs

    def _budget_seconds(self) -> float:
        """The FWT we advertised in the ATS, which is the one being counted."""
        return self.ats.fwt

    def _timeout_advice(self) -> str:
        return (f"This driver advertised FWI {self.ats.fwi} "
                f"({self.ats.fwt * 1000:.0f} ms) and sent {self.wtx_requests} "
                f"time extension(s). An expiry against a budget this large "
                f"means the extensions went out too late or were refused, not "
                f"that the budget was too small — check the S(WTX) exchanges "
                f"in the trace.")

    def run(self) -> int:
        """Wait for a terminal, then relay until it stops. Returns the count."""
        self.transport.connect()
        try:
            self._adopt_card_identity()
            activation = self.arm()
            # TgInitAsTarget hands back whatever activated us. With the chip's
            # PICC handling off that is usually the RATS itself, and answering
            # it here saves a round trip; when it is not, the loop picks it up.
            if is_rats(activation):
                self._handle_rats(activation)
            while not self._stop:
                if not self.relay_once():
                    break
        except (Deselected, Cancelled) as exc:
            logger.info("%s", exc)
        finally:
            self._return_chip()
            self.transport.disconnect()
        logger.info("Relay finished after %d exchange(s), %d time extension(s); "
                    "the card took %.0f ms in total, %.0f ms at its slowest, "
                    "and the terminal waited %.0f ms at worst",
                    self.exchanges, self.wtx_requests,
                    self.card_seconds * 1000, self.slowest_card * 1000,
                    self.slowest_turnaround * 1000)
        if self.rats_seen > 1 or (self.ats_seconds > ATS_DEADLINE
                                  and not self.exchanges):
            logger.warning(
                "The ATS took %.1f ms and the reader asked %d time(s) — the "
                "%.1f ms budget for it is fixed by ISO 14443-4 and is shorter "
                "than a USB round trip through this bridge. Owning the block "
                "layer from the host cannot beat that deadline; the chip's own "
                "ISO-DEP answers RATS in firmware, which is why the default "
                "path activates where this one does not.",
                self.ats_seconds * 1000, self.rats_seen, ATS_DEADLINE * 1000)
        else:
            # Only when activation itself was not the story — two competing
            # explanations for one failed run is worse than none.
            verdict = self._why_it_ended()
            if verdict:
                logger.warning("%s", verdict)
        return self.exchanges
