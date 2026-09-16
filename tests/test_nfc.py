"""
PN532 protocol, the ACR122 escape, and card emulation.

What these establish and what they cannot
-----------------------------------------
Covered: frame construction against the PN532 manual's own worked example,
parsing including every failure mode, command encoding, target parsing, the
ACR122 pseudo-APDU wrapper with its 61xx continuation, and the relay loop.

Not covered, and not coverable here: anything on the air. Whether a real
terminal selects the emulated card, whether timing budgets are met, whether a
particular EMV kernel accepts the ATS — all of that needs hardware.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from nfc.acr122 import ACR122Error, ACR122Link, _fallback_ioctls
from nfc.emulator import CardEmulator, EmulatedCard
from nfc.pn532 import (
    ACK,
    CMD_RF_CONFIGURATION,
    CMD_SAM_CONFIGURATION,
    CMD_SET_PARAMETERS,
    PREAMBLE,
    CMD_GET_FIRMWARE_VERSION,
    CMD_IN_DATA_EXCHANGE,
    CMD_TG_GET_DATA,
    CMD_TG_INIT_AS_TARGET,
    CMD_TG_SET_META_DATA,
    MAX_FRAME_DATA,
    NACK,
    unframe,
    PN532,
    PN532_TO_HOST,
    PN532Error,
    STATUS_FIELD_OFF,
    STATUS_RELEASED,
    Target,
    build_command,
    build_frame,
    describe_status,
    parse_frame,
)


def response_for(command: int, body: bytes = b"") -> bytes:
    """A well-formed chip response to `command`, framed as a serial link sends it."""
    return build_frame(bytes([PN532_TO_HOST, (command + 1) & 0xFF]) + body)


def bare_response_for(command: int, body: bytes = b"") -> bytes:
    """
    What an **ACR122U** answers with, which is not the same thing.

    Its microcontroller does the framing, so what crosses the pseudo-APDU is
    the bare response — ``D5 <command+1> <data>`` — and the reader adds its own
    90 00. The old double echoed whole frames instead, which is precisely why
    it never caught the link sending framed commands the reader ignores.
    """
    return bytes([PN532_TO_HOST, (command + 1) & 0xFF]) + body


# What TgInitAsTarget answers with on the firmware path: 106 kbps, Mifare
# framing, and bit 3 — activated as an ISO/IEC 14443-4 PICC. The value used to
# be an arbitrary 04, which under the reply's real layout is a reserved baud
# rate and ISO-DEP off; it went unnoticed for as long as nothing read the byte.
ACTIVATED_AS_PICC = b"\x08"


# Commands a chip answers with a bare acknowledgement and nothing else. The
# scripted queue is for the ones a test is actually about; serving these from
# it instead would mean every test had to know which housekeeping commands the
# code under test happens to send, and would break the moment one was added.
_ACKNOWLEDGED = {CMD_SET_PARAMETERS, CMD_SAM_CONFIGURATION, CMD_RF_CONFIGURATION}

# Commands a chip answers with real content whatever a test is about.
# GetFirmwareVersion is one: the emulator times the link with it before arming,
# and serving that from a scripted queue would hand the timing probe an answer
# meant for TgInitAsTarget.
_ALWAYS_ANSWERED = {CMD_GET_FIRMWARE_VERSION: b"\x32\x01\x06\x07"}


class FakeLink:
    """
    Stands in for the ACR122 link: replies from a scripted queue.

    Housekeeping commands are answered properly rather than off the queue,
    because a real chip answers the command it was asked. A blind queue makes
    every test in the file depend on the exact sequence of setup commands the
    driver sends, which is how adding one SetParameters call broke ten tests
    that had nothing to do with parameters.
    """

    def __init__(self, replies=None, prepend_ack=True, answer_always=True):
        self.replies = list(replies or [])
        self.prepend_ack = prepend_ack
        # Tests that are specifically about a command going unanswered turn
        # this off; everything else wants a chip that behaves like a chip.
        self.answer_always = answer_always
        self.sent: list[bytes] = []
        self.polls = 0

    def exchange(self, frame: bytes) -> bytes:
        if frame:
            self.sent.append(frame)
            payload = unframe(frame)
            if len(payload) >= 2 and payload[1] in _ACKNOWLEDGED:
                reply = response_for(payload[1])
                return (ACK + reply) if self.prepend_ack else reply
            if (self.answer_always and len(payload) >= 2
                    and payload[1] in _ALWAYS_ANSWERED):
                reply = response_for(payload[1], _ALWAYS_ANSWERED[payload[1]])
                return (ACK + reply) if self.prepend_ack else reply
        else:
            self.polls += 1
        if not self.replies:
            return b""
        reply = self.replies.pop(0)
        return (ACK + reply) if self.prepend_ack else reply


class AckThenAnswer:
    """
    A link that acknowledges first and answers on a later read.

    What a directly-attached PN532 does. The answer *is* coming, so the way to
    get it is to read again — re-sending would restart whatever the chip is
    part-way through.
    """

    def __init__(self, reply: bytes, quiet_reads: int = 2):
        self.reply = reply
        self.quiet_reads = quiet_reads
        self.sent: list[bytes] = []
        self.polls = 0

    def exchange(self, frame: bytes) -> bytes:
        if frame:
            self.sent.append(frame)
            return ACK
        self.polls += 1
        return b"" if self.polls <= self.quiet_reads else self.reply


class DropsUntil:
    """
    A bridged reader, as measured on an ACR122U.

    Its own timeout expires at about five seconds and takes the command with
    it: nothing comes back, a GET RESPONSE afterwards finds nothing either, and
    the only way forward is to send the command again. ``drops`` is how many
    sends are swallowed before the answer appears — a terminal turning up.
    """

    def __init__(self, reply: bytes, drops: int = 2):
        self.reply = reply
        self.drops = drops
        self.sent: list[bytes] = []
        self.polls = 0

    def exchange(self, frame: bytes) -> bytes:
        if not frame:
            self.polls += 1
            return b""                       # nothing is ever collected here
        self.sent.append(frame)
        return b"" if len(self.sent) <= self.drops else self.reply


# ── Framing ───────────────────────────────────────────────────────────────────

class TestFraming:
    def test_matches_the_manual_worked_example(self):
        """
        GetFirmwareVersion from the PN532 User Manual. An independent anchor —
        if the checksums were wrong, this is what would catch it.
        """
        assert build_command(CMD_GET_FIRMWARE_VERSION) == \
            bytes.fromhex("0000FF02FED4022A00")

    def test_round_trip(self):
        frame = response_for(CMD_GET_FIRMWARE_VERSION, b"\x32\x01\x06\x07")
        parsed = parse_frame(frame)
        assert parsed.is_data
        assert parsed.data == bytes([0x03, 0x32, 0x01, 0x06, 0x07])

    def test_checksums_are_actually_checked(self):
        frame = bytearray(response_for(CMD_GET_FIRMWARE_VERSION, b"\x32"))
        frame[-2] ^= 0xFF                       # corrupt the DCS
        with pytest.raises(PN532Error, match="data checksum"):
            parse_frame(bytes(frame))

    def test_length_checksum_is_checked(self):
        frame = bytearray(response_for(CMD_GET_FIRMWARE_VERSION, b"\x32"))
        frame[4] ^= 0xFF                        # corrupt the LCS
        with pytest.raises(PN532Error, match="length checksum"):
            parse_frame(bytes(frame))

    def test_ack_and_nack(self):
        assert parse_frame(ACK).kind == "ack"
        assert parse_frame(NACK).kind == "nack"

    @pytest.mark.parametrize("buf", [b"", b"\x00", b"\x00\x00\xFF", b"garbage"])
    def test_short_or_unrecognised_buffers_report_rather_than_raise(self, buf):
        """A link that splits the ACK from the response is normal, not an error."""
        assert parse_frame(buf).kind == "incomplete"

    def test_finds_a_frame_after_leading_noise(self):
        frame = response_for(CMD_GET_FIRMWARE_VERSION, b"\x32")
        assert parse_frame(b"\xAA\xBB" + frame).is_data

    def test_host_direction_byte_is_rejected(self):
        """A frame we sent must not be mistaken for one the chip sent."""
        with pytest.raises(PN532Error, match="chip-to-host"):
            parse_frame(build_command(CMD_GET_FIRMWARE_VERSION))

    def test_empty_command_is_refused_and_a_long_one_goes_extended(self):
        from nfc.pn532 import MAX_EXTENDED_FRAME

        with pytest.raises(PN532Error, match="empty"):
            build_frame(b"")

        # 300 bytes used to be refused. It is a certificate record's worth of
        # card, and refusing it is what handed a terminal 6F00 four commands
        # into a working transaction.
        long_one = build_frame(b"\xD5" + b"\x00" * 299)
        assert long_one[3:5] == b"\xFF\xFF"
        assert unframe(long_one) == b"\xD5" + b"\x00" * 299

        with pytest.raises(PN532Error, match="extended frame can describe"):
            build_frame(b"\xD5" * (MAX_EXTENDED_FRAME + 1))


# ── Chip ──────────────────────────────────────────────────────────────────────

class TestPN532:
    def test_firmware_version(self):
        chip = PN532(FakeLink([response_for(CMD_GET_FIRMWARE_VERSION,
                                            b"\x32\x01\x06\x07")]))
        assert chip.firmware_version() == {"chip": "PN532", "version": "1.6",
                                           "support": 7}

    def test_response_to_the_wrong_command_is_refused(self):
        """Out-of-sync links otherwise return one command's answer for another."""
        chip = PN532(FakeLink([response_for(0x40, b"\x00")],
                              answer_always=False))
        with pytest.raises(PN532Error, match="was for command"):
            chip.firmware_version()

    def test_ack_delivered_separately_is_handled(self):
        """Some links return the ACK and the response on separate reads."""
        link = FakeLink([ACK, response_for(CMD_GET_FIRMWARE_VERSION,
                                           b"\x32\x01\x06\x07")],
                        prepend_ack=False)
        assert PN532(link).firmware_version()["chip"] == "PN532"

    def test_silence_produces_a_legible_error(self):
        """The command by name, how long it was given, and what came back."""
        chip = PN532(FakeLink([], answer_always=False))
        with pytest.raises(PN532Error) as caught:
            chip.call(CMD_GET_FIRMWARE_VERSION, timeout=0.05)
        message = str(caught.value)
        assert "GetFirmwareVersion (D4 02)" in message
        assert "no response" in message

    def test_an_acknowledged_answer_is_collected_by_reading_again(self):
        """An ACK means the answer is coming. Read for it; do not re-send."""
        link = AckThenAnswer(response_for(CMD_GET_FIRMWARE_VERSION,
                                          b"\x32\x01\x06\x07"))
        assert PN532(link).firmware_version()["chip"] == "PN532"
        assert link.polls == 3, "the answer should have been read for"
        assert len(link.sent) == 1, "an acknowledged command is never re-sent"

    def test_a_command_the_reader_dropped_is_sent_again(self):
        """
        The ACR122U's bridge times out at about five seconds and discards the
        command. Nothing is left to collect, so the answer is to ask again —
        which is what re-arming target mode until a terminal turns up means.
        """
        from nfc.pn532 import CMD_TG_INIT_AS_TARGET

        link = DropsUntil(response_for(CMD_TG_INIT_AS_TARGET, b"\x00\xE0\x80"),
                          drops=2)
        assert PN532(link).call(CMD_TG_INIT_AS_TARGET) == b"\x00\xE0\x80"
        assert len(link.sent) == 3, "it should have been re-sent twice"
        assert link.polls == 0, "there is nothing to collect from this reader"

    def test_the_command_is_not_re_sent_once_it_has_been_acknowledged(self):
        """
        The distinction is sticky. A quiet read after an ACK means "not
        finished", never "start over" — re-sending TgInitAsTarget there would
        restart target mode every poll and never get past the first one.
        """
        from nfc.pn532 import CMD_TG_INIT_AS_TARGET

        link = AckThenAnswer(response_for(CMD_TG_INIT_AS_TARGET, b"\x00"),
                             quiet_reads=4)
        PN532(link).call(CMD_TG_INIT_AS_TARGET)
        assert len(link.sent) == 1

    def test_only_the_safe_commands_are_re_sent(self):
        """
        TgSetData twice would put a response on the air twice. A command with a
        side effect fails on the first silence rather than being repeated.
        """
        from nfc.pn532 import CMD_TG_SET_DATA

        link = DropsUntil(response_for(CMD_TG_SET_DATA, b"\x00"), drops=99)
        with pytest.raises(PN532Error, match="TgSetData"):
            PN532(link).call(CMD_TG_SET_DATA, b"\x90\x00", timeout=0.5)
        assert len(link.sent) == 1

    def test_the_three_waits_are_three_different_lengths(self):
        """
        A chip answering itself, a terminal already in a session, and a
        terminal that has not arrived yet are three different questions. One
        number for all of them is wrong for two of them.
        """
        from nfc.pn532 import (
            CMD_TG_GET_INITIATOR_COMMAND,
            CMD_TG_INIT_AS_TARGET,
            default_timeout,
        )

        chip_alone = default_timeout(CMD_GET_FIRMWARE_VERSION)
        mid_session = default_timeout(CMD_TG_GET_INITIATOR_COMMAND)
        arming = default_timeout(CMD_TG_INIT_AS_TARGET)
        assert chip_alone < mid_session < arming

    def test_the_receive_commands_never_slow_their_polling(self):
        """
        Once the target is selected the terminal is timing us against the frame
        waiting time. Easing off there would spend milliseconds of a
        millisecond budget on not asking.
        """
        from nfc.pn532 import (
            CMD_TG_GET_INITIATOR_COMMAND,
            CMD_TG_INIT_AS_TARGET,
            POLL_INTERVAL,
            _poll_interval,
        )

        assert _poll_interval(CMD_TG_GET_INITIATOR_COMMAND, 30.0) == POLL_INTERVAL
        assert _poll_interval(CMD_TG_GET_DATA, 30.0) == POLL_INTERVAL
        # Nothing is on the air until this one returns, so it may ease off —
        # but not before the wait looks like a human rather than a chip.
        assert _poll_interval(CMD_TG_INIT_AS_TARGET, 0.0) == POLL_INTERVAL
        assert _poll_interval(CMD_TG_INIT_AS_TARGET, 30.0) > POLL_INTERVAL

    def test_polling_does_not_overshoot_the_deadline(self):
        import time

        chip = PN532(FakeLink([], answer_always=False))
        began = time.monotonic()
        with pytest.raises(PN532Error):
            chip.call(CMD_GET_FIRMWARE_VERSION, timeout=0.05)
        assert time.monotonic() - began < 0.5

    def test_a_long_wait_can_be_called_off(self):
        """
        Waiting for a terminal is the one thing here that takes minutes. A
        deadline nobody can interrupt makes stop() a suggestion.
        """
        from nfc.pn532 import Cancelled

        polls = []

        def keep_waiting():
            polls.append(1)
            return len(polls) < 3

        from nfc.pn532 import CMD_TG_INIT_AS_TARGET

        link = DropsUntil(response_for(CMD_TG_INIT_AS_TARGET, b"\x00"), drops=99)
        with pytest.raises(Cancelled, match="Stopped while waiting"):
            PN532(link).call(CMD_TG_INIT_AS_TARGET, timeout=30.0,
                             keep_waiting=keep_waiting)
        assert len(polls) == 3, "it should have stopped at the first refusal"

    def test_a_cancelled_wait_is_not_a_chip_failure(self):
        """Callers separate the two, so the exception has to as well."""
        from nfc.pn532 import Cancelled

        assert issubclass(Cancelled, PN532Error)

    def test_the_link_may_explain_its_own_silence(self):
        """
        Why a command went unanswered is reader knowledge, not chip knowledge,
        so the chip layer asks the link rather than guessing.
        """
        class Explaining(FakeLink):
            @staticmethod
            def silence_hint(command):
                return "check the thing that is actually wrong"

        chip = PN532(Explaining([], answer_always=False))
        with pytest.raises(PN532Error, match="actually wrong"):
            chip.call(CMD_GET_FIRMWARE_VERSION, timeout=0.05)

    def test_a_link_that_explains_badly_does_not_hide_the_error(self):
        class Broken(FakeLink):
            @staticmethod
            def silence_hint(command):
                raise RuntimeError("boom")

        chip = PN532(Broken([], answer_always=False))
        with pytest.raises(PN532Error, match="GetFirmwareVersion"):
            chip.call(CMD_GET_FIRMWARE_VERSION, timeout=0.05)

    def test_list_passive_targets_parses_a_card(self):
        body = (b"\x01"                          # one target
                b"\x01"                          # target number
                b"\x04\x00"                      # ATQA
                b"\x20"                          # SAK — 14443-4
                b"\x04\xAA\xBB\xCC\xDD"          # UID length + UID
                b"\x05\x75\x33\x92\x03")         # ATS
        chip = PN532(FakeLink([response_for(0x4A, body)]))
        targets = chip.list_passive_targets()
        assert len(targets) == 1
        t = targets[0]
        assert t.uid == b"\xAA\xBB\xCC\xDD"
        assert t.sak == 0x20 and t.is_iso14443_4
        assert t.ats == b"\x75\x33\x92\x03"
        assert "AABBCCDD" in str(t)

    def test_a_certificate_sized_response_survives_the_framing(self):
        """
        The bytes that stopped every real transaction on this rig. A
        contactless READ RECORD carrying an ICC public key certificate answers
        254 bytes; the chip hands that back as D5 41 00 plus the lot, 259
        bytes, four past what a normal frame's single length byte describes.
        build_frame refused, so the reader's own answer was thrown away on the
        doorstep and the terminal got 6F00.
        """
        record = bytes.fromhex("7081FB") + bytes(range(251))
        card = record + b"\x90\x00"
        assert len(card) == 256

        reply = b"\xD5\x41\x00" + card
        assert len(reply) == 259

        frame = build_frame(reply)
        assert unframe(frame) == reply
        parsed = parse_frame(frame)
        assert parsed.kind == "data"
        assert parsed.data == reply[1:], "the card's bytes came back intact"

    def test_the_extended_marker_is_not_a_nack_or_a_full_normal_frame(self):
        """
        FF FF where the length byte goes says "extended". FF 00 is a NACK and
        FF 01 is a normal frame carrying its maximum 255. Reading any of the
        three as another desynchronises the link, and the failure would look
        like a corrupt card rather than a parser.
        """
        assert parse_frame(NACK).kind == "nack"

        full = build_frame(b"\xD5" + b"\xAA" * 254)
        assert full[3:5] == b"\xFF\x01", "255 bytes still fits a normal frame"
        assert parse_frame(full).kind == "data"

        over = build_frame(b"\xD5" + b"\xAA" * 255)
        assert over[3:5] == b"\xFF\xFF", "256 needs the extended shape"
        assert parse_frame(over).kind == "data"

    def test_an_extended_frame_arriving_in_pieces_is_not_called_corrupt(self):
        """
        A link that hands the header and the body over separately is normal —
        it is why parse_frame reports rather than raises — and the extended
        header is three bytes longer, so the window where that matters is
        wider.
        """
        frame = build_frame(b"\xD5\x41\x00" + b"\xBB" * 256)
        for cut in (4, 6, 8, 20, len(frame) - 2):
            assert parse_frame(frame[:cut]).kind == "incomplete", cut
        assert parse_frame(frame).kind == "data"

    def test_empty_field_is_an_empty_list_not_an_error(self):
        chip = PN532(FakeLink([response_for(0x4A, b"\x00")]))
        assert chip.list_passive_targets() == []

    def test_a_memory_card_is_recognised_as_not_speaking_apdus(self):
        """SAK without bit 5 means MIFARE Classic or similar — no APDUs."""
        assert not Target(1, b"\x04\x00", 0x08, b"\x01\x02\x03\x04").is_iso14443_4

    def test_data_exchange_returns_the_response(self):
        chip = PN532(FakeLink([response_for(CMD_IN_DATA_EXCHANGE,
                                            b"\x00\x6F\x00")]))
        assert chip.data_exchange(b"\x00\xA4\x04\x00") == b"\x6F\x00"

    def test_data_exchange_surfaces_the_chip_status(self):
        chip = PN532(FakeLink([response_for(CMD_IN_DATA_EXCHANGE, b"\x01")]))
        with pytest.raises(PN532Error, match="timeout"):
            chip.data_exchange(b"\x00\xA4\x04\x00")

    def test_oversized_apdu_is_refused_not_truncated(self):
        """A silently shortened APDU produces a response that looks real."""
        chip = PN532(FakeLink([]))
        with pytest.raises(PN532Error, match="chaining is not implemented"):
            chip.data_exchange(b"\x00" * (MAX_FRAME_DATA + 1))

    def test_status_codes_are_explained(self):
        assert "timeout" in describe_status(0x01)
        assert "left the field" in describe_status(0x2B)
        assert "0xFE" in describe_status(0xFE)


# ── ACR122 link ───────────────────────────────────────────────────────────────

class FakeConnection:
    """A pyscard connection whose transmit() is scripted."""

    def __init__(self, script):
        self.script = list(script)
        self.sent: list[bytes] = []

    def transmit(self, apdu):
        self.sent.append(bytes(apdu))
        if not self.script:
            return [], 0x6A, 0x81
        return self.script.pop(0)

    def disconnect(self):
        pass


class TestACR122Link:
    def _link(self, script):
        link = ACR122Link("ACS ACR122U PICC Interface 00")
        link._connection = FakeConnection(script)
        return link

    def test_sends_the_bare_command_not_a_framed_one(self):
        """
        FF 00 00 00 <Lc> D4 <command> — Lc counting the D4.

        The reader builds the normal information frame itself. Handing it one
        already built returns nothing at all: no error, an empty reply.
        """
        frame = build_command(CMD_GET_FIRMWARE_VERSION)
        link = self._link([(list(bare_response_for(CMD_GET_FIRMWARE_VERSION, b"\x32")),
                            0x90, 0x00)])
        link.exchange(frame)

        sent = link._connection.sent[0]
        assert sent[:4] == bytes([0xFF, 0x00, 0x00, 0x00])
        assert sent[5:] == bytes([0xD4, CMD_GET_FIRMWARE_VERSION])
        assert sent[4] == 2, "Lc counts the D4"
        assert PREAMBLE not in sent, "no frame preamble may reach the reader"

    def test_the_reply_is_reframed_for_the_chip_layer(self):
        """
        The link's contract with PN532 is whole frames both ways.

        Re-framing the bare answer keeps that promise, so the frame parser and
        everything built on it stay untouched by this reader's peculiarity.
        """
        link = self._link([(list(bare_response_for(CMD_GET_FIRMWARE_VERSION, b"\x32")),
                            0x90, 0x00)])
        out = link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))
        assert out == response_for(CMD_GET_FIRMWARE_VERSION, b"\x32")

    def test_an_empty_reply_is_not_yet_rather_than_never(self):
        """
        The reader answers when its own microcontroller is done, which for a
        command that waits on the outside world is before the chip has
        anything to say. Nothing back means ask again — the chip layer holds
        the deadline, and raising here would deny it one.
        """
        link = self._link([([], 0x90, 0x00)])
        assert link.exchange(build_command(CMD_GET_FIRMWARE_VERSION)) == b""

    def test_a_reply_that_arrives_later_is_reframed_normally(self):
        body = list(bare_response_for(CMD_GET_FIRMWARE_VERSION, b"\x32"))
        link = self._link([([], 0x90, 0x00), (body, 0x90, 0x00)])
        assert link.exchange(build_command(CMD_GET_FIRMWARE_VERSION)) == b""
        # An empty frame is the chip layer polling: GET RESPONSE, not a resend.
        assert link.exchange(b"") == response_for(CMD_GET_FIRMWARE_VERSION,
                                                  b"\x32")
        assert link._connection.sent[1][:4] == bytes([0xFF, 0xC0, 0x00, 0x00])

    def test_the_escape_status_word_comes_off_but_the_response_keeps_its_own(self):
        """
        A relayed card answers 90 00, and so does the reader. Only one of those
        two is the reader's.

        On the escape path the reply arrives undivided, so the last 90 00 is
        the reader's and comes off. On a transmit the driver has already
        separated it, so the 90 00 still on the end belongs to the card — and
        taking it would corrupt every successful response that crossed.
        """
        payload = bytes([PN532_TO_HOST, CMD_IN_DATA_EXCHANGE + 1, 0x00]) \
            + b"\x6F\x1A\x90\x00"

        escape = self._link([(list(payload + b"\x90\x00"), 0x90, 0x00)])
        escape._path = "control"
        assert unframe(escape.exchange(build_command(CMD_IN_DATA_EXCHANGE))) \
            == payload

        transmit = self._link([(list(payload), 0x90, 0x00)])
        transmit._path = None
        assert unframe(transmit.exchange(build_command(CMD_IN_DATA_EXCHANGE))) \
            == payload

    def test_silence_hint_names_what_to_look_at(self):
        from nfc.pn532 import CMD_TG_INIT_AS_TARGET

        link = self._link([])
        assert "ATR_RES" in link.silence_hint(CMD_TG_INIT_AS_TARGET)
        assert link.silence_hint(0x02), "an unknown command still says something"

    def test_raw_hands_back_the_reply_unsplit(self):
        """
        The probe needs the bytes as they arrived. On the escape path the 90 00
        in the tuple is synthetic, so appending it would invent two bytes that
        were never on the wire.
        """
        link = self._link([([0xD5, 0x03, 0x32], 0x90, 0x00)])
        link._path = "control"
        assert link.raw([0xFF, 0x00, 0x48, 0x00, 0x00]) == b"\xD5\x03\x32"

        link = self._link([([0xD5, 0x03, 0x32], 0x90, 0x00)])
        link._path = None
        assert link.raw([0xFF, 0x00, 0x48, 0x00, 0x00]) == b"\xD5\x03\x32\x90\x00"

    def test_follows_a_61xx_continuation(self):
        """The usual shape: 61 xx, then a GET RESPONSE for the body."""
        body = list(bare_response_for(CMD_GET_FIRMWARE_VERSION, b"\x32"))
        link = self._link([([], 0x61, len(body)), (body, 0x90, 0x00)])
        assert link.exchange(build_command(CMD_GET_FIRMWARE_VERSION)) == \
            response_for(CMD_GET_FIRMWARE_VERSION, b"\x32")
        assert link._connection.sent[1][:4] == bytes([0xFF, 0xC0, 0x00, 0x00])

    def test_a_rejected_escape_says_it_needs_an_acr122(self):
        link = self._link([([], 0x6A, 0x81)])
        with pytest.raises(ACR122Error, match="ACR122-specific"):
            link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))

    def test_the_ready_cue_blinks_green_and_beeps(self):
        """
        The operator has a few seconds to present the terminal and no way to
        know when they started. LED plus buzzer is the cue.
        """
        from nfc.acr122 import announce_armed

        link = self._link([([], 0x90, 0x00)])
        assert announce_armed(link) is True
        apdu = link._connection.sent[0]
        assert apdu[:3] == bytes([0xFF, 0x00, 0x40]), "LED control"
        assert apdu[3] & 0x08, "the green mask bit has to be set to act on it"
        assert apdu[-1] == 0x01, "buzzer on during T1"

        quiet = self._link([([], 0x90, 0x00)])
        announce_armed(quiet, buzzer=False)
        assert quiet._connection.sent[0][-1] == 0x00

    def test_the_ready_cue_never_stops_a_relay_arming(self):
        """
        A reader that is not an ACR122U, or one that refuses the command. The
        cue is a convenience; failing it must not cost the transaction.
        """
        from nfc.acr122 import announce_armed

        class Refuses:
            def peripheral(self, apdu, split_status=True):
                raise ACR122Error("no")

        assert announce_armed(Refuses()) is False
        assert announce_armed(object()) is False, "not every link is a reader"

    def test_the_probe_reads_a_real_activation_correctly(self):
        """
        The exact bytes an ACR122U216 returned, with a terminal on the reader.

        Reported as "mode D5, 212 kbps, PICC on" once, because the reply still
        had the reader's wrapping on it and D5 is the direction byte. Every
        field in that sentence was wrong.
        """
        from nfc.probe import _body
        from nfc.pn532 import CMD_TG_INIT_AS_TARGET

        raw = bytes.fromhex("D58D00E0809000")
        body = _body(raw, CMD_TG_INIT_AS_TARGET)
        assert body == bytes.fromhex("00E080")

        mode, activation = body[0], body[1:]
        assert mode == 0x00, "106 kbps, Mifare framing"
        assert not mode & 0x04, "PICC off — the chip is not doing ISO-DEP"
        assert activation == b"\xE0\x80", "a RATS for us to answer"

    def test_the_probe_leaves_an_unwrapped_reply_alone(self):
        """A body that is already bare must not lose two more bytes."""
        from nfc.probe import _body
        from nfc.pn532 import CMD_TG_INIT_AS_TARGET

        assert _body(b"\x00\xE0\x80", CMD_TG_INIT_AS_TARGET) == b"\x00\xE0\x80"
        assert _body(b"", CMD_TG_INIT_AS_TARGET) == b""

    def test_the_escape_verdict_names_the_ceiling_when_the_bridge_is_the_ceiling(self):
        """
        Three escapes per relayed APDU, causally ordered, none removable while
        the chip owns ISO-DEP. So the median escape times three is the floor
        before the card has done anything — and if that already exceeds a
        card-like frame waiting time, speeding up the card side cannot help.
        """
        import io
        import contextlib

        from nfc.probe import _read_escape_cost

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _read_escape_cost({"polling_on": [27.0] * 20})
        slow = out.getvalue()
        assert "81 ms" in slow, "three escapes, not one"
        assert "the transport is the ceiling" in slow

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _read_escape_cost({"polling_on": [8.0] * 20, "saved_ms": 6.0})
        fast = out.getvalue()
        assert "the card side is worth attacking" in fast
        assert "18 ms per exchange" in fast, "the saving is per escape, x3"

    def test_measuring_the_ats_ignores_the_real_card_on_the_reading_antenna(self):
        """
        On a relay rig the reading reader has a real card sitting on it, and an
        ACR122U finds that first — which is exactly what the first run of this
        measured and reported as the chip's own ATS.

        The emulated card is not ambiguous: the PN532 takes three NFCID1 bytes
        and prepends 08, so it is always that 4-byte UID. Anything else is a
        real card and must be skipped, not reported.
        """
        import nfc.probe as probe_mod
        from nfc.emulator import EmulatedCard
        from nfc.isodep import Ats

        ours = b"\x08" + bytes(EmulatedCard().nfcid1)
        # The real card from the rig, byte for byte.
        real_uid = bytes.fromhex("0586CC7A956300")
        real_ats = bytes.fromhex("78007002534C4A0130502310")
        emulated_ats = Ats(fwi=9, historical=b"KONA").build()

        def target(uid, ats):
            return type("T", (), {
                "uid": uid, "ats": ats,
                "__str__": lambda self_: f"UID {uid.hex().upper()}",
            })()

        class Link:
            def __init__(self, name, direct=False):
                pass

            def connect(self):
                pass

            def close(self):
                pass

            def raw(self, apdu):
                return b""

        class Chip:
            parameters = 0x14

            def __init__(self, link):
                self.link = link

            def sam_configuration(self):
                pass

            def update_parameters(self, *, set_bits=0, clear_bits=0):
                pass

            def set_parameters(self, flags):
                pass

            def list_passive_targets(self, limit=1):
                # The real card first, as the hardware actually returned it.
                return [target(real_uid, real_ats), target(ours, emulated_ats)]

        import nfc.acr122 as acr122_mod
        import nfc.pn532 as pn532_mod
        saved = (probe_mod.ACR122Link, acr122_mod.open_pn532, pn532_mod.PN532)
        probe_mod.ACR122Link = Link
        acr122_mod.open_pn532 = lambda name, direct=False: (Chip(Link(name)),
                                                            Link(name))
        pn532_mod.PN532 = Chip
        try:
            found = probe_mod.measure_emulated_ats("A", "B", wait=0.4)
        finally:
            (probe_mod.ACR122Link, acr122_mod.open_pn532,
             pn532_mod.PN532) = saved

        assert found.get("ats") == emulated_ats, (
            "it reported the real card's ATS instead of the emulated one")
        assert real_ats != found["ats"]

    def test_an_ats_without_its_length_byte_still_parses(self):
        """
        InListPassiveTarget strips TL. parse_ats wants the wire shape, and
        reading one as the other reported a perfectly good ATS as unparseable —
        this exact one, off the rig.
        """
        from nfc.isodep import parse_ats, with_length_byte

        stripped = bytes.fromhex("78007002534C4A0130502310")
        parsed = parse_ats(with_length_byte(stripped))
        assert parsed.fwi == 7 and parsed.fsci == 8

        # An ATS that already has TL must be left exactly as it is.
        from nfc.isodep import Ats

        built = Ats(fwi=9, historical=b"KONA").build()
        assert with_length_byte(built) == built
        assert parse_ats(with_length_byte(built)).fwi == 9

    def test_measuring_the_ats_never_touches_the_link_the_thread_owns(self):
        """
        The arming thread holds the target reader's link for its whole life.
        ACR122Link has no lock, and a CCID exchange torn between two threads on
        an ACR122U does not fail cleanly — it returns another command's
        response. So the cleanup has to wait for the thread, not race it.

        This is the hazard documented in transport/prefetch.py and then written
        straight into the first draft of this function.
        """
        import threading
        import time as _time

        import nfc.probe as probe_mod
        from nfc.isodep import Ats

        inside = threading.Event()
        overlap = []
        busy = threading.Lock()

        class Link:
            def __init__(self, name, direct=False):
                self.closed = False

            def connect(self):
                pass

            def close(self):
                self.closed = True

            def raw(self, apdu):
                # Fail loudly if two threads are ever in here at once.
                if not busy.acquire(blocking=False):
                    overlap.append(True)
                    raise AssertionError("two threads inside one CCID link")
                try:
                    inside.set()
                    _time.sleep(0.02)
                    return b""            # never activates; the thread loops
                finally:
                    busy.release()

        class Chip:
            parameters = 0x14

            def __init__(self, link):
                self.link = link
                self.writes = []

            def sam_configuration(self):
                pass

            def update_parameters(self, *, set_bits=0, clear_bits=0):
                self.parameters = (self.parameters | set_bits) & ~clear_bits

            def set_parameters(self, flags):
                # The unsafe moment: if the arming thread were still running,
                # this would be the second thread on the link.
                self.link.raw([0xFF])
                self.writes.append(flags)

            def list_passive_targets(self, limit=1):
                from nfc.emulator import EmulatedCard

                uid = b"\x08" + bytes(EmulatedCard().nfcid1)
                seen = type("T", (), {
                    "uid": uid,
                    "ats": Ats(fwi=9, historical=b"KONA").build(),
                    "__str__": lambda self_: f"UID {uid.hex().upper()}",
                })()
                return [seen]

        monkey = {}
        monkey["ACR122Link"] = probe_mod.ACR122Link
        probe_mod.ACR122Link = Link
        import nfc.acr122 as acr122_mod
        import nfc.pn532 as pn532_mod
        monkey["open_pn532"] = acr122_mod.open_pn532
        monkey["PN532"] = pn532_mod.PN532
        acr122_mod.open_pn532 = lambda name, direct=False: (
            Chip(Link(name)), Link(name))
        pn532_mod.PN532 = Chip

        try:
            found = probe_mod.measure_emulated_ats("A", "B", wait=0.4)
        finally:
            probe_mod.ACR122Link = monkey["ACR122Link"]
            acr122_mod.open_pn532 = monkey["open_pn532"]
            pn532_mod.PN532 = monkey["PN532"]

        assert inside.is_set(), "the arming thread never ran"
        assert not overlap, "the cleanup raced the arming thread on one link"
        assert found.get("ats"), "the ATS should have been read and reported"

    def test_the_emulated_ats_verdict_turns_on_the_chips_own_fwi(self):
        """
        The chip picks its own FWI in PICC mode and offers no way to read it
        back, so every conclusion about that path has assumed it is card-like.
        Two readers settle it — arm one, read it with the other — and the
        answer changes what to do next, so the verdict has to say which.
        """
        import contextlib
        import io

        from nfc.isodep import Ats, fwt_seconds, parse_ats
        from nfc.probe import _read_emulated_ats

        def verdict(fwi):
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                _read_emulated_ats(Ats(fwi=fwi, historical=b"KONA").build(),
                                   fwt_seconds, parse_ats)
            return out.getvalue()

        tight = verdict(7)
        assert "39 ms" in tight
        assert "does not fit" in tight, "a 50 ms card cannot live in 39 ms"

        roomy = verdict(9)
        assert "155 ms" in roomy
        assert "may fit after all" in roomy

    def test_an_emulated_card_with_no_ats_is_named_as_such(self):
        import contextlib
        import io

        from nfc.isodep import fwt_seconds, parse_ats
        from nfc.probe import _read_emulated_ats

        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            _read_emulated_ats(b"", fwt_seconds, parse_ats)
        assert "did not complete RATS" in out.getvalue()

    def test_the_probe_sends_exactly_what_the_link_sends(self):
        """
        A diagnostic that wraps commands differently from the code it is
        diagnosing proves nothing about the code it is diagnosing.
        """
        from nfc.probe import _Trace, _chip

        class Recording:
            def __init__(self):
                self.sent = []

            def raw(self, apdu):
                self.sent.append(bytes(apdu))
                return b""

        recorder = Recording()
        _chip(recorder, _Trace(), CMD_IN_DATA_EXCHANGE, b"\x01\x00\xA4")

        link = self._link([([], 0x90, 0x00)])
        link.exchange(build_command(CMD_IN_DATA_EXCHANGE, b"\x01\x00\xA4"))

        assert recorder.sent == [link._connection.sent[0]]

    def test_transmitting_without_connecting(self):
        with pytest.raises(ACR122Error, match="not connected"):
            ACR122Link("x").exchange(b"\x00")

    def test_a_payload_past_what_the_reader_takes_is_refused_not_stretched(self):
        """
        A single Lc byte can say 255 and ACS document that, but the reader
        does not honour it: Lc FF came back empty in twelve milliseconds and
        left the reader damaged — a 57-byte TgSetData that had worked a minute
        earlier then answered nothing for three runs, and one oversized send
        failed its control transfer after thirty seconds.

        So this refuses instead of stretching. ISO 7816-4's extended form would
        make a 265-byte APDU, which is further past the boundary rather than
        around it; callers split instead.
        """
        from nfc.acr122 import (MAX_PSEUDO_APDU_PAYLOAD, PSEUDO_APDU_PREFIX,
                                pseudo_apdu)

        assert MAX_PSEUDO_APDU_PAYLOAD < 255, (
            "255 is the size that wedges this reader, not a size to aim at")

        full = pseudo_apdu(b"\x00" * MAX_PSEUDO_APDU_PAYLOAD)
        assert full[:4] == PSEUDO_APDU_PREFIX
        assert full[4] == MAX_PSEUDO_APDU_PAYLOAD

        with pytest.raises(ACR122Error, match="send it in pieces"):
            pseudo_apdu(b"\x00" * (MAX_PSEUDO_APDU_PAYLOAD + 1))

    def test_missing_reader_is_reported_clearly(self, monkeypatch):
        pytest.importorskip("smartcard", reason="pyscard not installed")
        monkeypatch.setattr("smartcard.System.readers", lambda: [])
        with pytest.raises(ACR122Error, match="not connected"):
            ACR122Link("ACS ACR122U PICC Interface 00").connect()


class TestIdentify:
    """
    Two identical ACR122Us on a desk is the case naming cannot solve: PC/SC
    tells them apart and their USB addresses differ, but neither says which of
    the two in front of you it is. Making the reader light up does.
    """

    def test_the_led_command_matches_the_vendor_format(self):
        from nfc.acr122 import build_led_command

        # FF 00 40 <state> 04 <T1> <T2> <reps> <buzzer>, per the ACR122U API.
        apdu = build_led_command(green=True, red=False, t1=2, t2=2, repeat=3)
        assert apdu[:3] == bytes([0xFF, 0x00, 0x40])
        assert apdu[4] == 0x04, "Lc is fixed at four data bytes"
        assert apdu[5:] == bytes([0x02, 0x02, 0x03, 0x00])

    def test_green_sets_its_mask_initial_and_blink_bits(self):
        from nfc.acr122 import build_led_command

        state = build_led_command(green=True, red=False)[3]
        assert state == 0x08 | 0x20 | 0x80

    def test_the_final_state_bits_stay_clear_so_the_led_returns_to_off(self):
        """
        An identify that leaves a reader lit makes the next one ambiguous,
        which defeats the point of having one.
        """
        from nfc.acr122 import build_led_command

        state = build_led_command(green=True, red=True)[3]
        assert not state & 0x01 and not state & 0x02

    def test_both_colours_combine(self):
        from nfc.acr122 import build_led_command

        assert build_led_command(green=True, red=True)[3] == 0xFC

    def test_blinking_nothing_is_refused(self):
        from nfc.acr122 import build_led_command

        with pytest.raises(ACR122Error, match="green, red, or both"):
            build_led_command(green=False, red=False)

    def test_out_of_range_timings_are_named(self):
        from nfc.acr122 import build_led_command

        with pytest.raises(ACR122Error, match="repeat=300"):
            build_led_command(repeat=300)

    def test_a_bad_buzzer_link_is_refused(self):
        from nfc.acr122 import build_led_command

        with pytest.raises(ACR122Error, match="Buzzer link"):
            build_led_command(buzzer=0x09)

    def test_the_command_is_not_wrapped_in_the_pn532_escape(self):
        """
        The LED command is the reader's own, already an APDU. Wrapping it in
        FF 00 00 00 like a chip frame would send the reader a PN532 command
        that does not exist.
        """
        from nfc.acr122 import build_led_command

        conn = FakeConnection([([], 0x90, 0x02)])
        link = ACR122Link("ACS ACR122U PICC Interface 00 00")
        link._connection = conn

        apdu = build_led_command()
        link.peripheral(apdu)
        assert conn.sent == [apdu], "sent verbatim, not wrapped"

    def test_the_led_state_reply_is_not_read_as_a_failure(self, monkeypatch):
        """
        The reader answers 90 <LED state>, so SW2 carries data. Checking it
        against 9000 would report every success as a refusal.
        """
        pytest.importorskip("smartcard", reason="pyscard not installed")
        from nfc import acr122

        # identify() opens the reader directly — the field is empty — so the
        # escape channel is the path, exactly as it is for the chip.
        conn = DirectConnection([([], 0x90, 0x02)])

        class Link(acr122.ACR122Link):
            def connect(self):
                self._connection = conn

        monkeypatch.setattr(acr122, "ACR122Link", Link)
        out = acr122.identify("ACS ACR122U PICC Interface 00 00")
        assert out["led_state"] == 0x02

    def test_the_escape_path_does_not_bury_the_status_word(self, monkeypatch):
        """
        The escape hands back the whole reply with a synthetic 9000, because
        splitting a PN532 frame on its last two bytes breaks its checksum. A
        peripheral command is the opposite: its status word is the answer, and
        leaving it in the data reported every refusal as a success.
        """
        pytest.importorskip("smartcard", reason="pyscard not installed")
        from nfc.acr122 import build_led_command

        conn = DirectConnection([([0x11, 0x22], 0x6A, 0x81)])
        link = ACR122Link("ACS ACR122U PICC Interface 00 00", direct=True)
        link._connection = conn

        data, sw1, sw2 = link.peripheral(build_led_command())
        assert (sw1, sw2) == (0x6A, 0x81)
        assert data == bytes([0x11, 0x22])

    def test_a_command_answering_with_data_instead_keeps_every_byte(self, monkeypatch):
        """
        The firmware query returns its string *in place of* a status word, so
        splitting two bytes off the end would silently truncate the version.
        """
        pytest.importorskip("smartcard", reason="pyscard not installed")
        from nfc import acr122

        conn = DirectConnection([(list(b"ACR122U214"), 0x00, 0x00)])

        class Link(acr122.ACR122Link):
            def connect(self):
                self._connection = conn

        monkeypatch.setattr(acr122, "ACR122Link", Link)
        assert acr122.firmware_string("ACS ACR122U PICC Interface 00 00") == "ACR122U214"

    def test_a_refusal_says_the_command_is_acr122_specific(self, monkeypatch):
        pytest.importorskip("smartcard", reason="pyscard not installed")
        from nfc import acr122

        conn = DirectConnection([([], 0x6A, 0x81)])

        class Link(acr122.ACR122Link):
            def connect(self):
                self._connection = conn

        monkeypatch.setattr(acr122, "ACR122Link", Link)
        with pytest.raises(ACR122Error, match="ACR122-specific"):
            acr122.identify("Generic ICC Reader 00 00")


class DirectConnection(FakeConnection):
    """
    A direct pyscard connection: no negotiated protocol, so transmit() fails
    the way pcsc-lite makes it fail and only control() gets through.
    """

    def __init__(self, script, escape_ok=True, transmit_ok=False):
        super().__init__(script)
        self.escape_ok = escape_ok
        self.transmit_ok = transmit_ok
        self.controlled: list[bytes] = []
        self.codes: list[int] = []

    def transmit(self, apdu, protocol=None):
        if not self.transmit_ok:
            raise Exception("Invalid protocol in transmit: must be "
                            "CardConnection.T0_protocol, ...")
        return super().transmit(apdu)

    def control(self, code, apdu):
        self.codes.append(code)
        self.controlled.append(bytes(apdu))
        if not self.escape_ok:
            raise Exception("Failed to transmit with IOCTL. SCARD_E_NOT_TRANSACTED")
        data, sw1, sw2 = self.script.pop(0) if self.script else ([], 0x6A, 0x81)
        # The escape channel answers in one piece, status word included.
        return list(data) + [sw1, sw2]


class TestDirectMode:
    """
    The bug a direct session died on: SCardTransmit needs a negotiated protocol
    and SCARD_SHARE_DIRECT has none, so pyscard refused the call before the
    driver saw it. Card emulation only ever runs on a direct connection — the
    field is empty by definition — so this path had to work.
    """

    @pytest.fixture(autouse=True)
    def _needs_pyscard(self):
        # Only for smartcard.scard.SCARD_CTL_CODE — the platform's own way of
        # turning 3500 into an IOCTL, which is not worth reimplementing.
        pytest.importorskip("smartcard", reason="pyscard not installed")

    def _link(self, connection):
        link = ACR122Link("ACS ACR122U PICC Interface 00", direct=True)
        link._connection = connection
        return link

    def test_the_escape_code_comes_from_the_driver_not_the_platform(self):
        """
        The control code that carries an escape is not one number.

        libccid wants SCARD_CTL_CODE(1); Windows wants 3500; macOS and BSD want
        a third shape. Sending 3500 to libccid does not fail as "not
        authorised" — IFDHControl falls through to its default,
        IFD_ERROR_NOT_SUPPORTED (606), which surfaces as "Feature not
        supported" and reads exactly like the authorisation problem it is not.
        So ask the driver rather than guess.
        """
        from smartcard.scard import SCARD_CTL_CODE
        from nfc.acr122 import CM_IOCTL_GET_FEATURE_REQUEST, FEATURE_CCID_ESC_COMMAND

        wanted = SCARD_CTL_CODE(1)

        class Answers(DirectConnection):
            def control(self, code, apdu):
                if code == SCARD_CTL_CODE(CM_IOCTL_GET_FEATURE_REQUEST):
                    # tag, length, then the control code big-endian.
                    return [FEATURE_CCID_ESC_COMMAND, 4] + list(
                        wanted.to_bytes(4, "big"))
                if code != wanted:
                    raise Exception("Failed to control Feature not supported.")
                return super().control(code, apdu)

        conn = Answers([([0x00, 0x00, 0xFF, 0x00, 0xFF, 0x00], 0x90, 0x00)])
        link = ACR122Link("ACS ACR122U PICC Interface 00", direct=True)
        link._connection = conn
        link._discover_escape()

        assert link._escape_code == wanted, "the driver's answer must be used"
        assert link._escape_authorised is True
        link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))
        assert conn.codes[-1] == wanted

    def test_no_escape_feature_means_not_authorised(self):
        """
        libccid lists the escape feature only once it is authorised.

        Its absence from an answered query is therefore a definite answer, and
        a different problem from no control code working — which is what makes
        it worth telling them apart.
        """
        from smartcard.scard import SCARD_CTL_CODE
        from nfc.acr122 import CM_IOCTL_GET_FEATURE_REQUEST

        class NoEscape(DirectConnection):
            def control(self, code, apdu):
                if code == SCARD_CTL_CODE(CM_IOCTL_GET_FEATURE_REQUEST):
                    return [0x12, 4, 0x42, 0x00, 0x0D, 0x48]   # some other feature
                raise Exception("Failed to control Feature not supported.")

            def transmit(self, apdu, protocol=None):
                raise IndexError("list index out of range")

        link = ACR122Link("ACS ACR122U PICC Interface 00", direct=True)
        link._connection = NoEscape([])
        link._discover_escape()
        assert link._escape_authorised is False

        with pytest.raises(ACR122Error) as caught:
            link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))
        assert "not authorised" in str(caught.value)
        assert "ifdDriverOptions" in str(caught.value)

    def test_without_a_feature_query_every_code_is_tried(self):
        """A driver that will not answer the query still gets the guesses."""
        from smartcard.scard import SCARD_CTL_CODE

        class Stubborn(DirectConnection):
            def control(self, code, apdu):
                self.codes.append(code)
                raise Exception("Failed to control Feature not supported.")

            def transmit(self, apdu, protocol=None):
                raise IndexError("list index out of range")

        conn = Stubborn([])
        link = ACR122Link("ACS ACR122U PICC Interface 00", direct=True)
        link._connection = conn
        link._discover_escape()
        assert link._escape_authorised is None, "the query never answered"

        with pytest.raises(ACR122Error) as caught:
            link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))

        assert SCARD_CTL_CODE(1) in conn.codes, "libccid's code has to be tried"
        assert SCARD_CTL_CODE(3500) in conn.codes, "and Windows's"
        assert "606" in str(caught.value), (
            "the message should name the code pcscd logs for an unrecognised "
            "control code, since that is the symptom of this exact bug")

    def test_an_unauthorised_escape_explains_itself(self):
        """
        What a fresh Linux box actually does, and what it has to say about it.

        libccid refuses escape commands until ifdDriverOptions authorises
        them, and the raw fallback then returns nothing — pyscard reads the
        status word off the end of an empty list and raises "list index out of
        range", which tells the operator nothing at all. Both halves have to
        come out legible or the message is worse than useless.
        """
        class Unauthorised(DirectConnection):
            def transmit(self, apdu, protocol=None):
                # pyscard's own failure: sw1 = response[-2] on an empty reply.
                raise IndexError("list index out of range")

            def control(self, code, apdu):
                raise Exception("Failed to control Feature not supported.")

        link = self._link(Unauthorised([]))
        with pytest.raises(ACR122Error) as caught:
            link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))

        message = str(caught.value)
        assert "answered nothing" in message, (
            "'list index out of range' is pyscard's internal error, not a "
            "diagnosis — it has to be translated")
        assert "list index out of range" not in message

    def test_the_escape_channel_carries_the_bare_command(self):
        body = list(bare_response_for(CMD_GET_FIRMWARE_VERSION, b"\x32"))
        conn = DirectConnection([(body, 0x90, 0x00)])
        link = self._link(conn)

        out = link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))

        assert conn.controlled[0][:4] == bytes([0xFF, 0x00, 0x00, 0x00])
        assert conn.controlled[0][5:] == bytes([0xD4, CMD_GET_FIRMWARE_VERSION])
        assert out == response_for(CMD_GET_FIRMWARE_VERSION, b"\x32")
        assert conn.sent == [], "a direct connection must not use transmit()"

    def test_the_escape_prefers_libccids_code_on_linux(self):
        """
        This used to assert SCARD_CTL_CODE(3500) — which was the bug.

        3500 is the Windows number. libccid's escape is SCARD_CTL_CODE(1), and
        sending it 3500 falls through IFDHControl to IFD_ERROR_NOT_SUPPORTED
        (606) — indistinguishable, from the outside, from the authorisation
        error it is not. With no feature query to consult, the platform's own
        code has to be tried first.
        """
        from smartcard.scard import SCARD_CTL_CODE

        conn = DirectConnection([(list(response_for(CMD_GET_FIRMWARE_VERSION, b"\x32")),
                                  0x90, 0x00)])
        self._link(conn).exchange(build_command(CMD_GET_FIRMWARE_VERSION))
        expected = SCARD_CTL_CODE(1) if sys.platform.startswith("linux") \
            else _fallback_ioctls()[0]
        assert conn.codes[-1] == expected

    def test_a_response_ending_in_9000_is_not_truncated(self):
        """
        A response whose own last bytes are 90 00, followed by the reader's.

        Only one trailing status word may come off. Take two and the version
        bytes are silently short, which surfaces later as a checksum failure
        that says nothing about the real cause.
        """
        payload = b"\x32\x01\x90\x00"
        conn = DirectConnection(
            [(list(bare_response_for(CMD_GET_FIRMWARE_VERSION, payload)), 0x90, 0x00)])
        chip = PN532(self._link(conn))
        version = chip.firmware_version()
        assert version["chip"] == "PN532"
        assert version["version"] == "1.144", "the 90 00 in the payload survived"

    def test_a_stack_without_the_escape_falls_back_to_a_raw_transmit(self):
        body = list(bare_response_for(CMD_GET_FIRMWARE_VERSION, b"\x32"))
        conn = DirectConnection([(body, 0x90, 0x00)], escape_ok=False, transmit_ok=True)
        link = self._link(conn)
        assert link.exchange(build_command(CMD_GET_FIRMWARE_VERSION)) == \
            response_for(CMD_GET_FIRMWARE_VERSION, b"\x32")
        assert link._path == "raw"

    def test_the_working_path_is_settled_once_not_probed_per_frame(self):
        """
        Probing costs several control calls now that the code is not assumed —
        so the invariant is that it happens on the first frame and never again,
        not that it costs exactly one call.
        """
        body = list(response_for(CMD_GET_FIRMWARE_VERSION, b"\x32"))
        conn = DirectConnection([(body, 0x90, 0x00)] * 3,
                                escape_ok=False, transmit_ok=True)
        link = self._link(conn)

        link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))
        after_first = len(conn.controlled)
        assert after_first >= 1, "the escape has to be tried at least once"

        for _ in range(2):
            link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))
        assert len(conn.controlled) == after_first, (
            "the working path is remembered; escape must not be re-probed "
            "on every frame")

    def test_neither_path_working_names_the_libccid_setting(self):
        """
        Both remedies have to survive the case where nothing can be asked.

        With no feature query to answer it, the cause is genuinely unknown —
        so the message names the control-code mismatch first (the query failing
        suggests this is not libccid) and still points at the authorisation fix
        as the other candidate. Naming only one would send half of the people
        who hit this down the wrong path.
        """
        link = self._link(DirectConnection([], escape_ok=False, transmit_ok=False))
        with pytest.raises(ACR122Error) as caught:
            link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))
        message = str(caught.value)
        assert "ifdDriverOptions" in message
        assert "SCARD_CTL_CODE(1)" in message

    def test_a_card_present_link_is_untouched(self):
        """The ordinary T=1 path must not start going through control()."""
        body = list(response_for(CMD_GET_FIRMWARE_VERSION, b"\x32"))
        conn = DirectConnection([(body, 0x90, 0x00)], transmit_ok=True)
        link = ACR122Link("ACS ACR122U PICC Interface 00", direct=False)
        link._connection = conn
        link.exchange(build_command(CMD_GET_FIRMWARE_VERSION))
        assert conn.sent and not conn.controlled


# ── Emulation ─────────────────────────────────────────────────────────────────

class FakeCard:
    """A card that answers everything with 9000, for the relay loop."""

    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.received: list[bytes] = []
        self.connected = False

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def transmit(self, apdu):
        self.received.append(bytes(apdu))
        return self.responses.pop(0) if self.responses else b"\x90\x00"


class TestEmulatedCard:
    def test_init_body_layout(self):
        card = EmulatedCard()
        body = card.init_body()
        # mode + mifare(6) + felica(18) + nfcid3(10) + gt len + ats len + ats
        assert len(body) == 1 + 6 + 18 + 10 + 1 + 1 + len(card.historical)
        assert body[0] == 0x05, "PICC-only, passive"
        assert body[1:3] == card.atqa

    def test_sak_advertises_iso14443_4(self):
        """Without this bit a terminal will not send APDUs at all."""
        assert EmulatedCard().sak & 0x20

    def test_nfcid1_must_be_three_bytes(self):
        """The chip prepends 0x08 itself — the caller supplies the other three."""
        with pytest.raises(PN532Error, match="chip supplies the leading"):
            EmulatedCard(nfcid1=b"\x01\x02\x03\x04").mifare_params()

    def test_bad_atqa(self):
        with pytest.raises(PN532Error, match="ATQA"):
            EmulatedCard(atqa=b"\x04").mifare_params()


class TestFirmwareTargetMode:
    """
    The chip's own ISO-DEP path still has to borrow the chip properly.

    Both drivers enter target mode, so both have to clear AUTO_ATR_RES and put
    the byte back. The regression that made this worth pinning only broke this
    one, because the other path already cleared it.

    The other half is the opposite move: this driver needs PARAM_14443_4_PICC
    *on*, because that bit is what runs the chip's ISO-DEP state machine and
    TgGetData carries APDUs only while it does. The reader baseline is 0x14 —
    no PICC, because a reader has no use for it — so leaving the byte alone
    left the firmware path activating with ISO-DEP off and relaying nothing.
    """

    class Chip:
        """Just enough PN532 to arm target mode and be handed back."""

        def __init__(self):
            from nfc.pn532 import DEFAULT_PARAMETERS
            self.parameters = DEFAULT_PARAMETERS
            self.writes: list[int] = []

        def set_parameters(self, flags):
            self.parameters = flags & 0xFF
            self.writes.append(self.parameters)

        def update_parameters(self, *, set_bits=0, clear_bits=0):
            wanted = (self.parameters | set_bits) & ~clear_bits & 0xFF
            if wanted != self.parameters:
                self.set_parameters(wanted)
            return wanted

        # What the chip answers TgInitAsTarget with. 08 is a real firmware-path
        # activation: 106 kbps, Mifare framing, and bit 3 — ISO-DEP running.
        # Not bit 2: that is the *command parameter's* "PICC only", and reading
        # the reply by it is what rejected a working activation as DEP.
        mode = 0x08

        def call(self, command, body=b"", timeout=None, keep_waiting=None,
                 on_retry=None):
            self.init_timeout = timeout
            self.init_keep_waiting = keep_waiting
            return bytes([self.mode])    # activated, no initiator data

    def _run(self):
        from nfc.pn532 import DEFAULT_PARAMETERS
        chip = self.Chip()
        card = FakeCard()

        class OneShot(CardEmulator):
            def get_data(self_inner, timeout=None):
                return None          # the terminal leaves immediately

        OneShot(chip, card).run()
        return chip, DEFAULT_PARAMETERS

    def test_automatic_atr_res_is_cleared(self):
        from nfc.pn532 import PARAM_AUTO_ATR_RES
        chip, _ = self._run()
        assert chip.writes, "target mode must touch the parameter byte"
        assert not chip.writes[0] & PARAM_AUTO_ATR_RES, (
            "TgInitAsTarget answers nothing with automatic ATR_RES left on")

    def test_the_picc_flag_is_switched_on(self):
        """
        This path *wants* the chip framing ISO-DEP — that is its whole point,
        and the bit is not in the reader baseline, so it has to be set rather
        than assumed. Without it the chip activates, TgGetData hands over
        nothing, and the relay sits at zero exchanges saying nothing.
        """
        from nfc.pn532 import PARAM_14443_4_PICC
        chip, _ = self._run()
        assert chip.writes[0] & PARAM_14443_4_PICC, (
            "the firmware path cannot carry APDUs with ISO-DEP off")

    def test_a_release_after_a_slow_answer_is_named_as_a_timeout(self):
        """
        A release says "the initiator let go" whether the terminal finished or
        gave up waiting, and after one exchange the two look identical. A card
        that took longer than the advertised frame waiting time settles it —
        and that is the case --own-isodep exists for, which the operator has no
        way to guess from "Terminal ended the transaction".
        """
        emulator = CardEmulator(self.Chip(), FakeCard())
        emulator.session_exchanges = 1
        emulator.session_slowest_card = 0.400          # well past the chip's 155 ms
        emulator.ended_status = STATUS_RELEASED

        verdict = emulator._why_it_ended()
        assert verdict is not None
        assert "400 ms" in verdict
        assert "--own-isodep" in verdict

    def test_the_budget_is_the_one_the_chip_advertises(self):
        """
        CHIP_FWT was 39 ms on the guess that the firmware would advertise
        something card-like. measure-ats says FWI 9 — 155 ms. The guess was
        four times too strict, so exchanges that comfortably met the budget
        were being reported as timeouts, which is worse than saying nothing.
        """
        from nfc.isodep import fwt_seconds
        assert CardEmulator.CHIP_FWT == pytest.approx(fwt_seconds(9), abs=5e-4)

        emulator = CardEmulator(self.Chip(), FakeCard())
        emulator.session_exchanges, emulator.session_slowest_turnaround = 1, 0.144
        emulator.ended_status = STATUS_RELEASED
        verdict = emulator._why_it_ended()
        assert verdict is not None
        assert "timing out" not in verdict, (
            "144 ms is inside the measured budget and is not a timeout")

    def test_a_deliberate_deselect_inside_the_budget_is_called_a_decision(self):
        """
        The case that cost the most time on real hardware: a relay ends after
        one exchange having answered *quickly*. That is not a timeout, and
        saying it was sends the operator at latency they have already fixed.
        The terminal read something it did not like, and the last status word
        is the evidence, so the verdict has to carry it.
        """
        emulator = CardEmulator(self.Chip(), FakeCard())
        emulator.session_exchanges, emulator.session_slowest_turnaround = 1, 0.032
        emulator.ended_status = STATUS_RELEASED
        emulator.last_sw = b"\x6F\x00"

        verdict = emulator._why_it_ended()
        assert verdict is not None
        assert "6F00" in verdict
        assert "not a timeout" in verdict
        assert "--own-isodep" not in verdict, "nothing here is fixed by more time"

    def test_a_lost_field_is_not_blamed_on_the_relay(self):
        """
        0x2B and a release are opposite diagnoses and used to be one message.
        A field that went away is the card being lifted off the antenna; the
        timing is not the story and saying it is wastes the operator's time.
        """
        emulator = CardEmulator(self.Chip(), FakeCard())
        emulator.session_exchanges, emulator.session_slowest_turnaround = 1, 0.400
        emulator.ended_status = STATUS_FIELD_OFF

        verdict = emulator._why_it_ended()
        assert verdict is not None
        assert "field went away" in verdict
        assert "timing out" not in verdict, (
            "a slow exchange does not make a lost field a timeout")

    def test_a_deselect_before_any_exchange_points_at_what_we_advertised(self):
        """
        Activated, then dropped without a single command. Nothing about the
        relay's speed can explain that — the terminal read the ATS and
        declined.
        """
        emulator = CardEmulator(self.Chip(), FakeCard())
        emulator.ended_status = STATUS_RELEASED

        verdict = emulator._why_it_ended()
        assert verdict is not None
        assert "without asking" in verdict

    def test_the_two_endings_are_recorded_separately(self):
        """
        Both hand the relay None, and merging them throws away the only
        evidence there is about which happened.
        """
        for status in (STATUS_RELEASED, STATUS_FIELD_OFF):
            class Ending(self.Chip):
                def call(self_inner, command, body=b"", **kw):
                    return bytes([status])

            emulator = CardEmulator(Ending(), FakeCard())
            assert emulator.get_data() is None
            assert emulator.ended_status == status

    def test_a_transaction_that_ran_its_course_is_not_second_guessed(self):
        """
        Enough exchanges to be a transaction and the ending is just an ending,
        however long any one of them took. A verdict there would be noise on
        every successful run.
        """
        emulator = CardEmulator(self.Chip(), FakeCard())
        emulator.ended_status = STATUS_RELEASED
        emulator.session_exchanges, emulator.session_slowest_card = 12, 0.400
        assert emulator._why_it_ended() is None

    def test_an_ending_nobody_reported_is_not_blamed_on_the_terminal(self):
        """
        Ctrl-C during a slow exchange leaves counters identical to a timeout's.
        Without an observed ending there is nothing to base a verdict on, and
        inventing one is worse than staying quiet.
        """
        emulator = CardEmulator(self.Chip(), FakeCard())
        emulator.session_exchanges, emulator.session_slowest_card = 1, 0.400
        assert emulator.ended_status is None
        assert emulator._why_it_ended() is None

    def test_the_firmware_path_wears_the_cards_historical_bytes(self):
        """
        The whole point of a relay is that the two look alike. On this path the
        chip builds the ATS and the only say we get is the Tk field, so that is
        where the card's own bytes have to go — the raw driver already did
        this, and the firmware one advertised a placeholder while relaying a
        card that says "KONA".
        """
        chip = self.Chip()

        class KonaCard(FakeCard):
            def get_atr(self):
                return bytes.fromhex("788071024B4F4E411080")

        class OneShot(CardEmulator):
            def get_data(self_inner, timeout=None):
                return None

        emulator = OneShot(chip, KonaCard())
        emulator.run()
        assert emulator.card.historical == b"KONA\x10\x80"

    def test_a_card_with_no_ats_keeps_the_default(self):
        chip = self.Chip()

        class OneShot(CardEmulator):
            def get_data(self_inner, timeout=None):
                return None

        emulator = OneShot(chip, FakeCard())
        before = bytes(emulator.card.historical)
        emulator.run()
        assert emulator.card.historical == before

    def test_a_status_byte_is_read_without_its_flag_bits(self):
        """
        Bits 6 and 7 of a PN532 status byte are flags, not part of the error
        code — libnfc masks with 0x3f for exactly this reason. Comparing the
        whole byte turns a success carrying a flag into an unknown status and a
        hard failure.
        """
        from nfc.pn532 import status_of

        assert status_of(0x00) == 0x00
        assert status_of(0x40) == 0x00, "a flag bit is not an error"
        assert status_of(0x80) == 0x00
        assert status_of(0x02) == 0x02, "a real error code survives"
        assert status_of(0x42) == 0x02, "and survives alongside a flag"

    def test_the_reply_mode_byte_is_read_by_its_own_layout(self):
        """
        The reply's layout is not the command parameter's, and confusing the
        two rejected a working relay.

        Measured on an ACR122U216: a TgInitAsTarget asking for PICC-only came
        back 08. Read with the parameter's masks that is "DEP" — which the
        command it answered forbids, so the reading has to be wrong. Bit 3 is
        "activated as a PICC"; bit 4 is DEP.
        """
        from nfc.pn532 import describe_target_mode

        seen = describe_target_mode(0x08)
        assert seen["picc"] is True and seen["dep"] is False
        assert seen["baud"] == "106 kbps" and seen["framing"] == "Mifare"

        # And the raw path's own measured activation, where PICC is off on
        # purpose because this driver runs the block layer itself.
        raw = describe_target_mode(0x00)
        assert raw["picc"] is False and raw["dep"] is False

        assert describe_target_mode(0x10)["dep"] is True, "bit 4 is DEP"
        assert describe_target_mode(0x41)["baud"] == "212 kbps"
        assert describe_target_mode(0x41)["framing"] == "FeliCa"

    def test_activating_without_iso_dep_is_refused_where_the_cause_is_visible(self):
        """
        If the bit did not take, the chip will not carry APDUs — and the only
        symptom later is a relay that never moves. Better to say so here.
        """
        from nfc.pn532 import PN532Error

        chip = self.Chip()
        chip.mode = 0x10                 # activated in DEP, so not as a PICC

        class OneShot(CardEmulator):
            def get_data(self_inner, timeout=None):
                return None

        with pytest.raises(PN532Error, match="ISO-DEP off"):
            OneShot(chip, FakeCard()).wait_for_terminal()

    def test_the_chip_is_handed_back(self):
        chip, baseline = self._run()
        assert chip.parameters == baseline


class FakeEngine:
    """A MutationEngine's two hooks, scripted."""

    def __init__(self, command=None, response=None, raises=None):
        self._command = command
        self._response = response
        self._raises = raises
        self.saw_commands: list[bytes] = []
        self.saw_responses: list[bytes] = []

    def on_command(self, msg):
        self.saw_commands.append(bytes(msg))
        if self._raises == "on_command":
            raise RuntimeError("a rule blew up")
        return self._command if self._command is not None else msg

    def on_response(self, cmd, response):
        self.saw_responses.append(bytes(response))
        if self._raises == "on_response":
            raise RuntimeError("a rule blew up")
        return self._response if self._response is not None else response


def target_chip(commands):
    """
    A chip that yields the given APDUs to one terminal, then to nobody.

    Two armings, deliberately. A terminal deselecting is not the end of a run —
    the emulator re-arms, because kernels that read a card once and come back to
    transact are common — so a fixture that scripts a single arming does not
    describe a whole run and leaves the emulator waiting out its five-minute
    terminal timeout. The second session asks nothing, which is what ends it.
    """
    replies = [response_for(0x8C, ACTIVATED_AS_PICC)]           # TgInitAsTarget
    for command in commands:
        replies.append(response_for(CMD_TG_GET_DATA, b"\x00" + command))
        replies.append(response_for(0x8E, b"\x00"))            # TgSetData
    replies.append(response_for(CMD_TG_GET_DATA, b"\x29"))     # released
    replies.append(response_for(0x8C, ACTIVATED_AS_PICC))       # armed again
    replies.append(response_for(CMD_TG_GET_DATA, b"\x29"))     # nobody there
    return PN532(FakeLink(replies))


class TestMutationsInTheRelay:
    """
    The emulator's on_apdu hook fires after set_data, so it can only watch.
    Mutating needs the same two points the contact relay uses — before the card
    and before the terminal — which is what makes a playbook written for one
    interface run on the other.
    """

    _chip = staticmethod(target_chip)

    def test_a_mutated_command_is_what_reaches_the_card(self):
        original = bytes.fromhex("00A4040007A0000000031010")
        rewritten = bytes.fromhex("00A4040007A0000000041010")
        card = FakeCard([b"\x6F\x1A\x90\x00"])
        engine = FakeEngine(command=rewritten)

        CardEmulator(self._chip([original]), card, mutations=engine).run()

        assert card.received == [rewritten]
        assert engine.saw_commands == [original]

    def test_a_mutated_response_is_what_reaches_the_terminal(self):
        select = bytes.fromhex("00A4040007A0000000031010")
        card = FakeCard([bytes.fromhex("6F1A9000")])
        engine = FakeEngine(response=bytes.fromhex("6F0B9000"))
        seen = []

        CardEmulator(self._chip([select]), card, mutations=engine,
                     on_apdu=lambda c, r: seen.append(r)).run()

        assert engine.saw_responses == [bytes.fromhex("6F1A9000")]
        assert seen == [bytes.fromhex("6F0B9000")], (
            "the observer must see what actually went out, not the card's bytes")

    def test_on_response_is_given_the_mutated_command(self):
        """
        A response rule keyed on the INS it is answering has to see the command
        the card actually got, or the two halves of a playbook disagree.
        """
        rewritten = bytes.fromhex("80A80000238399")
        card = FakeCard([b"\x77\x0A\x90\x00"])
        pairs = []

        class Recorder(FakeEngine):
            def on_response(self, cmd, response):
                pairs.append(bytes(cmd))
                return response

        CardEmulator(self._chip([bytes.fromhex("80A80000238321")]), card,
                     mutations=Recorder(command=rewritten)).run()
        assert pairs == [rewritten]

    def test_no_engine_leaves_the_relay_exactly_as_it_was(self):
        select = bytes.fromhex("00A4040007A0000000031010")
        card = FakeCard([b"\x6F\x1A\x90\x00"])
        emulator = CardEmulator(self._chip([select]), card)
        assert emulator.run() == 1
        assert card.received == [select]

    @pytest.mark.parametrize("hook", ["on_command", "on_response"])
    def test_a_rule_that_raises_does_not_drop_the_field(self, hook):
        """
        The terminal is holding a transaction open and the operator is standing
        at it. An unmutated exchange they can see beats a dropped link they
        have to diagnose.
        """
        select = bytes.fromhex("00A4040007A0000000031010")
        card = FakeCard([b"\x6F\x1A\x90\x00"])
        emulator = CardEmulator(self._chip([select]), card,
                                mutations=FakeEngine(raises=hook))

        assert emulator.run() == 1
        assert card.received == [select]


class TestOversizeResponses:
    """
    The contactless-specific hazard, with no contact equivalent: a rule that
    lengthens a response can push it past the chip's frame, and set_data would
    take the link down with it.
    """

    _chip = staticmethod(target_chip)

    def test_a_grown_response_falls_back_to_the_cards_own_bytes(self):
        from nfc.emulator import MAX_CHAINED_RESPONSE as MAX_RESPONSE

        select = bytes.fromhex("00A4040007A0000000031010")
        original = bytes.fromhex("6F1A") + b"\x90\x00"
        card = FakeCard([original])
        grown = b"\xAA" * (MAX_RESPONSE + 1)
        emulator = CardEmulator(self._chip([select]), card,
                                mutations=FakeEngine(response=grown))
        seen = []
        emulator.on_apdu = lambda c, r: seen.append(r)

        assert emulator.run() == 1
        assert seen == [original], "the card's own response goes out instead"
        assert emulator.oversize == 1, "and the count says it happened"

    def test_a_response_that_still_fits_is_passed_through(self):
        from nfc.emulator import MAX_RESPONSE

        select = bytes.fromhex("00A4040007A0000000031010")
        card = FakeCard([b"\x90\x00"])
        exactly = b"\xAA" * MAX_RESPONSE
        emulator = CardEmulator(self._chip([select]), card,
                                mutations=FakeEngine(response=exactly))
        seen = []
        emulator.on_apdu = lambda c, r: seen.append(r)

        emulator.run()
        assert seen == [exactly]
        assert emulator.oversize == 0

    def test_the_cards_own_oversize_response_is_a_named_failure(self):
        """
        Not a crash and not a lie: CannotChain, so the caller above can tell
        the terminal the card failed and keep the session up. Every route
        below the APDU layer is closed on this reader, which is why
        --split-responses exists one layer above it.
        """
        from nfc.emulator import CannotChain, MAX_RESPONSE

        emulator = CardEmulator(PN532(FakeLink([])), FakeCard())
        with pytest.raises(CannotChain, match="no way to split it"):
            emulator.set_data(b"\xAA" * (MAX_RESPONSE + 1))


class TestFrameLimits:
    """
    Three different numbers, and knowing which one binds where is the whole
    of it: the chip's 262-byte buffer, the frame's length field, and the
    reader's single-byte Lc. The frame's field stopped binding when extended
    frames arrived — which is what lets a certificate record come *back*. On
    the way *out* the reader's Lc still binds at 255, so MAX_RESPONSE is the
    size of a piece, not of a response.
    """

    def test_a_piece_is_sized_to_what_the_reader_will_carry(self):
        from nfc.acr122 import MAX_PSEUDO_APDU_PAYLOAD, pseudo_apdu
        from nfc.emulator import MAX_RESPONSE
        from nfc.pn532 import CMD_TG_SET_DATA, build_command, unframe

        payload = unframe(build_command(CMD_TG_SET_DATA, b"\x00" * MAX_RESPONSE))
        assert len(payload) == MAX_PSEUDO_APDU_PAYLOAD, (
            "a full piece must fill the pseudo-APDU exactly, and not exceed it")
        pseudo_apdu(payload)          # must not raise

    def test_a_command_apdu_still_has_no_way_to_chain(self):
        """
        Responses chain with TgSetMetaData. Commands to a card have no
        equivalent here, so the limit is real and saying so beats framing
        something the reader will reject.
        """
        from nfc.pn532 import max_payload

        chip = PN532(FakeLink([]))
        with pytest.raises(PN532Error, match="chaining is not implemented"):
            chip.data_exchange(b"\x00" * (max_payload(3) + 1))

    def test_an_oversize_apdu_is_told_about_chaining_not_extended_frames(self):
        from nfc.pn532 import max_payload

        chip = PN532(FakeLink([]))
        with pytest.raises(PN532Error, match="chaining is not implemented"):
            chip.data_exchange(b"\x00" * (max_payload(3) + 1))

    def test_a_response_past_one_exchange_names_the_number(self):
        from nfc.emulator import CannotChain, MAX_RESPONSE

        emulator = CardEmulator(PN532(FakeLink([])), FakeCard())
        with pytest.raises(CannotChain, match=str(MAX_RESPONSE)):
            emulator.set_data(b"\x00" * (MAX_RESPONSE + 1))


class TestCardEmulator:
    _chip = staticmethod(target_chip)

    def test_the_command_riding_with_the_activation_is_relayed(self):
        """
        TgInitAsTarget answers with the mode byte followed by the first frame
        the chip received as a target. Whether the terminal's opening SELECT
        lands there or in the following TgGetData is a race, and dropping it
        costs the whole session: the terminal waits for an answer nobody saw
        while TgGetData waits for a command that is never sent. On the rig
        this happened every other session.
        """
        select = bytes.fromhex("00A404000E325041592E5359532E444446303100")
        replies = [response_for(0x8C, ACTIVATED_AS_PICC + select),
                   response_for(0x8E, b"\x00"),               # TgSetData
                   response_for(CMD_TG_GET_DATA, b"\x29"),    # released
                   response_for(0x8C, ACTIVATED_AS_PICC),
                   response_for(CMD_TG_GET_DATA, b"\x29")]
        card = FakeCard([b"\x6F\x1A\x90\x00"])
        emulator = CardEmulator(PN532(FakeLink(replies)), card)

        assert emulator.run() == 1
        assert card.received == [select], "the opening command was dropped"

    def test_a_rats_in_the_activation_is_not_relayed_as_an_apdu(self):
        """
        With the chip doing ISO-DEP it answers RATS itself, but the byte the
        driver reads is the same field either way. Putting E080 to a card
        would be nonsense and would spend the session's first exchange doing
        it.
        """
        replies = [response_for(0x8C, ACTIVATED_AS_PICC + b"\xE0\x80"),
                   response_for(CMD_TG_GET_DATA, b"\x29")]
        card = FakeCard([])
        emulator = CardEmulator(PN532(FakeLink(replies)), card)

        assert emulator.run() == 0
        assert card.received == []

    def test_an_activation_with_nothing_attached_waits_for_the_command(self):
        select = bytes.fromhex("00A40400023F00")
        replies = [response_for(0x8C, ACTIVATED_AS_PICC),
                   response_for(CMD_TG_GET_DATA, b"\x00" + select),
                   response_for(0x8E, b"\x00"),
                   response_for(CMD_TG_GET_DATA, b"\x29"),
                   response_for(0x8C, ACTIVATED_AS_PICC),
                   response_for(CMD_TG_GET_DATA, b"\x29")]
        card = FakeCard([b"\x90\x00"])
        emulator = CardEmulator(PN532(FakeLink(replies)), card)

        assert emulator.run() == 1
        assert card.received == [select]

    CERTIFICATE_RECORD = bytes.fromhex("7081FB") + bytes(range(251)) + b"\x90\x00"

    def _one_record(self, extra=()):
        read_record = bytes.fromhex("00B2012400")
        return ([response_for(0x8C, ACTIVATED_AS_PICC),
                 response_for(CMD_TG_GET_DATA, b"\x00" + read_record)]
                + list(extra)
                + [response_for(0x8E, b"\x00"),
                   response_for(CMD_TG_GET_DATA, b"\x29"),
                   response_for(0x8C, ACTIVATED_AS_PICC),
                   response_for(CMD_TG_GET_DATA, b"\x29")])

    def test_tgsetmetadata_never_reaches_the_wire(self):
        """
        Measured twice and dangerous once: at 190 bytes on a freshly plugged
        reader it returned nothing, and on another run the same send froze the
        reader until it was power-cycled. A command that is both unsupported
        and capable of taking the hardware down does not belong on the wire at
        all, whatever a caller asks for.
        """
        from nfc.pn532 import CMD_TG_SET_META_DATA

        link = FakeLink(self._one_record())
        emulator = CardEmulator(PN532(link), FakeCard([self.CERTIFICATE_RECORD]))
        emulator.run()

        sent = [unframe(f) for f in link.sent]
        assert not [q for q in sent
                    if q[:2] == bytes([0xD4, CMD_TG_SET_META_DATA])]


    def test_a_long_response_is_offered_as_61xx_and_collected(self):
        """
        The last route on this hardware, and one layer up from every other
        thing tried. Below the APDU layer everything is closed: one TgSetData
        is too small for a certificate record, the chip does not answer
        TgSetMetaData, and a Direct Transmit big enough for the whole thing
        damages the reader. ISO 7816-4's 61 XX has been sitting above it the
        whole time.
        """
        from nfc.emulator import MAX_RESPONSE

        read_record = bytes.fromhex("00B2012400")
        get_response = bytes.fromhex("00C00000BC")
        replies = [response_for(0x8C, ACTIVATED_AS_PICC),
                   response_for(CMD_TG_GET_DATA, b"\x00" + read_record),
                   response_for(0x8E, b"\x00"),
                   response_for(CMD_TG_GET_DATA, b"\x00" + get_response),
                   response_for(0x8E, b"\x00"),
                   response_for(CMD_TG_GET_DATA, b"\x00" + get_response),
                   response_for(0x8E, b"\x00"),
                   response_for(CMD_TG_GET_DATA, b"\x29"),
                   response_for(0x8C, ACTIVATED_AS_PICC),
                   response_for(CMD_TG_GET_DATA, b"\x29")]
        card = FakeCard([self.CERTIFICATE_RECORD])
        link = FakeLink(replies)
        emulator = CardEmulator(PN532(link), card, split_responses=True)
        emulator.run()

        out = [unframe(f)[2:] for f in link.sent if unframe(f)[:2] == b"\xD4\x8E"]
        assert len(out) == 3, "61 XX, a slice, and the tail"
        assert out[0] == b"\x61" + bytes([MAX_RESPONSE - 2])
        assert out[-1][-2:] == b"\x90\x00", "the card's own status word ends it"
        for piece in out:
            assert len(piece) <= MAX_RESPONSE

        rebuilt = b"".join(p[:-2] for p in out) + out[-1][-2:]
        assert rebuilt == self.CERTIFICATE_RECORD, (
            "the terminal must end up with exactly what the card said")
        assert card.received == [read_record], (
            "GET RESPONSE is ours to answer; it must never reach the card")

    def test_splitting_is_off_unless_asked_for(self):
        """
        It changes what the card appears to have said — one APDU becomes
        three — and ATRIUM's worth is that a trace says what the card did.
        """
        link = FakeLink(self._one_record())
        emulator = CardEmulator(PN532(link), FakeCard([self.CERTIFICATE_RECORD]))
        assert emulator.run() == 1
        assert emulator.undeliverable == 1
        assert emulator.split_responses_used == 0

    def test_a_terminal_that_walks_away_does_not_get_stale_bytes_later(self):
        """
        Held bytes belong to the command that produced them. A terminal that
        asks something else has moved on, and serving it a slice of the last
        answer would be a fabricated response to a live question.
        """
        read_record = bytes.fromhex("00B2012400")
        select = bytes.fromhex("00A40400023F00")
        link = FakeLink([response_for(0x8C, ACTIVATED_AS_PICC),
                         response_for(CMD_TG_GET_DATA, b"\x00" + read_record),
                         response_for(0x8E, b"\x00"),
                         response_for(CMD_TG_GET_DATA, b"\x00" + select),
                         response_for(0x8E, b"\x00"),
                         response_for(CMD_TG_GET_DATA, b"\x29"),
                         response_for(0x8C, ACTIVATED_AS_PICC),
                         response_for(CMD_TG_GET_DATA, b"\x29")])
        card = FakeCard([self.CERTIFICATE_RECORD, b"\x6F\x1A\x90\x00"])
        emulator = CardEmulator(PN532(link), card, split_responses=True)
        emulator.run()

        assert card.received == [read_record, select], (
            "the second command had to reach the card, not be answered from a "
            "buffer the terminal had abandoned")
        out = [unframe(f)[2:] for f in link.sent if unframe(f)[:2] == b"\xD4\x8E"]
        assert out[-1] == b"\x6F\x1A\x90\x00"

    def test_get_response_still_reaches_the_card_when_nothing_is_held(self):
        """Some cards implement it themselves; intercepting always would hide that."""
        get_response = bytes.fromhex("00C0000010")
        link = FakeLink(self._one_record())
        link.replies = [response_for(0x8C, ACTIVATED_AS_PICC),
                        response_for(CMD_TG_GET_DATA, b"\x00" + get_response),
                        response_for(0x8E, b"\x00"),
                        response_for(CMD_TG_GET_DATA, b"\x29"),
                        response_for(0x8C, ACTIVATED_AS_PICC),
                        response_for(CMD_TG_GET_DATA, b"\x29")]
        card = FakeCard([b"\xAB\xCD\x90\x00"])
        emulator = CardEmulator(PN532(link), card, split_responses=True)
        emulator.run()
        assert card.received == [get_response]

    def test_a_response_that_cannot_be_delivered_becomes_a_card_error(self):
        """
        The card answered and the answer cannot be got to the terminal without
        --split-responses. Raising there destroys the trace at exactly the
        point it becomes interesting; the terminal gets a legible card error
        instead and the session stays up, so what it does next is on the
        record.
        """
        link = FakeLink(self._one_record())
        emulator = CardEmulator(PN532(link), FakeCard([self.CERTIFICATE_RECORD]))

        assert emulator.run() == 1
        assert emulator.undeliverable == 1

        out = [unframe(f)[2:] for f in link.sent if unframe(f)[:2] == b"\xD4\x8E"]
        assert out and out[-1] == b"\x6F\x00"


    def test_the_message_for_an_unsupported_chain_does_not_blame_the_reader(self):
        """
        TgSetMetaData is settled — 190 bytes, freshly plugged reader, moments
        after a 173-byte TgSetData went through. Sending the operator to
        power-cycle for it would be sending them after a fault already ruled
        out, which is how three runs were spent the first time.
        """
        emulator = CardEmulator(PN532(FakeLink([])), FakeCard())
        message = emulator._why_the_send_went_unanswered(
            CMD_TG_SET_META_DATA, b"\x00" * 190)
        assert "does not answer" in message
        assert "Unplug" not in message
        assert "transmit-limit" in message

    def test_an_unanswered_send_sends_the_operator_to_unplug_the_reader(self):
        """
        Every piece now fits what the reader has been answering for days, so
        size is ruled out before the message is written — which leaves an
        unsupported command or a wedged reader, and wedged is the one that
        costs nothing to rule out. It is also the one that actually happened:
        three runs of this symptom, on a command that had worked a minute
        earlier, were one reader carrying a fault from the run before.
        """
        link = FakeLink([response_for(0x8C, ACTIVATED_AS_PICC),
                         response_for(CMD_TG_GET_DATA,
                                      b"\x00\x00\xA4\x04\x00")])
        emulator = CardEmulator(PN532(link), FakeCard([b"\x90\x00"]))
        with pytest.raises(PN532Error, match="Unplug the reader") as caught:
            emulator.run()
        assert "not the size" in str(caught.value)

    def test_a_response_that_fits_is_still_one_command(self):
        """Chaining costs an RF round trip; not paying it when it is not needed."""
        from nfc.pn532 import CMD_TG_SET_META_DATA

        select = bytes.fromhex("00A40400023F00")
        link = FakeLink([response_for(0x8C, ACTIVATED_AS_PICC),
                         response_for(CMD_TG_GET_DATA, b"\x00" + select),
                         response_for(0x8E, b"\x00"),
                         response_for(CMD_TG_GET_DATA, b"\x29"),
                         response_for(0x8C, ACTIVATED_AS_PICC),
                         response_for(CMD_TG_GET_DATA, b"\x29")])
        from nfc.emulator import MAX_RESPONSE
        fits = b"\xAA" * (MAX_RESPONSE - 2) + b"\x90\x00"     # exactly one
        emulator = CardEmulator(PN532(link), FakeCard([fits]))
        emulator.run()

        sent = [unframe(f) for f in link.sent]
        assert not [p for p in sent if p[:2] == bytes([0xD4, CMD_TG_SET_META_DATA])]
        assert emulator.chained_out == 0

    def test_a_runaway_mutation_is_still_refused(self):
        """
        Chaining raised the ceiling; it did not remove it. A rule that grows a
        response past ten blocks has run away, and relaying the card's own
        bytes is better than taking the link down over it.
        """
        from nfc.emulator import MAX_CHAINED_RESPONSE

        emulator = CardEmulator(PN532(FakeLink([])), FakeCard([]))
        original = b"\x6F\x1A\x90\x00"
        grown = b"\xAA" * (MAX_CHAINED_RESPONSE + 1)
        assert emulator._fit(original, grown) == original
        assert emulator.oversize == 1

    def test_a_deselect_is_not_the_end_of_the_run(self):
        """
        The finding this exists for: on real hardware the terminal read the
        PPSE, got a valid 9000, and deselected — every single time, at 32 ms,
        at 75 ms and at 144 ms. Timing was not the variable. Several kernels
        look at a card once to see what it offers, drop it, and come back to
        transact; an emulator that exits on the first S(DESELECT) never sees
        the second pass and reports "one exchange and it gave up" forever.
        """
        select = bytes.fromhex("00A404000E325041592E5359532E444446303100")
        gpo = bytes.fromhex("80A8000002830000")
        replies = []
        for command in (select, gpo):
            replies.append(response_for(0x8C, ACTIVATED_AS_PICC))
            replies.append(response_for(CMD_TG_GET_DATA, b"\x00" + command))
            replies.append(response_for(0x8E, b"\x00"))
            replies.append(response_for(CMD_TG_GET_DATA, b"\x29"))
        replies.append(response_for(0x8C, ACTIVATED_AS_PICC))
        replies.append(response_for(CMD_TG_GET_DATA, b"\x29"))

        card = FakeCard([b"\x6F\x1A\x90\x00", b"\x77\x0E\x90\x00"])
        emulator = CardEmulator(PN532(FakeLink(replies)), card)

        assert emulator.run() == 2, "the second pass was never seen"
        assert emulator.sessions == 3
        assert card.received == [select, gpo]

    def test_a_terminal_that_activates_and_goes_quiet_is_named_and_waited_for(
            self, monkeypatch):
        """
        Selected, then silence. TgGetData's own deadline is twenty seconds,
        which would hide both the fact and every session after it; and a
        terminal that is activating this card every couple of seconds is
        present and deciding, so the card goes back up rather than the run
        ending. When nobody turns up at all the run ends quietly instead of
        raising, which would bury whatever the earlier sessions did see.
        """
        monkeypatch.setattr("nfc.emulator.TERMINAL_WAIT", 0.05)

        class QuietAfterArming:
            """Arms twice, answers TgGetData with silence, then goes away."""

            def __init__(self, arms):
                self.arms = arms
                self.sent: list[bytes] = []

            def exchange(self, frame):
                if not frame:
                    return b""
                self.sent.append(frame)
                command = unframe(frame)[1]
                if command == CMD_TG_INIT_AS_TARGET and self.arms:
                    self.arms -= 1
                    return ACK + response_for(command, ACTIVATED_AS_PICC)
                if command in (CMD_TG_INIT_AS_TARGET, CMD_TG_GET_DATA):
                    return b""            # activated, and nothing to say
                return ACK + response_for(command)

        class Quiet(CardEmulator):
            FIRST_COMMAND_WAIT = 0.05

        emulator = Quiet(PN532(QuietAfterArming(arms=2)), FakeCard([]))

        assert emulator.run() == 0
        assert emulator.silent_activations == 2, (
            "a terminal that says nothing has to be distinguishable from one "
            "that deselected")
        assert emulator.sessions == 2, (
            "an arming nobody answered is not a terminal session")

    def test_a_terminal_that_asks_nothing_ends_the_run(self):
        """
        Activated and deselected without a command is a stray poll, not a
        kernel working through a transaction. Re-arming for it would leave the
        reader beeping at an empty room until someone noticed.
        """
        replies = [response_for(0x8C, ACTIVATED_AS_PICC),
                   response_for(CMD_TG_GET_DATA, b"\x29")]
        emulator = CardEmulator(PN532(FakeLink(replies)), FakeCard([]))

        assert emulator.run() == 0
        assert emulator.sessions == 1

    def test_re_arming_does_not_lose_the_chips_original_parameters(self):
        """
        Each session borrows the chip. A second borrow that recorded the
        borrowed byte as the baseline would "restore" the reader into
        target-mode parameters, and it would stop activating cards — the
        failure that takes a reader unplugging to clear.
        """
        select = bytes.fromhex("00A40400023F00")
        replies = [response_for(0x8C, ACTIVATED_AS_PICC),
                   response_for(CMD_TG_GET_DATA, b"\x00" + select),
                   response_for(0x8E, b"\x00"),
                   response_for(CMD_TG_GET_DATA, b"\x29"),
                   response_for(0x8C, ACTIVATED_AS_PICC),
                   response_for(CMD_TG_GET_DATA, b"\x29")]
        chip = PN532(FakeLink(replies))
        baseline = chip.parameters
        emulator = CardEmulator(chip, FakeCard([b"\x90\x00"]))
        emulator.run()

        assert emulator.sessions == 2
        assert chip.parameters == baseline, (
            "the reader was left holding target-mode parameters")

    def test_relays_apdus_both_ways(self):
        select = bytes.fromhex("00A4040007A0000000031010")
        card = FakeCard([b"\x6F\x1A\x90\x00"])
        emulator = CardEmulator(self._chip([select]), card)

        assert emulator.run() == 1
        assert card.received == [select]
        assert not card.connected, "the transport must be closed afterwards"

    def test_observer_sees_every_pair(self):
        seen = []
        card = FakeCard([b"\x90\x00", b"\x6A\x82"])
        emulator = CardEmulator(self._chip([b"\x00\xA4\x04\x00", b"\x00\xB2\x01\x0C"]),
                                card, on_apdu=lambda c, r: seen.append((c, r)))
        emulator.run()
        assert [r for _c, r in seen] == [b"\x90\x00", b"\x6A\x82"]

    def test_a_failing_card_answers_6f00_rather_than_dropping_the_link(self):
        """A terminal reporting a card error beats a mystery timeout."""
        class Broken(FakeCard):
            def transmit(self, apdu):
                raise ConnectionError("card gone")

        card = Broken()
        emulator = CardEmulator(self._chip([b"\x00\xA4\x04\x00"]), card)
        emulator.run()
        assert emulator.exchanges == 1

    def test_an_observer_that_raises_does_not_stop_the_relay(self):
        def _boom(_c, _r):
            raise ValueError("observer bug")

        emulator = CardEmulator(self._chip([b"\x00\xA4\x04\x00"]), FakeCard(),
                                on_apdu=_boom)
        assert emulator.run() == 1

    def test_release_ends_the_loop_cleanly(self):
        emulator = CardEmulator(self._chip([]), FakeCard())
        assert emulator.run() == 0

    def test_a_response_past_one_exchange_is_refused(self):
        from nfc.emulator import CannotChain, MAX_RESPONSE

        chip = PN532(FakeLink([]))
        with pytest.raises(CannotChain):
            CardEmulator(chip, FakeCard()).set_data(b"\x00" * (MAX_RESPONSE + 1))
