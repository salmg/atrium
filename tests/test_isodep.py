"""
Owning the ISO-DEP layer, and asking the terminal for more time.

The PN532 will do ISO/IEC 14443-4 itself, and when it does it picks FWI, never
sends S(WTX) and cannot chain — so a relay slower than the firmware's frame
waiting time is dropped with nothing said. `IsoDepEmulator` turns that handling
off and does the layer here instead, which is what makes S(WTX) possible.

The first half covers the bytes: every block shape, the ATS we answer RATS
with, and the arithmetic that turns FWI into a deadline. The second half runs
the driver against a fake terminal that implements the reader half of the same
protocol, so a passing test means the two halves actually agree — including the
case the whole exercise is for, a card too slow for one frame waiting time.

None of this has been in front of a real terminal. The blocks are covered here;
the RF behaviour is not, and cannot be from a machine with no reader.
"""
from __future__ import annotations

import sys
import time
from collections import deque
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from nfc.emulator import Deselected, EmulatedCard, IsoDepEmulator
from nfc.pn532 import (
    DEFAULT_PARAMETERS,
    PARAM_14443_4_PICC,
    PARAM_AUTO_ATR_RES,
    PARAM_AUTO_RATS,
    PN532Error,
    RFError,
)
from nfc.isodep import (
    ATS_DEADLINE,
    DELTA_FWT,
    historical_bytes,
    WTXM_MAX,
    Ats,
    BlockType,
    IsoDepError,
    SType,
    chain,
    frame_size,
    frame_size_index,
    fwt_seconds,
    i_block,
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
)

SELECT = bytes.fromhex("00A4040007A0000000031010")
SELECT_RESP = bytes.fromhex("6F1A840EA0000000031010A5089000")


# ── the bytes ────────────────────────────────────────────────────────────────

class TestBlocks:
    def test_i_block(self):
        assert i_block(0, b"\x90\x00") == bytes.fromhex("029000")
        assert i_block(1, b"\x90\x00") == bytes.fromhex("039000")

    def test_chaining_is_bit_five(self):
        """0x10, not 0x08 — the bit next to it is the CID flag."""
        assert i_block(0, b"x", chaining=True)[0] == 0x12
        assert i_block(0, b"x", cid=3)[0] == 0x0A

    def test_cid_rides_between_pcb_and_inf(self):
        raw = i_block(1, b"\xAB", cid=5)
        assert raw == bytes([0x0B, 0x05, 0xAB])
        block = parse_block(raw)
        assert block.cid == 5 and block.inf == b"\xAB"

    def test_r_blocks(self):
        assert r_block(0) == b"\xA2" and r_block(1) == b"\xA3"
        assert r_block(0, nak=True) == b"\xB2" and r_block(1, nak=True) == b"\xB3"
        assert r_block(0, cid=1) == bytes([0xAA, 0x01])

    def test_s_blocks(self):
        assert s_wtx(9) == bytes([0xF2, 0x09])
        assert s_wtx(9, cid=2) == bytes([0xFA, 0x02, 0x09])
        assert s_deselect() == b"\xC2"
        assert s_deselect(cid=2) == bytes([0xCA, 0x02])

    @pytest.mark.parametrize("wtxm", [0, WTXM_MAX + 1, -1])
    def test_wtxm_is_bounded(self, wtxm):
        with pytest.raises(ValueError, match="WTXM"):
            s_wtx(wtxm)

    def test_parse_identifies_each_type(self):
        assert parse_block(b"\x02").type is BlockType.I
        assert parse_block(b"\xA2").type is BlockType.R
        assert parse_block(b"\xC2").s_type is SType.DESELECT
        assert parse_block(b"\xF2\x09").s_type is SType.WTX

    def test_parse_reads_the_flags(self):
        block = parse_block(bytes([0x13, 0xAA]))
        assert block.chaining and block.block_number == 1 and block.inf == b"\xAA"
        assert parse_block(b"\xB3").nak and parse_block(b"\xA3").nak is False

    def test_wtxm_comes_off_six_bits(self):
        # The top two bits are RFU and must not leak into the multiplier.
        assert parse_block(bytes([0xF2, 0xC0 | 17])).wtxm == 17
        assert parse_block(b"\xA2").wtxm == 0, "not a WTX, so no multiplier"

    def test_nad_is_read_after_cid_not_before(self):
        """Swap the order and the first INF byte silently becomes a NAD."""
        raw = bytes([0x02 | 0x08 | 0x04, 0x07, 0x51, 0xAB])
        block = parse_block(raw)
        assert (block.cid, block.nad, block.inf) == (7, 0x51, b"\xAB")

    @pytest.mark.parametrize("bad", [
        b"",                        # empty
        b"\x40",                    # top bits 01 — not a PCB
        bytes([0x08]),              # CID promised, frame ends
        bytes([0x82]),              # R-block bits wrong
        bytes([0xD2]),              # S-block that is neither DESELECT nor WTX
    ])
    def test_malformed_blocks_are_rejected(self, bad):
        with pytest.raises(IsoDepError):
            parse_block(bad)


class TestTiming:
    def test_fwt_table(self):
        # FWT = (256 * 16 / 13.56e6) * 2^FWI
        assert fwt_seconds(0) == pytest.approx(302.065e-6, rel=1e-3)
        assert fwt_seconds(8) == pytest.approx(77.33e-3, rel=1e-3)
        assert fwt_seconds(14) == pytest.approx(4.949, rel=1e-3)

    def test_delta_fwt(self):
        assert DELTA_FWT == pytest.approx(3.625e-3, rel=1e-3)

    def test_frame_sizes(self):
        assert frame_size(0) == 16 and frame_size(8) == 256
        assert frame_size(12) == 256, "RFU indices behave as the largest"
        assert frame_size_index(256) == 8 and frame_size_index(100) == 6

    def test_max_inf_leaves_room_for_pcb_and_crc(self):
        assert max_inf_size(256) == 253
        assert max_inf_size(256, cid=True) == 252
        assert max_inf_size(256, cid=True, nad=True) == 251


class TestAts:
    def test_the_ats_carries_our_fwi(self):
        ats = Ats(fwi=12, sfgi=0, historical=bytes.fromhex("75339203"))
        raw = ats.build()
        assert raw == bytes.fromhex("0868C00275339203")
        assert raw[0] == len(raw), "TL counts itself"
        assert parse_ats(raw).fwi == 12

    def test_the_start_up_guard_time_is_long_enough_to_start_up(self):
        """
        SFGI is how long the reader waits after the ATS before its first
        command, and it is the field a host-side implementation cannot leave
        at its default.

        SFGI 0 invites the reader to speak 302 µs after the ATS, and it does:
        one run lost the first command entirely, the next came back mid-frame
        to a run of CRC errors. The gap to cover was 127 ms on the code that
        slept between reads and is nearer 8 ms now, but the margin is kept —
        it is spent once, and this bridge has been measured taking 108 ms for
        a command whose median is 2.8 ms.
        """
        from nfc.isodep import _FWT_UNIT

        ats = Ats()
        sfgt = _FWT_UNIT * (2 ** ats.sfgi)
        assert sfgt > 0.127, (
            "the reader may send its first command this soon after the ATS, "
            "and nothing is listening yet")

        # It rides in the same byte as FWI, so neither may clobber the other.
        # Read back through the parser rather than by index: TB(1) moves
        # depending on whether TA(1) is present, which is how this test was
        # wrong the first time.
        built = parse_ats(Ats(fwi=12, sfgi=10, historical=b"KONA").build())
        assert built.fwi == 12 and built.sfgi == 10

    def test_tb1_is_always_present(self):
        """Without it a reader assumes FWI 4 — about 4.8 ms, which no relay survives."""
        assert Ats(historical=b"").build()[1] & 0x20

    def test_ta1_is_omitted_unless_asked_for(self):
        assert not Ats().build()[1] & 0x10
        assert Ats(ta1=0x80).build()[1] & 0x10

    def test_tc1_advertises_cid(self):
        assert Ats(supports_cid=True).build()[1] & 0x40
        assert not Ats(supports_cid=False, supports_nad=False).build()[1] & 0x40

    def test_round_trip_through_parse(self):
        ats = Ats(fsci=7, fwi=11, sfgi=2, ta1=0x80, supports_cid=True,
                  supports_nad=True, historical=b"\x11\x22")
        back = parse_ats(ats.build())
        assert (back.fsci, back.fwi, back.sfgi, back.ta1) == (7, 11, 2, 0x80)
        assert back.supports_cid and back.supports_nad
        assert back.historical == b"\x11\x22"

    def test_a_relayed_cards_own_ats_can_be_adopted(self):
        """The most faithful FWI available is the real card's."""
        assert parse_ats(bytes.fromhex("0B28778073C021C0575900")).fwi == 7

    @pytest.mark.parametrize("kw", [{"fwi": 15}, {"fwi": -1}, {"fsci": 16}])
    def test_out_of_range_fields_are_refused(self, kw):
        with pytest.raises(ValueError):
            Ats(**kw)

    def test_rats(self):
        rats = parse_rats(bytes([0xE0, 0x80]))
        assert rats.fsdi == 8 and rats.cid == 0 and rats.fsd == 256
        assert parse_rats(bytes([0xE0, 0x53])).cid == 3
        assert is_rats(bytes([0xE0, 0x80])) and not is_rats(b"\x02")
        with pytest.raises(IsoDepError, match="not a RATS"):
            parse_rats(b"\x02\x00")

    def test_pps_is_echoed(self):
        assert is_pps(b"\xD0\x11\x00") and not is_pps(b"\xE0\x80")
        assert pps_response(b"\xD0\x11\x00") == b"\xD0"


class TestChaining:
    def test_a_short_response_is_one_block(self):
        assert chain(SELECT_RESP, 0, 253) == [i_block(0, SELECT_RESP)]

    def test_block_numbers_alternate(self):
        blocks = chain(b"ABCDE", 0, 2)
        assert [parse_block(b).block_number for b in blocks] == [0, 1, 0]

    def test_every_block_but_the_last_chains(self):
        blocks = chain(b"ABCDE", 0, 2)
        assert [parse_block(b).chaining for b in blocks] == [True, True, False]
        assert b"".join(parse_block(b).inf for b in blocks) == b"ABCDE"

    def test_an_empty_response_still_sends_a_block(self):
        """A zero-length answer is legal and must not vanish."""
        assert chain(b"", 0, 253) == [i_block(0, b"")]

    def test_chaining_starts_from_the_commands_block_number(self):
        assert parse_block(chain(b"AB", 1, 1)[0]).block_number == 1


# ── a terminal to talk to ────────────────────────────────────────────────────

class FakeTerminal:
    """
    The reader half of ISO-DEP, enough to hold a real conversation.

    Reactive rather than scripted: it is handed each frame the emulator sends
    and works out what a PCD would say next. That is the point — a test that
    scripts both sides proves only that the script matches itself.
    """

    def __init__(self, commands, *, cid=0, fsdi=8, grant=None, deselect=True):
        self.commands = deque(commands)
        self.cid = cid or None
        self.fsdi = fsdi
        # What to grant when asked for time; None means "whatever was asked".
        self.grant = grant
        self.deselect = deselect

        self.responses: list[bytes] = []
        self.ats: bytes | None = None
        self.wtx_seen = 0
        self.sent: list[bytes] = []
        # A real reader gives up when a block does not come back inside FWT.
        # Without a clock here the WTX tests would only prove that we ask for
        # time, not that asking keeps us inside the budget.
        self.timeouts: list[float] = []
        self._budget: float | None = None
        self._deadline: float | None = None
        # Part of the chip's surface: which status ended the last read. A real
        # PN532 sets it; this terminal deselects at the block layer, where the
        # driver sees the S(DESELECT) itself, so it stays None.
        self.release_status: int | None = None

        # It stands in for the chip as well as the reader, since the driver
        # reaches both through the same object. The parameter byte is cached
        # here exactly as the real chip's is, because there is no way to read
        # it back and that is the whole reason it has to be tracked.
        self.parameters = DEFAULT_PARAMETERS
        self.parameter_writes: list[int] = []
        self.init_mode: int | None = None

        self.pni = 0
        self._outbox = deque([bytes([0xE0, (fsdi << 4) | (cid & 0x0F)])])
        self._inbound = bytearray()
        self._pending: deque[bytes] = deque()
        self._finished = False

    # the chip half
    def set_parameters(self, flags):
        self.parameters = flags & 0xFF
        self.parameter_writes.append(self.parameters)

    def update_parameters(self, *, set_bits=0, clear_bits=0):
        wanted = (self.parameters | set_bits) & ~clear_bits & 0xFF
        if wanted != self.parameters:
            self.set_parameters(wanted)
        return wanted

    def call(self, command, body=b"", timeout=None, keep_waiting=None,
             on_retry=None):
        """TgInitAsTarget: report the mode byte, and no activation data."""
        self.init_mode = body[0] if body else None
        # The real chip takes a deadline and a way to be called off, because
        # this command waits on a person. A double that does not is a double
        # the emulator can outgrow without a test noticing.
        self.init_timeout = timeout
        self.init_keep_waiting = keep_waiting
        return b"\x08"

    # what the emulator calls
    def get_initiator_command(self):
        if not self._outbox:
            return None
        frame = self._outbox.popleft()
        if self._budget is not None:
            self._deadline = time.monotonic() + self._budget + DELTA_FWT
        return frame

    def response_to_initiator(self, frame):
        now = time.monotonic()
        if self._deadline is not None and now > self._deadline:
            self.timeouts.append(round((now - self._deadline) * 1000, 1))
        self.sent.append(bytes(frame))
        self._react(bytes(frame))

    # the reader's own logic
    def _react(self, frame):
        if self.ats is None and frame and frame[0] == len(frame):
            self.ats = frame
            # From here on, every block is on the clock the ATS just set.
            self._budget = fwt_seconds(parse_ats(frame).fwi)
            self._queue_next_command()
            return

        block = parse_block(frame)

        if block.type is BlockType.S and block.s_type is SType.WTX:
            self.wtx_seen += 1
            granted = self.grant if self.grant is not None else block.wtxm
            # Granting time is exactly what widens the next deadline.
            if self.ats is not None:
                self._budget = fwt_seconds(parse_ats(self.ats).fwi) * granted
            self._outbox.append(s_wtx(granted, cid=self.cid))
            return

        if block.type is BlockType.S and block.s_type is SType.DESELECT:
            self._finished = True
            return

        if block.type is BlockType.R and not block.nak:
            # It acknowledged one of our chained command blocks.
            if self._pending:
                self._outbox.append(self._pending.popleft())
            return

        if block.type is BlockType.I:
            if self.ats is not None:
                self._budget = fwt_seconds(parse_ats(self.ats).fwi)
            self._inbound.extend(block.inf)
            if block.chaining:
                self.pni ^= 1
                self._outbox.append(r_block(self.pni, cid=self.cid))
                return
            self.responses.append(bytes(self._inbound))
            self._inbound.clear()
            self.pni ^= 1
            self._queue_next_command()

    def _queue_next_command(self):
        if not self.commands:
            if self.deselect and not self._finished:
                self._outbox.append(s_deselect(cid=self.cid))
            return
        command = self.commands.popleft()
        room = max_inf_size(frame_size(self.fsdi), cid=self.cid is not None)
        blocks = chain(command, self.pni, room, cid=self.cid)
        self._outbox.append(blocks[0])
        self._pending = deque(blocks[1:])


class FakeCard:
    """The relayed card. Optionally slow, which is the whole point of WTX."""

    def __init__(self, responses=None, delay=0.0):
        self.responses = list(responses or [])
        self.delay = delay
        self.received: list[bytes] = []
        self.connected = False

    def connect(self):
        self.connected = True

    def disconnect(self):
        self.connected = False

    def transmit(self, apdu):
        self.received.append(bytes(apdu))
        if self.delay:
            time.sleep(self.delay)
        return self.responses.pop(0) if self.responses else b"\x90\x00"


# FWI 8 is a ~77 ms frame waiting time: long enough that ordinary scheduling
# noise cannot be mistaken for a blown deadline, short enough that a test card
# can outlast it in a fraction of a second. wtx_at leaves most of the budget as
# headroom, for the same reason.
TEST_FWI = 8
SLOW_CARD = 0.3          # comfortably past FWT, and still a brisk test


def _emulator(terminal, card, **kw):
    # No historical bytes, exactly as the API and CLI construct it — the driver
    # fills them from the card being relayed.
    kw.setdefault("ats", Ats(fwi=TEST_FWI))
    kw.setdefault("wtx_at", 0.35)
    return IsoDepEmulator(terminal, card, **kw)


# ── the driver ───────────────────────────────────────────────────────────────

class TestIsoDepRelay:
    def test_a_whole_transaction(self):
        terminal = FakeTerminal([SELECT])
        card = FakeCard([SELECT_RESP])
        emulator = _emulator(terminal, card)
        emulator.run()

        assert card.received == [SELECT]
        assert terminal.responses == [SELECT_RESP]
        assert emulator.exchanges == 1

    def test_rats_is_answered_with_our_ats(self):
        terminal = FakeTerminal([])
        emulator = _emulator(terminal, FakeCard(), ats=Ats(fwi=11, historical=b"\x75"))
        emulator.run()
        assert terminal.ats == Ats(fwi=11, historical=b"\x75").build()
        assert parse_ats(terminal.ats).fwi == 11, "the terminal's budget is ours"

    def test_the_chip_is_told_to_stop_doing_iso_dep(self):
        terminal = FakeTerminal([])
        _emulator(terminal, FakeCard()).run()
        assert terminal.init_mode == 0x01, "passive-only, no PICC restriction"
        armed = terminal.parameter_writes[0]
        assert not armed & PARAM_14443_4_PICC, "the chip must stop framing ISO-DEP"

    def test_automatic_atr_res_is_cleared_before_target_mode(self):
        """
        A 14443-A target needs it off, on either path.

        It belongs to DEP, and leaving it on stops TgInitAsTarget starting at
        all — the chip answers nothing and the emulation dies 20 ms in. That is
        what happened the moment a baseline was written at connect that turned
        it on: the raw path cleared it, the firmware path did not, and only the
        firmware path broke. libnfc clears it for every ISO14443-A target.
        """
        terminal = FakeTerminal([])
        _emulator(terminal, FakeCard()).run()
        armed = terminal.parameter_writes[0]
        assert not armed & PARAM_AUTO_ATR_RES

    def test_automatic_rats_survives_target_mode(self):
        """
        Writing the parameter byte whole is what broke a *later* session.

        AUTO_RATS has nothing to do with target mode, but it lives in the same
        byte — and a reader left without it stops activating 14443-4 cards. The
        next run to use that reader as the card side sees a card with no ATS
        that answers nothing, which points nowhere near here.
        """
        terminal = FakeTerminal([])
        _emulator(terminal, FakeCard()).run()

        armed = terminal.parameter_writes[0]
        assert armed & PARAM_AUTO_RATS, (
            "clearing the whole byte takes automatic RATS with it")

    def test_the_chip_is_handed_back_as_it_was_found(self):
        terminal = FakeTerminal([])
        _emulator(terminal, FakeCard()).run()
        assert terminal.parameters == DEFAULT_PARAMETERS, (
            "target mode is a loan, not a permanent change")

    def test_the_parameters_go_back_even_when_the_relay_raises(self):
        class Exploding(FakeTerminal):
            def get_initiator_command(self):
                raise PN532Error("something went wrong mid-relay")

        terminal = Exploding([])
        with pytest.raises(PN532Error):
            _emulator(terminal, FakeCard()).run()
        assert terminal.parameters == DEFAULT_PARAMETERS

    def test_a_rats_arriving_with_the_activation_is_used(self):
        """TgInitAsTarget can hand back the RATS itself; that saves a round trip."""
        class Early(FakeTerminal):
            def call(self, command, body=b"", timeout=None, keep_waiting=None,
                     on_retry=None):
                self.init_mode = body[0] if body else None
                # Mode byte, then the RATS as the activation data.
                return b"\x08" + self._outbox.popleft()

        terminal = Early([SELECT])
        card = FakeCard([SELECT_RESP])
        _emulator(terminal, card).run()
        assert terminal.ats is not None, "the ATS still goes out"
        assert terminal.responses == [SELECT_RESP]

    def test_the_operator_is_cued_before_the_wait_begins(self):
        """
        Not decoration. The reader listens for about five seconds at a time and
        re-arms, so from the desk a working relay and a broken one look the
        same until a terminal is presented at the right moment.
        """
        cues = []

        class Chip(FakeTerminal):
            link = type("L", (), {
                "peripheral": lambda self, apdu, split_status=True: (
                    cues.append(bytes(apdu)) or (b"", 0x90, 0x00))
            })()

        _emulator(Chip([]), FakeCard([])).run()
        assert len(cues) == 1, "once, before arming — not on every re-arm"
        assert cues[0][:3] == bytes([0xFF, 0x00, 0x40]), "LED control"

    def test_the_cue_can_be_turned_off(self):
        cues = []

        class Chip(FakeTerminal):
            link = type("L", (), {
                "peripheral": lambda self, apdu, split_status=True: (
                    cues.append(bytes(apdu)) or (b"", 0x90, 0x00))
            })()

        emulator = _emulator(Chip([]), FakeCard([]))
        emulator.alert = False
        emulator.run()
        assert cues == []

    def test_a_repeated_rats_is_reported_as_a_late_ats(self):
        """
        The reader only sends RATS twice when no valid ATS reached it in time,
        and that arrives before any CRC error does — so it is the signal worth
        naming. Seen on hardware: two RATS 18 ms apart, then a run of CRC
        errors that read like an RF problem and were not.
        """
        terminal = FakeTerminal([])
        emulator = _emulator(terminal, FakeCard([]))
        rats = bytes.fromhex("E080")

        emulator._handle_rats(rats)
        assert emulator.rats_seen == 1
        assert terminal.ats is not None

        # A reader re-sends RATS precisely because it gave up on the first
        # ATS, so it no longer holds one. Modelling it any other way would be
        # modelling a reader that had no reason to ask again.
        terminal.ats = None
        emulator._handle_rats(rats)

        assert emulator.rats_seen == 2, "a repeat has to be counted, not merged"
        assert len(terminal.sent) == 2, "and answered again regardless"
        assert terminal.ats is not None, "the second answer still goes out"

    def test_the_ats_clock_accounts_for_the_leg_it_cannot_see(self):
        """
        The reader's deadline starts when it sends RATS. This process first
        sees the RATS after it has crossed USB inside TgInitAsTarget's reply,
        and that leg is invisible from here — so timing only the visible part
        under-reports. It did: a run logged "8.2 ms, inside the 8.5 ms
        deadline" and then failed every subsequent read.
        """
        terminal = FakeTerminal([])
        emulator = _emulator(terminal, FakeCard([]))
        emulator.link_round_trip = 0.009        # a 9 ms round trip to the chip

        emulator._handle_rats(bytes.fromhex("E080"))

        # Whatever the visible send cost, the estimate must include half the
        # round trip for the leg before it.
        assert emulator.ats_seconds >= 0.0045, (
            "the unseen leg has to be counted, or the deadline check lies")

    def test_the_ats_deadline_is_the_one_we_do_not_choose(self):
        """
        Every other budget on this card is ours: FWI, WTXM, SFGI. The ATS
        deadline is not — before the ATS exists there is no FWI to read, so
        ISO 14443-4 fixes it at FWI 4 plus the reader's tolerance.
        """
        from nfc.isodep import ATS_DEADLINE, DELTA_FWT, fwt_seconds

        assert ATS_DEADLINE == pytest.approx(fwt_seconds(4) + DELTA_FWT)
        assert ATS_DEADLINE == pytest.approx(8.46e-3, rel=1e-2)
        # And it is far shorter than anything else this card advertises.
        assert Ats().fwt > ATS_DEADLINE * 100

    def test_a_mangled_frame_is_retried_without_going_deaf(self):
        """
        The chip only hears the terminal while TgGetInitiatorCommand is
        outstanding — it blocks inside the command until the bridge's own ~5 s
        discard, which is why an idle run re-arms it four times in twenty
        seconds rather than returning at once.

        So sleeping between reads is not patience, it is deafness. An earlier
        fix paced retries at a share of FWT — 177 ms of sleep per 9 ms read,
        leaving the relay listening under 5% of the time and structurally
        unable to catch a retransmission that arrived perfectly. The budget is
        wall clock now, and the reads are back to back.
        """
        import time as _time

        slept = []
        real_sleep = _time.sleep

        class Broken(FakeTerminal):
            def get_initiator_command(self):
                raise RFError("TgGetInitiatorCommand: CRC error", 0x02)

        emulator = _emulator(Broken([SELECT]), FakeCard([SELECT_RESP]))
        emulator.RF_RETRY_SECONDS = 0.05

        try:
            _time.sleep = lambda d: (slept.append(d), real_sleep(0))[1]
            with pytest.raises(PN532Error):
                emulator._receive()
        finally:
            _time.sleep = real_sleep

        # A floor exists only so an instantly-failing link cannot spin; it must
        # stay far below the ~9 ms a real read costs, or it becomes pacing
        # again by another name.
        assert all(d <= emulator.MIN_READ_INTERVAL for d in slept)
        assert emulator.MIN_READ_INTERVAL < 0.009, (
            "the floor must be smaller than a real read, or the chip spends "
            "meaningful time not listening")

    def test_re_arming_is_reported_rather_than_silent(self):
        """
        The reader listens about five seconds at a time. Without a word between
        those, five minutes of correct waiting and a hang look the same — and
        the count is what the dashboard shows instead of a blank.
        """
        seen = []

        class Retrying(FakeTerminal):
            def call(self, command, body=b"", timeout=None, keep_waiting=None,
                     on_retry=None):
                for attempt in (2, 3, 4):
                    on_retry(attempt, attempt * 5.0)
                    seen.append(attempt)
                return b"\x08"

        emulator = _emulator(Retrying([]), FakeCard([]))
        emulator.run()
        assert seen == [2, 3, 4]
        assert emulator.arm_attempts == 4

    def test_the_wait_for_a_terminal_is_long_and_interruptible(self):
        """
        A person carrying a reader to a till needs longer than the chip's own
        default, and an operator who changes their mind needs the wait to end.
        """
        from nfc.emulator import TERMINAL_WAIT

        terminal = FakeTerminal([])
        emulator = _emulator(terminal, FakeCard([]))
        emulator.run()

        assert terminal.init_timeout == TERMINAL_WAIT
        assert TERMINAL_WAIT > 60, "a minute is not long enough to walk anywhere"
        assert terminal.init_keep_waiting() is True
        emulator.stop()
        assert terminal.init_keep_waiting() is False

    def test_a_slow_card_asks_the_terminal_for_more_time(self):
        """The reason this driver exists."""
        terminal = FakeTerminal([SELECT])
        card = FakeCard([SELECT_RESP], delay=SLOW_CARD)
        emulator = _emulator(terminal, card)      # FWI 8 → FWT ≈ 77 ms
        emulator.run()

        assert terminal.wtx_seen >= 1, "a 300 ms card inside a 77 ms budget must ask"
        assert emulator.wtx_requests == terminal.wtx_seen
        assert terminal.responses == [SELECT_RESP], "and still deliver the answer"
        assert terminal.timeouts == [], (
            "asking for time has to keep every block inside the reader's "
            f"deadline; overran by {terminal.timeouts} ms")

    def test_without_wtx_the_same_card_blows_the_deadline(self):
        """
        The control for the test above — and for the fake reader's clock.

        This is the firmware path's behaviour: relay, say nothing, hope. A test
        harness that cannot see this fail is not evidence that WTX works.
        """
        class Silent(IsoDepEmulator):
            def _relay_with_wtx(self, command):
                return self._relay(command)

        terminal = FakeTerminal([SELECT])
        emulator = Silent(terminal, FakeCard([SELECT_RESP], delay=SLOW_CARD),
                          ats=Ats(fwi=TEST_FWI, historical=bytes(EmulatedCard().historical)))
        emulator.run()

        assert emulator.wtx_requests == 0
        assert terminal.timeouts, "a 300 ms silence inside 77 ms must overrun"

    def test_a_fast_card_asks_for_nothing(self):
        terminal = FakeTerminal([SELECT])
        emulator = IsoDepEmulator(terminal, FakeCard([SELECT_RESP]),
                                  ats=Ats(fwi=12))
        emulator.run()
        assert terminal.wtx_seen == 0 and emulator.wtx_requests == 0

    def test_a_reduced_grant_is_respected(self):
        """The reader may grant less than was asked; the smaller number wins."""
        terminal = FakeTerminal([SELECT], grant=1)
        card = FakeCard([SELECT_RESP], delay=SLOW_CARD)
        emulator = _emulator(terminal, card, wtxm=32)
        emulator.run()
        assert terminal.wtx_seen >= 2, "a grant of 1 buys little time, so it asks again"
        assert terminal.responses == [SELECT_RESP]
        assert terminal.timeouts == [], "a small grant just means asking more often"

    def test_a_long_response_is_chained(self):
        """The 262-byte ceiling the firmware path carries does not apply here."""
        long_response = bytes(range(256)) * 3 + b"\x90\x00"
        terminal = FakeTerminal([SELECT])
        emulator = _emulator(terminal, FakeCard([long_response]))
        emulator.run()

        assert terminal.responses == [long_response]
        assert emulator.chained_out == 1
        blocks = [parse_block(f) for f in terminal.sent if f != terminal.ats]
        assert sum(1 for b in blocks if b.chaining) >= 2

    def test_a_long_command_is_reassembled(self):
        long_command = bytes.fromhex("00A40400") + bytes(range(200)) * 2
        terminal = FakeTerminal([long_command], fsdi=0)     # 16-byte frames
        card = FakeCard([SELECT_RESP])
        _emulator(terminal, card).run()
        assert card.received == [long_command]

    def test_a_cid_is_carried_on_every_block(self):
        terminal = FakeTerminal([SELECT], cid=7)
        card = FakeCard([SELECT_RESP])
        _emulator(terminal, card).run()
        assert terminal.responses == [SELECT_RESP]
        blocks = [parse_block(f) for f in terminal.sent if f != terminal.ats]
        assert blocks and all(b.cid == 7 for b in blocks)

    def test_deselect_ends_the_relay(self):
        terminal = FakeTerminal([SELECT])
        emulator = _emulator(terminal, FakeCard([SELECT_RESP]))
        emulator.run()
        assert terminal.sent[-1] == s_deselect(), "we answer the deselect"

    def test_a_nak_resends_the_last_block(self):
        """A garbled response earns an R(NAK), and the answer must survive it."""

        class NakOnce(FakeTerminal):
            naked = False

            def _react(self, frame):
                try:
                    block = parse_block(frame)
                except IsoDepError:
                    return super()._react(frame)     # the ATS
                if not self.naked and block.type is BlockType.I:
                    # Pretend it arrived corrupt: ask again, and do not consume
                    # it — the resend is what we are testing.
                    self.naked = True
                    self._outbox.append(r_block(self.pni, nak=True))
                    return
                super()._react(frame)

        terminal = NakOnce([SELECT])
        _emulator(terminal, FakeCard([SELECT_RESP])).run()

        assert terminal.naked, "the test did not actually NAK anything"
        assert terminal.responses == [SELECT_RESP], "a NAK must not lose the answer"
        assert terminal.sent.count(i_block(0, SELECT_RESP)) == 2, "sent twice"

    def test_the_card_is_connected_and_released(self):
        card = FakeCard([SELECT_RESP])
        _emulator(FakeTerminal([SELECT]), card).run()
        assert not card.connected, "the transport is closed when the relay ends"

    def test_a_failing_card_answers_6f00_rather_than_dropping_the_link(self):
        class Broken(FakeCard):
            def transmit(self, apdu):
                raise RuntimeError("the card went away")

        terminal = FakeTerminal([SELECT])
        _emulator(terminal, Broken()).run()
        assert terminal.responses == [b"\x6F\x00"]

    def test_mutations_run_on_this_path_too(self):
        rewritten = bytes.fromhex("00A4040007A0000000041010")

        class Engine:
            def on_command(self, msg):
                return rewritten
            def on_response(self, cmd, response):
                return response

        card = FakeCard([SELECT_RESP])
        _emulator(FakeTerminal([SELECT]), card, mutations=Engine()).run()
        assert card.received == [rewritten]

    def test_wtxm_is_validated(self):
        with pytest.raises(ValueError, match="WTXM"):
            IsoDepEmulator(FakeTerminal([]), FakeCard(), wtxm=0)

    @pytest.mark.parametrize("bad", [0, 1, 1.5, -0.2])
    def test_wtx_at_must_be_a_fraction(self, bad):
        with pytest.raises(ValueError, match="fraction"):
            IsoDepEmulator(FakeTerminal([]), FakeCard(), wtx_at=bad)

    def test_deselect_while_waiting_for_time_ends_cleanly(self):
        class Impatient(FakeTerminal):
            def _react(self, frame):
                block_is_wtx = False
                try:
                    b = parse_block(frame)
                    block_is_wtx = b.type is BlockType.S and b.s_type is SType.WTX
                except IsoDepError:
                    pass
                if block_is_wtx:
                    self.wtx_seen += 1
                    self._outbox.append(s_deselect(cid=self.cid))
                    return
                super()._react(frame)

        terminal = Impatient([SELECT])
        emulator = _emulator(terminal, FakeCard([SELECT_RESP], delay=SLOW_CARD))
        emulator.run()
        assert terminal.wtx_seen >= 1
        assert emulator.exchanges == 0, "the exchange never completed"


class TestSurvivingTheAir:
    """
    A mangled frame is not the end of a transaction.

    This is what killed the first relay against a real terminal: one CRC error
    on TgGetInitiatorCommand tore the whole session down, and the terminal
    showed a dead card. ISO/IEC 14443-4 expects the opposite — the card stays
    silent, the reader retries — so reading again is both the fix and the
    behaviour the standard asks for.
    """

    def test_a_crc_error_does_not_end_the_relay(self):
        class Flaky(FakeTerminal):
            fired = False

            def get_initiator_command(self):
                if not self.fired and self.ats is not None:
                    self.fired = True
                    raise RFError("TgGetInitiatorCommand: CRC error", 0x02)
                return super().get_initiator_command()

        terminal = Flaky([SELECT])
        card = FakeCard([SELECT_RESP])
        emulator = _emulator(terminal, card)
        emulator.run()

        assert terminal.fired, "the test did not actually inject an error"
        assert emulator.rf_errors == 1
        assert terminal.responses == [SELECT_RESP], "the transaction survived"

    def test_a_persistently_bad_link_gives_up_and_says_why(self):
        """Retrying forever would hide a genuinely broken setup."""
        class Broken(FakeTerminal):
            def get_initiator_command(self):
                raise RFError("TgGetInitiatorCommand: CRC error", 0x02)

        emulator = _emulator(Broken([SELECT]), FakeCard([SELECT_RESP]))
        emulator.RF_RETRY_SECONDS = 0.05
        with pytest.raises(PN532Error):
            emulator.run()
        assert emulator.rf_errors > 1, "it has to actually retry before giving up"

    def test_a_late_ats_is_blamed_before_the_air_is(self):
        """
        Measured on hardware: the ATS went out 12.8 ms after the reader asked,
        against an 8.46 ms deadline, and then two hundred reads came back
        garbled. The reader had given up and restarted activation, so what was
        being read was fragments of an activation this chip was no longer part
        of. One exchange slipped through the middle of that, which is luck —
        so the late ATS has to be blamed whatever the exchange count says.
        """
        class Broken(FakeTerminal):
            def get_initiator_command(self):
                raise RFError("TgGetInitiatorCommand: CRC error", 0x02)

        emulator = _emulator(Broken([SELECT]), FakeCard([SELECT_RESP]))
        emulator.RF_RETRY_SECONDS = 0.05
        emulator.ats_seconds = 0.0128        # what the rig actually measured
        emulator.exchanges = 1               # and one did get through

        with pytest.raises(PN532Error, match="late") as caught:
            emulator._receive()
        message = str(caught.value)
        assert "restarts activation" in message
        assert "--own-isodep" in message
        assert "move the reader" not in message, (
            "a late ATS must not be reported as an RF problem")

    def test_failure_before_any_command_is_not_called_interference(self):
        """
        The same reader relays a full PPSE on the default path, so telling an
        operator to move it sends them to fix the wrong thing.
        """
        class Broken(FakeTerminal):
            def get_initiator_command(self):
                raise RFError("TgGetInitiatorCommand: parity error", 0x03)

        emulator = _emulator(Broken([SELECT]), FakeCard([SELECT_RESP]))
        emulator.RF_RETRY_SECONDS = 0.05
        with pytest.raises(PN532Error, match="out of step") as caught:
            emulator.run()
        assert "--own-isodep" in str(caught.value)
        assert emulator.exchanges == 0

    def test_failure_after_clean_exchanges_is_still_called_rf(self):
        """
        Once a command has gone through cleanly, a later burst really is the
        air — the bridge just proved it can carry a frame.
        """
        class GoesBad(FakeTerminal):
            def get_initiator_command(self):
                # Behave until one command has been answered end to end, so
                # the bridge has demonstrably carried a frame; only then does
                # the air go bad.
                if not self.responses:
                    return super().get_initiator_command()
                raise RFError("TgGetInitiatorCommand: CRC error", 0x02)

        emulator = _emulator(GoesBad([SELECT]), FakeCard([SELECT_RESP]))
        emulator.RF_RETRY_SECONDS = 0.05
        with pytest.raises(PN532Error, match="really may be the air"):
            emulator.run()
        assert emulator.exchanges >= 1
        assert emulator.ats_seconds <= ATS_DEADLINE, (
            "this branch is only reachable when activation was sound")

    def test_the_count_resets_between_good_frames(self):
        """
        Ordinary interference must not accumulate into a false failure.

        The budget is per receive, so a link that drops one frame in two is
        noisy but usable: every frame that does arrive ends a _receive call and
        the next one starts with a full budget again. Otherwise a busy room
        looks like broken hardware.
        """
        class Intermittent(FakeTerminal):
            def __init__(self, *a, **kw):
                super().__init__(*a, **kw)
                self.armed = True

            def get_initiator_command(self):
                # Never twice in a row: error, frame, error, frame…
                if self.armed and self.ats is not None:
                    self.armed = False
                    raise RFError("TgGetInitiatorCommand: CRC error", 0x02)
                self.armed = True
                return super().get_initiator_command()

        # Enough exchanges that the running total is well past any one budget.
        rounds = 12
        terminal = Intermittent([SELECT] * rounds)
        emulator = _emulator(terminal, FakeCard([SELECT_RESP] * rounds))
        emulator.run()

        assert len(terminal.responses) == rounds, "every exchange still completed"
        assert emulator.rf_errors >= rounds, (
            "it absorbed an error before every single exchange and still "
            "finished — the budget has to be per receive, not cumulative")


class TestCardIdentity:
    def test_the_relayed_cards_historical_bytes_are_worn(self):
        """
        A terminal reading the real card sees 'KONA'; it should see it here too.

        The ATS the driver builds is otherwise its own — chiefly FWI, which is
        the whole point of owning this layer and must not be copied from a card
        sized for card timings.
        """
        class KonaCard(FakeCard):
            def get_atr(self):
                # As the PN532 hands it over: TL already stripped.
                return bytes.fromhex("788071024B4F4E411080")

        terminal = FakeTerminal([SELECT])
        emulator = _emulator(terminal, KonaCard([SELECT_RESP]))
        emulator.run()

        assert emulator.ats.historical == b"KONA\x10\x80"
        assert parse_ats(terminal.ats).historical == b"KONA\x10\x80"
        assert emulator.ats.fwi == TEST_FWI, "FWI stays ours, not the card's"

    def test_an_explicitly_pinned_identity_is_left_alone(self):
        class KonaCard(FakeCard):
            def get_atr(self):
                return bytes.fromhex("788071024B4F4E411080")

        terminal = FakeTerminal([SELECT])
        emulator = IsoDepEmulator(terminal, KonaCard([SELECT_RESP]),
                                  ats=Ats(fwi=TEST_FWI, historical=b"\xAA\xBB"),
                                  wtx_at=0.35)
        emulator.run()
        assert emulator.ats.historical == b"\xAA\xBB"

    def test_a_card_with_no_ats_leaves_the_default(self):
        terminal = FakeTerminal([SELECT])
        emulator = _emulator(terminal, FakeCard([SELECT_RESP]))
        emulator.run()
        assert emulator.ats.historical == bytes(EmulatedCard().historical)

    def test_an_ats_passed_without_historical_bytes_still_gets_them(self):
        """
        The bug the first hardware run exposed: an explicit Ats() dropped them.

        The API passes Ats(fwi=...) and nothing else, so the emulated card went
        on the air with no historical bytes at all — an ATS of four bytes where
        the real card had ten.
        """
        emulator = IsoDepEmulator(FakeTerminal([]), FakeCard(), ats=Ats(fwi=13))
        assert emulator.ats.historical == bytes(EmulatedCard().historical)
        assert emulator.ats.fwi == 13


class TestHistoricalBytes:
    @pytest.mark.parametrize("raw,expected", [
        ("788071024B4F4E411080", "4B4F4E411080"),   # PN532 form, TL stripped
        ("0B788071024B4F4E411080", "4B4F4E411080"),  # with TL
        ("0578807102", ""),                          # interface bytes, no Tk
        ("0278", ""),                                # T0 only
        ("", ""),                                    # nothing at all
    ])
    def test_both_shapes_are_read(self, raw, expected):
        """
        The PN532 strips TL from a card's ATS and our own builder does not, so
        both shapes reach this. Reading one as the other yields nonsense rather
        than an error, which is why it is worth pinning.
        """
        assert historical_bytes(bytes.fromhex(raw)).hex().upper() == expected


class TestDeselected:
    def test_it_is_an_exception(self):
        assert issubclass(Deselected, Exception)
