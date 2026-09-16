"""
The relay, end to end, with a terminal and a card that are both in-process.

Every other test in this suite exercises one seam: the framing, the ISO-DEP
layer, the transport.  This one runs the whole path the ``nfc emulate``
command runs — a reactive terminal, the real ``CardEmulator``, the real
``PN532`` and its framing, a card at the far end — and asserts the thing the
relay actually promises: that what the terminal receives is what the card
said, byte for byte.

It is the regression net under ``tools/relay_loopback.py``, which is the same
rig with a command line on it.
"""
import logging
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from tools.relay_loopback import (
    MASTERCARD,
    MASTERCARD_ATS,
    MASTERCARD_UID,
    ContactlessKernel,
    LoopbackLink,
    ScriptedCard,
    dol_pairs,
    tlv_find,
)

from nfc.emulator import CardEmulator, EmulatedCard
from nfc.pn532 import PN532

PPSE = bytes.fromhex("00A404000E325041592E5359532E444446303100")
SELECT_AID = bytes.fromhex("00A4040007A000000004101000")


def _run(sessions=1, stop_after=None, card_delay=0.0, mutations=None,
         kernels=None):
    card = ScriptedCard(MASTERCARD, atr=MASTERCARD_ATS, uid=MASTERCARD_UID,
                        delay=card_delay)
    if kernels is None:
        kernels = [ContactlessKernel(stop_after=stop_after)
                   for _ in range(sessions)]
    emulator = CardEmulator(PN532(LoopbackLink(kernels)), card,
                            card=EmulatedCard(), mutations=mutations,
                            alert=False)
    emulator.run()
    return emulator, card, kernels


class TestAWholeTransaction:

    def test_the_terminal_gets_through_a_full_emv_selection(self):
        _, card, kernels = _run()

        assert [c.hex().upper() for c in kernels[0].sent] == [
            "00A404000E325041592E5359532E444446303100",   # PPSE
            "00A4040007A000000004101000",                 # SELECT AID
            "80A800000683043600000000",                   # GPO
            "00B2010C00",                                 # READ RECORD
        ], "the kernel must reach a record read, not stall at the PPSE"
        assert card.unknown == [], (
            "the card was asked something it had no answer for")

    def test_what_the_terminal_receives_is_what_the_card_said(self):
        _, card, kernels = _run()

        assert kernels[0].received == card.answered

    def test_the_terminal_picks_its_aid_out_of_the_ppse(self):
        _, _, kernels = _run()

        assert any("A0000000041010" in note for note in kernels[0].notes)

    def test_the_emulator_wears_the_relayed_cards_historical_bytes(self):
        emulator, _, _ = _run()

        assert emulator.card.historical == bytes.fromhex("534C4A0130502310"), (
            "the one part of the ATS this path owns must come from the card")


class TestHowASessionEnds:
    """
    The three endings the emulator has to tell apart, made reproducible.

    The live command can only wait for a terminal to do one of them; here each
    is asked for directly, which is what makes the verdicts testable.
    """

    def test_a_terminal_that_only_reads_the_ppse_ends_inside_the_budget(
            self, caplog):
        # The verdict is per session and the counters behind it are reset by
        # the next one, so it has to be read from the log as it is emitted —
        # which is where an operator reads it too.
        with caplog.at_level(logging.WARNING, logger="nfc.emulator"):
            emulator, _, kernels = _run(stop_after=1)

        assert kernels[0].sent == [PPSE]
        assert emulator.exchanges == 1
        assert any("not a timeout" in r.message for r in caplog.records), (
            "a deselect inside the frame waiting time is a decision, not a "
            "timeout — mislabelling it is what sent this rig chasing latency")

    def test_a_slow_card_is_reported_as_a_timeout(self, caplog):
        # The session has to end short for the verdict to run at all: past
        # three exchanges the emulator stops guessing. So this is a terminal
        # that gave up two commands in, which is the shape a real timeout has.
        with caplog.at_level(logging.WARNING, logger="nfc.emulator"):
            emulator, _, _ = _run(stop_after=2, card_delay=0.2)

        assert emulator.slowest_card > emulator.CHIP_FWT
        assert any("timing out" in r.message for r in caplog.records)

    def test_the_run_wide_maxima_survive_for_the_closing_summary(self):
        # Judging a session on its own clock must not cost the run its totals:
        # the line printed at the end still reports the worst of the whole run.
        emulator, _, _ = _run(stop_after=2, card_delay=0.2)

        assert emulator.slowest_card > 0.15
        assert emulator.session_slowest_card == 0.0, (
            "the last session asked nothing, so its own clock reads zero")

    def test_a_silent_session_after_a_slow_one_is_not_a_timeout(self, caplog):
        """
        A slow session must not poison the verdict on the next one.

        Session 1 takes long enough to blow the frame waiting time. Session 2
        activates and asks nothing at all, so there is no waiting in it to time
        out. Reporting a timeout there points the operator at latency this
        session never spent — the same mislabelling the CHIP_FWT comment says
        cost this rig days of work.
        """
        kernels = [ContactlessKernel(), ContactlessKernel(stop_after=0)]
        with caplog.at_level(logging.WARNING, logger="nfc.emulator"):
            _run(kernels=kernels, card_delay=0.2)

        verdicts = [r.message for r in caplog.records]
        assert any("asking anything at all" in v for v in verdicts), (
            "a session with no exchanges is a decision about the activation, "
            "and that is what its verdict has to say")
        assert not any("timing out" in v for v in verdicts), (
            "no frame was waited on in the silent session, so nothing in it "
            "can have expired")

    def test_the_relay_re_arms_and_sees_a_second_terminal(self):
        emulator, _, kernels = _run(sessions=2)

        assert emulator.sessions == 3, (
            "two terminals, then the empty arming that ends the run")
        assert all(k.sent for k in kernels)
        assert emulator.exchanges == 8


class TestTheHarnessCatchesARelayBug:
    """
    A harness that cannot fail the relay is not testing it.
    """

    def test_a_rewritten_response_shows_up_as_a_mismatch(self):
        class Corrupt:
            def on_command(self, command):
                return command

            def on_response(self, command, response):
                return b"\x6F\x00" if command == PPSE else response

        _, card, kernels = _run(mutations=Corrupt())

        assert kernels[0].received != card.answered, (
            "the terminal was handed bytes the card never said and the "
            "comparison did not notice")

    def test_a_terminal_stops_when_the_ppse_carries_no_aid(self):
        stripped = dict(MASTERCARD)
        stripped[PPSE.hex().upper()] = "6F0A840E325041592E5359532E44444630319000"
        card = ScriptedCard(stripped, atr=MASTERCARD_ATS)
        kernels = [ContactlessKernel()]
        CardEmulator(PN532(LoopbackLink(kernels)), card,
                     card=EmulatedCard(), alert=False).run()

        assert kernels[0].sent == [PPSE]
        assert any("no application identifier" in n for n in kernels[0].notes)


class TestTheTlvTheTerminalNeeds:

    def test_a_tag_is_found_inside_a_constructed_one(self):
        ppse = bytes.fromhex(MASTERCARD[PPSE.hex().upper()])[:-2]

        assert tlv_find(ppse, b"\x4F") == bytes.fromhex("A0000000041010")
        assert tlv_find(ppse, b"\x50") == b"Debit Mastercard"

    def test_a_dol_is_read_as_tag_length_pairs_with_no_values(self):
        assert list(dol_pairs(bytes.fromhex("9F6604"))) == [(b"\x9F\x66", 4)]
