"""
The contactless card transport, and the target it has to keep hold of.

What these establish: that the reader's own polling loop is switched off while
this transport is holding a card, that a target lost anyway is recovered rather
than turned into a card error, and that recovery refuses a card that is not the
one the operator chose.

Why it matters: the ACR122U's firmware polls for cards independently of the
PN532 commands sent over the escape channel, and every sweep redoes
anticollision. During a relay the card sits activated for however long it takes
a terminal to arrive — seconds — and a sweep in that window drops the target.
The next InDataExchange answers 27 and the emulator, having nothing to relay,
answers the terminal 6F00. On real hardware that looked exactly like a card
refusing a SELECT it had answered a moment earlier.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from nfc.acr122 import PICC_POLLING_OFF, PICC_POLLING_ON
from nfc.pn532 import PN532Error, Target, TargetLost
from transport.contactless import ContactlessTransport

CARD = Target(number=1, atqa=b"\x00\x44", sak=0x20,
              uid=bytes.fromhex("0586CC7A956300"),
              ats=bytes.fromhex("007002534C4A0130502310"))
OTHER = Target(number=1, atqa=b"\x00\x44", sak=0x20,
               uid=bytes.fromhex("DEADBEEF"), ats=CARD.ats)

SELECT = bytes.fromhex("00A404000E325041592E5359532E444446303100")


class FakeChip:
    """A PN532 that can be told to forget its target, as a real one does."""

    def __init__(self, targets=(CARD,), lose_after=None):
        self._targets = list(targets)
        # Which exchange the target goes stale on, counting from one.
        self.lose_after = lose_after
        self.exchanges = 0
        self.listings = 0
        self.released = []
        self.retries = None

    def set_retries(self, n):
        self.retries = n

    def list_passive_targets(self, limit=1):
        self.listings += 1
        return self._targets[:limit]

    def data_exchange(self, apdu, target=1):
        self.exchanges += 1
        if self.lose_after is not None and self.exchanges == self.lose_after:
            raise TargetLost("InDataExchange failed: the command makes no "
                             "sense in the current context")
        return b"\x6F\x1A\x90\x00"

    def release(self, number):
        self.released.append(number)


class FakeLink:
    def __init__(self):
        self.parameters = []
        self.closed = False

    def peripheral(self, apdu):
        self.parameters.append(apdu[-2])
        return b"", 0x90, 0x00

    def close(self):
        self.closed = True


def connected(monkeypatch, chip, link=None) -> ContactlessTransport:
    link = link or FakeLink()
    monkeypatch.setattr("nfc.acr122.open_pn532", lambda name, direct: (chip, link))
    transport = ContactlessTransport("ACS ACR122U PICC Interface 01 00")
    transport.connect()
    return transport


class TestReaderPolling:
    def test_the_readers_own_polling_is_switched_off_while_a_card_is_held(
            self, monkeypatch):
        link = FakeLink()
        connected(monkeypatch, FakeChip(), link)
        assert PICC_POLLING_OFF in link.parameters, (
            "the reader kept sweeping and will drop the target mid-relay")

    def test_the_reader_is_put_back_the_way_it_was_found(self, monkeypatch):
        link = FakeLink()
        transport = connected(monkeypatch, FakeChip(), link)
        transport.disconnect()
        assert link.parameters[-1] == PICC_POLLING_ON, (
            "a reader left unable to find cards breaks the next session")

    def test_a_reader_that_refuses_the_setting_still_works(self, monkeypatch):
        """
        Not every reader takes the parameter. That is a reason to carry on
        without it, not to refuse to read a card.
        """
        class Stubborn(FakeLink):
            def peripheral(self, apdu):
                raise RuntimeError("not supported")

        transport = connected(monkeypatch, FakeChip(), Stubborn())
        assert transport.transmit(SELECT).endswith(b"\x90\x00")
        transport.disconnect()


class TestRecoveringALostTarget:
    def test_a_lost_target_is_activated_again_and_the_command_retried(
            self, monkeypatch):
        chip = FakeChip(lose_after=1)
        transport = connected(monkeypatch, chip)

        assert transport.transmit(SELECT).endswith(b"\x90\x00")
        assert transport.reactivations == 1
        assert chip.exchanges == 2, "the command was dropped rather than retried"

    def test_recovery_refuses_a_card_that_is_not_the_one_chosen(
            self, monkeypatch):
        """
        Anticollision picks whatever is in the field, and on a relay rig the
        field is where cards get put. Silently continuing against a different
        one would relay a card the operator did not choose — worse than failing.
        """
        chip = FakeChip(lose_after=1)
        transport = connected(monkeypatch, chip)
        chip._targets = [OTHER]

        with pytest.raises(TargetLost):
            transport.transmit(SELECT)
        assert transport.reactivations == 0

    def test_an_empty_field_is_reported_rather_than_retried_forever(
            self, monkeypatch):
        chip = FakeChip(lose_after=1)
        transport = connected(monkeypatch, chip)
        chip._targets = []

        with pytest.raises(TargetLost):
            transport.transmit(SELECT)

    def test_the_retry_happens_once_per_command(self, monkeypatch):
        """
        A second loss on the retry is a card that is genuinely gone, and a
        transport that keeps re-activating would spend a terminal's whole
        frame waiting time doing it.
        """
        class AlwaysLoses(FakeChip):
            def data_exchange(self, apdu, target=1):
                self.exchanges += 1
                raise TargetLost("no target")

        chip = AlwaysLoses()
        transport = connected(monkeypatch, chip)
        with pytest.raises(TargetLost):
            transport.transmit(SELECT)
        assert chip.exchanges == 2

    def test_any_other_chip_failure_is_not_treated_as_a_lost_target(
            self, monkeypatch):
        """
        Only status 27 means "no target activated". Re-activating on anything
        else would hide a real fault and reset the card's selection doing it.
        """
        class Broken(FakeChip):
            def data_exchange(self, apdu, target=1):
                raise PN532Error("InDataExchange failed: syntax error")

        transport = connected(monkeypatch, Broken())
        with pytest.raises(PN532Error):
            transport.transmit(SELECT)
        assert transport.reactivations == 0


class TestWireTrace:
    """
    The byte-level record, which is off unless asked for.

    Every layer above this one interprets, and interpretation is what has
    repeatedly been wrong on this hardware — "the card refused" for a 6F00 we
    fabricated ourselves, "timing out" for an exchange inside its budget. The
    trace is the only place that says what the reader was actually told.
    """

    def _link(self):
        from nfc.acr122 import ACR122Link

        link = ACR122Link("ACS ACR122U PICC Interface 00 00", direct=True)
        link._connection = object()
        link._path = "control"
        link.direct = True
        return link

    def test_it_is_silent_until_switched_on(self, monkeypatch, caplog):
        from nfc.acr122 import wire

        link = self._link()
        monkeypatch.setattr(type(link), "_escape",
                            lambda self, apdu: (b"\xD5\x03\x32\x01\x06\x07\x90\x00", 0x90, 0x00))
        with caplog.at_level("INFO", logger="nfc.wire"):
            wire.setLevel(logging.WARNING)
            link._transmit(b"\xFF\x00\x00\x00\x02\xD4\x02")
        assert not [r for r in caplog.records if r.name == "nfc.wire"]

    def test_both_directions_are_recorded_when_it_is_on(self, monkeypatch, caplog):
        from nfc.acr122 import wire

        link = self._link()
        monkeypatch.setattr(type(link), "_escape",
                            lambda self, apdu: (b"\xD5\x03\x32\x01\x06\x07\x90\x00", 0x90, 0x00))
        try:
            wire.setLevel(logging.INFO)
            with caplog.at_level("INFO", logger="nfc.wire"):
                link._transmit(b"\xFF\x00\x00\x00\x02\xD4\x02")
        finally:
            wire.setLevel(logging.WARNING)

        lines = [r.getMessage() for r in caplog.records if r.name == "nfc.wire"]
        assert any("FF00000002D402" in line for line in lines), "the command"
        assert any("D503320106 07".replace(" ", "") in line for line in lines), "the reply"

    def test_a_reader_that_answered_nothing_says_so(self, monkeypatch, caplog):
        """
        The case the whole thing exists for. An empty reply is not an error
        anywhere in this stack — it is the ACR122U's bridge answering before
        the chip has anything — and it is invisible one layer up.
        """
        from nfc.acr122 import wire

        link = self._link()
        monkeypatch.setattr(type(link), "_escape",
                            lambda self, apdu: (b"", 0x90, 0x00))
        try:
            wire.setLevel(logging.INFO)
            with caplog.at_level("INFO", logger="nfc.wire"):
                link._transmit(b"\xFF\x00\x00\x00\x02\xD4\x86")
        finally:
            wire.setLevel(logging.WARNING)

        lines = [r.getMessage() for r in caplog.records if r.name == "nfc.wire"]
        assert any("answered with nothing" in line for line in lines)

    def test_the_status_word_is_shown_once(self, monkeypatch, caplog):
        """
        On the escape path the (sw1, sw2) tuple is synthetic and the reader's
        real status is the tail of the reply, so printing both showed it twice
        — and beside a card response that ends in its own 9000, three 9000s in
        a row. An operator stopped mid-diagnosis to ask what was wrong with
        that, which is exactly what a wire trace is supposed to prevent.
        """
        from nfc.acr122 import wire

        link = self._link()
        card = bytes.fromhex("7081FB9F46") + b"\x90\x00"     # ends in its own SW
        reply = b"\xD5\x41\x00" + card + b"\x90\x00"       # + the reader's
        monkeypatch.setattr(type(link), "_escape",
                            lambda self, apdu: (reply, 0x90, 0x00))
        try:
            wire.setLevel(logging.INFO)
            with caplog.at_level("INFO", logger="nfc.wire"):
                link._transmit(b"\xFF\x00\x00\x00\x02\xD4\x40")
        finally:
            wire.setLevel(logging.WARNING)

        line = [r.getMessage() for r in caplog.records
                if r.name == "nfc.wire" and r.getMessage().startswith("←")][0]
        assert "90009000" not in line, (
            "the reader's status word is being printed on top of the card's")
        assert line.count("9000") == 2, "the card's own, and the reader's"

    def test_a_failure_is_recorded_with_how_long_it_took(self, monkeypatch, caplog):
        from nfc.acr122 import ACR122Error, wire

        link = self._link()

        def boom(self, apdu):
            raise ACR122Error("the reader went away")

        monkeypatch.setattr(type(link), "_escape", boom)
        try:
            wire.setLevel(logging.INFO)
            with caplog.at_level("INFO", logger="nfc.wire"):
                with pytest.raises(ACR122Error):
                    link._transmit(b"\xFF\x00\x00\x00\x02\xD4\x02")
        finally:
            wire.setLevel(logging.WARNING)

        lines = [r.getMessage() for r in caplog.records if r.name == "nfc.wire"]
        assert any("went away" in line for line in lines)
