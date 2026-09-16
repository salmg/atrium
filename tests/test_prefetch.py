"""
The prefetching card transport.

What these establish: that only the two deterministic SELECTs are ever answered
from memory, that the warm-up never lands in the relay's timing, that a card
left on the wrong application gets put back, and that the commands whose whole
value is being live are never cached.

What they cannot establish: whether a cached exchange actually fits inside a
terminal's frame waiting time. That is a stopwatch against real hardware.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from transport.base import CardTransport
from transport.prefetch import (
    PPSE_NAME,
    PrefetchingTransport,
    aids_in_ppse,
    select_by_name,
)

# The real PPSE this rig's Mastercard answered, byte for byte.
PPSE_RESPONSE = bytes.fromhex(
    "6F40840E325041592E5359532E4444463031A52EBF0C2B61294F08A0000000041010"
    "01500A4D43454E4742524742508701019F120D6D6320656E20676272206762709000")
AID = bytes.fromhex("A000000004101001")


def ppse_listing(*aids: bytes) -> bytes:
    """A PPSE FCI advertising these applications, in this order."""
    def tlv(tag: bytes, value: bytes) -> bytes:
        return tag + bytes([len(value)]) + value

    templates = b"".join(
        tlv(b"\x61", tlv(b"\x4F", aid) + tlv(b"\x87", bytes([i + 1])))
        for i, aid in enumerate(aids))
    directory = tlv(b"\xBF\x0C"[:1] + b"\x0C", templates)
    fci = tlv(b"\x84", PPSE_NAME) + tlv(b"\xA5", directory)
    return tlv(b"\x6F", fci) + b"\x90\x00"


class FakeCard(CardTransport):
    """A card that answers SELECTs and counts what actually reached it."""

    def __init__(self, aids=(AID,), fail=(), ppse=None):
        self.aids = list(aids)
        self.fail = set(fail)
        self.ppse = ppse if ppse is not None else PPSE_RESPONSE
        self.seen: list[bytes] = []
        self.connected = False

    def connect(self) -> None:
        self.connected = True

    def get_atr(self) -> bytes:
        return bytes.fromhex("788071024B4F4E411080")

    def transmit(self, apdu: bytes) -> bytes:
        command = bytes(apdu)
        self.seen.append(command)
        if command in self.fail:
            return b"\x6A\x82"
        name = self._name(command)
        if name == PPSE_NAME:
            return self.ppse
        if name is not None and name in self.aids:
            return b"\x6F\x1A" + b"\x90\x00"
        if command[:2] == b"\x80\xA8":                 # GPO
            return b"\x77\x0E" + b"\x90\x00"
        return b"\x6D\x00"

    @staticmethod
    def _name(command: bytes):
        if len(command) < 6 or command[:4] != b"\x00\xA4\x04\x00":
            return None
        return command[5:5 + command[4]]


class TestDirectoryParsing:
    def test_the_aid_comes_out_of_the_real_ppse(self):
        assert aids_in_ppse(PPSE_RESPONSE) == [AID]

    def test_a_4f_buried_in_some_other_value_is_not_an_aid(self):
        """
        Walking the TLV rather than scanning for the tag. A byte-scan would
        find the 4F inside this label and emulate an application that does not
        exist.
        """
        label = b"\x4F\x08\xDE\xAD\xBE\xEF\xDE\xAD\xBE\xEF"
        response = b"\x6F" + bytes([len(label) + 2]) + b"\x50" + \
            bytes([len(label)]) + label + b"\x90\x00"
        assert aids_in_ppse(response) == []

    def test_a_malformed_directory_warms_less_rather_than_raising(self):
        assert aids_in_ppse(b"\x6F\x7F\x90\x00") == []
        assert aids_in_ppse(b"") == []
        assert aids_in_ppse(b"\x90\x00") == []


class TestWhatMayBeCached:
    def test_only_select_by_name_by_default(self):
        cacheable = PrefetchingTransport.is_cacheable
        assert cacheable(select_by_name(AID))
        assert not cacheable(bytes.fromhex("00B2010C00")), "READ RECORD is opt-in"

    def test_the_live_commands_are_never_cacheable(self):
        """
        Each of these is uncacheable for its own reason, and the last one is
        the reason this project exists.
        """
        cacheable = PrefetchingTransport.is_cacheable
        for name, apdu in [
            ("GET PROCESSING OPTIONS", "80A80000023800"),
            ("GENERATE AC", "80AE80001D00"),
            ("EXCHANGE RELAY RESISTANCE DATA", "80EA000008AABBCCDDEEFF0011"),
            ("INTERNAL AUTHENTICATE", "0088000004AABBCCDD"),
        ]:
            command = bytes.fromhex(apdu)
            assert not cacheable(command), name
            assert not cacheable(command, read_records=True), name


class TestWarmUp:
    def _warm(self, card=None, **kw):
        transport = PrefetchingTransport(card or FakeCard(), **kw)
        transport.connect()
        return transport

    def test_it_fetches_the_ppse_and_every_aid_before_a_terminal_arrives(self):
        card = FakeCard()
        self._warm(card)
        names = [FakeCard._name(c) for c in card.seen]
        assert PPSE_NAME in names
        assert AID in names

    def test_both_le_forms_are_warmed(self):
        """
        Kernels differ on whether a SELECT carries a trailing Le, and the cache
        is keyed on exact bytes — so warming one form is a cache that never
        hits the other.
        """
        card = FakeCard()
        self._warm(card)
        assert select_by_name(PPSE_NAME, le=True) in card.seen
        assert select_by_name(PPSE_NAME, le=False) in card.seen
        assert select_by_name(AID, le=True) in card.seen
        assert select_by_name(AID, le=False) in card.seen

    def test_a_warmed_select_never_reaches_the_card_again(self):
        card = FakeCard()
        transport = self._warm(card)
        card.seen.clear()

        response = transport.transmit(select_by_name(PPSE_NAME))
        assert response == PPSE_RESPONSE
        assert card.seen == [], "a hit must not cost a card round trip"
        assert transport.hits == 1

    def test_anything_not_warmed_goes_to_the_card(self):
        card = FakeCard()
        transport = self._warm(card)
        card.seen.clear()

        gpo = bytes.fromhex("80A80000023800")
        transport.transmit(gpo)
        assert gpo in card.seen, "GPO must always be live"
        assert transport.misses == 1

    def test_a_refusal_is_not_remembered(self):
        """
        A cached 6A82 would make the emulated card permanently refuse an
        application the real one might serve on the next attempt.
        """
        card = FakeCard(fail={select_by_name(AID), select_by_name(AID, le=False)})
        transport = self._warm(card)
        card.seen.clear()

        transport.transmit(select_by_name(AID))
        assert card.seen, "the refusal was cached instead of being retried live"

    def test_a_card_with_no_ppse_simply_warms_nothing(self):
        class Silent(FakeCard):
            def transmit(self, apdu):
                self.seen.append(bytes(apdu))
                return b"\x6D\x00"

        card = Silent()
        transport = self._warm(card)
        card.seen.clear()
        transport.transmit(select_by_name(PPSE_NAME))
        assert card.seen, "with nothing warmed, every command is live"


class TestApplicationState:
    def test_the_card_is_put_back_when_the_terminal_picks_another_aid(self):
        """
        A cache hit never reaches the card, so after the terminal's SELECTs are
        answered from memory the card is still where the warm-up left it. If
        the terminal chose a different application, the live GPO would arrive
        with the wrong one selected and the card would answer 6985 — a card
        fault that is not one.
        """
        other = bytes.fromhex("A0000000031010")
        card = FakeCard(aids=[other, AID], ppse=ppse_listing(other, AID))
        transport = PrefetchingTransport(card)
        transport.connect()
        assert transport._resting_aid == AID, "the last warmed is where it rests"

        # The terminal picks the *other* application, from cache.
        transport.transmit(select_by_name(other))
        card.seen.clear()

        transport.transmit(bytes.fromhex("80A80000023800"))
        selected = [c for c in card.seen if FakeCard._name(c) == other]
        assert selected, "the card was left on the wrong application"

    def test_no_repair_when_the_terminal_agrees_with_the_warm_up(self):
        card = FakeCard()
        transport = PrefetchingTransport(card)
        transport.connect()
        transport.transmit(select_by_name(AID))
        card.seen.clear()

        transport.transmit(bytes.fromhex("80A80000023800"))
        assert len(card.seen) == 1, "an unnecessary re-SELECT costs an exchange"

    def test_the_repair_happens_once(self):
        other = bytes.fromhex("A0000000031010")
        card = FakeCard(aids=[other, AID], ppse=ppse_listing(other, AID))
        transport = PrefetchingTransport(card)
        transport.connect()
        transport.transmit(select_by_name(other))

        transport.transmit(bytes.fromhex("80A80000023800"))
        card.seen.clear()
        transport.transmit(bytes.fromhex("80AE80001D00"))
        assert all(FakeCard._name(c) != other for c in card.seen), (
            "the card was re-selected a second time, costing an exchange")


class TestPassThrough:
    def test_the_wrapped_transports_own_attributes_still_reach_through(self):
        card = FakeCard()
        card.reader_name = "ACS ACR122U PICC Interface 01 00"
        transport = PrefetchingTransport(card)
        assert transport.reader_name == card.reader_name
        assert transport.get_atr() == card.get_atr()

    def test_disconnect_reaches_the_card(self):
        closed = []

        class Closing(FakeCard):
            def disconnect(self):
                closed.append(True)

        transport = PrefetchingTransport(Closing())
        transport.connect()
        transport.disconnect()
        assert closed == [True]
