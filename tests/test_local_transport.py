"""
The local card transport.

Split out of RelayOS so a request handler can open a card without inheriting
that class's ``sys.exit`` on a missing reader — which would take the web server
down with it. The subtle part is the status word: pyscard is inconsistent about
whether SW1/SW2 are also left on the end of the response data, and appending
them unconditionally produces an APDU with the status word twice. A duplicated
9000 is not obviously wrong to read, which is exactly why it needs a test.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.readers import CONTACT, VIRTUAL, Reader, ReaderError
from transport.local import LocalCardTransport


class FakeSession:
    """pyscard's Session, in whichever of its two shapes is asked for."""

    def __init__(self, data, sw1, sw2, atr=b"\x3B\x65\x00"):
        self._reply = (list(data), sw1, sw2)
        self._atr = list(atr)
        self.closed = False
        self.sent = []

    def sendCommandAPDU(self, apdu):
        self.sent.append(bytes(apdu))
        return self._reply

    def getATR(self):
        return self._atr

    def close(self):
        self.closed = True


def _connected(session) -> LocalCardTransport:
    card = LocalCardTransport()
    card._session = session
    return card


class TestTransmit:
    def test_status_word_is_appended_when_the_data_lacks_it(self):
        card = _connected(FakeSession([0x6F, 0x1A], 0x90, 0x00))
        assert card.transmit(b"\x00\xA4\x04\x00") == bytes.fromhex("6F1A9000")

    def test_status_word_is_not_doubled_when_the_data_already_has_it(self):
        card = _connected(FakeSession([0x6F, 0x1A, 0x90, 0x00], 0x90, 0x00))
        assert card.transmit(b"\x00\xA4\x04\x00") == bytes.fromhex("6F1A9000")

    def test_a_bare_status_word_response(self):
        card = _connected(FakeSession([], 0x6A, 0x82))
        assert card.transmit(b"\x00\xA4\x04\x00") == bytes.fromhex("6A82")

    def test_data_ending_in_the_same_two_bytes_by_coincidence(self):
        """
        Not a false positive: data really ending 90 00 before a 90 00 status is
        indistinguishable from the duplicated case, and pyscard's own callers
        make the same choice. Recorded so the behaviour is a decision, not a
        surprise.
        """
        card = _connected(FakeSession([0x01, 0x90, 0x00], 0x90, 0x00))
        assert card.transmit(b"\x00\xB0\x00\x00") == bytes.fromhex("019000")

    def test_the_command_reaches_the_card_as_a_list_of_ints(self):
        session = FakeSession([], 0x90, 0x00)
        _connected(session).transmit(b"\x80\xA8\x00\x00")
        assert session.sent == [b"\x80\xA8\x00\x00"]


class TestLifecycle:
    def test_using_it_before_connecting_says_so(self):
        with pytest.raises(RuntimeError, match="connect"):
            LocalCardTransport().transmit(b"\x00\xA4")

    def test_atr_comes_back_as_bytes(self):
        assert _connected(FakeSession([], 0x90, 0x00)).get_atr() == b"\x3B\x65\x00"

    def test_disconnect_closes_once_and_is_safe_to_repeat(self):
        session = FakeSession([], 0x90, 0x00)
        card = _connected(session)
        card.disconnect()
        card.disconnect()                       # must not raise
        assert session.closed

    def test_a_close_that_fails_still_drops_the_session(self):
        class _Stubborn(FakeSession):
            def close(self):
                raise RuntimeError("reader unplugged")

        card = _connected(_Stubborn([], 0x90, 0x00))
        card.disconnect()                       # must not raise
        assert card._session is None


class TestReaderChoice:
    def test_the_virtual_reader_is_refused_rather_than_relayed_to_itself(self, monkeypatch):
        """
        The virtual reader is ATRIUM's own output side. Connecting a relay to it
        loops the relay back on itself, and the failure reads as a card fault
        rather than as the wiring mistake it is.
        """
        virtual = Reader(index=0, name="Virtual PCD 00 00", kind=VIRTUAL)
        monkeypatch.setattr("core.readers.resolve", lambda spec: virtual)
        with pytest.raises(ReaderError, match="virtual"):
            LocalCardTransport(0).connect()

    def test_a_reader_that_cannot_be_opened_raises_rather_than_exiting(self, monkeypatch):
        """
        The reason this class exists: RelayOS calls sys.exit here, which inside
        a request handler stops the server instead of returning an error.
        """
        real = Reader(index=1, name="Generic ICC Reader 00 00", kind=CONTACT)
        monkeypatch.setattr("core.readers.resolve", lambda spec: real)

        smartcard = pytest.importorskip("smartcard")
        monkeypatch.setattr(smartcard, "Session",
                            lambda name: (_ for _ in ()).throw(RuntimeError("no card")))

        with pytest.raises(ReaderError, match="Generic ICC Reader"):
            LocalCardTransport(1).connect()
