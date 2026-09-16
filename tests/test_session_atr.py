"""
Session ATR reporting.

The dashboard and toolbar both display the card's ATR. Until now the value was
initialised to None and never assigned, so both readouts were permanently "—":
a dead feature that looked like a working one. These cover the formatter that
now fills it, including the type disagreement that made it fiddly — pyscard
hands back a list of ints, the remote transport returns bytes, and older
versions return a str of char-codes.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from api.routes.session import _format_atr


class TestFormatAtr:
    @pytest.mark.parametrize("value", [
        b"\x3B\x65\x00\x00",
        bytearray(b"\x3B\x65\x00\x00"),
        [0x3B, 0x65, 0x00, 0x00],
        (0x3B, 0x65, 0x00, 0x00),
        "\x3B\x65\x00\x00",
    ])
    def test_every_transport_shape_renders_the_same_hex(self, value):
        assert _format_atr(value) == "3B650000"

    def test_none_and_empty_stay_none(self):
        """An absent ATR must not display as an empty string."""
        assert _format_atr(None) is None
        assert _format_atr(b"") is None
        assert _format_atr([]) is None

    def test_unconvertible_input_does_not_raise(self):
        """A transport returning something unexpected must not break status."""
        assert _format_atr(object()) is None

    def test_output_is_uppercase(self):
        assert _format_atr(b"\xab\xcd") == "ABCD"


class TestStatusContract:
    def test_status_reports_atr_and_stop_clears_it(self, monkeypatch):
        from api.routes import session

        monkeypatch.setattr(session, "_card_atr", "3B650000")
        assert session.session_status()["atr"] == "3B650000"

        session.stop_session()
        assert session.session_status()["atr"] is None
