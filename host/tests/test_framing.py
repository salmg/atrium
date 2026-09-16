"""
Framing tests — MLI variants and the TPDU split.

Getting the envelope wrong is the most common reason a decoder produces
garbage against a real link, so every shipped variant is pinned to explicit
bytes rather than round-tripped against itself.
"""
from __future__ import annotations

import pytest

from host.iso8583.framing import (
    Framing,
    FramingError,
    IncompleteMessage,
    iter_common_framings,
)

BODY = b"\x01\x02\x03\x04\x05"          # five bytes


class TestMliEncoding:
    @pytest.mark.parametrize("framing,expected_prefix", [
        (Framing(2, "binary", False), b"\x00\x05"),
        (Framing(2, "binary", True),  b"\x00\x07"),   # 5 body + 2 MLI
        (Framing(4, "ascii",  False), b"0005"),
        (Framing(2, "bcd",    False), b"\x00\x05"),
        (Framing(4, "binary", False), b"\x00\x00\x00\x05"),
    ])
    def test_wrap_writes_the_expected_prefix(self, framing, expected_prefix):
        assert framing.wrap(BODY) == expected_prefix + BODY

    @pytest.mark.parametrize("framing", [
        Framing(2, "binary", False),
        Framing(2, "binary", True),
        Framing(4, "ascii",  False),
        Framing(2, "bcd",    False),
    ])
    def test_round_trip(self, framing):
        body, consumed = framing.unwrap(framing.wrap(BODY))
        assert body == BODY
        assert consumed == len(BODY) + framing.mli_bytes

    def test_bcd_length_is_decimal_not_hex(self):
        """BCD 0x0016 is sixteen, not twenty-two."""
        framing = Framing(2, "bcd", False)
        assert framing.wrap(b"x" * 16)[:2] == b"\x00\x16"
        body, _ = framing.unwrap(b"\x00\x16" + b"x" * 16)
        assert len(body) == 16


class TestStreamBehaviour:
    def test_short_buffer_asks_for_more(self):
        framing = Framing(2, "binary", False)
        wire = framing.wrap(BODY)
        with pytest.raises(IncompleteMessage):
            framing.unwrap(wire[:-1])
        with pytest.raises(IncompleteMessage):
            framing.unwrap(b"\x00")          # MLI itself incomplete

    def test_consumed_count_allows_a_second_message(self):
        framing = Framing(2, "binary", False)
        stream = framing.wrap(BODY) + framing.wrap(b"\xAA\xBB")
        first, consumed = framing.unwrap(stream)
        assert first == BODY
        second, _ = framing.unwrap(stream[consumed:])
        assert second == b"\xAA\xBB"

    def test_impossible_lengths_are_rejected_not_hung_on(self):
        with pytest.raises(FramingError):
            Framing(2, "binary", True).unwrap(b"\x00\x01xxxx")   # shorter than the MLI
        with pytest.raises(FramingError):
            Framing(2, "binary", False).unwrap(b"\x00\x00xxxx")  # empty message
        with pytest.raises(FramingError):
            Framing(4, "ascii", False).unwrap(b"12x4rest")       # not decimal


class TestTpdu:
    def test_split_and_join_are_inverse(self):
        framing = Framing(2, "binary", False, tpdu_length=5)
        tpdu = bytes.fromhex("6000030000")
        joined = framing.join_tpdu(tpdu, BODY)
        assert joined == tpdu + BODY
        assert framing.split_tpdu(joined) == (tpdu, BODY)

    def test_absent_tpdu_is_a_no_op(self):
        framing = Framing(2, "binary", False, tpdu_length=0)
        assert framing.split_tpdu(BODY) == (b"", BODY)
        assert framing.join_tpdu(b"", BODY) == BODY

    def test_message_too_short_for_its_tpdu_is_an_error(self):
        framing = Framing(2, "binary", False, tpdu_length=5)
        with pytest.raises(FramingError):
            framing.split_tpdu(b"\x01\x02")


class TestConfiguration:
    def test_rejects_unknown_encoding(self):
        with pytest.raises(FramingError):
            Framing(2, "morse", False)

    def test_from_dict_reads_a_dialect_fragment(self):
        framing = Framing.from_dict({
            "mli":  {"bytes": 4, "encoding": "ascii", "includes_self": True},
            "tpdu": {"present": True, "length": 5},
        })
        assert framing.mli_bytes == 4
        assert framing.mli_encoding == "ascii"
        assert framing.mli_includes_self is True
        assert framing.tpdu_length == 5

    def test_from_dict_defaults_to_the_common_case(self):
        framing = Framing.from_dict({})
        assert (framing.mli_bytes, framing.mli_encoding) == (2, "binary")
        assert framing.mli_includes_self is False
        assert framing.tpdu_length == 0

    def test_detection_sweep_covers_tpdu_both_ways(self):
        shapes = list(iter_common_framings())
        assert any(f.tpdu_length == 5 for f in shapes)
        assert any(f.tpdu_length == 0 for f in shapes)
        # The most common real-world shape should be tried first.
        assert shapes[0] == Framing(2, "binary", False, 0)
