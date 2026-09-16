"""
Dialect detection tests.

The property that matters: pointed at bytes from a known configuration,
detection must rank that configuration first. The property that matters almost
as much: it must not answer confidently when it has no business doing so.
"""
from __future__ import annotations

import pytest

from host.iso8583 import Message, load_dialect, pack
from host.iso8583.detect import describe, detect
from host.iso8583.framing import Framing

FIELDS = {
    2:  "4111111111111111",
    3:  "000000",
    4:  "000000001000",
    11: "000123",
    41: "TERM0001",
    49: "840",
}


def _wire(dialect_name: str) -> bytes:
    """Encode the reference fields, supplying a TPDU when the dialect wants one."""
    dialect = load_dialect(dialect_name)
    tpdu = bytes.fromhex("6000030000") if dialect.framing.tpdu_length else b""
    return pack(dialect, Message(mti="0100", fields=dict(FIELDS), tpdu=tpdu))


class TestRecognisesWhatItEncoded:
    @pytest.mark.parametrize("name", ["iso8583-1987", "postilion", "base24"])
    def test_top_candidate_is_the_right_dialect(self, name):
        best = detect(_wire(name))[0]
        assert best.dialect.name == name
        assert best.score >= 0.7, f"weak confidence: {best}"
        assert best.message.mti == "0100"

    def test_recovers_the_fields_it_ranked_on(self):
        best = detect(_wire("iso8583-1987"))[0]
        assert best.message.fields == FIELDS
        assert best.message.complete

    def test_identifies_the_framing_not_just_the_field_table(self):
        best = detect(_wire("base24"))[0]
        assert best.framing.tpdu_length == 5

    def test_ascii_and_bcd_dialects_are_told_apart(self):
        """Postilion and the ISO base differ only in numeric encoding."""
        assert detect(_wire("postilion"))[0].dialect.name == "postilion"
        assert detect(_wire("iso8583-1987"))[0].dialect.name == "iso8583-1987"


class TestFramingVariants:
    @pytest.mark.parametrize("framing", [
        Framing(2, "binary", False),
        Framing(2, "binary", True),
        Framing(4, "ascii",  False),
    ])
    def test_finds_the_mli_variant_in_use(self, framing):
        dialect = load_dialect("iso8583-1987")
        wire = pack(dialect, Message(mti="0100", fields=dict(FIELDS)), framing)
        best = detect(wire)[0]
        assert best.framing.mli_bytes == framing.mli_bytes
        assert best.framing.mli_encoding == framing.mli_encoding
        assert best.framing.mli_includes_self == framing.mli_includes_self


class TestRefusesToGuess:
    def test_random_bytes_produce_no_confident_answer(self):
        noise = bytes(range(256))[:80]
        results = detect(noise)
        assert not results or results[0].score < 0.6

    def test_empty_and_truncated_input_are_handled(self):
        assert detect(b"") == []
        assert detect(b"\x00") == []

    def test_a_body_with_no_valid_mti_scores_nothing(self):
        wire = bytes.fromhex("0010") + b"\xff" * 16
        assert all(c.score == 0 for c in detect(wire)) or detect(wire) == []

    def test_low_confidence_is_stated_in_the_report(self):
        results = detect(bytes.fromhex("000AFFFFFFFFFFFFFFFFFFFF"))
        text = describe(results)
        assert "Low confidence" in text or "No dialect decoded" in text


class TestReporting:
    def test_describe_ranks_and_labels(self):
        text = describe(detect(_wire("iso8583-1987")))
        assert "Ranked dialect candidates" in text
        assert "iso8583-1987" in text
        assert "2-byte binary" in text

    def test_describe_handles_no_candidates(self):
        assert "No dialect decoded" in describe([])

    def test_limit_is_respected(self):
        assert len(detect(_wire("iso8583-1987"), limit=2)) <= 2

    def test_caller_can_restrict_the_dialect_set(self):
        results = detect(_wire("iso8583-1987"), dialects=["base24"])
        assert all(c.dialect.name == "base24" for c in results)
