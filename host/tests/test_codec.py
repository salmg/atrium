"""
Codec tests.

The central fixture is hand-assembled from explicit bytes rather than produced
by our own packer, so a symmetric bug — one that encodes and decodes wrongly in
the same direction — cannot pass.
"""
from __future__ import annotations

import pytest

from host.iso8583.codec import CodecError, Message, build_bitmap, pack, pack_body, read_bitmap, unpack, unpack_body
from host.iso8583.dialect import load_dialect

# ── Reference message, byte by byte ───────────────────────────────────────────
#
#   0023                MLI: 35 bytes to follow
#   30313030            MTI "0100" in ASCII
#   7020000000008000    bitmap: fields 2, 3, 4, 11, 49
#   16                  DE2 length prefix: 16 digits, BCD
#   4111111111111111    DE2 PAN, packed BCD
#   000000              DE3 processing code
#   000000001000        DE4 amount, 12 digits packed
#   000123              DE11 STAN
#   0840                DE49 currency "840", odd digits padded left with zero
REFERENCE_WIRE = bytes.fromhex(
    "0023"
    "30313030"
    "7020000000008000"
    "16" "4111111111111111"
    "000000"
    "000000001000"
    "000123"
    "0840"
)

REFERENCE_FIELDS = {
    2:  "4111111111111111",
    3:  "000000",
    4:  "000000001000",
    11: "000123",
    49: "840",
}


@pytest.fixture
def iso():
    return load_dialect("iso8583-1987")


class TestReferenceMessage:
    def test_decodes_to_the_expected_fields(self, iso):
        msg, consumed = unpack(iso, REFERENCE_WIRE)
        assert consumed == len(REFERENCE_WIRE)
        assert msg.mti == "0100"
        assert msg.fields == REFERENCE_FIELDS
        assert msg.problems == []
        assert msg.trailing == b""
        assert msg.complete

    def test_encodes_back_to_the_same_bytes(self, iso):
        msg = Message(mti="0100", fields=dict(REFERENCE_FIELDS))
        assert pack(iso, msg) == REFERENCE_WIRE

    def test_bitmap_names_exactly_the_present_fields(self):
        bitmap = bytes.fromhex("7020000000008000")
        assert read_bitmap(bitmap) == [2, 3, 4, 11, 49]
        assert build_bitmap([2, 3, 4, 11, 49]) == bitmap


class TestBitmap:
    def test_secondary_bitmap_appears_only_when_needed(self):
        assert len(build_bitmap([2, 3])) == 8
        wide = build_bitmap([2, 100])
        assert len(wide) == 16
        assert wide[0] & 0x80, "bit 1 must flag the secondary bitmap"
        assert read_bitmap(wide) == [2, 100]

    def test_field_one_is_an_indicator_not_a_field(self):
        assert 1 not in read_bitmap(build_bitmap([2, 100]))

    def test_round_trip_over_a_wide_field_set(self, iso):
        fields = {2: "4111111111111111", 4: "000000001000", 100: "12345"}
        msg = Message(mti="0100", fields=fields)
        back, _ = unpack(iso, pack(iso, msg))
        assert back.fields == fields


class TestEncodings:
    def test_ascii_numerics(self, tmp_path):
        dialect = load_dialect("postilion")
        msg = Message(mti="0200", fields={3: "000000", 4: "000000001000"})
        wire = pack(dialect, msg)
        # ASCII numerics mean the amount is legible in the raw bytes.
        assert b"000000001000" in wire
        back, _ = unpack(dialect, wire)
        assert back.fields[4] == "000000001000"

    def test_ebcdic_body(self, tmp_path):
        """A text field encodes to cp500, not ASCII."""
        src = (tmp_path / "ebcdic-test.yaml")
        src.write_text(
            "name: ebcdic-test\n"
            "body_encoding: ebcdic\n"
            "fields:\n"
            "  41: {name: Terminal ID, type: ans, length: 8}\n"
        )
        dialect = load_dialect("ebcdic-test", tmp_path)
        msg = Message(mti="0100", fields={41: "TERM0001"})
        wire = pack(dialect, msg)
        assert b"TERM0001" not in wire, "EBCDIC output must not read as ASCII"
        assert "TERM0001".encode("cp500") in wire
        back, _ = unpack(dialect, wire)
        assert back.fields[41] == "TERM0001"

    def test_hex_bitmap(self, tmp_path):
        src = tmp_path / "hexbmp.yaml"
        src.write_text(
            "name: hexbmp\n"
            "bitmap: {encoding: hex}\n"
            "fields:\n"
            "  3: {name: Processing Code, type: n, length: 6}\n"
        )
        dialect = load_dialect("hexbmp", tmp_path)
        wire = pack(dialect, Message(mti="0100", fields={3: "000000"}))
        assert b"2000000000000000" in wire, "bitmap should be 16 hex characters"
        back, _ = unpack(dialect, wire)
        assert back.fields[3] == "000000"

    def test_bcd_mti(self, tmp_path):
        src = tmp_path / "bcdmti.yaml"
        src.write_text(
            "name: bcdmti\n"
            "mti: {encoding: bcd}\n"
            "fields:\n"
            "  3: {name: Processing Code, type: n, length: 6}\n"
        )
        dialect = load_dialect("bcdmti", tmp_path)
        wire = pack(dialect, Message(mti="0200", fields={3: "000000"}))
        assert wire[2:4] == b"\x02\x00"
        back, _ = unpack(dialect, wire)
        assert back.mti == "0200"


class TestVariableLength:
    def test_odd_pan_pads_right_with_f(self, iso):
        """A 19-digit PAN is left-justified; the pad nibble goes on the end."""
        pan = "4" * 19
        wire = pack(iso, Message(mti="0100", fields={2: pan}))
        assert bytes.fromhex("4" * 19 + "F") in wire
        back, _ = unpack(iso, wire)
        assert back.fields[2] == pan

    def test_binary_field_length_counts_bytes_not_digits(self, iso):
        """DE55 is binary: the LLLVAR prefix is a byte count."""
        icc = bytes.fromhex("9F02060000000010009F360200FF")
        wire = pack(iso, Message(mti="0100", fields={55: icc}))
        back, _ = unpack(iso, wire)
        assert back.fields[55] == icc
        assert len(icc) == 14
        assert bytes.fromhex("0014") in wire, "BCD length prefix should read 014"

    def test_exceeding_the_dialect_maximum_is_refused(self, iso):
        with pytest.raises(CodecError, match="exceeds the dialect maximum"):
            pack(iso, Message(mti="0100", fields={2: "9" * 25}))


class TestDegradation:
    """Pointed at a near-miss dialect, decode as far as possible and say why."""

    def test_unknown_field_stops_parsing_but_keeps_what_was_read(self, tmp_path):
        src = tmp_path / "partial.yaml"
        src.write_text(
            "name: partial\n"
            "fields:\n"
            "  3: {name: Processing Code, type: n, length: 6}\n"
        )
        partial = load_dialect("partial", tmp_path)
        # Bitmap claims fields 3 and 4, but the dialect only defines 3.
        msg = unpack_body(partial, bytes.fromhex("30313030") +
                          build_bitmap([3, 4]) + bytes.fromhex("000000" "000000001000"))
        assert msg.fields == {3: "000000"}
        assert any("field 4" in p for p in msg.problems)
        assert not msg.complete

    def test_truncated_field_is_reported_not_raised(self, iso):
        body = bytes.fromhex("30313030") + build_bitmap([4]) + bytes.fromhex("0000")
        msg = unpack_body(iso, body)
        assert msg.problems and "only 2 left" in msg.problems[0]

    def test_garbage_mti_is_reported_not_raised(self, iso):
        msg = unpack_body(iso, b"\xff\xff\xff\xff" + build_bitmap([3]))
        assert msg.problems and "not four digits" in msg.problems[0]

    def test_trailing_bytes_are_surfaced(self, iso):
        msg = unpack_body(iso, REFERENCE_WIRE[2:] + b"\xAA\xBB")
        assert msg.trailing == b"\xAA\xBB"
        assert not msg.complete


class TestPackValidation:
    def test_mti_must_be_four_digits(self, iso):
        for bad in ("010", "01000", "0A00", ""):
            with pytest.raises(CodecError, match="MTI"):
                pack_body(iso, Message(mti=bad, fields={3: "000000"}))

    def test_undefined_field_is_refused(self, iso):
        with pytest.raises(CodecError, match="no definition for field"):
            pack_body(iso, Message(mti="0100", fields={99: "x"}))

    def test_binary_field_rejects_non_hex_text(self, iso):
        with pytest.raises(CodecError, match="not hex"):
            pack_body(iso, Message(mti="0100", fields={55: "not hex"}))
