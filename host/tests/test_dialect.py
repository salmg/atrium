"""Dialect loading, inheritance and validation."""
from __future__ import annotations

import pytest

from host.iso8583.dialect import (
    DialectError,
    FieldSpec,
    available_dialects,
    load_dialect,
)


class TestShippedDialects:
    def test_all_shipped_dialects_load(self):
        names = available_dialects()
        assert {"iso8583-1987", "postilion", "base24"} <= set(names)
        for name in names:
            load_dialect(name)          # must not raise

    def test_iso_base_defaults(self):
        iso = load_dialect("iso8583-1987")
        assert iso.numeric_encoding == "bcd"
        assert iso.mti_encoding == "ascii"
        assert iso.bitmap_encoding == "binary"
        assert iso.framing.mli_bytes == 2
        assert iso.framing.tpdu_length == 0

    def test_de55_is_wired_to_the_tlv_core(self):
        spec = load_dialect("iso8583-1987").field(55)
        assert spec.type == "b"
        assert spec.codec == "ber_tlv"
        assert spec.length == "lllvar"


class TestInheritance:
    def test_child_overrides_scalars_and_keeps_the_parent_field_table(self):
        postilion = load_dialect("postilion")
        iso = load_dialect("iso8583-1987")
        assert postilion.numeric_encoding == "ascii"        # overridden
        assert postilion.length_encoding == "ascii"         # overridden
        assert postilion.field(2).name == iso.field(2).name  # inherited
        assert postilion.field(55).codec == "ber_tlv"        # inherited

    def test_child_can_redefine_one_field_without_restating_the_rest(self):
        postilion = load_dialect("postilion")
        assert postilion.field(63).name == "Postilion Switch Data"
        assert len(postilion.fields) >= len(load_dialect("iso8583-1987").fields)

    def test_framing_merges_key_by_key(self):
        base24 = load_dialect("base24")
        assert base24.framing.tpdu_length == 5          # set by the child
        assert base24.framing.mli_encoding == "binary"  # from the parent

    def test_inheritance_loop_is_caught(self, tmp_path):
        (tmp_path / "a.yaml").write_text("name: a\nextends: b\nfields: {3: {name: x, type: n, length: 6}}\n")
        (tmp_path / "b.yaml").write_text("name: b\nextends: a\nfields: {3: {name: x, type: n, length: 6}}\n")
        with pytest.raises(DialectError, match="loops"):
            load_dialect("a", tmp_path)


class TestValidation:
    def test_missing_dialect_lists_what_is_available(self):
        with pytest.raises(DialectError, match="Available:"):
            load_dialect("no-such-switch")

    def test_unknown_field_type_is_refused(self, tmp_path):
        (tmp_path / "bad.yaml").write_text(
            "name: bad\nfields:\n  3: {name: x, type: quux, length: 6}\n")
        with pytest.raises(DialectError, match="unknown type"):
            load_dialect("bad", tmp_path)

    def test_variable_field_without_a_maximum_is_refused(self, tmp_path):
        (tmp_path / "bad.yaml").write_text(
            "name: bad\nfields:\n  2: {name: PAN, type: n, length: llvar}\n")
        with pytest.raises(DialectError, match="need a 'max'"):
            load_dialect("bad", tmp_path)

    def test_out_of_range_field_number_is_refused(self, tmp_path):
        (tmp_path / "bad.yaml").write_text(
            "name: bad\nfields:\n  999: {name: x, type: n, length: 6}\n")
        with pytest.raises(DialectError, match="out of range"):
            load_dialect("bad", tmp_path)

    def test_empty_field_table_is_refused(self, tmp_path):
        (tmp_path / "bare.yaml").write_text("name: bare\nfields: {}\n")
        with pytest.raises(DialectError, match="no fields"):
            load_dialect("bare", tmp_path)


class TestFieldSpec:
    def test_padding_convention_follows_justification(self):
        """Quantities pad left with zero; left-justified strings pad right with F."""
        fixed = FieldSpec(number=4, name="Amount", type="n", length=12)
        variable = FieldSpec(number=2, name="PAN", type="n", length="llvar", max=19)
        assert fixed.pad_mode == "left_zero"
        assert variable.pad_mode == "right_f"

    def test_explicit_padding_wins(self):
        spec = FieldSpec(number=2, name="PAN", type="n", length="llvar",
                         max=19, pad="left_zero")
        assert spec.pad_mode == "left_zero"

    def test_length_prefix_width(self):
        assert FieldSpec(2, "PAN", "n", "llvar", 19).length_digits == 2
        assert FieldSpec(55, "ICC", "b", "lllvar", 999).length_digits == 3
        assert FieldSpec(4, "Amount", "n", 12).length_digits == 0
