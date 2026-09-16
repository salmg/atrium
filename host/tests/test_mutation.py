"""
Mutation engine — modes, gating, playbooks, and the safety rules.

The safety rules get more attention than the features, because this is the
component that can break a live link. Rewriting a message means re-encoding it
from the decoded form, so a codec bug stops being a bad capture and becomes a
bad transaction.
"""
from __future__ import annotations

import pytest

from host.iso8583 import Message, load_dialect, pack_body
from host.iso8583 import de55 as de55_mod
from host.mutation import (
    MUTATION_MODES,
    De55Mutation,
    FieldMutation,
    MutationError,
    Playbook,
    apply_playbook,
    available_playbooks,
    compute_bytes,
    compute_text,
    load_playbook,
    mutate_wire,
)

ICC = bytes.fromhex(
    "9F0206000000001000"    # amount 10.00
    "5F2A020840"            # currency 840
    "9F360200FF"            # ATC 255
    "9F2608AABBCCDDEEFF0011"  # cryptogram
)

A2I = "acquirer->issuer"
I2A = "issuer->acquirer"


@pytest.fixture
def iso():
    return load_dialect("iso8583-1987")


@pytest.fixture
def msg():
    return Message(mti="0100", fields={
        2: "4111111111111111", 4: "000000001000", 11: "000123",
        22: "051", 49: "840", 55: ICC,
    })


# ── Modes ─────────────────────────────────────────────────────────────────────

class TestComputeBytes:
    def test_replace(self):
        assert compute_bytes("replace", b"\x01\x02", b"\xAA") == b"\xAA"

    def test_delete_returns_none(self):
        assert compute_bytes("delete", b"\x01", b"") is None

    def test_prepend_and_append(self):
        assert compute_bytes("prepend", b"\x02", b"\x01") == b"\x01\x02"
        assert compute_bytes("append", b"\x01", b"\x02") == b"\x01\x02"

    def test_xor_pads_short_values_with_zero(self):
        assert compute_bytes("xor", b"\xFF\xFF", b"\x0F") == b"\xF0\xFF"

    def test_xor_truncates_long_values_to_the_original_length(self):
        """The field keeps its size; a longer mask must not extend it."""
        assert compute_bytes("xor", b"\xFF", b"\x0F\x0F") == b"\xF0"

    def test_flip_bit_is_msb_zero_based(self):
        assert compute_bytes("flip_bit", b"\x00", b"", 0) == b"\x80"
        assert compute_bytes("flip_bit", b"\x00", b"", 7) == b"\x01"
        assert compute_bytes("flip_bit", b"\x00\x00", b"", 8) == b"\x00\x80"

    def test_flip_bit_past_the_end_is_refused(self):
        with pytest.raises(MutationError, match="past the end"):
            compute_bytes("flip_bit", b"\x00", b"", 64)

    def test_unknown_mode(self):
        with pytest.raises(MutationError, match="Unknown mutation mode"):
            compute_bytes("scramble", b"\x00", b"")


class TestComputeText:
    def test_basic_modes(self):
        assert compute_text("replace", "abc", "xyz") == "xyz"
        assert compute_text("delete", "abc", "") is None
        assert compute_text("prepend", "bc", "a") == "abc"
        assert compute_text("append", "ab", "c") == "abc"

    @pytest.mark.parametrize("mode", ["xor", "flip_bit"])
    def test_binary_modes_are_refused_on_text(self, mode):
        """There is no honest answer to 'which bytes' for a BCD-packed field."""
        with pytest.raises(MutationError, match="needs a binary field"):
            compute_text(mode, "000000001000", "01")

    def test_mode_vocabulary_matches_the_card_side(self):
        assert MUTATION_MODES == {"replace", "delete", "xor", "flip_bit",
                                  "prepend", "append"}


# ── Spec validation ───────────────────────────────────────────────────────────

class TestSpecValidation:
    def test_unknown_mode_is_refused(self):
        with pytest.raises(MutationError, match="Unknown mutation mode"):
            FieldMutation(de=4, mode="obliterate")

    def test_unknown_direction_is_refused(self):
        with pytest.raises(MutationError, match="Unknown direction"):
            FieldMutation(de=4, mode="replace", value="1", direction="sideways")

    def test_value_requiring_modes_need_one(self):
        for mode in ("replace", "prepend", "append", "xor"):
            with pytest.raises(MutationError, match="needs a 'value'"):
                FieldMutation(de=4, mode=mode)

    def test_delete_and_flip_bit_need_no_value(self):
        FieldMutation(de=4, mode="delete")
        FieldMutation(de=4, mode="flip_bit", bit_position=3)

    def test_field_number_range(self):
        with pytest.raises(MutationError, match="out of range"):
            FieldMutation(de=999, mode="delete")

    def test_de55_tag_must_be_hex(self):
        with pytest.raises(MutationError, match="not hex"):
            De55Mutation(tag="ZZ", mode="delete")

    def test_de55_tag_is_required_and_normalised(self):
        with pytest.raises(MutationError, match="needs a 'tag'"):
            De55Mutation(tag="", mode="delete")
        assert De55Mutation(tag="9f36", mode="delete").tag == "9F36"


class TestGating:
    def test_direction_gate(self):
        rule = FieldMutation(de=4, mode="replace", value="1", direction=A2I)
        assert rule.applies_to("0100", A2I)
        assert not rule.applies_to("0100", I2A)

    def test_both_matches_either_direction(self):
        rule = FieldMutation(de=4, mode="replace", value="1", direction="both")
        assert rule.applies_to("0100", A2I) and rule.applies_to("0100", I2A)

    def test_mti_gate(self):
        rule = FieldMutation(de=4, mode="replace", value="1", on_mti=("0100", "0200"))
        assert rule.applies_to("0100", A2I)
        assert not rule.applies_to("0400", A2I)

    def test_empty_mti_list_matches_everything(self):
        rule = FieldMutation(de=4, mode="replace", value="1")
        assert rule.applies_to("0800", A2I)

    def test_disabled_rule_never_applies(self):
        rule = FieldMutation(de=4, mode="replace", value="1", enabled=False)
        assert not rule.applies_to("0100", A2I)


# ── Applying ──────────────────────────────────────────────────────────────────

class TestFieldMutations:
    def test_replace_a_data_element(self, iso, msg):
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=4, mode="replace", value="000000009999"),))
        out, records = apply_playbook(pb, iso, msg, A2I)
        assert out.fields[4] == "000000009999"
        assert len(records) == 1
        assert records[0].before == "000000001000"
        assert records[0].after == "000000009999"

    def test_original_message_is_untouched(self, iso, msg):
        """Mutation works on a copy — the capture must still show what arrived."""
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=4, mode="replace", value="000000009999"),))
        apply_playbook(pb, iso, msg, A2I)
        assert msg.fields[4] == "000000001000"

    def test_delete_clears_the_bitmap_bit(self, iso, msg):
        pb = Playbook(name="t", field_mutations=(FieldMutation(de=22, mode="delete"),))
        out, _ = apply_playbook(pb, iso, msg, A2I)
        assert 22 not in out.fields
        # And the re-encoded message really does not carry it.
        from host.iso8583.codec import unpack_body
        assert 22 not in unpack_body(iso, pack_body(iso, out)).fields

    def test_replace_can_add_an_absent_field(self, iso, msg):
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=39, mode="replace", value="00"),))
        out, records = apply_playbook(pb, iso, msg, A2I)
        assert out.fields[39] == "00"
        assert records[0].before == ""

    def test_other_modes_refuse_an_absent_field(self, iso, msg):
        pb = Playbook(name="t", field_mutations=(FieldMutation(de=39, mode="delete"),))
        with pytest.raises(MutationError, match="nothing to act on"):
            apply_playbook(pb, iso, msg, A2I)

    def test_field_the_dialect_does_not_define(self, iso, msg):
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=99, mode="replace", value="x"),))
        with pytest.raises(MutationError, match="no definition for DE99"):
            apply_playbook(pb, iso, msg, A2I)

    def test_binary_field_takes_hex(self, iso, msg):
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=55, mode="replace", value="9F360200FF"),))
        out, _ = apply_playbook(pb, iso, msg, A2I)
        assert out.fields[55] == bytes.fromhex("9F360200FF")


class TestDe55Mutations:
    def test_replace_a_tag(self, iso, msg):
        pb = Playbook(name="t", de55_mutations=(
            De55Mutation(tag="9F36", mode="replace", value="0001"),))
        out, records = apply_playbook(pb, iso, msg, A2I)
        nodes = de55_mod.from_message(out)
        assert de55_mod.tag_value(nodes, "9F36") == "0001"
        assert records[0].before == "00FF"

    def test_other_tags_survive(self, iso, msg):
        pb = Playbook(name="t", de55_mutations=(
            De55Mutation(tag="9F36", mode="replace", value="0001"),))
        out, _ = apply_playbook(pb, iso, msg, A2I)
        nodes = de55_mod.from_message(out)
        assert de55_mod.tag_value(nodes, "9F02") == "000000001000"
        assert de55_mod.tag_value(nodes, "5F2A") == "0840"

    def test_flip_a_cryptogram_bit(self, iso, msg):
        pb = Playbook(name="t", de55_mutations=(
            De55Mutation(tag="9F26", mode="flip_bit", bit_position=0),))
        out, _ = apply_playbook(pb, iso, msg, A2I)
        assert de55_mod.tag_value(de55_mod.from_message(out), "9F26") == "2ABBCCDDEEFF0011"

    def test_delete_a_tag(self, iso, msg):
        pb = Playbook(name="t", de55_mutations=(De55Mutation(tag="9F36", mode="delete"),))
        out, _ = apply_playbook(pb, iso, msg, A2I)
        assert de55_mod.tag_value(de55_mod.from_message(out), "9F36") == ""

    def test_replace_can_add_a_missing_tag(self, iso, msg):
        pb = Playbook(name="t", de55_mutations=(
            De55Mutation(tag="9F34", mode="replace", value="010002"),))
        out, _ = apply_playbook(pb, iso, msg, A2I)
        assert de55_mod.tag_value(de55_mod.from_message(out), "9F34") == "010002"

    def test_message_without_de55_is_refused(self, iso):
        bare = Message(mti="0100", fields={4: "000000001000"})
        pb = Playbook(name="t", de55_mutations=(De55Mutation(tag="9F36", mode="delete"),))
        with pytest.raises(MutationError, match="no readable DE55"):
            apply_playbook(pb, iso, bare, A2I)

    def test_mutating_de55_creates_a_real_amount_mismatch(self, iso, msg):
        """The two halves compose: change 9F02, and cross_check notices."""
        pb = Playbook(name="t", de55_mutations=(
            De55Mutation(tag="9F02", mode="replace", value="000000000001"),))
        out, _ = apply_playbook(pb, iso, msg, A2I)
        assert [d.what for d in de55_mod.cross_check(out)] == ["amount mismatch"]


# ── mutate_wire safety rules ──────────────────────────────────────────────────

class TestSafetyRules:
    def test_no_matching_rule_means_forward_the_original(self, iso, msg):
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=4, mode="replace", value="1", on_mti=("0800",)),))
        raw, records, note = mutate_wire(pb, iso, msg, A2I, iso.framing)
        assert raw is None and records == [] and note == ""

    def test_dirty_decode_is_never_mutated(self, iso, msg):
        """Re-encoding would silently drop whatever the dialect did not read."""
        msg.problems.append("field 62: truncated length prefix")
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=4, mode="replace", value="000000009999"),))
        raw, records, note = mutate_wire(pb, iso, msg, A2I, iso.framing)
        assert raw is None
        assert records == []
        assert "did not decode cleanly" in note
        assert "truncated" in note

    def test_trailing_bytes_also_block_mutation(self, iso, msg):
        msg.trailing = b"\xAA\xBB"
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=4, mode="replace", value="000000009999"),))
        raw, _, note = mutate_wire(pb, iso, msg, A2I, iso.framing)
        assert raw is None and "did not decode cleanly" in note

    def test_inapplicable_rule_forwards_original_with_an_explanation(self, iso, msg):
        pb = Playbook(name="t", field_mutations=(FieldMutation(de=39, mode="delete"),))
        raw, records, note = mutate_wire(pb, iso, msg, A2I, iso.framing)
        assert raw is None and records == []
        assert "not mutated" in note and "nothing to act on" in note

    def test_successful_mutation_produces_framed_wire_bytes(self, iso, msg):
        from host.iso8583.codec import unpack
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=4, mode="replace", value="000000009999"),))
        raw, records, note = mutate_wire(pb, iso, msg, A2I, iso.framing)
        assert raw is not None and note == ""
        back, consumed = unpack(iso, raw)
        assert consumed == len(raw)
        assert back.fields[4] == "000000009999"
        assert back.fields[2] == "4111111111111111", "untouched fields survive"

    def test_tpdu_survives_a_rewrite(self, iso, msg):
        base24 = load_dialect("base24")
        msg.tpdu = bytes.fromhex("6000030000")
        pb = Playbook(name="t", field_mutations=(
            FieldMutation(de=4, mode="replace", value="000000009999"),))
        raw, _, _ = mutate_wire(pb, base24, msg, A2I, base24.framing)
        from host.iso8583.codec import unpack
        back, _ = unpack(base24, raw)
        assert back.tpdu == bytes.fromhex("6000030000")

    def test_inactive_playbook_changes_nothing(self, iso, msg):
        pb = Playbook(name="t", enabled=False, field_mutations=(
            FieldMutation(de=4, mode="replace", value="1"),))
        assert not pb.active
        raw, records, _ = mutate_wire(pb, iso, msg, A2I, iso.framing)
        assert raw is None and records == []


# ── Playbook loading ──────────────────────────────────────────────────────────

class TestPlaybookLoading:
    def test_all_shipped_playbooks_load_and_are_active(self):
        names = available_playbooks()
        assert {"amount-mismatch", "atc-replay", "cryptogram-tamper",
                "cvm-forgery", "entry-mode-downgrade", "response-tamper"} <= set(names)
        for name in names:
            pb = load_playbook(name)
            assert pb.active, name
            assert pb.description, f"{name} should say what it is for"

    def test_shipped_playbooks_declare_direction_and_mti(self):
        """An ungated rule would fire on network-management traffic too."""
        for name in available_playbooks():
            pb = load_playbook(name)
            for rule in (*pb.field_mutations, *pb.de55_mutations):
                assert rule.direction != "both", f"{name}/{rule.target}"
                assert rule.on_mti, f"{name}/{rule.target}"

    def test_response_tamper_runs_on_the_return_leg(self):
        pb = load_playbook("response-tamper")
        rule = pb.field_mutations[0]
        assert rule.direction == I2A
        assert rule.applies_to("0110", I2A)
        assert not rule.applies_to("0100", A2I)

    def test_missing_playbook_lists_what_exists(self):
        with pytest.raises(MutationError, match="Available:"):
            load_playbook("no-such-playbook")

    def test_empty_playbook_is_refused(self, tmp_path):
        (tmp_path / "empty.yaml").write_text("name: empty\n")
        with pytest.raises(MutationError, match="defines no mutations"):
            load_playbook("empty", tmp_path)

    def test_loads_from_an_explicit_path(self, tmp_path):
        p = tmp_path / "custom.yaml"
        p.write_text(
            "name: custom\n"
            "field_mutations:\n"
            "  - {de: 4, mode: replace, value: '000000000001', on_mti: ['0100'],\n"
            "     direction: acquirer->issuer}\n"
        )
        pb = load_playbook(str(p))
        assert pb.name == "custom" and len(pb.field_mutations) == 1

    def test_summary_lists_the_rules(self):
        text = load_playbook("atc-replay").summary()
        assert "2 active rule(s)" in text
        assert "DE55/9F36" in text and "DE55/9F13" in text
