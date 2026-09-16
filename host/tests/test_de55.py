"""
DE55 bridge tests, including the cross-layer consistency check.

The amount appears twice in an authorisation — once as DE4, which the switch
routes and authorises on, and once as tag 9F02 inside DE55, which the
cryptogram covers. Detecting disagreement between the two is the headline
reason this layer exists.
"""
from __future__ import annotations

import pytest

from host.iso8583 import Message, load_dialect, pack, unpack
from host.iso8583 import de55
from host.iso8583.tlv import find_tag

ICC = bytes.fromhex(
    "9F0206000000001000"    # 9F02 Amount Authorised — 10.00
    "5F2A020840"            # 5F2A Transaction Currency — 840 (USD)
    "9F360200FF"            # 9F36 ATC — 255
    "9F270180"              # 9F27 CID — ARQC
)


@pytest.fixture
def iso():
    return load_dialect("iso8583-1987")


class TestBridge:
    def test_parses_hex_and_bytes_alike(self):
        assert de55.parse(ICC) == de55.parse(ICC.hex())

    def test_round_trips_through_the_tlv_core(self):
        nodes = de55.parse(ICC)
        assert de55.serialize(nodes) == ICC

    def test_reads_tags_out_of_a_decoded_message(self, iso):
        wire = pack(iso, Message(mti="0100", fields={4: "000000001000", 55: ICC}))
        msg, _ = unpack(iso, wire)
        nodes = de55.from_message(msg)
        assert de55.tag_value(nodes, de55.TAG_AMOUNT_AUTHORISED) == "000000001000"
        assert de55.tag_value(nodes, de55.TAG_ATC) == "00FF"

    def test_absent_de55_is_empty_not_an_error(self, iso):
        msg, _ = unpack(iso, pack(iso, Message(mti="0100", fields={4: "000000001000"})))
        assert de55.from_message(msg) == []
        assert de55.cross_check(msg) == []

    def test_missing_tag_reads_as_empty(self):
        assert de55.tag_value(de55.parse(ICC), "9F99") == ""


class TestSetTag:
    def test_replaces_a_value_and_recomputes_length(self):
        nodes = de55.parse(ICC)
        assert de55.set_tag(nodes, de55.TAG_ATC, "0001")
        node = find_tag(nodes, de55.TAG_ATC)
        assert node.value == bytes.fromhex("0001")
        assert node.length == 2
        # Re-serialises cleanly and reads back through a fresh parse.
        assert de55.tag_value(de55.parse(de55.serialize(nodes)), de55.TAG_ATC) == "0001"

    def test_length_follows_a_size_change(self):
        nodes = de55.parse(ICC)
        de55.set_tag(nodes, de55.TAG_ATC, "01020304")
        reparsed = de55.parse(de55.serialize(nodes))
        assert de55.tag_value(reparsed, de55.TAG_ATC) == "01020304"

    def test_absent_tag_reports_failure(self):
        assert de55.set_tag(de55.parse(ICC), "9F99", "00") is False


class TestCrossCheck:
    def test_consistent_message_reports_nothing(self, iso):
        msg = Message(mti="0100", fields={4: "000000001000", 49: "840", 55: ICC})
        assert de55.cross_check(msg) == []

    def test_amount_mismatch_is_found(self, iso):
        """DE4 says 20.00, the cryptogram covers 10.00."""
        msg = Message(mti="0100", fields={4: "000000002000", 49: "840", 55: ICC})
        found = de55.cross_check(msg)
        assert len(found) == 1
        assert found[0].what == "amount mismatch"
        assert found[0].de_value == "000000002000"
        assert found[0].tag_value == "000000001000"
        assert "DE4" in str(found[0])

    def test_currency_mismatch_is_found(self, iso):
        msg = Message(mti="0100", fields={4: "000000001000", 49: "978", 55: ICC})
        found = de55.cross_check(msg)
        assert [d.what for d in found] == ["currency mismatch"]

    def test_leading_zeros_do_not_count_as_a_mismatch(self, iso):
        """DE49 is three digits, 5F2A is two bytes — same value, different width."""
        msg = Message(mti="0100", fields={4: "1000", 49: "840", 55: ICC})
        assert de55.cross_check(msg) == []

    def test_both_mismatches_reported_together(self, iso):
        msg = Message(mti="0100", fields={4: "000000009999", 49: "978", 55: ICC})
        assert {d.what for d in de55.cross_check(msg)} == {
            "amount mismatch", "currency mismatch"}

    def test_survives_a_full_wire_round_trip(self, iso):
        """The check must work on a message decoded off the wire, not just built."""
        wire = pack(iso, Message(mti="0100",
                                 fields={4: "000000002000", 49: "840", 55: ICC}))
        msg, _ = unpack(iso, wire)
        assert [d.what for d in de55.cross_check(msg)] == ["amount mismatch"]


class TestSummary:
    def test_reports_the_authorisation_relevant_tags(self):
        got = de55.summary(de55.parse(ICC))
        assert got[de55.TAG_ATC] == "00FF"
        assert got[de55.TAG_CID] == "80"
        assert de55.TAG_CRYPTOGRAM not in got, "absent tags are omitted"
