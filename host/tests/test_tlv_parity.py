"""
Drift guard for the vendored TLV core.

``host/iso8583/tlv.py`` is a deliberate duplicate of ATRIUM's TLV code, kept so
the host tool needs no pyscard install. Duplication is only safe while the two
copies agree, and DE55 correctness depends on the same parser being right on
both sides — so this compares them over a corpus and fails on any divergence.

When both collapse into a shared ``paycore.tlv``, this file goes away with them.

Skipped rather than failed when ATRIUM's modules cannot be imported: the host
tool is meant to run on machines with no card stack, and that must not look
like a regression.
"""
from __future__ import annotations

import pytest

from host.iso8583.tlv import parse_tlv as host_parse
from host.iso8583.tlv import serialize_tlv as host_serialize

emv_logger = pytest.importorskip("emv_logger", reason="ATRIUM card stack not importable")
mutation_engine = pytest.importorskip("mutation_engine", reason="ATRIUM card stack not importable")

CORPUS = [
    # A realistic DE55 payload.
    "9F02060000000010005F2A0208409F360200FF9F270180",
    # Constructed template with nested children (FCI).
    "6F1A840E315041592E5359532E4444463031A5088801025F2D02656E",
    # Multi-byte tag and a length in the 0x81 form.
    "9F4F81050102030405",
    # Response template around a cryptogram.
    "770F9F2701809F360200019F2608AABBCCDDEEFF0011",
    # Padding bytes that both parsers must skip identically.
    "00009F1A020840FFFF",
    # Truncated tail — the interesting case, since both must stop in the same place.
    "9F0206000000001000" "9F3602",
    # Empty and single-byte inputs.
    "",
    "9F",
]


def _shape(nodes):
    """Compare structure only — the vendored copy omits the display name table."""
    return [
        (n.tag, n.length, n.value.hex().upper(), n.constructed, _shape(n.children))
        for n in nodes
    ]


@pytest.mark.parametrize("hex_data", CORPUS)
def test_parsers_agree(hex_data):
    data = bytes.fromhex(hex_data)
    assert _shape(host_parse(data)) == _shape(emv_logger.parse_tlv(data))


@pytest.mark.parametrize("hex_data", CORPUS)
def test_serialisers_agree(hex_data):
    data = bytes.fromhex(hex_data)
    host_nodes = host_parse(data)
    atrium_nodes = emv_logger.parse_tlv(data)
    assert host_serialize(host_nodes) == mutation_engine.serialize_tlv(atrium_nodes)


@pytest.mark.parametrize("hex_data", CORPUS)
def test_round_trip_is_stable(hex_data):
    """Re-serialising a parse must not change what a re-parse sees."""
    data = bytes.fromhex(hex_data)
    once = host_serialize(host_parse(data))
    twice = host_serialize(host_parse(once))
    assert once == twice
