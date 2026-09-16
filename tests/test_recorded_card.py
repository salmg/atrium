"""
Replaying a capture as a card, and choosing what emulation relays to.

Card emulation needed a real card on the other side, which is a hard
requirement when the point is just to see what a terminal asks. These cover the
file formats a capture arrives in, the matching rules that serve it back, and
the reader arithmetic — chiefly the mistake that looks like a hardware fault:
relaying to the very reader that is presenting the emulated card.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.readers import VIRTUAL, Reader
from transport.recorded import (
    RecordedCardError,
    RecordedCardTransport,
    load_pairs,
)
from transport.source import CardSourceError, open_card_source


SELECT = bytes.fromhex("00A4040007A0000000031010")
SELECT_RESP = bytes.fromhex("6F1A840EA0000000031010A5089000")
GPO = bytes.fromhex("80A80000238321")
GPO_RESP = bytes.fromhex("77129F2701809F3602001A9000")


def _card(tmp_path, text, name="capture.txt", **kw) -> RecordedCardTransport:
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    card = RecordedCardTransport(path, **kw)
    card.connect()
    return card


# ── formats ──────────────────────────────────────────────────────────────────

class TestFormats:
    def test_direction_marked_lines(self, tmp_path):
        card = _card(tmp_path, f"""
            # a hand-written capture
            > {SELECT.hex()}
            < {SELECT_RESP.hex()}
        """)
        assert card.transmit(SELECT) == SELECT_RESP

    def test_one_pair_per_line(self, tmp_path):
        card = _card(tmp_path, f"{SELECT.hex()}  {SELECT_RESP.hex()}\n")
        assert card.transmit(SELECT) == SELECT_RESP

    def test_spaced_hex_is_accepted(self, tmp_path):
        spaced = " ".join(SELECT.hex().upper()[i:i + 2] for i in range(0, len(SELECT.hex()), 2))
        card = _card(tmp_path, f"> {spaced}\n< 6F 1A 90 00\n")
        assert card.transmit(SELECT) == bytes.fromhex("6F1A9000")

    def test_atrium_hexlog(self, tmp_path):
        text = (f"1700000000000  C  [abc12345]  {SELECT.hex().upper()}\n"
                f"1700000000001  R  [abc12345]  {SELECT_RESP.hex().upper()}\n"
                "# session abc12345 ended  AID=A0000000031010\n")
        card = _card(tmp_path, text, name="apdu.hexlog")
        assert card.transmit(SELECT) == SELECT_RESP

    def test_session_json(self, tmp_path):
        doc = {"session_id": "abc", "apdus": [
            {"direction": "terminal→card", "raw_hex": SELECT.hex().upper()},
            {"direction": "card→terminal", "raw_hex": SELECT_RESP.hex().upper()},
        ]}
        card = _card(tmp_path, json.dumps(doc), name="session_abc.json")
        assert card.transmit(SELECT) == SELECT_RESP

    def test_jsonl_of_pairs(self, tmp_path):
        text = json.dumps({"cmd": SELECT.hex(), "resp": SELECT_RESP.hex()}) + "\n"
        card = _card(tmp_path, text, name="trace.jsonl")
        assert card.transmit(SELECT) == SELECT_RESP

    def test_the_format_is_sniffed_when_the_suffix_lies(self, tmp_path):
        doc = {"apdus": [
            {"direction": "terminal→card", "raw_hex": SELECT.hex()},
            {"direction": "card→terminal", "raw_hex": SELECT_RESP.hex()},
        ]}
        card = _card(tmp_path, json.dumps(doc), name="renamed.capture")
        assert card.transmit(SELECT) == SELECT_RESP

    def test_a_command_with_no_response_is_dropped_not_mispaired(self, tmp_path):
        """
        Pairing a command with the *next command's* response would attribute one
        card's answer to a different question, which is worse than losing it.
        """
        text = (f"1  C  [x]  {SELECT.hex()}\n"
                f"2  C  [x]  {GPO.hex()}\n"
                f"3  R  [x]  {GPO_RESP.hex()}\n")
        pairs, _ = load_pairs(_write(tmp_path, text, "a.hexlog"))
        assert pairs == [(GPO, GPO_RESP)]

    def test_an_empty_capture_says_what_it_wanted(self, tmp_path):
        with pytest.raises(RecordedCardError, match="hexlog"):
            load_pairs(_write(tmp_path, "# nothing here\n", "empty.txt"))

    def test_a_missing_file_is_a_clear_error(self, tmp_path):
        with pytest.raises(RecordedCardError, match="Could not read"):
            load_pairs(tmp_path / "absent.hexlog")

    def test_non_hex_is_named_rather_than_swallowed(self, tmp_path):
        with pytest.raises(RecordedCardError, match="not hex"):
            load_pairs(_write(tmp_path, "> zzzz\n< 9000\n", "bad.txt"))


def _write(tmp_path, text, name):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


# ── matching ─────────────────────────────────────────────────────────────────

class TestMatching:
    def test_repeats_are_served_in_recorded_order(self, tmp_path):
        """
        READ RECORD walks a file and counters move, so the same command asked
        twice usually has two different answers. Collapsing them to the first
        would replay a card that does not exist.
        """
        read = bytes.fromhex("00B2010C00")
        card = _card(tmp_path, f"> {read.hex()}\n< 70019000\n"
                               f"> {read.hex()}\n< 70029000\n")
        assert card.transmit(read) == bytes.fromhex("70019000")
        assert card.transmit(read) == bytes.fromhex("70029000")

    def test_a_different_pdol_still_gets_the_recorded_gpo(self, tmp_path):
        """
        The point of the loose match: a terminal picks its own unpredictable
        number, so a GPO will never be byte-identical to the recorded one. The
        response is stale by construction — that is a documented limit, not a
        bug — but the flow keeps moving.
        """
        card = _card(tmp_path, f"> {GPO.hex()}\n< {GPO_RESP.hex()}\n")
        different = bytes.fromhex("80A80000238399")
        assert card.transmit(different) == GPO_RESP

    def test_strict_mode_refuses_to_guess(self, tmp_path):
        card = _card(tmp_path, f"> {GPO.hex()}\n< {GPO_RESP.hex()}\n", strict=True)
        assert card.transmit(bytes.fromhex("80A80000238399")) == bytes.fromhex("6D00")

    def test_an_unknown_command_gets_6d00_rather_than_silence(self, tmp_path):
        card = _card(tmp_path, f"> {SELECT.hex()}\n< {SELECT_RESP.hex()}\n")
        assert card.transmit(bytes.fromhex("00840000 08".replace(" ", ""))) == bytes.fromhex("6D00")
        assert card.misses, "a miss is recorded so the operator can see the gaps"

    def test_exact_match_wins_over_a_header_match(self, tmp_path):
        other = bytes.fromhex("00A4040007A0000000041010")
        card = _card(tmp_path, f"> {other.hex()}\n< 6F0190009000\n"
                               f"> {SELECT.hex()}\n< {SELECT_RESP.hex()}\n")
        assert card.transmit(SELECT) == SELECT_RESP

    def test_the_atr_comes_from_the_capture_when_it_has_one(self, tmp_path):
        doc = {"atr": "3B6500", "apdus": [
            {"direction": "terminal→card", "raw_hex": SELECT.hex()},
            {"direction": "card→terminal", "raw_hex": SELECT_RESP.hex()},
        ]}
        card = _card(tmp_path, json.dumps(doc), name="s.json")
        assert card.get_atr() == bytes.fromhex("3B6500")


# ── choosing the card source ─────────────────────────────────────────────────

EMULATOR = "ACS ACR122U PICC Interface 00 00"
SECOND = "ACS ACR122U PICC Interface 01 00"


def _probe(monkeypatch, *names):
    from core.readers import classify
    readers = [Reader(index=i, name=n, kind=classify(n)) for i, n in enumerate(names)]
    monkeypatch.setattr("core.readers.probe", lambda: (readers, ""))
    return readers


class TestCardSource:
    def test_a_file_beats_every_reader_question(self, tmp_path):
        path = _write(tmp_path, f"> {SELECT.hex()}\n< {SELECT_RESP.hex()}\n", "c.txt")
        card, described = open_card_source(from_file=str(path))
        assert isinstance(card, RecordedCardTransport)
        assert "recorded capture" in described

    def test_a_second_acr122_is_used_over_its_rf_field(self, monkeypatch):
        _probe(monkeypatch, EMULATOR, SECOND)
        card, described = open_card_source(exclude_reader=EMULATOR)
        from transport.contactless import ContactlessTransport
        assert isinstance(card, ContactlessTransport)
        assert card.reader_name == SECOND
        assert "contactless" in described

    def test_the_emulating_reader_is_never_chosen_by_itself(self, monkeypatch):
        """
        One ACR122U cannot be a target and an initiator at once, and the failure
        from trying is a timeout rather than a message.
        """
        _probe(monkeypatch, EMULATOR)
        with pytest.raises(CardSourceError, match="second"):
            open_card_source(exclude_reader=EMULATOR)

    def test_naming_the_emulating_reader_is_an_error_not_a_substitution(self, monkeypatch):
        readers = _probe(monkeypatch, EMULATOR, SECOND)
        monkeypatch.setattr("core.readers.resolve", lambda spec: readers[0])
        with pytest.raises(CardSourceError, match="presenting the emulated card"):
            open_card_source(reader=EMULATOR, exclude_reader=EMULATOR)

    def test_a_contact_reader_is_preferred_over_a_contactless_one(self, monkeypatch):
        _probe(monkeypatch, EMULATOR, SECOND, "Generic ICC Reader 00 00")
        card, described = open_card_source(exclude_reader=EMULATOR)
        from transport.local import LocalCardTransport
        assert isinstance(card, LocalCardTransport)
        assert "Generic ICC Reader" in described

    def test_the_virtual_reader_is_not_a_card_source(self, monkeypatch):
        _probe(monkeypatch, EMULATOR, "Virtual PCD 00 00")
        with pytest.raises(CardSourceError, match="second"):
            open_card_source(exclude_reader=EMULATOR)

    def test_naming_the_virtual_reader_says_what_it_is(self, monkeypatch):
        virtual = Reader(index=0, name="Virtual PCD 00 00", kind=VIRTUAL)
        monkeypatch.setattr("core.readers.resolve", lambda spec: virtual)
        with pytest.raises(CardSourceError, match="virtual"):
            open_card_source(reader=0, exclude_reader=EMULATOR)
