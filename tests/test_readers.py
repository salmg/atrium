"""
Reader discovery, classification and auto-selection.

The bug these exist for: with vpcd running, the virtual reader usually takes
index 0 — and the virtual reader is ATRIUM's own output side, the thing
presenting a card to the terminal, not a slot a card sits in. Defaulting to it
is always wrong on a working setup, and the failure looks like a card fault
rather than a wiring mistake.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.readers import (
    CONTACT,
    CONTACTLESS,
    UNKNOWN,
    VIRTUAL,
    Reader,
    ReaderError,
    classify,
    describe,
    pick_default,
    probe,
    resolve,
)


def _readers(*names) -> list[Reader]:
    return [Reader(index=i, name=n, kind=classify(n)) for i, n in enumerate(names)]


class TestClassification:
    @pytest.mark.parametrize("name,expected", [
        ("Virtual PCD 00 00", VIRTUAL),
        ("Virtual PCD 01 00", VIRTUAL),
        ("vpcd 00 00", VIRTUAL),
        ("Gemalto PC Twin Reader 00 00", CONTACT),
        ("OMNIKEY 3x21 00 00", CONTACT),
        ("ACS ACR122U PICC Interface 00", CONTACTLESS),
        ("Identiv SCL3711 00 00", CONTACTLESS),
        ("HID Global OMNIKEY 5422 Contactless 01", CONTACTLESS),
        ("", UNKNOWN),
        ("   ", UNKNOWN),
    ])
    def test_names_map_to_the_right_kind(self, name, expected):
        assert classify(name) == expected

    def test_dual_interface_slots_are_told_apart(self):
        """
        Both slots carry the same model name; only the interface marker
        distinguishes them. The marker has to outrank the model, or the contact
        half of a contactless-famous reader is misfiled.
        """
        assert classify("ACS ACR1281U-C1 ICC Reader 00") == CONTACT
        assert classify("ACS ACR1281U-C1 PICC Reader 01") == CONTACTLESS

    def test_picc_contains_icc_and_must_not_match_it(self):
        assert classify("Some PICC Reader") == CONTACTLESS


class TestPickDefault:
    def test_prefers_a_contact_reader_over_the_virtual_one(self):
        """The situation that motivated this: vpcd at 0, the real reader at 2."""
        readers = _readers("Virtual PCD 00 00", "ACS ACR122U PICC Interface 00",
                           "Gemalto PC Twin Reader 00 00")
        chosen = pick_default(readers)
        assert chosen.index == 2
        assert chosen.kind == CONTACT

    def test_falls_back_to_contactless_when_there_is_no_contact_slot(self):
        readers = _readers("Virtual PCD 00 00", "ACS ACR122U PICC Interface 00")
        assert pick_default(readers).index == 1

    def test_never_picks_virtual_when_anything_else_exists(self):
        for others in (["Gemalto PC Twin Reader 00 00"],
                       ["ACS ACR122U PICC Interface 00"],
                       [""]):
            readers = _readers("Virtual PCD 00 00", *others)
            assert not pick_default(readers).is_virtual

    def test_virtual_only_is_returned_rather_than_nothing(self):
        """Better to hand it back and let the caller warn than to return None."""
        readers = _readers("Virtual PCD 00 00")
        assert pick_default(readers).is_virtual

    def test_no_readers(self):
        assert pick_default([]) is None


class TestResolve:
    @pytest.fixture(autouse=True)
    def _fake_probe(self, monkeypatch):
        readers = _readers("Virtual PCD 00 00",
                           "ACS ACR122U PICC Interface 00",
                           "Gemalto PC Twin Reader 00 00")
        monkeypatch.setattr("core.readers.probe", lambda: (readers, ""))
        return readers

    def test_none_auto_selects(self):
        assert resolve(None).kind == CONTACT

    def test_index_still_works(self):
        """Stored settings and existing API calls keep meaning what they meant."""
        assert resolve(0).is_virtual
        assert resolve(2).name.startswith("Gemalto")

    def test_numeric_string_is_treated_as_an_index(self):
        assert resolve("2").name.startswith("Gemalto")

    def test_name_fragment_matches_case_insensitively(self):
        assert resolve("acr122").index == 1
        assert resolve("Gemalto").index == 2

    def test_exact_name_wins(self):
        assert resolve("ACS ACR122U PICC Interface 00").index == 1

    def test_out_of_range_index_lists_what_exists(self):
        with pytest.raises(ReaderError) as ei:
            resolve(9)
        assert "Gemalto" in str(ei.value) and "contact" in str(ei.value)

    def test_unmatched_name_lists_what_exists(self):
        with pytest.raises(ReaderError) as ei:
            resolve("nosuchreader")
        assert "Virtual PCD" in str(ei.value)

    def test_ambiguous_fragment_is_refused_rather_than_guessed(self):
        """"PC" is in both "Virtual PCD" and "Gemalto PC Twin"."""
        with pytest.raises(ReaderError, match="more than one") as ei:
            resolve("PC")
        assert "Virtual PCD" in str(ei.value), "the error should list the candidates"

    def test_a_fragment_matching_exactly_one_is_accepted(self):
        assert resolve("Twin").index == 2

    def test_an_all_digit_string_is_an_index_not_a_name(self):
        """
        Otherwise "00" would be ambiguous with every PC/SC slot number, and the
        index behaviour that stored settings rely on would quietly change.
        """
        assert resolve("0").is_virtual
        assert resolve("00").is_virtual


class TestProbeDegradesGracefully:
    def test_missing_pyscard_is_explained_not_raised(self, monkeypatch):
        """The host layer runs on machines with no card stack at all."""
        import builtins
        real_import = builtins.__import__

        def _fail(name, *a, **k):
            if name.startswith("smartcard"):
                raise ImportError("no pyscard")
            return real_import(name, *a, **k)

        monkeypatch.setattr(builtins, "__import__", _fail)
        readers, problem = probe()
        assert readers == []
        assert "pyscard" in problem

    def test_resolve_surfaces_the_reason(self, monkeypatch):
        monkeypatch.setattr("core.readers.probe", lambda: ([], "pcscd is not running"))
        with pytest.raises(ReaderError, match="pcscd is not running"):
            resolve(None)


class TestDescribe:
    def test_marks_the_default_and_warns_about_the_virtual_one(self):
        text = describe(_readers("Virtual PCD 00 00", "Gemalto PC Twin Reader 00 00"))
        assert "default" in text
        assert "not where a card goes" in text

    def test_flags_pn532_hardware(self):
        text = describe(_readers("ACS ACR122U PICC Interface 00"))
        assert "PN532" in text

    def test_empty_reports_the_problem(self):
        assert "not running" in describe([], "pcscd is not running")


class TestApi:
    def test_endpoint_shape(self, monkeypatch):
        from fastapi.testclient import TestClient
        monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
        readers = _readers("Virtual PCD 00 00", "Gemalto PC Twin Reader 00 00")
        monkeypatch.setattr("core.readers.probe", lambda: (readers, ""))

        from api.server import create_app
        body = TestClient(create_app()).get("/api/readers").json()
        assert body["ok"] is True
        assert body["default"] == 1, "must not default to the virtual reader"
        assert body["only_virtual"] is False
        assert body["readers"][0]["virtual"] is True
        assert body["readers"][0]["kind"] == VIRTUAL

    def test_reports_when_only_the_virtual_reader_is_present(self, monkeypatch):
        from fastapi.testclient import TestClient
        monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
        monkeypatch.setattr("core.readers.probe",
                            lambda: (_readers("Virtual PCD 00 00"), ""))
        from api.server import create_app
        assert TestClient(create_app()).get("/api/readers").json()["only_virtual"] is True
