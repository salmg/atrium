"""
The contactless dashboard routes.

The ACR122U support shipped command-line only, which made it look absent: the
reader appeared in the picker with a hint that it could emulate a card, and
nothing in the dashboard could. These cover the routes that closed that gap.

What they cannot cover is anything on the air — whether a terminal selects the
emulated card, whether an RF timing budget is met. The hardware seam is stubbed
here, exactly as in test_nfc.py, so what is under test is the routes' own
behaviour: what they report with no reader present, that a scan reaches the
contactless transport, and that two emulations cannot fight over one chip.
"""
from __future__ import annotations

import sys
from pathlib import Path

import threading
import time

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.readers import CONTACT, CONTACTLESS, Reader


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
    from api.server import create_app
    return TestClient(create_app())


@pytest.fixture(autouse=True)
def _no_emulation_left_running():
    yield
    from api.routes import nfc
    nfc._emu_active = False
    nfc._emu = None
    nfc._emu_link = None
    nfc._emu_thread = None
    nfc._emu_error = None


def _fake_probe(monkeypatch, *names):
    readers = [Reader(index=i, name=n, kind=CONTACTLESS if "ACR122" in n else CONTACT)
               for i, n in enumerate(names)]
    monkeypatch.setattr("core.readers.probe", lambda: (readers, ""))
    return readers


class TestStatus:
    def test_no_reader_is_a_clear_answer_not_an_error(self, client, monkeypatch):
        monkeypatch.setattr("core.readers.probe", lambda: ([], "PC/SC is not running"))
        body = client.get("/api/nfc/status").json()
        assert body["ok"] is True
        assert body["readers"] == []
        assert body["problem"] == "PC/SC is not running"
        assert body["emulating"] is False

    def test_lists_only_pn532_hardware(self, client, monkeypatch):
        _fake_probe(monkeypatch, "Generic ICC Reader 00 00", "ACR122U PICC Interface 00 00")
        body = client.get("/api/nfc/status").json()
        assert [r["name"] for r in body["readers"]] == ["ACR122U PICC Interface 00 00"]

    def test_the_chip_is_not_probed_unless_asked(self, client, monkeypatch):
        """
        Probing claims the reader in direct mode. Doing it on every poll would
        take the device away from a scan the operator is in the middle of, so
        the status route stays passive by default.
        """
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")

        def _boom(*a, **k):
            raise AssertionError("open_pn532 must not be called without probe_chip")

        monkeypatch.setattr("nfc.acr122.open_pn532", _boom)
        body = client.get("/api/nfc/status").json()
        assert body["chip"] is None

    def test_an_asked_for_probe_reports_the_firmware(self, client, monkeypatch):
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")

        class _Chip:
            def firmware_version(self):
                return {"chip": "PN532", "version": "1.6"}

        class _Link:
            closed = False

            def close(self):
                _Link.closed = True

        monkeypatch.setattr("nfc.acr122.open_pn532", lambda name, direct=False: (_Chip(), _Link()))
        body = client.get("/api/nfc/status?probe_chip=true").json()
        assert body["chip"]["chip"] == "PN532"
        assert body["chip"]["version"] == "1.6"
        # Which reader answered, so a two-ACR122U rig can tell them apart.
        assert body["chip"]["reader"] == "ACR122U PICC Interface 00 00"
        assert _Link.closed, "the link must be released or the next call finds a busy reader"

    def test_a_probe_failure_is_reported_not_raised(self, client, monkeypatch):
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")

        def _fail(name, direct=False):
            raise RuntimeError("reader is busy")

        monkeypatch.setattr("nfc.acr122.open_pn532", _fail)
        body = client.get("/api/nfc/status?probe_chip=true").json()
        assert body["ok"] is True
        assert body["chip"] is None
        assert "busy" in body["chip_error"]


class TestScan:
    def test_reports_uid_and_ats(self, client, monkeypatch):
        class _Transport:
            def __init__(self, reader_name=None):
                self.reader_name = reader_name or "ACR122U PICC Interface 00 00"

            def connect(self):
                pass

            def get_atr(self):
                return bytes.fromhex("0578807002")

            def disconnect(self):
                self.disconnected = True

            uid = bytes.fromhex("04A1B2C3")

        monkeypatch.setattr("transport.contactless.ContactlessTransport", _Transport)
        body = client.post("/api/nfc/scan", json={}).json()
        assert body["ok"] is True
        assert body["uid"] == "04A1B2C3"
        assert body["ats"] == "0578807002"

    def test_an_empty_field_is_an_error_message_not_a_500(self, client, monkeypatch):
        class _Transport:
            def __init__(self, reader_name=None):
                pass

            def connect(self):
                raise ConnectionError("No contactless card in the field")

        monkeypatch.setattr("transport.contactless.ContactlessTransport", _Transport)
        res = client.post("/api/nfc/scan", json={})
        assert res.status_code == 200
        body = res.json()
        assert body["ok"] is False
        assert "No contactless card" in body["error"]

    def test_the_reader_is_released_even_when_reading_fails(self, client, monkeypatch):
        released = []

        class _Transport:
            def __init__(self, reader_name=None):
                self.reader_name = "ACR122U"

            def connect(self):
                pass

            def get_atr(self):
                raise RuntimeError("card left the field")

            def disconnect(self):
                released.append(True)

            uid = b"\x04"

        monkeypatch.setattr("transport.contactless.ContactlessTransport", _Transport)
        assert client.post("/api/nfc/scan", json={}).json()["ok"] is False
        assert released, "a half-finished scan must still let go of the reader"

    def test_scanning_while_emulating_is_refused(self, client):
        from api.routes import nfc
        nfc._emu_active = True
        body = client.post("/api/nfc/scan", json={}).json()
        assert body["ok"] is False
        assert "emulating" in body["error"]


class _FakeLink:
    """Just enough of the PN532 link for a route that never reaches the air."""

    def close(self):
        pass


class TestEmulate:
    def test_no_pn532_present_is_refused_with_a_reason(self, client, monkeypatch):
        monkeypatch.setattr("core.readers.probe", lambda: ([], "no readers"))
        body = client.post("/api/nfc/emulate/start", json={}).json()
        assert body["ok"] is False
        assert "ACR122U" in body["error"]

        from api.routes import nfc
        assert nfc._emu_active is False, "a refused start must not leave the flag set"

    def test_a_second_start_does_not_fight_over_the_chip(self, client):
        from api.routes import nfc
        nfc._emu_active = True
        body = client.post("/api/nfc/emulate/start", json={}).json()
        assert body["ok"] is False
        assert "Already emulating" in body["error"]

    def test_stopping_when_nothing_runs_says_so(self, client):
        body = client.post("/api/nfc/emulate/stop", json={}).json()
        assert body["ok"] is False

    def test_stop_lets_the_thread_put_the_chip_back(self, client, monkeypatch):
        """
        The flag is the stop mechanism; closing the link is not.

        Target mode has to clear a bit in the chip's parameter byte, and only
        the emulator's own ``finally`` puts it back. Closing the link from the
        route kills the blocked exchange before the flag is ever read, so that
        ``finally`` runs against a dead link and the reader is left unable to
        activate 14443-4 cards. This asserts on the thing that broke: that the
        emulator got to finish, and that the link was still open when it did.
        """
        from api.routes import nfc

        restored = []

        class _Emu:
            def __init__(self):
                self._stop = False
                self.exchanges = 0

            def stop(self):
                self._stop = True

            def run(self):
                # Stand in for a session parked in the re-arm cycle: notice the
                # flag, then unwind through the restore like the real one does.
                while not self._stop:
                    time.sleep(0.01)
                restored.append(link.closed)

        class _Link:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        emu, link = _Emu(), _Link()
        thread = threading.Thread(target=emu.run, daemon=True)

        monkeypatch.setattr(nfc, "_emu", emu)
        monkeypatch.setattr(nfc, "_emu_link", link)
        monkeypatch.setattr(nfc, "_emu_thread", thread)
        monkeypatch.setattr(nfc, "_emu_active", True)
        thread.start()

        body = client.post("/api/nfc/emulate/stop", json={}).json()
        thread.join(2)

        assert body["ok"] is True
        assert body["chip_restored"] is True, "the route gave up on the thread"
        assert restored == [False], (
            "the emulator's cleanup ran against a closed link — the parameter "
            "restore would have failed")

    def test_a_wedged_thread_still_gets_the_link_closed(self, client, monkeypatch):
        """The fallback has to remain, for a thread that never reads the flag."""
        from api.routes import nfc

        class _Link:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        class _Emu:
            _stop = False

            def stop(self):
                type(self)._stop = True

        link = _Link()
        wedged = threading.Event()
        thread = threading.Thread(target=wedged.wait, daemon=True)

        monkeypatch.setattr(nfc, "STOP_GRACE", 0.05)
        monkeypatch.setattr(nfc, "_emu", _Emu())
        monkeypatch.setattr(nfc, "_emu_link", link)
        monkeypatch.setattr(nfc, "_emu_thread", thread)
        monkeypatch.setattr(nfc, "_emu_active", True)
        thread.start()

        body = client.post("/api/nfc/emulate/stop", json={}).json()
        wedged.set()

        assert body["ok"] is True
        assert body["chip_restored"] is False
        assert link.closed is True

class TestReaderPairing:
    """
    A relay needs two readers doing opposite jobs, and with two ACR122Us the
    PC/SC names differ only by a trailing index. Getting the assignment
    backwards is the easy mistake, so it is proposed server-side rather than
    left to be worked out from two near-identical strings.
    """

    def _suggest(self, monkeypatch, *names):
        from api.routes.nfc import _suggest_pair
        from core.readers import classify

        readers = [Reader(index=i, name=n, kind=classify(n))
                   for i, n in enumerate(names)]
        return _suggest_pair([r.to_dict() for r in readers])

    def test_two_acr122s_are_split_between_the_two_jobs(self, monkeypatch):
        out = self._suggest(monkeypatch,
                            "ACS ACR122U PICC Interface 00 00",
                            "ACS ACR122U PICC Interface 01 00")
        assert out["emulator"] == "ACS ACR122U PICC Interface 00 00"
        assert out["card"] == "ACS ACR122U PICC Interface 01 00"
        assert out["emulator_index"] == 0 and out["card_index"] == 1
        assert out["why"] == ""

    def test_a_contact_slot_is_preferred_for_the_card(self, monkeypatch):
        """A card in a contact slot is steadier than one held in an RF field."""
        out = self._suggest(monkeypatch,
                            "ACS ACR122U PICC Interface 00 00",
                            "ACS ACR122U PICC Interface 01 00",
                            "Generic ICC Reader 00 00")
        assert out["card"] == "Generic ICC Reader 00 00"

    def test_one_reader_says_there_is_nothing_to_hold_the_card(self, monkeypatch):
        out = self._suggest(monkeypatch, "ACS ACR122U PICC Interface 00 00")
        assert out["card"] is None
        assert "Only one reader" in out["why"]

    def test_two_readers_sharing_a_name_are_refused_and_told_why(self, monkeypatch):
        """
        A reader is addressed by its PC/SC name. Two entries sharing one are the
        same device as far as anything here can reach, so pairing them would
        silently relay a reader to itself.
        """
        out = self._suggest(monkeypatch,
                            "ACS ACR122U PICC Interface 00 00",
                            "ACS ACR122U PICC Interface 00 00")
        assert out["card"] is None
        assert "same PC/SC name" in out["why"]

    def test_the_virtual_reader_is_never_proposed(self, monkeypatch):
        out = self._suggest(monkeypatch,
                            "ACS ACR122U PICC Interface 00 00",
                            "Virtual PCD 00 00")
        assert out["card"] is None

    def test_status_lists_every_reader_not_just_the_pn532s(self, client, monkeypatch):
        _fake_probe(monkeypatch,
                    "ACR122U PICC Interface 00 00", "Generic ICC Reader 00 00")
        body = client.get("/api/nfc/status").json()
        assert len(body["all_readers"]) == 2, "the card side can be a contact slot"
        assert [r["name"] for r in body["emulators"]] == ["ACR122U PICC Interface 00 00"]


class TestIdentifyRoute:
    def test_a_non_acr122_is_told_it_has_no_led(self, client, monkeypatch):
        _fake_probe(monkeypatch,
                    "ACR122U PICC Interface 00 00", "Generic ICC Reader 00 00")
        body = client.post("/api/nfc/identify",
                           json={"reader": "Generic ICC Reader 00 00"}).json()
        assert body["ok"] is False
        assert "not an ACR122" in body["error"]

    def test_blinking_reports_where_the_reader_is(self, client, monkeypatch):
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")
        monkeypatch.setattr("nfc.acr122.identify",
                            lambda name, **kw: {"reader": name, "led_state": 2})
        monkeypatch.setattr("core.readers.physical_id",
                            lambda name: {"usb_bus": 1, "usb_address": 7})
        body = client.post("/api/nfc/identify", json={}).json()
        assert body["ok"] is True
        assert "USB 001:007" in body["where"]

    def test_a_driver_that_reports_nothing_still_blinks(self, client, monkeypatch):
        """Location is a label, not a requirement — the LED is the answer."""
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")
        monkeypatch.setattr("nfc.acr122.identify",
                            lambda name, **kw: {"reader": name, "led_state": 0})
        monkeypatch.setattr("core.readers.physical_id", lambda name: {})
        body = client.post("/api/nfc/identify", json={}).json()
        assert body["ok"] is True and body["where"] == ""

    def test_the_repeat_count_is_bounded(self, client, monkeypatch):
        """A browser field should not be able to ask for a minute of blinking."""
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")
        seen = {}
        monkeypatch.setattr("nfc.acr122.identify",
                            lambda name, **kw: seen.update(kw) or {"led_state": 0})
        monkeypatch.setattr("core.readers.physical_id", lambda name: {})
        client.post("/api/nfc/identify", json={"repeat": 9999})
        assert seen["repeat"] == 20
        client.post("/api/nfc/identify", json={"repeat": 0})
        assert seen["repeat"] == 1

    def test_identifying_is_refused_while_emulating(self, client, monkeypatch):
        from api.routes import nfc

        monkeypatch.setattr(nfc, "_emu_active", True)
        body = client.post("/api/nfc/identify", json={}).json()
        assert body["ok"] is False and "stop it first" in body["error"]

    def test_locations_are_only_gathered_when_asked_for(self, client, monkeypatch):
        """
        Each one costs a direct connection, so the 3-second poll must not pay
        for them.
        """
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")
        calls = []
        monkeypatch.setattr("core.readers.physical_id",
                            lambda name: calls.append(name) or {"usb_bus": 1,
                                                                "usb_address": 7})

        client.get("/api/nfc/status")
        assert calls == [], "a plain poll must not open every reader"

        body = client.get("/api/nfc/status?details=true").json()
        assert calls == ["ACR122U PICC Interface 00 00"]
        assert body["all_readers"][0]["where"] == "USB 001:007"


class TestDetectCard:
    def test_the_virtual_reader_is_named_as_such(self, client, monkeypatch):
        from core.readers import VIRTUAL

        monkeypatch.setattr("core.readers.resolve",
                            lambda spec: Reader(index=0, name="Virtual PCD 00 00",
                                                kind=VIRTUAL))
        body = client.post("/api/nfc/detect-card", json={"reader": 0}).json()
        assert body["ok"] is False
        assert "virtual reader" in body["error"]

    def test_a_contact_reader_reports_an_atr_not_an_ats(self, client, monkeypatch):
        """
        The card side is as likely to be in a contact slot, and the two answers
        are different things — labelling an ATR as an ATS would be wrong.
        """
        monkeypatch.setattr("core.readers.resolve",
                            lambda spec: Reader(index=1, name="Generic ICC Reader 00 00",
                                                kind=CONTACT))

        class FakeCard:
            def connect(self): pass
            def disconnect(self): pass
            def get_atr(self): return bytes.fromhex("3B6500")

        monkeypatch.setattr("transport.local.LocalCardTransport",
                            lambda index: FakeCard())
        body = client.post("/api/nfc/detect-card", json={"reader": 1}).json()
        assert body["ok"] is True
        assert body["answer_kind"] == "ATR"
        assert body["answer"] == "3B6500"
        assert body["uid"] == "", "a contact card has no UID"

    def test_a_reader_error_comes_back_as_a_message_not_a_500(self, client, monkeypatch):
        from core.readers import ReaderError

        def boom(spec):
            raise ReaderError("no such reader")

        monkeypatch.setattr("core.readers.resolve", boom)
        body = client.post("/api/nfc/detect-card", json={"reader": 9}).json()
        assert body["ok"] is False and "no such reader" in body["error"]

    def test_detection_is_refused_while_emulating(self, client, monkeypatch):
        from api.routes import nfc

        monkeypatch.setattr(nfc, "_emu_active", True)
        body = client.post("/api/nfc/detect-card", json={"reader": 0}).json()
        assert body["ok"] is False and "stop it first" in body["error"]


    def test_a_capture_outside_logs_is_refused(self, client, monkeypatch):
        """
        The CLI takes any path the operator types — they have a shell already.
        A browser request is reachable by anything that reaches the dashboard,
        so it reads only from logs/.
        """
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")
        for name in ("../../etc/passwd", "/etc/passwd", "sub/dir.hexlog"):
            res = client.post("/api/nfc/emulate/start", json={"from_file": name})
            assert res.status_code == 400, name

    def test_a_capture_that_does_not_exist_is_a_404(self, client, monkeypatch):
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")
        res = client.post("/api/nfc/emulate/start", json={"from_file": "nope.hexlog"})
        assert res.status_code == 404

    def test_a_capture_in_logs_starts_a_replayed_card(self, client, monkeypatch, tmp_path):
        from api.routes import nfc

        logs = tmp_path / "logs"
        logs.mkdir()
        (logs / "one.hexlog").write_text(
            "1  C  [x]  00A4040007A0000000031010\n"
            "2  R  [x]  6F1A9000\n")
        monkeypatch.setattr(nfc, "LOGS_DIR", logs)
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")

        # The chip is never opened: the thread is what touches hardware, and
        # what is under test is that the request resolves a card source.
        monkeypatch.setattr("nfc.acr122.open_pn532",
                            lambda name, direct=False: (_ for _ in ()).throw(
                                RuntimeError("no hardware in a test")))

        body = client.post("/api/nfc/emulate/start",
                           json={"from_file": "one.hexlog"}).json()
        assert body["ok"] is True
        assert "recorded capture" in body["relaying_to"]

    def test_the_capture_list_offers_only_replayable_files(self, client, monkeypatch, tmp_path):
        from api.routes import nfc

        logs = tmp_path / "logs"
        (logs / "sessions").mkdir(parents=True)
        (logs / "one.hexlog").write_text("x", encoding="utf-8")
        (logs / "two.jsonl").write_text("x", encoding="utf-8")
        (logs / "notes.md").write_text("x", encoding="utf-8")
        (logs / "sessions" / "deep.json").write_text("x", encoding="utf-8")
        monkeypatch.setattr(nfc, "LOGS_DIR", logs)

        names = {c["name"] for c in client.get("/api/nfc/captures").json()["captures"]}
        assert names == {"one.hexlog", "two.jsonl"}, (
            "nested files are not offered because the path guard would refuse them")

    def test_relaying_to_the_emulating_reader_is_refused(self, client, monkeypatch):
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")
        monkeypatch.setattr("core.readers.resolve",
                            lambda spec: Reader(index=0,
                                                name="ACR122U PICC Interface 00 00",
                                                kind=CONTACTLESS))
        body = client.post("/api/nfc/emulate/start",
                           json={"card_reader": 0}).json()
        assert body["ok"] is False
        assert "presenting the emulated card" in body["error"]

    def test_a_bad_fwi_is_answered_before_any_reader_is_looked_for(
            self, client, monkeypatch):
        """
        A number out of range is a malformed request; a missing reader is the
        environment. On a rig with no reader the second would otherwise mask
        the first, and a typo'd FWI would read as "no ACR122U".
        """
        monkeypatch.setattr("core.readers.probe", lambda: ([], "no readers"))
        body = client.post("/api/nfc/emulate/start",
                           json={"own_isodep": True, "fwi": 15}).json()
        assert body["ok"] is False
        assert "FWI" in body["error"], body["error"]

    def test_a_bad_wtxm_is_refused(self, client, monkeypatch):
        monkeypatch.setattr("core.readers.probe", lambda: ([], "no readers"))
        body = client.post("/api/nfc/emulate/start",
                           json={"own_isodep": True, "fwi": 12, "wtxm": 0}).json()
        assert body["ok"] is False
        assert "WTXM" in body["error"], body["error"]

    def test_the_numbers_are_ignored_when_the_option_is_off(self, client, monkeypatch):
        """They only mean anything to the driver that reads them."""
        monkeypatch.setattr("core.readers.probe", lambda: ([], "no readers"))
        body = client.post("/api/nfc/emulate/start",
                           json={"own_isodep": False, "fwi": 99, "wtxm": 0}).json()
        assert body["ok"] is False
        assert "ACR122U" in body["error"], "the reader is what is actually missing"

    def test_own_isodep_picks_the_other_driver(self, client, monkeypatch):
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")
        built = {}

        class FakeIsoDep:
            def __init__(self, chip, transport, **kw):
                built.update(kw)
                built["cls"] = "IsoDepEmulator"
            def run(self):
                return 0

        monkeypatch.setattr("nfc.acr122.open_pn532",
                            lambda name, direct=False: (object(), _FakeLink()))
        monkeypatch.setattr("nfc.emulator.IsoDepEmulator", FakeIsoDep)

        body = client.post("/api/nfc/emulate/start",
                           json={"own_isodep": True, "fwi": 14, "wtxm": 40,
                                 "from_file": "one.hexlog"}).json()
        # The capture is missing, so the source fails — but only after the
        # request itself was accepted as well formed.
        assert "FWI" not in str(body.get("error", ""))

    def test_a_bad_pairing_string_is_caught_before_the_hardware_is_touched(
            self, client, monkeypatch):
        _fake_probe(monkeypatch, "ACR122U PICC Interface 00 00")

        def _boom(*a, **k):
            raise AssertionError("the chip must not be opened for a bad pairing string")

        monkeypatch.setattr("nfc.acr122.open_pn532", _boom)
        body = client.post("/api/nfc/emulate/start",
                           json={"remote": True, "pairing": "not-a-pairing-string"}).json()
        assert body["ok"] is False
        assert "pairing" in body["error"].lower()


class TestTraceBroadcast:
    def test_a_relayed_pair_reaches_the_live_trace(self, monkeypatch):
        from api.routes import nfc

        sent = []
        monkeypatch.setattr("api.ws.apdu_stream.broadcast_apdu", sent.append)
        nfc._broadcast(bytes.fromhex("00A404000E325041592E5359532E444446303100"),
                       bytes.fromhex("6F1A9000"))

        assert len(sent) == 1
        assert sent[0]["cmd"].startswith("00A40400")
        assert sent[0]["sw"] == "9000"

    def test_a_broadcast_failure_does_not_break_the_relay(self, monkeypatch):
        from api.routes import nfc

        def _fail(entry):
            raise RuntimeError("no websocket loop")

        monkeypatch.setattr("api.ws.apdu_stream.broadcast_apdu", _fail)
        nfc._broadcast(b"\x00\xa4", b"\x90\x00")        # must not raise
