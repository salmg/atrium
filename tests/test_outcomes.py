"""
Mutation outcome store and Live Trace wiring.

Salvaged from the closed PR #46. Two things are covered: the outcome store
itself, and the fact that the logger actually feeds the dashboard — main had
broadcast_apdu() defined but nothing calling it, so Live Trace stayed empty
during a live session.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


class TestAutoLabelling:
    """Routine status words must not be stored, or the table becomes noise."""

    @pytest.mark.parametrize("sw", ["9000", "6100", "611A", "6C14", "6C00"])
    def test_routine_codes_are_skipped(self, sw):
        from emv_logger import _auto_label_sw
        assert _auto_label_sw(sw) is None

    @pytest.mark.parametrize("sw", ["6983", "6984", "6985", "6986", "6988"])
    def test_security_conditions_are_labelled(self, sw):
        from emv_logger import _auto_label_sw
        assert _auto_label_sw(sw) == "security_condition"

    @pytest.mark.parametrize("sw", ["6A82", "6700", "6D00", "6E00"])
    def test_other_6xxx_is_interesting(self, sw):
        from emv_logger import _auto_label_sw
        assert _auto_label_sw(sw) == "interesting"

    @pytest.mark.parametrize("bad", ["", "90", "900000", None])
    def test_malformed_input_is_ignored(self, bad):
        from emv_logger import _auto_label_sw
        assert _auto_label_sw(bad) is None


class TestOutcomeStore:
    def _db(self, tmp_path):
        import inspect
        from card_intel import CardIntelDB
        if "db_path" in inspect.signature(CardIntelDB.__init__).parameters:
            return CardIntelDB(db_path=str(tmp_path / "intel.db"))
        return CardIntelDB()

    def test_records_and_summarises_per_card(self, tmp_path):
        db = self._db(tmp_path)
        for sw, label, ins in [("6A82", "interesting", "A4"),
                               ("6985", "security_condition", "AE"),
                               ("6A82", "interesting", "A4")]:
            db.record_outcome(label=label, fingerprint_hash="card-a", session_id="s1",
                              cmd_hex="00" + ins, cmd_ins=ins, resp_hex=sw, sw=sw,
                              source="auto")
        s = db.get_outcomes_summary("card-a")
        assert s["total"] == 3
        assert s["by_label"]["interesting"] == 2
        assert s["by_label"]["security_condition"] == 1
        db.close()

    def test_summary_is_scoped_to_one_card(self, tmp_path):
        db = self._db(tmp_path)
        db.record_outcome(label="interesting", fingerprint_hash="card-a", session_id="s",
                          cmd_hex="00A4", cmd_ins="A4", resp_hex="6A82", sw="6A82",
                          source="auto")
        db.record_outcome(label="interesting", fingerprint_hash="card-b", session_id="s",
                          cmd_hex="00A4", cmd_ins="A4", resp_hex="6A82", sw="6A82",
                          source="auto")
        assert db.get_outcomes_summary("card-a")["total"] == 1
        db.close()

    def test_cross_card_patterns_count_distinct_cards(self, tmp_path):
        db = self._db(tmp_path)
        for card in ("card-a", "card-b", "card-c"):
            db.record_outcome(label="interesting", fingerprint_hash=card, session_id="s",
                              cmd_hex="80AE", cmd_ins="AE", resp_hex="6985", sw="6985",
                              source="auto")
        top = db.get_cross_card_patterns()["patterns"][0]
        assert top["cards"] == 3 and top["count"] == 3
        db.close()


class TestOutcomesApi:
    def _client(self, monkeypatch):
        monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
        from fastapi.testclient import TestClient
        from api.server import create_app
        return TestClient(create_app())

    def test_mark_then_read_back(self, monkeypatch):
        c = self._client(monkeypatch)
        r = c.post("/api/outcomes/mark", json={
            "label": "interesting", "session_id": "s1", "cmd_hex": "00A40400",
            "cmd_ins": "A4", "resp_hex": "6A82", "sw": "6A82"})
        assert r.status_code == 200 and r.json()["ok"] is True
        assert c.get("/api/outcomes").status_code == 200


class TestLiveTraceIsFed:
    """
    broadcast_apdu() existed on main with no producer, so the trace table never
    populated. These assert the handler exists, is registered, and stays inert
    outside the API server.
    """

    def test_handler_is_registered_with_the_logger(self):
        import inspect
        import emv_logger
        assert "WebSocketHandler()" in inspect.getsource(emv_logger.EMVLogger)

    def test_is_a_noop_without_the_api_server(self, monkeypatch):
        import sys as _sys
        import emv_logger
        # Simulate running the CLI relay, where api.ws is not importable
        monkeypatch.setitem(_sys.modules, "api.ws.apdu_stream", None)
        h = emv_logger.WebSocketHandler()
        h.on_session_end(None)          # must not raise

    def test_pairs_command_with_response_into_one_entry(self, monkeypatch):
        """
        One trace row per exchange, not one per APDU. The handler buffers the
        command and emits only when the response arrives.
        """
        import types
        import emv_logger
        from emv_logger import Direction

        sent = []
        fake = types.ModuleType("api.ws.apdu_stream")
        fake.broadcast_apdu = sent.append
        monkeypatch.setitem(sys.modules, "api.ws.apdu_stream", fake)

        def rec(direction, raw, **kw):
            r = types.SimpleNamespace(
                direction=direction, raw_hex=raw, ts_ms=1_000, duration_us=42,
                sw1=kw.get("sw1", ""), sw2=kw.get("sw2", ""), tlv_nodes=[],
                session_id="s1", ins_name=kw.get("ins_name", ""), ins=kw.get("ins", ""),
            )
            return r

        h = emv_logger.WebSocketHandler()

        # Command alone must not emit anything yet
        h.on_apdu(rec(Direction.TERMINAL_TO_CARD, "00A4040007A0000000031010",
                      ins_name="SELECT", ins="A4"), None)
        assert sent == [], "command should be buffered, not broadcast on its own"

        # Response completes the pair
        h.on_apdu(rec(Direction.CARD_TO_TERMINAL, "6F1A9000", sw1="90", sw2="00"), None)
        assert len(sent) == 1, "one entry per command/response exchange"

        entry = sent[0]
        assert entry["cmd"] == "00A4040007A0000000031010"
        assert entry["resp"] == "6F1A9000"
        assert entry["sw"] == "9000"
        assert entry["desc"] == "SELECT"
        assert h._pending_cmd is None, "buffer must clear after pairing"
