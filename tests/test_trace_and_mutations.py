"""
Live Trace plumbing and the splice mutation mode.

Three of these cover things a researcher reads off the screen and acts on, so
being wrong is worse than being absent: which direction an APDU travelled,
whether the bytes shown are the card's own, and what a rule actually changed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from mutation_engine import (
    MUTATION_MODES,
    MutationLog,
    MutationRecord,
    ResponseTagMutation,
    _compute_new_value,
    drain_live_records,
)


@pytest.fixture(autouse=True)
def _clear_sink():
    drain_live_records()
    yield
    drain_live_records()


# ── splice ────────────────────────────────────────────────────────────────────

class TestSplice:
    def test_is_a_registered_mode(self):
        assert "splice" in MUTATION_MODES

    def test_overwrites_only_the_named_bytes(self):
        """The whole point: change part of a value, leave the rest as sent."""
        original = bytes.fromhex("000000001000")
        spec = ResponseTagMutation(tag="9F02", mode="splice", value="9999", offset=2)
        assert _compute_new_value(spec, original).hex().upper() == "000099991000"

    def test_at_offset_zero(self):
        spec = ResponseTagMutation(tag="95", mode="splice", value="FF", offset=0)
        assert _compute_new_value(spec, bytes.fromhex("0000000000")) \
            .hex().upper() == "FF00000000"

    def test_preserves_length(self):
        """
        A splice that resized the value would shift every byte after it — a
        different mutation wearing this one's name, and inside a signed
        template it would invalidate far more than intended.
        """
        original = bytes.fromhex("0102030405")
        spec = ResponseTagMutation(tag="9F36", mode="splice", value="FFFF", offset=1)
        assert len(_compute_new_value(spec, original)) == len(original)

    def test_overrun_is_refused_with_advice(self):
        original = bytes.fromhex("000000001000")
        spec = ResponseTagMutation(tag="9F02", mode="splice", value="999999", offset=5)
        with pytest.raises(ValueError, match="runs past the end"):
            _compute_new_value(spec, original)

    def test_negative_offset_is_refused(self):
        spec = ResponseTagMutation(tag="9F02", mode="splice", value="99", offset=-1)
        with pytest.raises(ValueError, match="negative"):
            _compute_new_value(spec, bytes.fromhex("0000"))

    def test_empty_value_is_a_no_op_not_a_wipe(self):
        original = bytes.fromhex("0102")
        spec = ResponseTagMutation(tag="9F02", mode="splice", value="", offset=0)
        assert _compute_new_value(spec, original) == original

    def test_offset_survives_the_yaml_round_trip(self):
        spec = ResponseTagMutation.from_dict(
            {"tag": "9F02", "mode": "splice", "value": "9999", "offset": 2})
        assert spec.offset == 2 and spec.mode == "splice"

    def test_offset_defaults_to_zero_when_absent(self):
        assert ResponseTagMutation.from_dict(
            {"tag": "9F02", "mode": "replace", "value": "00"}).offset == 0


# ── live sink ─────────────────────────────────────────────────────────────────

def _record(**kw):
    base = dict(ts_ms=1, session_id="s", direction="response",
                mutation_type="response_tag", tag="9F36", mode="replace",
                original_hex="00FF", mutated_hex="0001", ins="CA")
    base.update(kw)
    return MutationRecord(**base)


class TestLiveSink:
    def test_records_reach_the_sink_without_a_log_file(self):
        """
        A researcher should not have to turn on file logging to see in the UI
        why a response differs from what the card sent.
        """
        MutationLog(None).write([_record()])
        drained = drain_live_records()
        assert len(drained) == 1
        assert drained[0].tag == "9F36"

    def test_draining_empties_it(self):
        MutationLog(None).write([_record()])
        assert len(drain_live_records()) == 1
        assert drain_live_records() == []

    def test_records_also_reach_the_file_when_one_is_configured(self, tmp_path):
        path = tmp_path / "mut.jsonl"
        log = MutationLog(str(path))
        log.write([_record()])
        log.close()
        assert "9F36" in path.read_text(encoding="utf-8")
        assert len(drain_live_records()) == 1, "and the sink still got them"

    def test_empty_write_is_a_no_op(self):
        MutationLog(None).write([])
        assert drain_live_records() == []

    def test_to_dict_carries_what_the_ui_needs(self):
        """The trace renders direction, tag, mode and both hex values."""
        d = _record(comment="ATC frozen").to_dict()
        assert {"direction", "tag", "mode", "original_hex", "mutated_hex",
                "comment"} <= set(d)
        assert d["original_hex"] == "00FF" and d["mutated_hex"] == "0001"


# ── the WebSocket entry ───────────────────────────────────────────────────────

class TestWebSocketEntry:
    def _exchange(self, monkeypatch, cmd_hex, resp_hex):
        """Drive one command/response pair through the handler."""
        from emv_logger import (
            SessionInfo, WebSocketHandler, parse_command_apdu, parse_response_apdu,
        )

        sent = []
        fake = type(sys)("api.ws.apdu_stream")
        fake.broadcast_apdu = sent.append
        monkeypatch.setitem(sys.modules, "api.ws", type(sys)("api.ws"))
        monkeypatch.setitem(sys.modules, "api.ws.apdu_stream", fake)

        handler = WebSocketHandler()
        session = SessionInfo(session_id="s", started_at_ms=0, started_at_str="")
        handler.on_apdu(parse_command_apdu(bytes.fromhex(cmd_hex), "s", 1), session)
        handler.on_apdu(parse_response_apdu(bytes.fromhex(resp_hex), "s", 2), session)
        return sent

    def test_a_paired_exchange_carries_its_mutations(self, monkeypatch):
        """
        The handler drains the sink when the command/response pair completes,
        so the trace row can show what the rule changed on that exchange.
        """
        MutationLog(None).write([_record()])
        sent = self._exchange(monkeypatch, "80CA9F3600", "9F360200019000")

        assert len(sent) == 1
        entry = sent[0]
        assert entry["cmd"] == "80CA9F3600"
        assert entry["mutations"][0]["original_hex"] == "00FF"
        assert entry["mutations"][0]["mutated_hex"] == "0001"
        assert entry["mutations"][0]["direction"] == "response"

    def test_an_untouched_exchange_carries_no_mutations_key(self, monkeypatch):
        sent = self._exchange(monkeypatch, "00A4040000", "9000")
        assert len(sent) == 1
        assert "mutations" not in sent[0]


# ── the active-playbook endpoint ──────────────────────────────────────────────

class TestActivePlaybook:
    """
    Applying a playbook used to leave nothing behind that said which one was
    live — the card flashed for 1.2 s and then looked unselected again.
    """

    def _client(self, monkeypatch):
        from fastapi.testclient import TestClient
        monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
        from api.server import create_app
        return TestClient(create_app())

    def test_active_is_not_swallowed_by_the_name_route(self, monkeypatch):
        """
        FastAPI matches in registration order, so /active has to be declared
        before /{name} or it reads as a playbook called "active".
        """
        body = self._client(monkeypatch).get("/api/playbooks/active").json()
        assert "active" in body, body
        assert "detail" not in body, "the /{name} route swallowed it"

    def test_reports_the_playbook_whose_content_is_live(self, monkeypatch, tmp_path):
        from api.routes import playbooks

        pb = tmp_path / "books"
        pb.mkdir()
        (pb / "demo.yaml").write_text("enabled: true\nresponse_mutations: []\n", encoding="utf-8")
        live = tmp_path / "mutations.yaml"
        live.write_text("enabled: true\nresponse_mutations: []\n", encoding="utf-8")
        monkeypatch.setattr(playbooks, "PLAYBOOKS_DIR", pb)
        monkeypatch.setattr(playbooks, "MUTATIONS_YAML", live)

        assert playbooks.active_playbook()["active"] == "demo"

    def test_whitespace_does_not_break_the_match(self, monkeypatch, tmp_path):
        from api.routes import playbooks

        pb = tmp_path / "books"
        pb.mkdir()
        (pb / "demo.yaml").write_text("enabled: true\n\nresponse_mutations: []\n", encoding="utf-8")
        live = tmp_path / "mutations.yaml"
        live.write_text("enabled: true   \nresponse_mutations: []", encoding="utf-8")
        monkeypatch.setattr(playbooks, "PLAYBOOKS_DIR", pb)
        monkeypatch.setattr(playbooks, "MUTATIONS_YAML", live)

        assert playbooks.active_playbook()["active"] == "demo"

    def test_a_hand_edited_config_matches_nothing_and_says_so(self, monkeypatch, tmp_path):
        """Self-correcting: a remembered name would keep asserting a stale truth."""
        from api.routes import playbooks

        pb = tmp_path / "books"
        pb.mkdir()
        (pb / "demo.yaml").write_text("enabled: true\nresponse_mutations: []\n", encoding="utf-8")
        live = tmp_path / "mutations.yaml"
        live.write_text("enabled: true\nresponse_mutations: []\nafl_mutations: []\n", encoding="utf-8")
        monkeypatch.setattr(playbooks, "PLAYBOOKS_DIR", pb)
        monkeypatch.setattr(playbooks, "MUTATIONS_YAML", live)

        result = playbooks.active_playbook()
        assert result["active"] is None
        assert "does not match" in result["reason"]

    def test_disarming_the_engine_does_not_unload_the_playbook(self, monkeypatch, tmp_path):
        """
        The engine switch and the loaded playbook are separate facts. Matching
        deliberately ignores the top-level ``enabled:`` line so that turning the
        mutations off leaves the card still showing which rules are staged —
        otherwise deactivating would look like the playbook had vanished.
        """
        from api.routes import playbooks

        pb = tmp_path / "books"
        pb.mkdir()
        (pb / "demo.yaml").write_text("enabled: true\nresponse_mutations: []\n", encoding="utf-8")
        live = tmp_path / "mutations.yaml"
        live.write_text("enabled: false\nresponse_mutations: []\n", encoding="utf-8")
        monkeypatch.setattr(playbooks, "PLAYBOOKS_DIR", pb)
        monkeypatch.setattr(playbooks, "MUTATIONS_YAML", live)

        result = playbooks.active_playbook()
        assert result["active"] == "demo"
        assert result["engine_enabled"] is False

    def test_missing_config_is_not_an_error(self, monkeypatch, tmp_path):
        from api.routes import playbooks
        monkeypatch.setattr(playbooks, "MUTATIONS_YAML", tmp_path / "absent.yaml")
        assert playbooks.active_playbook()["active"] is None
