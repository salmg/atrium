"""Capture records, masking, and STAN-based correlation."""
from __future__ import annotations

import json

import pytest

from host.capture import (
    CaptureLog,
    Correlator,
    Record,
    is_response,
    load_capture,
    masked_fields,
    observe,
    request_mti_for,
    summarise,
)
from host.iso8583 import Message, load_dialect, pack_body
from host.scoping import Scope

ICC = bytes.fromhex("9F0206000000001000" "5F2A020840" "9F360200FF")


@pytest.fixture
def iso():
    return load_dialect("iso8583-1987")


def _body(iso, **kwargs) -> bytes:
    fields = {2: "4111111111111111", 4: "000000001000", 11: "000123", 49: "840"}
    fields.update(kwargs.pop("fields", {}))
    return pack_body(iso, Message(mti=kwargs.get("mti", "0100"), fields=fields))


class TestMasking:
    def test_pan_never_reaches_the_decoded_view(self, iso):
        msg = Message(mti="0100", fields={2: "4111111111111111", 4: "1000"})
        out = masked_fields(msg)
        assert out["2"] == "411111******1111"
        assert "4111111111111111" not in json.dumps(out)

    def test_track_data_is_masked(self):
        msg = Message(mti="0100", fields={35: "4111111111111111D25121011234"})
        assert masked_fields(msg)["35"] == "411111******1111D..."

    def test_binary_fields_render_as_hex(self):
        msg = Message(mti="0100", fields={55: ICC})
        assert masked_fields(msg)["55"] == ICC.hex().upper()

    def test_ordinary_fields_pass_through(self):
        msg = Message(mti="0100", fields={4: "000000001000", 39: "00"})
        out = masked_fields(msg)
        assert out["4"] == "000000001000" and out["39"] == "00"


class TestObserve:
    def test_decodes_and_records(self, iso):
        body = _body(iso)
        record = observe(iso, body, b"\x00\x23" + body, conn="c1",
                         leg="acquirer->issuer", seq=1)
        assert record.mti == "0100"
        assert record.fields["4"] == "000000001000"
        assert record.problems == []

    def test_raw_bytes_are_preserved_for_replay(self, iso):
        body = _body(iso)
        raw = b"\x00\x23" + body
        record = observe(iso, body, raw, conn="c1", leg="a", seq=1)
        assert record.raw == raw.hex().upper()

    def test_de55_summary_and_discrepancies(self, iso):
        body = pack_body(iso, Message(mti="0100", fields={
            4: "000000002000", 49: "840", 11: "000123", 55: ICC}))
        record = observe(iso, body, body, conn="c1", leg="a", seq=1)
        assert record.de55["9F36"] == "00FF"
        assert any("amount mismatch" in d for d in record.discrepancies)

    def test_undecodable_message_is_recorded_not_raised(self, iso):
        record = observe(iso, b"\xff\xff\xff\xff\xff", b"\xff", conn="c1",
                         leg="a", seq=1)
        assert record.problems, "a failure to decode must still produce a record"
        assert record.raw == "FF"

    def test_scope_warning_is_attached(self, iso):
        body = pack_body(iso, Message(mti="0100", fields={2: "4999888877776666"}))
        record = observe(iso, body, body, conn="c1", leg="a", seq=1, scope=Scope())
        assert record.warnings and "outside the configured test ranges" in record.warnings[0]

    def test_scope_abort_propagates(self, iso):
        from host.scoping import ScopeError
        body = pack_body(iso, Message(mti="0100", fields={2: "4999888877776666"}))
        with pytest.raises(ScopeError):
            observe(iso, body, body, conn="c1", leg="a", seq=1,
                    scope=Scope(on_live_pan="abort"))


class TestCorrelation:
    def test_response_mti_recognition(self):
        assert is_response("0110") and is_response("0210") and is_response("0810")
        assert not is_response("0100") and not is_response("0200")
        assert request_mti_for("0110") == "0100"
        assert request_mti_for("0210") == "0200"

    def test_matches_by_stan_not_arrival_order(self, iso):
        """Two requests out, answered in the opposite order."""
        correlator = Correlator()
        first = Message(mti="0100", fields={11: "000001"})
        second = Message(mti="0100", fields={11: "000002"})
        correlator.note_request(first, 100.0)
        correlator.note_request(second, 101.0)

        rtt_second = correlator.match_response(Message(mti="0110", fields={11: "000002"}), 101.5)
        rtt_first = correlator.match_response(Message(mti="0110", fields={11: "000001"}), 102.0)

        assert rtt_second == 500.0, "matched the request with the same STAN"
        assert rtt_first == 2000.0

    def test_unmatched_response_reports_none(self):
        assert Correlator().match_response(
            Message(mti="0110", fields={11: "000999"}), 1.0) is None

    def test_message_without_a_stan_is_skipped(self):
        correlator = Correlator()
        correlator.note_request(Message(mti="0100", fields={}), 1.0)
        assert correlator.outstanding == 0

    def test_pending_table_is_bounded(self):
        """An unanswering host must not become a memory leak."""
        correlator = Correlator(max_pending=4)
        for i in range(50):
            correlator.note_request(Message(mti="0100", fields={11: f"{i:06d}"}), float(i))
        assert correlator.outstanding == 4

    def test_outstanding_drops_when_answered(self):
        correlator = Correlator()
        correlator.note_request(Message(mti="0200", fields={11: "000123"}), 1.0)
        assert correlator.outstanding == 1
        correlator.match_response(Message(mti="0210", fields={11: "000123"}), 1.1)
        assert correlator.outstanding == 0


class TestCaptureLog:
    def test_writes_jsonl_that_reads_back(self, tmp_path):
        path = tmp_path / "cap.jsonl"
        with CaptureLog(path) as capture:
            capture.write(Record(ts=1.0, conn="c1", leg="a", seq=1, raw="AABB", mti="0100"))
            capture.write(Record(ts=2.0, conn="c1", leg="b", seq=2, raw="CCDD", mti="0110"))

        records = load_capture(path)
        assert [r["mti"] for r in records] == ["0100", "0110"]
        assert records[0]["raw"] == "AABB"

    def test_flushes_so_a_killed_process_keeps_its_capture(self, tmp_path):
        path = tmp_path / "cap.jsonl"
        capture = CaptureLog(path)
        capture.write(Record(ts=1.0, conn="c1", leg="a", seq=1, raw="AABB"))
        assert path.read_text().strip(), "record must be on disk before close()"
        capture.close()

    def test_no_raw_mode_drops_the_bytes(self, tmp_path):
        path = tmp_path / "cap.jsonl"
        with CaptureLog(path, include_raw=False) as capture:
            capture.write(Record(ts=1.0, conn="c1", leg="a", seq=1, raw="AABB", mti="0100"))
        assert "AABB" not in path.read_text()

    def test_memory_only_capture_needs_no_path(self):
        capture = CaptureLog(None)
        capture.write(Record(ts=1.0, conn="c1", leg="a", seq=1, raw="AA"))
        assert len(capture.records) == 1

    def test_malformed_lines_are_skipped_not_fatal(self, tmp_path):
        path = tmp_path / "cap.jsonl"
        path.write_text('{"mti":"0100","seq":1,"ts":0}\nnot json\n\n{"mti":"0110","seq":2,"ts":0}\n')
        assert [r["mti"] for r in load_capture(path)] == ["0100", "0110"]


class TestSummary:
    def test_reports_counts_and_flags(self):
        text = summarise([
            {"mti": "0100", "seq": 1, "discrepancies": ["amount mismatch: ..."]},
            {"mti": "0110", "seq": 2, "rtt_ms": 42.0},
            {"mti": "0100", "seq": 3, "problems": ["field 62: truncated"]},
        ])
        assert "3 messages" in text
        assert "0100×2" in text
        assert "1 DE55 discrepancies" in text
        assert "1 decode problems" in text

    def test_empty_capture(self):
        assert "empty" in summarise([])
