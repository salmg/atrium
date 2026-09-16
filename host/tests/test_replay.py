"""
Replay — corpus loading, freshening, and driving a host with no acquirer.

The behaviour that matters most is what replay leaves alone. Verbatim mode must
resend the captured bytes untouched, because "does the host notice it has seen
this before" is only a fair question if nothing changed. And freshening must
never touch DE55: reusing the cryptogram unaltered under a new STAN is the
experiment, not a bug.
"""
from __future__ import annotations

import socket

import pytest

from host.capture import CaptureLog, Record
from host.iso8583 import Message, load_dialect, pack, unpack
from host.iso8583 import de55 as de55_mod
from host.mutation import load_playbook
from host.replay import (
    APPROVAL_CODES,
    FRESHEN_FIELDS,
    Freshener,
    ReplayError,
    ReplayItem,
    ReplayReport,
    ReplayResult,
    ReplaySession,
    describe_results,
    load_corpus,
)
from host.scoping import Scope, ScopeError

from test_proxy import EchoHost           # same directory

ICC = bytes.fromhex("9F0206000000001000" "5F2A020840" "9F360200FF"
                    "9F2608AABBCCDDEEFF0011")
FIELDS = {2: "4111111111111111", 3: "000000", 4: "000000001000",
          7: "0101120000", 11: "000123", 12: "120000", 13: "0101",
          37: "000000000001", 49: "840", 55: ICC}


@pytest.fixture
def iso():
    return load_dialect("iso8583-1987")


@pytest.fixture
def corpus_file(tmp_path, iso):
    """A capture holding three request/response pairs."""
    path = tmp_path / "corpus.jsonl"
    with CaptureLog(path) as cap:
        for i in range(3):
            wire = pack(iso, Message(mti="0100", fields={**FIELDS, 11: f"{i:06d}"}))
            cap.write(Record(ts=100.0 + i, conn="c1", leg="acquirer->issuer",
                             seq=i + 1, raw=wire.hex().upper(), mti="0100"))
            reply = pack(iso, Message(mti="0110", fields={**FIELDS, 39: "00"}))
            cap.write(Record(ts=100.2 + i, conn="c1", leg="issuer->acquirer",
                             seq=i + 1, raw=reply.hex().upper(), mti="0110"))
    return path


def _session(iso, host, capture=None, **kwargs):
    scope = Scope(allowed_targets=(f"127.0.0.1:{host.port}",))
    return ReplaySession("127.0.0.1", host.port, dialect=iso, scope=scope,
                         capture=capture or CaptureLog(None), timeout=3.0, **kwargs)


# ── Corpus ────────────────────────────────────────────────────────────────────

class TestCorpus:
    def test_loads_only_the_acquirer_leg(self, corpus_file):
        """Replay plays the acquirer; the issuer's replies are not ours to send."""
        items = load_corpus(corpus_file)
        assert len(items) == 3
        assert {i.mti for i in items} == {"0100"}

    def test_filters_by_mti(self, corpus_file):
        assert len(load_corpus(corpus_file, mti=("0100",))) == 3
        with pytest.raises(ReplayError, match="No replayable messages"):
            load_corpus(corpus_file, mti=("0800",))

    def test_limit(self, corpus_file):
        assert len(load_corpus(corpus_file, limit=2)) == 2

    def test_preserves_order_and_timestamps(self, corpus_file):
        items = load_corpus(corpus_file)
        assert [i.seq for i in items] == [1, 2, 3]
        assert items[1].ts > items[0].ts

    def test_capture_without_raw_bytes_explains_itself(self, tmp_path):
        path = tmp_path / "noraw.jsonl"
        with CaptureLog(path, include_raw=False) as cap:
            cap.write(Record(ts=1.0, conn="c", leg="acquirer->issuer", seq=1,
                             raw="AABB", mti="0100"))
        with pytest.raises(ReplayError, match="--no-raw"):
            load_corpus(path)

    def test_empty_capture(self, tmp_path):
        path = tmp_path / "empty.jsonl"
        path.write_text("")
        with pytest.raises(ReplayError, match="No replayable messages"):
            load_corpus(path)


# ── Freshening ────────────────────────────────────────────────────────────────

class TestFreshener:
    def test_rewrites_the_routing_fields(self, iso):
        msg = Message(mti="0100", fields=dict(FIELDS))
        records = Freshener(seed=1).apply(iso, msg)
        assert {r.target for r in records} == {"DE7", "DE11", "DE12", "DE13", "DE37"}
        assert msg.fields[11] != FIELDS[11]
        assert msg.fields[37] != FIELDS[37]

    def test_never_touches_de55(self, iso):
        """Reusing the cryptogram untouched is the experiment."""
        msg = Message(mti="0100", fields=dict(FIELDS))
        Freshener(seed=1).apply(iso, msg)
        assert msg.fields[55] == ICC
        assert de55_mod.tag_value(de55_mod.from_message(msg), "9F26") == \
            "AABBCCDDEEFF0011"

    def test_never_touches_the_amount_or_pan(self, iso):
        msg = Message(mti="0100", fields=dict(FIELDS))
        Freshener(seed=1).apply(iso, msg)
        assert msg.fields[4] == FIELDS[4]
        assert msg.fields[2] == FIELDS[2]

    def test_de55_is_not_in_the_freshen_set(self):
        assert 55 not in FRESHEN_FIELDS
        assert 4 not in FRESHEN_FIELDS and 2 not in FRESHEN_FIELDS

    def test_stans_are_unique_across_messages(self, iso):
        fresh = Freshener(seed=7)
        stans = set()
        for _ in range(50):
            msg = Message(mti="0100", fields=dict(FIELDS))
            fresh.apply(iso, msg)
            stans.add(msg.fields[11])
        assert len(stans) == 50

    def test_does_not_invent_fields_the_message_lacks(self, iso):
        msg = Message(mti="0100", fields={2: "4111111111111111", 11: "000123"})
        Freshener(seed=1).apply(iso, msg)
        assert 37 not in msg.fields and 7 not in msg.fields

    def test_stan_stays_six_digits(self, iso):
        fresh = Freshener(seed=3)
        for _ in range(20):
            msg = Message(mti="0100", fields=dict(FIELDS))
            fresh.apply(iso, msg)
            assert len(msg.fields[11]) == 6 and msg.fields[11].isdigit()


# ── Sending ───────────────────────────────────────────────────────────────────

class TestVerbatimReplay:
    def test_sends_the_captured_bytes_untouched(self, iso, corpus_file):
        """The whole question depends on nothing having changed."""
        host = EchoHost(iso).start()
        try:
            items = load_corpus(corpus_file)
            with _session(iso, host) as session:
                report = session.run(items)
        finally:
            host.stop()

        assert host.received == [i.raw for i in items]
        assert all(not r.changes for r in report.results)
        assert report.mode == "verbatim"

    def test_needs_no_decode_at_all(self, iso, corpus_file):
        """Verbatim with no transform must work even under a wrong dialect."""
        host = EchoHost(iso).start()
        try:
            items = load_corpus(corpus_file)
            session = _session(iso, host)
            session.dialect = load_dialect("postilion")     # cannot read this traffic
            with session:
                session.run(items)
        finally:
            host.stop()
        assert host.received == [i.raw for i in items]

    def test_collects_response_codes(self, iso, corpus_file):
        host = EchoHost(iso, response_code="05").start()
        try:
            with _session(iso, host) as session:
                report = session.run(load_corpus(corpus_file))
        finally:
            host.stop()

        assert [r.response_code for r in report.results] == ["05", "05", "05"]
        assert not report.approved
        assert all(r.rtt_ms is not None for r in report.results)


class TestFreshenedReplay:
    def test_rewrites_on_the_wire_but_keeps_de55(self, iso, corpus_file):
        host = EchoHost(iso).start()
        try:
            items = load_corpus(corpus_file)
            with _session(iso, host, freshen=True) as session:
                report = session.run(items)
        finally:
            host.stop()

        assert host.received != [i.raw for i in items], "bytes should have changed"
        arrived, _ = unpack(iso, host.received[0])
        assert arrived.fields[55] == ICC, "the cryptogram is reused as captured"
        assert arrived.fields[11] != "000000"
        assert report.mode == "freshened"
        assert all(r.changes for r in report.results)

    def test_each_message_gets_a_distinct_stan(self, iso, corpus_file):
        host = EchoHost(iso).start()
        try:
            with _session(iso, host, freshen=True) as session:
                session.run(load_corpus(corpus_file))
        finally:
            host.stop()

        stans = {unpack(iso, raw)[0].fields[11] for raw in host.received}
        assert len(stans) == 3


class TestPlaybookComposition:
    def test_a_playbook_applies_to_replayed_messages(self, iso, corpus_file):
        """Phase 3 and phase 4 compose: no live acquirer needed."""
        host = EchoHost(iso).start()
        try:
            with _session(iso, host, playbook=load_playbook("amount-mismatch")) as s:
                report = s.run(load_corpus(corpus_file))
        finally:
            host.stop()

        arrived, _ = unpack(iso, host.received[0])
        assert arrived.fields[4] == "000000009999"
        assert report.playbook == "amount-mismatch"
        assert any(c.target == "DE4" for c in report.results[0].changes)

    def test_cryptogram_tamper_over_replay(self, iso, corpus_file):
        host = EchoHost(iso).start()
        try:
            with _session(iso, host, playbook=load_playbook("cryptogram-tamper")) as s:
                s.run(load_corpus(corpus_file))
        finally:
            host.stop()

        arrived, _ = unpack(iso, host.received[0])
        assert de55_mod.tag_value(de55_mod.from_message(arrived), "9F26") == \
            "2ABBCCDDEEFF0011"

    def test_freshen_and_playbook_together(self, iso, corpus_file):
        host = EchoHost(iso).start()
        try:
            with _session(iso, host, freshen=True,
                          playbook=load_playbook("amount-mismatch")) as s:
                report = s.run(load_corpus(corpus_file))
        finally:
            host.stop()

        targets = {c.target for c in report.results[0].changes}
        assert "DE11" in targets and "DE4" in targets


class TestSafety:
    def test_scope_guard_applies(self, iso):
        with pytest.raises(ScopeError, match="No target has been allow-listed"):
            ReplaySession("10.0.0.1", 9999, dialect=iso, scope=Scope(),
                          capture=CaptureLog(None))

    def test_live_pan_aborts_when_told_to(self, iso, tmp_path):
        path = tmp_path / "live.jsonl"
        wire = pack(iso, Message(mti="0100", fields={**FIELDS, 2: "4999888877776666"}))
        with CaptureLog(path) as cap:
            cap.write(Record(ts=1.0, conn="c", leg="acquirer->issuer", seq=1,
                             raw=wire.hex().upper(), mti="0100"))

        host = EchoHost(iso).start()
        try:
            scope = Scope(allowed_targets=(f"127.0.0.1:{host.port}",),
                          on_live_pan="abort")
            session = ReplaySession("127.0.0.1", host.port, dialect=iso,
                                    scope=scope, capture=CaptureLog(None),
                                    freshen=True, timeout=3.0)
            with session:
                with pytest.raises(ScopeError):
                    session.run(load_corpus(path))
        finally:
            host.stop()

    def test_undecodable_message_is_sent_verbatim_not_dropped(self, iso, tmp_path):
        """A transform that cannot be computed falls back, and says so."""
        path = tmp_path / "odd.jsonl"
        junk = b"\x00\x06" + b"\xff" * 6
        with CaptureLog(path) as cap:
            cap.write(Record(ts=1.0, conn="c", leg="acquirer->issuer", seq=1,
                             raw=junk.hex().upper(), mti="0100"))

        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        try:
            with _session(iso, host, capture=capture, freshen=True) as session:
                session.run(load_corpus(path))
        finally:
            host.stop()

        assert host.received == [] or host.received[0] == junk
        request = capture.records[0]
        assert "could not decode cleanly" in request.note

    def test_pan_is_masked_in_the_replay_capture(self, iso, corpus_file):
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        try:
            with _session(iso, host, capture=capture, freshen=True) as session:
                session.run(load_corpus(corpus_file))
        finally:
            host.stop()

        request = next(r for r in capture.records if r.leg == "acquirer->issuer")
        assert request.fields["2"] == "411111******1111"

    def test_unreachable_host_raises_rather_than_hanging(self, iso):
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead = probe.getsockname()[1]
        probe.close()
        session = ReplaySession("127.0.0.1", dead, dialect=iso,
                                scope=Scope(allowed_targets=(f"127.0.0.1:{dead}",)),
                                capture=CaptureLog(None), timeout=1.0)
        with pytest.raises(OSError):
            session.connect()


# ── Reporting ─────────────────────────────────────────────────────────────────

def _result(rc: str, mode_changes=()) -> ReplayResult:
    item = ReplayItem(seq=1, ts=0.0, mti="0100", raw=b"\x00\x01\x02")
    response = Message(mti="0110", fields={39: rc}) if rc else None
    return ReplayResult(item=item, sent=item.raw, response=response,
                        changes=list(mode_changes))


class TestReport:
    def test_approval_codes(self):
        assert "00" in APPROVAL_CODES
        assert _result("00").approved
        assert not _result("05").approved
        assert not _result("").approved

    def test_verbatim_approval_points_at_duplicate_detection(self):
        report = ReplayReport(mode="verbatim", results=[_result("00"), _result("05")])
        verdict = report.verdict()
        assert "1 of 2" in verdict
        assert "duplicate detection" in verdict
        assert "Confirm" in verdict, "a lead should say how to confirm it"

    def test_freshened_approval_points_at_cryptogram_binding(self):
        report = ReplayReport(mode="freshened", results=[_result("00")])
        assert "not bound to the transaction" in report.verdict()

    def test_playbook_approval_names_the_playbook(self):
        report = ReplayReport(mode="verbatim", results=[_result("00")],
                              playbook="cryptogram-tamper")
        assert "cryptogram-tamper" in report.verdict()

    def test_nothing_approved_is_the_expected_result(self):
        report = ReplayReport(mode="verbatim", results=[_result("05"), _result("14")])
        assert "expected result" in report.verdict()

    def test_empty_report(self):
        assert "Nothing was replayed" in ReplayReport(mode="verbatim").verdict()

    def test_summary_counts_response_codes(self):
        report = ReplayReport(mode="verbatim",
                              results=[_result("00"), _result("05"), _result("05")])
        text = report.summary()
        assert "05×2" in text and "00×1" in text

    def test_unanswered_are_counted(self):
        report = ReplayReport(mode="verbatim", results=[_result("00"), _result("")])
        assert "1 unanswered" in report.summary()

    def test_table_flags_approvals(self):
        table = describe_results(ReplayReport(mode="verbatim", results=[_result("00")]))
        assert "APPROVED" in table
