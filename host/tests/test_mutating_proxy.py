"""
MutatingProxy over real loopback sockets.

Phase 2's guarantee was that bytes are forwarded exactly as received. This
component gives that up on purpose, so the tests that matter most are the ones
pinning how far it gives it up: only messages a rule actually matched, only
when they decoded cleanly, and never at the cost of the link staying alive.
"""
from __future__ import annotations

import socket
import time

import pytest

from host.capture import CaptureLog
from host.iso8583 import Message, load_dialect, pack, unpack
from host.mutation import FieldMutation, MutationError, Playbook, load_playbook
from host.proxy import MutatingProxy
from host.scoping import Scope, ScopeError

from test_proxy import EchoHost           # same directory

ICC = bytes.fromhex("9F0206000000001000" "5F2A020840" "9F360200FF")
FIELDS = {2: "4111111111111111", 3: "000000", 4: "000000001000",
          11: "000123", 22: "051", 49: "840", 55: ICC}


@pytest.fixture
def iso():
    return load_dialect("iso8583-1987")


def _run(iso, playbook, wire, response_code="00", dialect=None):
    """Push one message through a mutating proxy. Returns (host, capture, replies)."""
    host = EchoHost(iso, response_code=response_code).start()
    capture = CaptureLog(None)
    scope = Scope(allowed_targets=(f"127.0.0.1:{host.port}",))
    proxy = MutatingProxy("127.0.0.1", 0, "127.0.0.1", host.port,
                          dialect=dialect or iso, scope=scope,
                          capture=capture, playbook=playbook)
    replies = []
    try:
        with proxy:
            client = socket.create_connection(("127.0.0.1", proxy.bound_port), timeout=5)
            client.settimeout(3)
            client.sendall(wire)
            buf = b""
            deadline = time.time() + 3
            while time.time() < deadline:
                try:
                    chunk = client.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                buf += chunk
                try:
                    _b, consumed = iso.framing.unwrap(buf)
                except Exception:
                    continue
                replies.append(buf[:consumed])
                buf = buf[consumed:]
                break
            time.sleep(0.3)
            client.close()
    finally:
        host.stop()
    return host, capture, replies


class TestRequestLegMutation:
    def test_amount_is_rewritten_before_it_reaches_the_host(self, iso):
        playbook = load_playbook("amount-mismatch")
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        host, capture, _ = _run(iso, playbook, wire)

        assert host.received, "the host must still have received something"
        arrived, _ = unpack(iso, host.received[0])
        assert arrived.fields[4] == "000000009999", "DE4 should have been rewritten"
        assert arrived.fields[55] == ICC, "the cryptogram's own amount is untouched"

    def test_the_rewrite_creates_the_mismatch_it_is_meant_to(self, iso):
        """End to end: the host now sees DE4 disagreeing with tag 9F02."""
        from host.iso8583 import de55
        playbook = load_playbook("amount-mismatch")
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        host, _, _ = _run(iso, playbook, wire)

        arrived, _ = unpack(iso, host.received[0])
        assert [d.what for d in de55.cross_check(arrived)] == ["amount mismatch"]

    def test_de55_tag_rewrite_reaches_the_host(self, iso):
        from host.iso8583 import de55
        playbook = load_playbook("atc-replay")
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        host, _, _ = _run(iso, playbook, wire)

        arrived, _ = unpack(iso, host.received[0])
        assert de55.tag_value(de55.from_message(arrived), "9F36") == "0001"

    def test_capture_records_what_arrived_and_what_was_sent(self, iso):
        playbook = load_playbook("amount-mismatch")
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        host, capture, _ = _run(iso, playbook, wire)

        request = next(r for r in capture.records if r.leg == "acquirer->issuer")
        assert bytes.fromhex(request.raw) == wire, "raw is what arrived"
        assert request.sent and bytes.fromhex(request.sent) == host.received[0]
        assert request.raw != request.sent
        assert request.mutations[0]["target"] == "DE4"
        assert request.mutations[0]["before"] == "000000001000"
        assert request.mutations[0]["after"] == "000000009999"


class TestResponseLegMutation:
    def test_decline_is_rewritten_to_approval_on_the_way_back(self, iso):
        playbook = load_playbook("response-tamper")
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        host, capture, replies = _run(iso, playbook, wire, response_code="05")

        assert replies, "a reply must still reach the client"
        got, _ = unpack(iso, replies[0])
        assert got.fields[39] == "00", "DE39 should have been rewritten to approved"

    def test_the_request_leg_is_forwarded_byte_for_byte(self, iso):
        """
        The rule is gated to the response direction, so the request must keep
        the phase 2 guarantee in full — not be round-tripped through the codec.
        """
        playbook = load_playbook("response-tamper")
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        host, capture, _ = _run(iso, playbook, wire, response_code="05")

        assert host.received[0] == wire
        request = next(r for r in capture.records if r.leg == "acquirer->issuer")
        assert request.mutations == []
        assert request.sent == "", "no rewrite means nothing was re-encoded"


class TestSafetyUnderFailure:
    def test_wrong_dialect_forwards_the_original_untouched(self, iso):
        """
        A dialect that cannot read the traffic must not rewrite it. The bytes
        reach the host exactly as sent, and the capture explains why.
        """
        playbook = load_playbook("amount-mismatch")
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        host, capture, replies = _run(iso, playbook, wire,
                                      dialect=load_dialect("postilion"))

        assert host.received[0] == wire, "a wrong dialect must not corrupt the link"
        assert replies, "the response must still come back"
        request = next(r for r in capture.records if r.leg == "acquirer->issuer")
        assert request.mutations == []
        assert "did not decode cleanly" in request.note

    def test_rule_that_cannot_apply_forwards_the_original(self, iso):
        playbook = Playbook(name="t", field_mutations=(
            FieldMutation(de=39, mode="delete", direction="acquirer->issuer",
                          on_mti=("0100",)),))
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        host, capture, _ = _run(iso, playbook, wire)

        assert host.received[0] == wire
        request = next(r for r in capture.records if r.leg == "acquirer->issuer")
        assert "nothing to act on" in request.note

    def test_untargeted_mti_passes_through_unchanged(self, iso):
        playbook = Playbook(name="t", field_mutations=(
            FieldMutation(de=4, mode="replace", value="000000009999",
                          direction="acquirer->issuer", on_mti=("0200",)),))
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        host, capture, _ = _run(iso, playbook, wire)

        assert host.received[0] == wire
        request = next(r for r in capture.records if r.leg == "acquirer->issuer")
        assert request.mutations == [] and request.note == ""

    def test_pan_is_still_masked_in_a_mutating_capture(self, iso):
        playbook = load_playbook("amount-mismatch")
        wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
        _host, capture, _ = _run(iso, playbook, wire)
        request = next(r for r in capture.records if r.leg == "acquirer->issuer")
        assert request.fields["2"] == "411111******1111"


class TestConstruction:
    def test_requires_a_playbook(self, iso):
        with pytest.raises(MutationError, match="needs a playbook"):
            MutatingProxy("127.0.0.1", 0, "127.0.0.1", 9, dialect=iso,
                          scope=Scope(allowed_targets=("127.0.0.1:9",)),
                          capture=CaptureLog(None))

    def test_refuses_an_inactive_playbook(self, iso):
        dead = Playbook(name="off", enabled=False, field_mutations=(
            FieldMutation(de=4, mode="replace", value="1"),))
        with pytest.raises(MutationError, match="at least one enabled"):
            MutatingProxy("127.0.0.1", 0, "127.0.0.1", 9, dialect=iso,
                          scope=Scope(allowed_targets=("127.0.0.1:9",)),
                          capture=CaptureLog(None), playbook=dead)

    def test_scope_guard_still_applies(self, iso):
        with pytest.raises(ScopeError, match="No target has been allow-listed"):
            MutatingProxy("127.0.0.1", 0, "10.0.0.1", 9999, dialect=iso,
                          scope=Scope(), capture=CaptureLog(None),
                          playbook=load_playbook("amount-mismatch"))
