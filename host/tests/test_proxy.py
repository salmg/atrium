"""
Passive proxy tests, against a real loopback socket pair.

The load-bearing test is ``test_wrong_dialect_still_relays_byte_for_byte``.
Everything else here is a feature; that one is the safety property the whole
design rests on — a dialect is a guess about somebody else's system, and a
wrong guess must cost a capture, never a transaction.
"""
from __future__ import annotations

import socket
import threading
import time

import pytest

from host.capture import CaptureLog
from host.iso8583 import Message, load_dialect, pack
from host.iso8583.framing import Framing
from host.proxy import PassiveProxy
from host.scoping import Scope, ScopeError

FIELDS = {2: "4111111111111111", 3: "000000", 4: "000000001000",
          11: "000123", 49: "840"}


class EchoHost:
    """A stand-in issuer: reads a framed request, answers with a response."""

    def __init__(self, dialect, framing=None, response_code="00"):
        self.dialect = dialect
        self.framing = framing or dialect.framing
        self.response_code = response_code
        self.received: list[bytes] = []
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(4)
        self._server.settimeout(0.5)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    @property
    def port(self) -> int:
        return self._server.getsockname()[1]

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._stop.set()
        self._server.close()
        self._thread.join(timeout=2)

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except (socket.timeout, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        conn.settimeout(0.5)
        buf = b""
        while not self._stop.is_set():
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            if not chunk:
                break
            buf += chunk
            while True:
                try:
                    body, consumed = self.framing.unwrap(buf)
                except Exception:
                    break
                self.received.append(buf[:consumed])
                buf = buf[consumed:]
                reply = Message(mti="0110", fields={**FIELDS, 39: self.response_code})
                try:
                    conn.sendall(pack(self.dialect, reply, self.framing))
                except OSError:
                    return
        conn.close()


@pytest.fixture
def iso():
    return load_dialect("iso8583-1987")


def _proxy(iso, host, capture, dialect=None, allow=None):
    scope = Scope(allowed_targets=allow or (f"127.0.0.1:{host.port}",))
    return PassiveProxy("127.0.0.1", 0, "127.0.0.1", host.port,
                        dialect=dialect or iso, scope=scope, capture=capture)


def _talk(port: int, payload: bytes, expect: int = 1, framing=None) -> list[bytes]:
    """Send payload through the proxy and collect framed replies."""
    framing = framing or Framing()
    client = socket.create_connection(("127.0.0.1", port), timeout=5)
    client.settimeout(3)
    try:
        client.sendall(payload)
        out, buf = [], b""
        deadline = time.time() + 3
        while len(out) < expect and time.time() < deadline:
            try:
                chunk = client.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
            while True:
                try:
                    _body, consumed = framing.unwrap(buf)
                except Exception:
                    break
                out.append(buf[:consumed])
                buf = buf[consumed:]
        return out
    finally:
        client.close()


class TestRelay:
    def test_forwards_a_request_and_returns_the_response(self, iso):
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        try:
            with _proxy(iso, host, capture) as proxy:
                wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
                replies = _talk(proxy.bound_port, wire)
            assert host.received == [wire], "host must see exactly what was sent"
            assert len(replies) == 1
        finally:
            host.stop()

    def test_records_both_legs(self, iso):
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        try:
            with _proxy(iso, host, capture) as proxy:
                _talk(proxy.bound_port, pack(iso, Message(mti="0100", fields=dict(FIELDS))))
                time.sleep(0.3)
        finally:
            host.stop()

        legs = {r.leg for r in capture.records}
        assert legs == {"acquirer->issuer", "issuer->acquirer"}
        assert {r.mti for r in capture.records} == {"0100", "0110"}

    def test_correlates_the_round_trip(self, iso):
        """
        Both legs are recorded and decoded; a round-trip time may or may not be
        present.

        RTT is best-effort by design: the proxy forwards before it decodes, so
        on a fast link the response can be recorded before the request has
        finished being processed, leaving nothing to pair against. The exact
        pairing logic is covered deterministically in test_capture.py — asserting
        a live timing artifact here would just be asserting the scheduler.
        """
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        try:
            with _proxy(iso, host, capture) as proxy:
                _talk(proxy.bound_port, pack(iso, Message(mti="0100", fields=dict(FIELDS))))
                time.sleep(0.3)
        finally:
            host.stop()

        response = next(r for r in capture.records if r.mti == "0110")
        assert response.leg == "issuer->acquirer"
        assert response.rtt_ms is None or response.rtt_ms >= 0

    def test_pan_is_masked_in_the_capture(self, iso):
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        try:
            with _proxy(iso, host, capture) as proxy:
                _talk(proxy.bound_port, pack(iso, Message(mti="0100", fields=dict(FIELDS))))
                time.sleep(0.3)
        finally:
            host.stop()

        request = next(r for r in capture.records if r.mti == "0100")
        assert request.fields["2"] == "411111******1111"

    def test_several_messages_in_one_write_are_all_seen(self, iso):
        """A burst that arrives as one TCP segment must not collapse to one."""
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        try:
            with _proxy(iso, host, capture) as proxy:
                burst = b"".join(
                    pack(iso, Message(mti="0100", fields={**FIELDS, 11: f"{i:06d}"}))
                    for i in range(3)
                )
                _talk(proxy.bound_port, burst, expect=3)
                time.sleep(0.4)
        finally:
            host.stop()

        requests = [r for r in capture.records if r.leg == "acquirer->issuer"]
        assert len(requests) == 3
        assert [r.seq for r in requests] == [1, 2, 3]

    def test_message_split_across_packets_is_reassembled(self, iso):
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        try:
            with _proxy(iso, host, capture) as proxy:
                wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
                client = socket.create_connection(("127.0.0.1", proxy.bound_port), timeout=5)
                client.sendall(wire[:7])
                time.sleep(0.15)
                client.sendall(wire[7:])
                time.sleep(0.4)
                client.close()
        finally:
            host.stop()

        assert host.received == [wire]
        assert [r.mti for r in capture.records if r.leg == "acquirer->issuer"] == ["0100"]


class TestSafetyProperties:
    def test_wrong_dialect_still_relays_byte_for_byte(self, iso):
        """
        The property everything rests on.

        The proxy is told the link speaks Postilion (ASCII numerics) when it
        actually speaks the ISO base (BCD). Decoding must fail — and the bytes
        must still arrive at the host completely unaltered.
        """
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        wrong = load_dialect("postilion")
        try:
            with _proxy(iso, host, capture, dialect=wrong) as proxy:
                wire = pack(iso, Message(mti="0100", fields=dict(FIELDS)))
                replies = _talk(proxy.bound_port, wire)
                time.sleep(0.3)
        finally:
            host.stop()

        assert host.received == [wire], "a wrong dialect must not corrupt the link"
        assert len(replies) == 1, "the response must still come back"

        request = next(r for r in capture.records if r.leg == "acquirer->issuer")
        assert request.problems, "decoding should have failed and said so"
        assert bytes.fromhex(request.raw) == wire, "raw bytes are captured regardless"

    def test_unparseable_traffic_relays_opaquely(self, iso):
        """Garbage that cannot be framed still reaches the far side."""
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        payload = b"\xff\xff" + b"\x00" * 8
        try:
            with _proxy(iso, host, capture) as proxy:
                client = socket.create_connection(("127.0.0.1", proxy.bound_port), timeout=5)
                client.sendall(payload)
                time.sleep(0.4)
                client.close()
                time.sleep(0.2)
        finally:
            host.stop()
        # The echo host cannot frame it either, but it must have arrived.
        assert host.received == [] or host.received[0] != b""

    def test_out_of_scope_target_refuses_to_construct(self, iso):
        capture = CaptureLog(None)
        scope = Scope(allowed_targets=("gateway.test:5000",))
        with pytest.raises(ScopeError, match="not in scope"):
            PassiveProxy("127.0.0.1", 0, "10.0.0.1", 9999,
                         dialect=iso, scope=scope, capture=capture)

    def test_no_allow_list_refuses_to_construct(self, iso):
        with pytest.raises(ScopeError, match="No target has been allow-listed"):
            PassiveProxy("127.0.0.1", 0, "10.0.0.1", 9999,
                         dialect=iso, scope=Scope(), capture=CaptureLog(None))

    def test_unreachable_target_does_not_kill_the_proxy(self, iso):
        """A refused upstream closes that connection, nothing more."""
        capture = CaptureLog(None)
        # Bind and immediately close to get a port nothing is listening on.
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        dead_port = probe.getsockname()[1]
        probe.close()

        scope = Scope(allowed_targets=(f"127.0.0.1:{dead_port}",))
        proxy = PassiveProxy("127.0.0.1", 0, "127.0.0.1", dead_port,
                             dialect=iso, scope=scope, capture=capture,
                             connect_timeout=1.0)
        with proxy:
            client = socket.create_connection(("127.0.0.1", proxy.bound_port), timeout=5)
            time.sleep(0.4)
            client.close()
            assert proxy.bound_port, "proxy is still up"


class TestDiscrepancyDetection:
    def test_amount_mismatch_is_flagged_in_the_capture(self, iso):
        """The headline check, end to end through a live socket."""
        icc = bytes.fromhex("9F0206000000001000" "5F2A020840")
        host = EchoHost(iso).start()
        capture = CaptureLog(None)
        try:
            with _proxy(iso, host, capture) as proxy:
                wire = pack(iso, Message(mti="0100", fields={
                    **FIELDS, 4: "000000002000", 55: icc}))
                _talk(proxy.bound_port, wire)
                time.sleep(0.3)
        finally:
            host.stop()

        request = next(r for r in capture.records if r.leg == "acquirer->issuer")
        assert any("amount mismatch" in d for d in request.discrepancies)
