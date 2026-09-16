"""
Speaking NFCGate's protocol, and a phone standing in for a card.

The wire format is hand-encoded rather than pulled from ``protobuf``, so the
first half of this file is the codec: what proto3 leaves out, what a newer peer
might add, and what an NCI configuration stream yields about the tag. The
second half runs the transport against a fake hub with the same broadcast
semantics as NFCGate's own server — the handshake in both arrival orders, an
exchange, and the ways the far end goes away.

The hub here is a stand-in. That the codec is byte-identical to real protobuf,
and that the framing works against NFCGate's actual server, are checked by
``doc/verify_proto.py`` and ``doc/verify_relay.py``, which need the real
dependency and the real project cloned and so do not run here.
"""
from __future__ import annotations

import contextlib
import socket
import struct
import time
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from nfcgate.proto import (
    CARD,
    CONTINUATION,
    INITIAL,
    OP_ACK,
    OP_FIN,
    OP_PSH,
    OP_SYN,
    READER,
    NFCData,
    NFCGateProtocolError,
    TagConfig,
    decode_nfcdata,
    decode_serverdata,
    encode_nfcdata,
    encode_serverdata,
    parse_config_stream,
)
from nfcgate.session import NFCGateError, NFCGateSession, PeerGone
from transport.nfcgate import NFCGateTransport
from transport.source import CardSourceError, open_card_source

SELECT = bytes.fromhex("00A4040007A0000000031010")
SELECT_RESP = bytes.fromhex("6F1A840EA0000000031010A5089000")

# A config stream shaped like the one IsoDepReader builds for a Type A tag.
TAG_STREAM = bytes([
    0x33, 4, 0x04, 0xA2, 0xB1, 0xC0,                      # LA_NFCID1  — UID
    0x32, 1, 0x20,                                        # LA_SEL_INFO — SAK
    0x30, 1, 0x04,                                        # ATQA[0]
    0x31, 1, 0x00,                                        # ATQA[1]
    0x58, 1, 0x77,                                        # LI_A_RATS_TB1
    0x59, 8, 0x80, 0x73, 0xC0, 0x21, 0xC0, 0x57, 0x59, 0x00,   # historical bytes
])


# ── the codec ────────────────────────────────────────────────────────────────

class TestServerData:
    def test_round_trip(self):
        for opcode in (OP_PSH, OP_SYN, OP_ACK, OP_FIN):
            assert decode_serverdata(encode_serverdata(opcode, b"xyz")) == (opcode, b"xyz")

    def test_proto3_omits_the_defaults(self):
        # OP_PSH is 0 and an empty body is the default: both disappear, which
        # is what makes a bare handshake frame two bytes rather than five.
        assert encode_serverdata(OP_PSH, b"") == b""
        assert decode_serverdata(b"") == (OP_PSH, b"")

    def test_a_syn_is_two_bytes(self):
        assert encode_serverdata(OP_SYN) == bytes([0x08, 0x01])


class TestNFCData:
    def test_round_trip(self):
        raw = encode_nfcdata(SELECT, data_source=READER, data_type=CONTINUATION,
                             timestamp=1761400000123)
        assert decode_nfcdata(raw) == NFCData(READER, CONTINUATION, SELECT, 1761400000123)

    def test_every_enum_combination(self):
        for source in (READER, CARD):
            for kind in (INITIAL, CONTINUATION):
                got = decode_nfcdata(encode_nfcdata(b"\x01\x02", data_source=source,
                                                    data_type=kind))
                assert (got.data_source, got.data_type) == (source, kind)

    def test_a_large_timestamp_survives(self):
        # Unix millis are past 2^40; a varint that stopped at 32 bits would
        # silently truncate them.
        raw = encode_nfcdata(b"", timestamp=1_761_400_000_123)
        assert decode_nfcdata(raw).timestamp == 1_761_400_000_123

    def test_unknown_fields_are_skipped(self):
        # A newer NFCGate adding a field must not turn into an error here.
        raw = encode_nfcdata(SELECT, data_source=CARD) + bytes([0x28, 0x2A])  # field 5 varint
        assert decode_nfcdata(raw).data == SELECT

    def test_helpers_read_the_enums(self):
        card = decode_nfcdata(encode_nfcdata(b"", data_source=CARD, data_type=INITIAL))
        assert card.from_card and card.is_initial
        reader = decode_nfcdata(encode_nfcdata(b"", data_source=READER,
                                               data_type=CONTINUATION))
        assert not reader.from_card and not reader.is_initial

    def test_str_names_the_direction(self):
        assert str(NFCData(CARD, INITIAL, b"\xAB")) == "C: (initial) AB"
        assert str(NFCData(READER, CONTINUATION, b"\xAB")) == "R: AB"

    @pytest.mark.parametrize("bad", [
        bytes([0x08]),                 # varint key, no value
        bytes([0x1A, 0x05, 0x01]),     # length runs past the message
        bytes([0x0B]),                 # wire type 3 — start-group, not in either message
        bytes([0x00, 0x01]),           # field number 0
    ])
    def test_malformed_input_is_rejected(self, bad):
        with pytest.raises(NFCGateProtocolError):
            decode_nfcdata(bad)

    def test_a_varint_where_bytes_belong_is_rejected(self):
        with pytest.raises(NFCGateProtocolError):
            decode_nfcdata(bytes([0x18, 0x01]))        # field 3 as a varint


# ── the tag configuration ────────────────────────────────────────────────────

class TestTagConfig:
    def test_fields_the_phone_reports(self):
        tag = TagConfig.from_stream(TAG_STREAM)
        assert tag.uid == bytes.fromhex("04A2B1C0")
        assert tag.sak == 0x20
        assert tag.atqa == bytes.fromhex("0400")
        assert tag.historical_bytes == bytes.fromhex("8073C021C0575900")

    def test_the_ats_is_rebuilt_from_what_survived(self):
        ats = TagConfig.from_stream(TAG_STREAM).ats
        # TL, then T0 with the TB(1) bit and the stand-in FSCI, then TB(1),
        # then the historical bytes.
        assert ats == bytes.fromhex("0B28778073C021C0575900")
        assert ats[0] == len(ats)

    def test_tc1_sets_its_own_presence_bit(self):
        tag = TagConfig.from_stream(TAG_STREAM + bytes([0x5C, 1, 0x02]))
        assert tag.ats[1] & 0x40                      # TC(1) present
        assert tag.ats[1] & 0x20                      # TB(1) still present
        assert tag.ats[2:4] == bytes([0x77, 0x02])    # in T0 order

    def test_ta1_is_never_reconstructed(self):
        # NFCGate sends findMaxNCIBitRate(TA1), a lossy code, so putting a
        # TA(1) back would be inventing one.
        tag = TagConfig.from_stream(TAG_STREAM + bytes([0x5B, 1, 0x01]))
        assert not tag.ats[1] & 0x10

    def test_no_historical_bytes_means_no_ats(self):
        tag = TagConfig.from_stream(bytes([0x33, 4, 1, 2, 3, 4]))
        assert tag.ats == b""
        assert not tag.ats_is_partial
        assert tag.uid == bytes([1, 2, 3, 4])

    def test_a_truncated_record_ends_the_walk(self):
        # A length byte overrunning the buffer is a partial read, not a
        # different protocol — keep what parsed.
        options = parse_config_stream(bytes([0x33, 4, 1, 2, 3, 4, 0x32, 9, 0x20]))
        assert options == {0x33: bytes([1, 2, 3, 4])}

    def test_type_b_is_recognised(self):
        tag = TagConfig.from_stream(bytes([0x39, 4, 0xAA, 0xBB, 0xCC, 0xDD]))
        assert tag.is_type_b and tag.pupi == bytes.fromhex("AABBCCDD")

    def test_describe_names_what_was_reported(self):
        assert "UID 04A2B1C0" in TagConfig.from_stream(TAG_STREAM).describe()
        assert TagConfig().describe() == "no recognised tag fields"

    def test_empty_is_falsey(self):
        assert not TagConfig()
        assert TagConfig.from_stream(TAG_STREAM)


# ── a hub with NFCGate's semantics, and a phone to talk to ───────────────────

class FakeHub:
    """
    NFCGate's server, reduced to what it actually does.

    Reads ``uint32 length + uint8 session + body`` and forwards the body, with
    a bare ``uint32 length``, to every *other* client in that session. It never
    parses the payload — which is the property the whole integration rests on.
    """

    def __init__(self) -> None:
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(8)
        self.port = self._listener.getsockname()[1]
        self._sessions: dict[int, list[socket.socket]] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._accepting = threading.Thread(target=self._accept, daemon=True)
        self._accepting.start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            thread = threading.Thread(target=self._serve, args=(client,), daemon=True)
            self._threads.append(thread)
            thread.start()

    def _serve(self, client: socket.socket) -> None:
        session = None
        try:
            while not self._stop.is_set():
                header = _read_exact(client, 5)
                if header is None:
                    return
                length, number = struct.unpack("!IB", header)
                body = _read_exact(client, length) if length else b""
                if body is None:
                    return
                if length == 0 and number == 0 and session is None:
                    return
                if session != number:
                    self._leave(client, session)
                    session = number
                    with self._lock:
                        self._sessions.setdefault(session, []).append(client)
                self._publish(session, client, body)
        except OSError:
            return
        finally:
            self._leave(client, session)
            client.close()

    def _publish(self, session: int, origin: socket.socket, body: bytes) -> None:
        with self._lock:
            peers = [c for c in self._sessions.get(session, []) if c is not origin]
        for peer in peers:
            try:
                peer.sendall(struct.pack("!I", len(body)) + body)
            except OSError:
                pass

    def _leave(self, client: socket.socket, session) -> None:
        if session is None:
            return
        with self._lock:
            if client in self._sessions.get(session, []):
                self._sessions[session].remove(client)

    def members(self, session: int) -> int:
        with self._lock:
            return len(self._sessions.get(session, []))

    def wait_for_members(self, count: int, session: int = 1,
                         timeout: float = 5.0) -> None:
        """
        Block until `count` clients are registered in `session`.

        A client joins on its first *frame*, not on connect, and each is served
        by its own thread — so which of two clients lands in a session first is
        not decided by the order the test connected them. Any test whose
        expected frames depend on that order has to pin it here rather than
        assume it. (One did not, and CI caught it.)
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.members(session) >= count:
                return
            time.sleep(0.005)
        raise AssertionError(
            f"only {self.members(session)} of {count} client(s) joined session "
            f"{session} within {timeout}s")

    def close(self) -> None:
        self._stop.set()
        self._listener.close()


class FakePhone:
    """The other peer: NFCGate in reader mode, with a scripted card."""

    def __init__(self, port: int, session: int = 1) -> None:
        self._sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        self._sock.settimeout(5)
        self.session = session
        self.received: list[NFCData] = []

    def send(self, opcode: int, payload: bytes = b"") -> None:
        body = encode_serverdata(opcode, payload)
        self._sock.sendall(struct.pack("!IB", len(body), self.session) + body)

    def handshake(self) -> None:
        """
        SYN on connect, then wait for the other side — what the app does.

        Two halves, both load-bearing. A client is only in a session once it
        has *sent* something, so a peer that waits to be greeted is never
        greeted. And a client must not relay before the peer is there: the hub
        forwards to whoever is in the session *at that moment*, so a tag
        announced too early is broadcast to nobody and simply lost.
        """
        self.send(OP_SYN)
        while True:
            opcode, _ = self.read()
            if opcode == OP_SYN:
                self.send(OP_ACK)
                return
            if opcode == OP_ACK:
                return

    def read_nfcdata(self) -> NFCData:
        """
        Read until an OP_PSH, answering any SYN on the way.

        Both peers SYN on connect and the hub gives no ordering guarantee
        between two clients joining, so each can see the other's SYN and reply
        ACK — meaning a handshake frame can arrive at any point, including
        between a command and its response.
        """
        while True:
            opcode, payload = self.read()
            if opcode == OP_SYN:
                self.send(OP_ACK)
                continue
            if opcode != OP_PSH:
                continue
            message = decode_nfcdata(payload)
            self.received.append(message)
            return message

    def announce_tag(self, stream: bytes = TAG_STREAM) -> None:
        self.send(OP_PSH, encode_nfcdata(stream, data_source=CARD, data_type=INITIAL))

    def answer(self, response: bytes) -> None:
        self.send(OP_PSH, encode_nfcdata(response, data_source=CARD,
                                         data_type=CONTINUATION))

    def read(self) -> tuple[int, bytes]:
        header = _read_exact(self._sock, 4)
        assert header is not None, "hub closed on the phone"
        (length,) = struct.unpack("!I", header)
        return decode_serverdata(_read_exact(self._sock, length) or b"")

    def close(self) -> None:
        self._sock.close()


def _drain(phone: FakePhone, limit: float = 2.0) -> list[tuple[int, bytes]]:
    """Whatever the phone still has waiting, without blocking past `limit`."""
    phone._sock.settimeout(limit)
    out = []
    try:
        while True:
            out.append(phone.read())
    except (OSError, AssertionError):
        return out


def _read_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except TimeoutError:
            # Distinct from a close, and the distinction is the whole diagnosis
            # when a frame simply never comes.
            raise
        except OSError:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


@contextlib.contextmanager
def _rogue_server(payload: bytes):
    """A listener that accepts one client and sends `payload` verbatim."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def run():
        try:
            client, _ = listener.accept()
            client.recv(64)                           # our OP_SYN
            client.sendall(payload)
            client.close()
        except OSError:
            pass

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        listener.close()
        thread.join(timeout=2)


@pytest.fixture
def hub():
    h = FakeHub()
    yield h
    h.close()


def _serve_in_background(phone: FakePhone, responses: list[bytes]) -> threading.Thread:
    """A phone that announces its tag, then answers each command in turn."""
    def run():
        try:
            phone.handshake()
            phone.announce_tag()
            for response in responses:
                phone.read_nfcdata()
                phone.answer(response)
        except (AssertionError, OSError, NFCGateProtocolError):
            pass
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


# ── the session ──────────────────────────────────────────────────────────────

class TestSession:
    def test_a_peer_already_there_acks(self, hub):
        phone = FakePhone(hub.port)
        phone.send(OP_SYN)
        # Wait for the hub to actually register it: joining happens on the
        # first frame, in that client's own thread, so "sent first" is not
        # "joined first" without this.
        hub.wait_for_members(1)

        session = NFCGateSession("127.0.0.1", hub.port, 1, timeout=5)
        session.connect()
        try:
            assert phone.read()[0] == OP_SYN          # ours reaches it
            phone.send(OP_ACK)
            session.wait_for_peer(5)
            assert session.peer_present
        finally:
            session.close()
            phone.close()

    def test_a_peer_arriving_later_is_acked(self, hub):
        session = NFCGateSession("127.0.0.1", hub.port, 1, timeout=5)
        session.connect()
        hub.wait_for_members(1)                       # we are in, alone

        phone = FakePhone(hub.port)
        try:
            phone.send(OP_SYN)
            session.wait_for_peer(5)
            assert session.peer_present
            assert phone.read()[0] == OP_ACK          # we answered it
        finally:
            session.close()
            phone.close()

    def test_sessions_do_not_cross(self, hub):
        session = NFCGateSession("127.0.0.1", hub.port, 7, timeout=1)
        session.connect()
        stranger = FakePhone(hub.port, session=9)
        try:
            stranger.send(OP_SYN)
            with pytest.raises(PeerGone):
                session.wait_for_peer(0.6)
        finally:
            session.close()
            stranger.close()

    @pytest.mark.parametrize("number", [0, 256, -1])
    def test_the_session_number_is_bounded(self, number):
        # 0 is the server's "no session" value, so it is never a choice.
        with pytest.raises(NFCGateError, match="1–255"):
            NFCGateSession("127.0.0.1", 5566, number)

    def test_an_oversized_length_prefix_is_refused(self):
        """
        A length prefix off a socket is how a peer turns into an allocator.

        This one comes straight from the listener rather than through the hub:
        the hub would block reading a gigabyte that never arrives, so the frame
        would never reach the client being tested.
        """
        with _rogue_server(struct.pack("!I", 1 << 30) + b"\x00") as port:
            session = NFCGateSession("127.0.0.1", port, 1, timeout=5)
            session.connect()
            try:
                with pytest.raises(NFCGateError, match="over the"):
                    session.recv_nfcdata(5)
            finally:
                session.close()

    def test_a_frame_that_is_not_nfcgate_is_refused(self):
        # Wire type 3 (start-group) appears in neither message, so this is a
        # different protocol on the port rather than a corrupt NFCGate frame.
        body = bytes([0x0B, 0x00])
        with _rogue_server(struct.pack("!I", len(body)) + body) as port:
            session = NFCGateSession("127.0.0.1", port, 1, timeout=5)
            session.connect()
            try:
                with pytest.raises(NFCGateError, match="[Nn]ot an NFCGate server"):
                    session.recv_nfcdata(5)
            finally:
                session.close()

    def test_a_departing_peer_raises(self, hub):
        session = NFCGateSession("127.0.0.1", hub.port, 1, timeout=5)
        session.connect()
        # This phone never reads, so it cannot answer a SYN it is sent — which
        # makes it the one shape where the join order has to be pinned: we must
        # already be in the session for the phone's own SYN to reach us.
        hub.wait_for_members(1)

        phone = FakePhone(hub.port)
        try:
            phone.send(OP_SYN)
            session.wait_for_peer(5)
            phone.send(OP_FIN)
            with pytest.raises(PeerGone, match="left the NFCGate session"):
                session.recv_nfcdata(5)
        finally:
            session.close()
            phone.close()

    def test_an_unreachable_server_says_where_to_get_one(self):
        closed = socket.socket()
        closed.bind(("127.0.0.1", 0))
        port = closed.getsockname()[1]
        closed.close()
        session = NFCGateSession("127.0.0.1", port, 1, timeout=1)
        with pytest.raises(NFCGateError, match="nfcgate/server"):
            session.connect()


# ── the transport ────────────────────────────────────────────────────────────

class TestTransport:
    def test_a_phone_stands_in_for_a_card(self, hub):
        phone = FakePhone(hub.port)
        _serve_in_background(phone, [SELECT_RESP])
        card = NFCGateTransport("127.0.0.1", hub.port, 1, tag_wait=5, timeout=5)
        try:
            card.connect()
            assert card.transmit(SELECT) == SELECT_RESP
            assert phone.received[0].data == SELECT
            assert phone.received[0].data_source == READER
        finally:
            card.disconnect()
            phone.close()

    def test_the_tag_arrives_before_any_command(self, hub):
        phone = FakePhone(hub.port)
        _serve_in_background(phone, [])
        card = NFCGateTransport("127.0.0.1", hub.port, 1, tag_wait=5, timeout=5)
        try:
            card.connect()
            assert card.tag.uid == bytes.fromhex("04A2B1C0")
            assert card.get_atr() == bytes.fromhex("0B28778073C021C0575900")
        finally:
            card.disconnect()
            phone.close()

    def test_several_commands_keep_their_order(self, hub):
        phone = FakePhone(hub.port)
        second = bytes.fromhex("770F9F2701809000")
        _serve_in_background(phone, [SELECT_RESP, second])
        card = NFCGateTransport("127.0.0.1", hub.port, 1, tag_wait=5, timeout=5)
        try:
            card.connect()
            assert card.transmit(SELECT) == SELECT_RESP
            assert card.transmit(bytes.fromhex("80A8000002830000")) == second
        finally:
            card.disconnect()
            phone.close()

    def test_a_re_tap_mid_exchange_updates_the_tag(self, hub):
        """A phone that re-detects a tag sends another INITIAL — not a response."""
        phone = FakePhone(hub.port)
        other = bytes([0x33, 4, 0xDE, 0xAD, 0xBE, 0xEF,
                       0x59, 4, 0x80, 0x73, 0x00, 0x00])

        def run():
            phone.handshake()
            phone.announce_tag()
            phone.read_nfcdata()
            phone.announce_tag(other)                 # re-tap, then the answer
            phone.answer(SELECT_RESP)

        threading.Thread(target=run, daemon=True).start()
        card = NFCGateTransport("127.0.0.1", hub.port, 1, tag_wait=5, timeout=5)
        try:
            card.connect()
            assert card.transmit(SELECT) == SELECT_RESP
            assert card.tag.uid == bytes.fromhex("DEADBEEF")
        finally:
            card.disconnect()
            phone.close()

    def test_a_stray_ack_mid_exchange_is_not_a_response(self, hub):
        """
        Both peers SYN on connect, so an ACK can arrive at any point.

        The hub gives no ordering guarantee between two clients joining, so
        each can end up seeing the other's SYN and answering ACK — and that
        second ACK lands wherever it lands, including between a command and
        its response. Reading it as data yields an empty APDU. Found by
        running the real transport against NFCGate's own server, where it
        happened on roughly half the runs.
        """
        phone = FakePhone(hub.port)

        def run():
            phone.handshake()
            phone.announce_tag()
            phone.read_nfcdata()
            phone.send(OP_ACK)                        # the late handshake frame
            phone.answer(SELECT_RESP)

        threading.Thread(target=run, daemon=True).start()
        card = NFCGateTransport("127.0.0.1", hub.port, 1, tag_wait=5, timeout=5)
        try:
            card.connect()
            assert card.transmit(SELECT) == SELECT_RESP
        finally:
            card.disconnect()
            phone.close()

    def test_a_stray_syn_mid_exchange_is_answered_and_skipped(self, hub):
        """A peer re-announcing itself must be acked, not mistaken for data."""
        phone = FakePhone(hub.port)

        def run():
            phone.handshake()
            phone.announce_tag()
            phone.read_nfcdata()
            phone.send(OP_SYN)
            phone.answer(SELECT_RESP)

        threading.Thread(target=run, daemon=True).start()
        card = NFCGateTransport("127.0.0.1", hub.port, 1, tag_wait=5, timeout=5)
        try:
            card.connect()
            assert card.transmit(SELECT) == SELECT_RESP
            # The ack has to reach the phone, or a real one waits forever.
            assert any(op == OP_ACK for op, _ in _drain(phone))
        finally:
            card.disconnect()
            phone.close()

    def test_an_empty_answer_means_the_card_left_the_field(self, hub):
        phone = FakePhone(hub.port)
        _serve_in_background(phone, [b""])
        card = NFCGateTransport("127.0.0.1", hub.port, 1, tag_wait=5, timeout=5)
        try:
            card.connect()
            with pytest.raises(PeerGone, match="left the field"):
                card.transmit(SELECT)
        finally:
            card.disconnect()
            phone.close()

    def test_no_tag_times_out_rather_than_failing_later(self, hub):
        """A transport that never saw a card must not pretend it has one."""
        phone = FakePhone(hub.port)

        def run():
            phone.handshake()                         # joins, but never taps a tag

        threading.Thread(target=run, daemon=True).start()
        card = NFCGateTransport("127.0.0.1", hub.port, 1, tag_wait=0.6, timeout=0.6)
        with pytest.raises(PeerGone):
            card.connect()
        phone.close()

    def test_a_failed_connect_leaves_no_socket_open(self, hub):
        card = NFCGateTransport("127.0.0.1", hub.port, 1, tag_wait=0.5, timeout=0.5)
        with pytest.raises(PeerGone):
            card.connect()
        assert card._session._sock is None


# ── choosing it as the card source ───────────────────────────────────────────

class TestSource:
    def test_open_card_source_builds_one(self):
        card, described = open_card_source(
            nfcgate=True, nfcgate_host="10.0.0.5", nfcgate_port=5566,
            nfcgate_session=3)
        assert isinstance(card, NFCGateTransport)
        assert (card.host, card.port, card.session_number) == ("10.0.0.5", 5566, 3)
        assert "NFCGate session 3" in described

    def test_a_bad_session_number_is_a_source_error(self):
        # Caught where the choice is made, not at connect time, so the message
        # lands next to the field that is wrong.
        with pytest.raises(CardSourceError, match="1–255"):
            open_card_source(nfcgate=True, nfcgate_session=0)

    def test_a_capture_still_wins(self, tmp_path):
        # from_file is checked first: naming both is a contradiction, and the
        # recorded card is the one that needs no network.
        capture = tmp_path / "c.txt"
        capture.write_text("> 00A404\n< 9000\n", encoding="utf-8")
        card, described = open_card_source(from_file=str(capture), nfcgate=True)
        assert not isinstance(card, NFCGateTransport)
        assert "recorded capture" in described
