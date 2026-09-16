"""
One side of an NFCGate relay session.

The server is a session-scoped broadcast bus: everything a client sends is
forwarded verbatim to every *other* client sharing its one-byte session number,
and never back to the sender.  Two peers in a session therefore talk to each
other, and this is one of them.

Framing, which is asymmetric and easy to get wrong::

    client → server   uint32 big-endian length, then uint8 session, then body
    server → client   uint32 big-endian length, then body

The body is a ``ServerData``; on ``OP_PSH`` its ``data`` is an ``NFCData``.

Handshake
---------
Send ``OP_SYN`` on connect.  A peer already in the session answers ``OP_ACK``;
a peer that arrives later sends its own ``OP_SYN``, which this answers with
``OP_ACK``.  Either way, one of those two opcodes means somebody is on the
other end.  ``OP_FIN`` means they left.

A note on trust
---------------
NFCGate's server has no authentication, by design — its README says so and says
not to put it on a public network.  Its TLS support is confidentiality only.
This client will speak plaintext, because that is what the phone speaks, but it
will not pretend an unverified TLS socket is a secure one: ``cafile`` is
required to turn TLS on.  See ``doc/nfcgate-android.md``.
"""
from __future__ import annotations

import logging
import socket
import ssl
import struct

from nfcgate.proto import (
    MAX_MESSAGE,
    OP_ACK,
    OP_FIN,
    OP_PSH,
    OP_SYN,
    NFCData,
    NFCGateProtocolError,
    decode_nfcdata,
    decode_serverdata,
    encode_nfcdata,
    encode_serverdata,
    opcode_name,
)

logger = logging.getLogger(__name__)

DEFAULT_PORT = 5566
DEFAULT_SESSION = 1


class NFCGateError(RuntimeError):
    """Something went wrong with the session. User-facing."""


class PeerGone(NFCGateError):
    """The other side of the relay left, or never arrived."""


class NFCGateSession:
    """A client for one side of an NFCGate session."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        session: int = DEFAULT_SESSION,
        *,
        timeout: float = 10.0,
        cafile: str | None = None,
    ) -> None:
        if not 1 <= session <= 255:
            # 0 is the server's "no session" value: a frame carrying it before
            # a session is set closes the connection, so it is never a choice.
            raise NFCGateError(
                f"Session number must be 1–255, not {session}. Both this and the "
                f"phone must be set to the same one, in NFCGate's Settings.")
        self.host = host
        self.port = port
        self.session = session
        self.timeout = timeout
        self.cafile = cafile
        self._sock: socket.socket | None = None
        self._peer_seen = False

    @property
    def secure(self) -> bool:
        return self.cafile is not None

    @property
    def peer_present(self) -> bool:
        return self._peer_seen

    # ── lifecycle ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        try:
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        except OSError as exc:
            raise NFCGateError(
                f"Could not reach an NFCGate server at {self.host}:{self.port} — {exc}. "
                f"Start one with 'python3 server.py' from github.com/nfcgate/server, "
                f"and make sure the phone can reach the same address.") from exc

        if self.cafile:
            try:
                context = ssl.create_default_context(cafile=self.cafile)
                sock = context.wrap_socket(sock, server_hostname=self.host)
            except (ssl.SSLError, OSError) as exc:
                sock.close()
                raise NFCGateError(f"TLS to {self.host}:{self.port} failed: {exc}") from exc

        self._sock = sock
        self._peer_seen = False
        # Announce ourselves. This also creates the session server-side, so a
        # phone joining later lands in the same one.
        self._send_server(OP_SYN)
        logger.info("NFCGate: joined session %d on %s:%d%s",
                    self.session, self.host, self.port,
                    " over TLS" if self.secure else "")

    def close(self) -> None:
        if not self._sock:
            return
        try:
            self._send_server(OP_FIN)
        except (OSError, NFCGateError):
            pass                                    # already gone; nothing to say
        try:
            self._sock.close()
        except OSError:
            pass
        self._sock = None
        self._peer_seen = False

    # ── the relay ────────────────────────────────────────────────────────────

    def send_nfcdata(self, data: bytes, *, data_source: int, data_type: int,
                     timestamp: int = 0) -> None:
        """Push one NFCData to the peer."""
        self._send_server(
            OP_PSH,
            encode_nfcdata(data, data_source=data_source, data_type=data_type,
                           timestamp=timestamp))

    def wait_for_peer(self, timeout: float | None = None) -> None:
        """
        Block until the other side is known to be there.

        Returns immediately once a SYN or ACK has been seen. Any NFCData that
        arrives while waiting is dropped: a peer talking before we have
        acknowledged it is describing a tag we have no transport for yet.
        """
        if self._peer_seen:
            return
        deadline = _Deadline(timeout)
        while not self._peer_seen:
            self._pump(deadline.remaining(), waiting_for="the phone to join")

    def recv_nfcdata(self, timeout: float | None = None,
                     *, want_card: bool = True) -> NFCData:
        """
        Block for the next NFCData from the peer.

        ``want_card`` skips anything the *reader* side sent. In this direction
        that is our own kind of message coming from a third client in the
        session — an observer, or a second rig — and answering it as if the
        card had spoken would be wrong.
        """
        deadline = _Deadline(timeout)
        while True:
            message = self._pump(deadline.remaining(), waiting_for="the phone to answer")
            if message is None:
                continue
            if want_card and not message.from_card:
                logger.warning("NFCGate: ignoring a reader-sourced message in session %d "
                               "— is a third client connected?", self.session)
                continue
            return message

    # ── internals ────────────────────────────────────────────────────────────

    def _pump(self, timeout: float | None, *, waiting_for: str) -> NFCData | None:
        """
        Read one frame and act on it.

        Returns the NFCData for an OP_PSH, or None for anything handled here —
        so callers loop rather than assuming one frame is one message.
        """
        opcode, payload = self._read_server(timeout, waiting_for=waiting_for)

        if opcode == OP_SYN:
            # A peer that arrived after us. Acknowledge, or it waits forever.
            self._peer_seen = True
            self._send_server(OP_ACK)
            logger.info("NFCGate: the phone joined session %d", self.session)
            return None
        if opcode == OP_ACK:
            self._peer_seen = True
            logger.info("NFCGate: the phone was already in session %d", self.session)
            return None
        if opcode == OP_FIN:
            self._peer_seen = False
            raise PeerGone(
                "The phone left the NFCGate session. Re-arm relay mode in the app "
                "and try again.")
        if opcode != OP_PSH:
            logger.warning("NFCGate: ignoring unexpected %s", opcode_name(opcode))
            return None

        # An OP_PSH before the handshake still proves somebody is there.
        self._peer_seen = True
        try:
            return decode_nfcdata(payload)
        except NFCGateProtocolError as exc:
            logger.warning("NFCGate: undecodable NFCData (%s) — ignoring", exc)
            return None

    def _send_server(self, opcode: int, data: bytes = b"") -> None:
        if not self._sock:
            raise NFCGateError("Not connected — call connect() first")
        body = encode_serverdata(opcode, data)
        try:
            self._sock.sendall(struct.pack("!IB", len(body), self.session) + body)
        except OSError as exc:
            raise NFCGateError(f"Sending to the NFCGate server failed: {exc}") from exc

    def _read_server(self, timeout: float | None,
                     *, waiting_for: str) -> tuple[int, bytes]:
        length = struct.unpack("!I", self._recv_exact(4, timeout, waiting_for))[0]
        if length > MAX_MESSAGE:
            raise NFCGateError(
                f"NFCGate server announced a {length}-byte message, over the "
                f"{MAX_MESSAGE}-byte limit. Wrong port, or not an NFCGate server.")
        body = self._recv_exact(length, timeout, waiting_for) if length else b""
        try:
            return decode_serverdata(body)
        except NFCGateProtocolError as exc:
            raise NFCGateError(f"Not an NFCGate server, or a corrupted frame: {exc}") from exc

    def _recv_exact(self, n: int, timeout: float | None, waiting_for: str) -> bytes:
        if not self._sock:
            raise NFCGateError("Not connected")
        # The socket timeout is per-recv; the deadline the caller passed is for
        # the whole wait, and _Deadline shrinks it on every pass.
        self._sock.settimeout(timeout if timeout is not None else self.timeout)
        buf = b""
        while len(buf) < n:
            try:
                chunk = self._sock.recv(n - len(buf))
            except socket.timeout as exc:
                raise PeerGone(f"Timed out waiting for {waiting_for}.") from exc
            except OSError as exc:
                raise NFCGateError(f"Reading from the NFCGate server failed: {exc}") from exc
            if not chunk:
                raise PeerGone(
                    "The NFCGate server closed the connection. It drops clients that "
                    "go 300 seconds without sending anything.")
            buf += chunk
        return buf

    # ── context manager ──────────────────────────────────────────────────────

    def __enter__(self) -> NFCGateSession:
        self.connect()
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()


class _Deadline:
    """A whole-operation budget, spent across however many recv calls it takes."""

    def __init__(self, timeout: float | None) -> None:
        self._timeout = timeout
        self._end = None if timeout is None else _now() + timeout

    def remaining(self) -> float | None:
        if self._end is None:
            return None
        left = self._end - _now()
        if left <= 0:
            raise PeerGone(f"Timed out after {self._timeout:g}s.")
        return left


def _now() -> float:
    import time
    return time.monotonic()
