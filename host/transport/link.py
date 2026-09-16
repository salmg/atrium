"""
TCP link with MLI framing.

Also provides ``FrameReader``, the buffering the proxy uses directly: it hands
back both the decoded body *and* the exact bytes that carried it, because a
passive proxy must forward what it received rather than what it understood.
"""
from __future__ import annotations

import socket

from host.iso8583.framing import Framing, FramingError, IncompleteMessage
from host.transport.base import HostTransport


class FrameReader:
    """
    Incremental message splitter over a byte stream.

    ``feed`` returns complete messages as (body, raw) pairs.  ``raw`` includes
    the MLI, so a relay can forward it verbatim — re-encoding would mean a
    dialect bug silently corrupting a live link.
    """

    def __init__(self, framing: Framing, max_buffer: int = 1 << 20) -> None:
        self.framing = framing
        self.max_buffer = max_buffer
        self._buf = b""

    @property
    def pending(self) -> bytes:
        return self._buf

    def feed(self, chunk: bytes) -> list[tuple[bytes, bytes]]:
        """
        Add bytes and return whatever whole messages they completed.

        Raises FramingError if the stream cannot be this framing at all — the
        caller decides what to do, and for a proxy the answer is to stop
        decoding and keep relaying.
        """
        self._buf += chunk
        if len(self._buf) > self.max_buffer:
            raise FramingError(
                f"Buffered {len(self._buf)} bytes without completing a message; "
                "the framing is almost certainly wrong."
            )

        out: list[tuple[bytes, bytes]] = []
        while self._buf:
            try:
                body, consumed = self.framing.unwrap(self._buf)
            except IncompleteMessage:
                break
            raw, self._buf = self._buf[:consumed], self._buf[consumed:]
            out.append((body, raw))
        return out

    def drain(self) -> bytes:
        """Take whatever is buffered and forget it."""
        rest, self._buf = self._buf, b""
        return rest


class TcpLink(HostTransport):
    """A framed message link over TCP, optionally wrapped in TLS."""

    def __init__(self, host: str, port: int, framing: Framing | None = None,
                 timeout: float = 30.0, use_tls: bool = False) -> None:
        self.host = host
        self.port = port
        self.framing = framing or Framing()
        self.timeout = timeout
        self.use_tls = use_tls
        self._sock: socket.socket | None = None
        self._reader = FrameReader(self.framing)
        self._ready: list[tuple[bytes, bytes]] = []

    # ── lifecycle ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        if self._sock is not None:
            return
        sock = socket.create_connection((self.host, self.port), timeout=self.timeout)
        if self.use_tls:
            import ssl
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        self._sock = sock

    @classmethod
    def from_socket(cls, sock: socket.socket, framing: Framing | None = None,
                    timeout: float = 30.0) -> "TcpLink":
        """Adopt an already-connected socket (an accepted server-side one)."""
        link = cls("", 0, framing, timeout)
        link._sock = sock
        return link

    def close(self) -> None:
        sock, self._sock = self._sock, None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass

    # ── HostTransport ────────────────────────────────────────────────────────

    def send(self, body: bytes) -> None:
        if self._sock is None:
            raise ConnectionError("Link is not connected")
        self._sock.sendall(self.framing.wrap(body))

    def send_raw(self, raw: bytes) -> None:
        """Write pre-framed bytes untouched — what a passive relay forwards."""
        if self._sock is None:
            raise ConnectionError("Link is not connected")
        self._sock.sendall(raw)

    def receive(self, timeout: float | None = None) -> bytes | None:
        pair = self.receive_framed(timeout)
        return None if pair is None else pair[0]

    def receive_framed(self, timeout: float | None = None) -> tuple[bytes, bytes] | None:
        """
        Read one message as (body, raw_including_mli).

        One recv can complete several messages, so they are queued rather than
        returned-and-dropped — otherwise a burst would silently lose all but
        the first.
        """
        if self._sock is None:
            raise ConnectionError("Link is not connected")

        if self._ready:
            return self._ready.pop(0)

        # Bytes already buffered may complete a message with no further read.
        self._ready.extend(self._reader.feed(b""))
        if self._ready:
            return self._ready.pop(0)

        self._sock.settimeout(self.timeout if timeout is None else timeout)
        while True:
            try:
                chunk = self._sock.recv(4096)
            except socket.timeout:
                return None
            if not chunk:
                return None                      # peer closed
            self._ready.extend(self._reader.feed(chunk))
            if self._ready:
                return self._ready.pop(0)
