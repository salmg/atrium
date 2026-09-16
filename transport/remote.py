"""
Remote card transport — connects to a ``card_proxy.py`` server running on the
machine that has physical access to the card reader.

Wire protocol (over TCP, optionally wrapped in TLS):
    Request:  2-byte big-endian length  +  APDU bytes
    Response: 2-byte big-endian length  +  response bytes

Special one-byte requests:
    b'A'  → server replies with ATR bytes (no length prefix on ATR)
    b'R'  → server performs a card reset and replies b'OK'

Usage example
-------------
    from transport.remote import RemoteCardTransport
    t = RemoteCardTransport(host="192.168.1.50", port=7654)
    t.connect()
    atr = t.get_atr()
    resp = t.transmit(bytes.fromhex("00A4040007A0000000031010"))
    t.disconnect()
"""
from __future__ import annotations

import socket
import struct

from transport.base import CardTransport


class RemoteCardTransport(CardTransport):
    """
    Client for a remote card_proxy.py server.

    Two modes:

    * **paired** — pass ``pairing`` (the string from ``atrium pair`` on the card
      host).  TLS with the server certificate pinned by fingerprint, plus a
      token.  Use this whenever the link crosses a network.
    * **plaintext** — pass ``host``/``port``.  No encryption and no
      authentication, so only over loopback or an SSH tunnel.
    """

    DEFAULT_PORT = 7654

    def __init__(
        self,
        host: str = "",
        port: int = DEFAULT_PORT,
        timeout: float = 10.0,
        pairing: str | None = None,
    ) -> None:
        """
        host/port      plaintext link — loopback or an SSH tunnel only.
        pairing        pairing string from `atrium pair` on the card host. When
                       given it supplies the address too, and the link is TLS
                       with a pinned certificate and token auth.
        """
        self.timeout = timeout
        self.pairing = pairing
        self._sock: socket.socket | None = None

        if not pairing and not host:
            raise ValueError("RemoteCardTransport needs either a pairing string "
                             "or a host address")

        if pairing:
            from secure_link import parse_pairing
            info = parse_pairing(pairing)
            self.host = info["host"]
            self.port = info["port"]
            self._fingerprint = info["fingerprint"]
            self._token = info["token"]
        else:
            self.host = host
            self.port = port
            self._fingerprint = None
            self._token = None

    @property
    def secure(self) -> bool:
        return self._fingerprint is not None

    # ------------------------------------------------------------------
    # CardTransport interface
    # ------------------------------------------------------------------

    def connect(self) -> None:
        if self.secure:
            # Pinned TLS + token. The previous code fell back to CERT_NONE when
            # no CA was supplied, which encrypts but authenticates nothing and
            # is trivially machine-in-the-middled.
            from secure_link import connect_authenticated
            self._sock = connect_authenticated(
                self.host, self.port, self._fingerprint, self._token, self.timeout
            )
        else:
            self._sock = socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            )

    def get_atr(self) -> bytes:
        # 'A' is a framed 1-byte payload, not a bare byte: card_proxy reads a
        # 2-byte length header for every request.
        self._send_framed(b"A")
        length = struct.unpack("!H", self._recv_exact(2))[0]
        return self._recv_exact(length)

    def reset(self) -> bytes:
        """Ask the proxy to power-cycle the card and return the new ATR."""
        self._send_framed(b"R")
        length = struct.unpack("!H", self._recv_exact(2))[0]
        self._recv_exact(length)          # "OK"
        return self.get_atr()

    def transmit(self, apdu: bytes) -> bytes:
        self._send_framed(apdu)
        length = struct.unpack("!H", self._recv_exact(2))[0]
        return self._recv_exact(length)

    def disconnect(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _send_framed(self, data: bytes) -> None:
        frame = struct.pack("!H", len(data)) + data
        self._send_raw(frame)

    def _send_raw(self, data: bytes) -> None:
        assert self._sock is not None, "Not connected — call connect() first"
        self._sock.sendall(data)

    def _recv_exact(self, n: int) -> bytes:
        assert self._sock is not None, "Not connected"
        buf = b""
        while len(buf) < n:
            chunk = self._sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("Remote closed connection mid-receive")
            buf += chunk
        return buf
