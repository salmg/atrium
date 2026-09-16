"""
RemoteRelayOS — drive a card that lives on another machine.

The relay stack expects a virtualsmartcard ``SmartcardOS`` (getATR / powerUp /
powerDown / reset / execute).  ``transport.remote.RemoteCardTransport`` speaks a
different, simpler shape (connect / get_atr / transmit / disconnect).  This
adapter bridges the two so ``VirtualCard`` can relay to a remote reader exactly
as it does to a local one.

Server side is ``card_proxy.py`` running next to the physical reader.

Note that the proxy has no authentication: keep it on loopback and reach it
through an SSH tunnel rather than exposing the port.  See README § Security
model.
"""
from __future__ import annotations

import atexit
import logging

from virtualsmartcard.VirtualSmartcard import SmartcardOS

from transport.remote import RemoteCardTransport

log = logging.getLogger(__name__)


class RemoteRelayOS(SmartcardOS):
    """SmartcardOS backed by a card_proxy.py instance over TCP."""

    def __init__(self, host: str = "", port: int = 7654, timeout: float = 10.0,
                 pairing: str | None = None) -> None:
        self._transport = RemoteCardTransport(
            host=host, port=port, timeout=timeout, pairing=pairing
        )
        self.host = self._transport.host
        self.port = self._transport.port
        self.secure = self._transport.secure
        self._connected = False
        self.connect()
        atexit.register(self.cleanup)

    # ── connection lifecycle ─────────────────────────────────────────────
    def connect(self) -> None:
        if self._connected:
            return
        self._transport.connect()
        self._connected = True
        log.info("Connected to remote card proxy at %s:%d (%s)", self.host,
                 self.port, "TLS + pinned cert" if self.secure else "plaintext")

    def cleanup(self) -> None:
        if not self._connected:
            return
        try:
            self._transport.disconnect()
        except Exception as exc:                       # noqa: BLE001 — best effort
            log.warning("Error closing remote card connection: %s", exc)
        finally:
            self._connected = False

    # ── SmartcardOS interface ────────────────────────────────────────────
    def getATR(self) -> bytes:
        self.connect()
        return self._transport.get_atr()

    def powerUp(self) -> None:
        # A TCP transport has no power line; reconnecting is the closest
        # equivalent and makes a dropped proxy recoverable.
        self.connect()

    def powerDown(self) -> None:
        self.cleanup()

    def reset(self) -> None:
        self.powerDown()
        self.powerUp()

    def execute(self, msg) -> bytes:
        """
        Relay one command APDU.  vpcd hands us either bytes or a str of
        char-codes depending on version, matching RelayOS's own handling.
        """
        if isinstance(msg, (bytes, bytearray)):
            apdu = bytes(msg)
        else:
            apdu = bytes(ord(c) for c in msg)

        self.connect()
        return self._transport.transmit(apdu)
