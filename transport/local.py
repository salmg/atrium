"""
A card in a local PC/SC reader, behind the ``CardTransport`` interface.

The relay already talks to local cards through ``RelayOS``, but that class is a
``SmartcardOS`` for the virtual-card side and calls ``sys.exit`` when a reader
is missing — fine for a CLI, fatal for a request handler. Everything that just
needs "the card in that reader" uses this instead, and the three transports
then cover the three places a card can be: local, remote, and in an RF field.
"""
from __future__ import annotations

import logging

from transport.base import CardTransport

logger = logging.getLogger(__name__)


class LocalCardTransport(CardTransport):
    """A contact card in a PC/SC reader, addressed by index or name fragment."""

    def __init__(self, reader: int | str | None = None) -> None:
        self.reader = reader
        self.name: str | None = None
        self._session = None

    # ── lifecycle ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        from core.readers import ReaderError, resolve

        # Reader choice is settled before pyscard is imported, so pointing the
        # relay at its own output side is refused with the same message on a
        # machine that has no PC/SC stack installed at all.
        chosen = resolve(self.reader)          # raises ReaderError, does not exit
        if chosen.is_virtual:
            raise ReaderError(
                f"Reader '{chosen.name}' is the virtual one — it is ATRIUM's own "
                f"output side, not a slot holding a card. Name a real reader.")

        self.name = chosen.name
        import smartcard
        try:
            self._session = smartcard.Session(chosen.name)
        except Exception as exc:               # noqa: BLE001 — pyscard raises several
            raise ReaderError(f"Could not connect to a card in '{chosen.name}': {exc}") from exc
        logger.info("Connected to card in '%s'", chosen.name)

    def disconnect(self) -> None:
        if self._session is None:
            return
        try:
            self._session.close()
        except Exception:                      # noqa: BLE001
            logger.debug("Ignoring error while closing the card session", exc_info=True)
        finally:
            self._session = None

    # ── traffic ──────────────────────────────────────────────────────────────

    def _require(self):
        if self._session is None:
            raise RuntimeError("LocalCardTransport.connect() has not been called")
        return self._session

    def get_atr(self) -> bytes:
        return bytes(self._require().getATR())

    def transmit(self, apdu: bytes) -> bytes:
        data, sw1, sw2 = self._require().sendCommandAPDU(list(apdu))
        data = list(data)
        # pyscard is inconsistent about whether the status word is also left on
        # the end of the data (sourceforge #3083586), so appending it blindly
        # duplicates it for some readers. Only add it when it is not there.
        if data[-2:] != [sw1, sw2]:
            data = data + [sw1, sw2]
        return bytes(data)
