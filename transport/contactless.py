"""
Contactless card transport — an ACR122U in reader mode.

Implements the same ``CardTransport`` the contact side uses, so a contactless
card can be fingerprinted, relayed and mutated by code that has no idea which
interface it is talking to.  APDUs are the same currency either way.

Two honest differences from the contact transport
--------------------------------------------------
A contactless card answers with an **ATS**, not an ATR.  ``get_atr`` returns
the ATS bytes because that is what the interface has to offer, and callers that
print it as "ATR" will be printing an ATS.  The two are not interchangeable —
ATRIUM is named after the ATR precisely because the contact interface is its
home ground.

The chip's buffer caps one exchange at 262 bytes, so an APDU longer than that
needs chaining, which is not implemented.  It raises rather than truncating,
because a silently shortened APDU produces a response that looks real.
"""
from __future__ import annotations

import logging

from transport.base import CardTransport

logger = logging.getLogger(__name__)


class ContactlessTransport(CardTransport):
    """
    A card in an ACR122U's field.

    Ordinary contactless reads could go through PC/SC directly; this drives the
    PN532 instead so that reading and emulating share one code path and one set
    of error messages.
    """

    def __init__(self, reader_name: str | None = None, retries: int = 2) -> None:
        self.reader_name = reader_name
        self.retries = retries
        self._chip = None
        self._link = None
        self._target = None
        # Whether this transport was the one that switched the reader's own
        # polling off, so disconnect only restores what it changed.
        self._polling_suspended = False
        # How many times a stale target had to be re-activated mid-session.
        # Reported rather than hidden: a re-activation resets the card to the
        # master file, so anything selected before it is no longer selected.
        self.reactivations = 0

    # ── lifecycle ────────────────────────────────────────────────────────────

    def _resolve_reader(self) -> str:
        if self.reader_name:
            return self.reader_name
        from core.readers import ReaderError, probe

        readers, problem = probe()
        if not readers:
            raise ReaderError(problem or "No readers available")
        for reader in readers:
            if reader.is_pn532:
                return reader.name
        raise ReaderError(
            "No PN532-based reader found. This needs an ACR122U; the readers "
            "present are:\n" + "\n".join(f"  {r.label}  ({r.kind})" for r in readers))

    def connect(self) -> None:
        from nfc.acr122 import ACR122Error, open_pn532
        from nfc.pn532 import PN532Error

        name = self._resolve_reader()
        # Record which reader was actually used, so a caller that passed None
        # can still name the hardware in an error or a status readout.
        self.reader_name = name
        # Connect to the reader rather than to a card: at this point the field
        # may well be empty, and finding the card is this method's job.
        self._chip, self._link = open_pn532(name, direct=True)

        try:
            self._chip.set_retries(self.retries)
            targets = self._chip.list_passive_targets(limit=1)
        except (ACR122Error, PN532Error):
            self.disconnect()
            raise

        if not targets:
            self.disconnect()
            raise ConnectionError(
                f"No contactless card in the field of '{name}'. Place the card "
                "on the reader and try again.")

        self._target = targets[0]
        if not self._target.is_iso14443_4:
            self.disconnect()
            raise ConnectionError(
                f"The card in the field does not speak ISO 14443-4 (SAK "
                f"{self._target.sak:02X}), so it cannot carry APDUs. EMV needs "
                "a 14443-4 card; this looks like a memory card such as a "
                "MIFARE Classic.")
        if not self._target.ats:
            self.disconnect()
            raise ConnectionError(
                f"The card on '{name}' says it speaks ISO 14443-4 (SAK "
                f"{self._target.sak:02X}) but returned no ATS, which means RATS "
                f"never completed — so it is not actually activated and will "
                f"answer nothing.\n"
                f"Usually the chip has automatic RATS switched off from an "
                f"earlier session. Re-running this reopens the reader and "
                f"restores it; if it persists, unplug the reader.\n"
                f"Otherwise the card moved out of the field mid-activation — "
                f"hold it still and try again.")

        self._suspend_reader_polling()
        logger.info("Contactless card selected on %s: %s", name, self._target)

    def _suspend_reader_polling(self) -> None:
        """
        Stop the ACR122U hunting for cards while we are holding one.

        The reader's firmware runs its own polling loop independently of the
        PN532 commands sent over the escape channel. Every sweep redoes
        anticollision, and that drops the target this transport activated —
        after which InDataExchange answers 27, "the command makes no sense in
        the current context", and the card appears to have failed when it was
        never asked.

        It costs nothing while the field is idle and everything during a
        relay, where the card sits activated for however long it takes a
        terminal to arrive. That wait is seconds; the polling interval is
        shorter.
        """
        from nfc.acr122 import PICC_POLLING_OFF, set_picc_polling

        if self._link is None:
            return
        if set_picc_polling(self._link, PICC_POLLING_OFF) is None:
            logger.debug("Reader would not suspend its own polling; a long "
                         "idle may cost the target")
            return
        self._polling_suspended = True
        logger.debug("Reader's own card polling suspended for this session")

    def _restore_reader_polling(self) -> None:
        """Put the reader back the way it was found."""
        from nfc.acr122 import PICC_POLLING_ON, set_picc_polling

        if not self._polling_suspended or self._link is None:
            return
        self._polling_suspended = False
        set_picc_polling(self._link, PICC_POLLING_ON)

    def disconnect(self) -> None:
        self._restore_reader_polling()
        if self._chip is not None and self._target is not None:
            self._chip.release(self._target.number)
        if self._link is not None:
            self._link.close()
        self._chip = self._link = self._target = None

    # ── CardTransport ────────────────────────────────────────────────────────

    def get_atr(self) -> bytes:
        """
        The card's ATS.

        Named get_atr because that is the interface the rest of the codebase
        speaks; the bytes are an ATS, which is a different thing carrying a
        similar job. Empty when the card gave none.
        """
        if self._target is None:
            raise ConnectionError("Not connected — call connect() first")
        return bytes(self._target.ats)

    @property
    def uid(self) -> bytes:
        if self._target is None:
            raise ConnectionError("Not connected — call connect() first")
        return bytes(self._target.uid)

    def transmit(self, apdu: bytes) -> bytes:
        from nfc.pn532 import TargetLost

        if self._chip is None or self._target is None:
            raise ConnectionError("Not connected — call connect() first")
        try:
            return self._chip.data_exchange(bytes(apdu),
                                            target=self._target.number)
        except TargetLost:
            # Suspending the reader's polling should prevent this; a reader
            # that would not take the setting can still lose the target, and
            # the alternative to recovering is a failed transaction.
            if not self._reactivate():
                raise
        return self._chip.data_exchange(bytes(apdu), target=self._target.number)

    def _reactivate(self) -> bool:
        """
        Find the same card again after the chip lost it. False if it is gone.

        Deliberately refuses a *different* card. Anticollision picks whatever
        is in the field, and on a relay rig the field is a place cards get put;
        silently continuing against another one would relay a card the operator
        did not choose, which is worse than failing.

        The recovered card is at the master file: activation resets it, so any
        application selected before this is no longer selected. Said out loud
        because a 6985 two commands later is otherwise unattributable.
        """
        from nfc.pn532 import PN532Error

        was = bytes(self._target.uid) if self._target else b""
        try:
            targets = self._chip.list_passive_targets(limit=1)
        except PN532Error:
            logger.debug("Could not look for the card again", exc_info=True)
            return False
        if not targets:
            logger.warning("The chip lost the card and it is no longer in the "
                           "field of '%s'", self.reader_name)
            return False
        if bytes(targets[0].uid) != was:
            logger.warning(
                "The chip lost card %s and found %s in its place — refusing to "
                "carry on against a card that was not the one chosen",
                was.hex().upper(), bytes(targets[0].uid).hex().upper())
            return False

        self._target = targets[0]
        self.reactivations += 1
        logger.warning(
            "The chip had lost card %s and it has been activated again. That "
            "resets it to the master file, so any application selected before "
            "now is not selected any more. Usually the reader's own polling "
            "loop; this transport asks it to stop, and this reader did not.",
            was.hex().upper())
        return True
