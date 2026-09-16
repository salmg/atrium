import logging
import sys
import atexit

import smartcard
from virtualsmartcard.VirtualSmartcard import SmartcardOS


class RelayOS(SmartcardOS):
    """
    This class implements relaying of a (physical) smartcard. The RelayOS
    forwards the command APDUs received from the vpcd to the real smartcard via
    an actual smart card reader and sends the responses back to the vpcd.
    This class can be used to implement relay or MitM attacks.
    """
    def __init__(self, readernum=None):
        """
        Initialize the connection to the (physical) smart card via a given
        reader.

        ``readernum`` may be an index, a name fragment, or None to let
        core.readers choose. None is the useful default: with vpcd running the
        virtual reader usually takes index 0, and that is this relay's own
        output side rather than a slot holding a card.
        """
        from core.readers import ReaderError, resolve

        try:
            chosen = resolve(readernum)
        except ReaderError as exc:
            logging.error("%s", exc)
            sys.exit(1)

        if chosen.is_virtual:
            logging.warning(
                "Reader '%s' is the virtual one — relaying a card to itself "
                "will not work. Plug in a reader, or name the right one.",
                chosen.name)

        # XXX this is a workaround, see on sourceforge bug #3083254
        # should better use
        # self.reader = smartcard.System.readers()[readernum]
        self.reader = chosen.name
        try:
            self.session = smartcard.Session(self.reader)
        except smartcard.Exceptions.CardConnectionException as e:
            logging.error("Error connecting to card: %s", e.message)
            sys.exit()

        logging.info("Connected to card in '%s'", self.reader)

        atexit.register(self.cleanup)

    def cleanup(self):
        """
        Close the connection to the physical card
        """
        try:
            self.session.close()
        except smartcard.Exceptions.CardConnectionException as e:
            logging.warning("Error disconnecting from card: %s", e.message)

    def getATR(self):
        # when powerDown has been called, fetching the ATR will throw an error.
        # In this case we must try to reconnect (and then get the ATR).
        try:
            atr = self.session.getATR()
        except (smartcard.Exceptions.CardConnectionException, SystemError, Exception) as e:
            try:
                # Try to reconnect to the card
                self.session.close()
                self.session = smartcard.Session(self.reader)
                atr = self.session.getATR()
            except (smartcard.Exceptions.CardConnectionException, SystemError, Exception) as e:
                logging.error("Error getting ATR: %s", e)
                sys.exit()

        return bytes(atr)

    def powerUp(self):
        # When powerUp is called multiple times the session is valid (and the
        # card is implicitly powered) we can check for an ATR. But when
        # powerDown has been called, the session gets lost. In this case we
        # must try to reconnect (and power the card).
        try:
            self.session.getATR()
        except smartcard.Exceptions.CardConnectionException as e:
            try:
                self.session = smartcard.Session(self.reader)
            except smartcard.Exceptions.CardConnectionException as e:
                logging.error("Error connecting to card: %s", e.message)
                sys.exit()

    def powerDown(self):
        # There is no power down in the session context so we simply
        # disconnect, which should implicitly power down the card.
        try:
            self.session.close()
        except smartcard.Exceptions.CardConnectionException as e:
            logging.error("Error disconnecting from card: %s", str(e))
            sys.exit()

    def reset(self):
        self.powerDown()
        self.powerUp()

    def execute(self, msg):
        # sendCommandAPDU() expects a list of APDU bytes
        if isinstance(msg, (bytes, bytearray)):
            apdu = list(msg)
        else:
            apdu = [ord(c) for c in msg]

        try:
            rapdu, sw1, sw2 = self.session.sendCommandAPDU(apdu)
        except smartcard.Exceptions.CardConnectionException as e:
            logging.error("Error transmitting APDU: %s", str(e))
            sys.exit()

        # XXX this is a workaround, see on sourceforge bug #3083586
        # should better use
        # rapdu = rapdu + [sw1, sw2]
        if rapdu[-2:] == [sw1, sw2]:
            pass
        else:
            rapdu = rapdu + [sw1, sw2]

        return bytes(rapdu)
