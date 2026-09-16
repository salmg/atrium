"""
An Android phone as the card, over NFCGate.

The phone runs NFCGate in **reader mode** with a card in its RF field; ATRIUM
joins the same session as the other peer and sends the commands.  From above,
that is the same ``CardTransport`` as a card in a local reader — APDUs are the
same currency however far they travel::

    ATRIUM ──► NFCGateTransport ──► server ──► phone (reader mode) ──RF──► card

What this is good for is the case the ACR122U path cannot cover: reading a
contactless card with hardware you already own, anywhere the phone can reach
the server.  No root, no Xposed — reader mode is a stock-Android feature of the
app.  (Presenting a card *to* a terminal from the phone is the other half, and
needs both; see ``doc/nfcgate-android.md``.)

Three honest differences from the contact transport
---------------------------------------------------
**It answers with an ATS, and a partial one.**  Like the ACR122U path, a
contactless card has no ATR.  Worse here: NFCGate forwards the tag's NCI
configuration rather than the ATS itself, and two fields do not survive — FSCI
is never sent, and TA(1) arrives as a lossy bit-rate code.  ``get_atr`` returns
what can be rebuilt, and says so in the log once.  ``tag`` has the fields the
phone really did report, which is more than the ACR122U hands over: UID, SAK
and ATQA all arrive named.

**Timing is not transparent, and there is a network in it.**  Every APDU is an
RF exchange, a phone's NFC stack, a network round trip and back.  EMV
contactless kernels enforce a transaction budget; this will sometimes lose that
race, and mutation rules that inject extra commands spend it twice.

**The link is only as private as the server.**  NFCGate's server has no
authentication by design.  Keep it on loopback or a network you own.

None of this has been exercised against a real phone from the machine it was
written on.  The protocol is covered by tests against a fake peer, and was
verified end-to-end against NFCGate's own server (``doc/verify_relay.py``); the
RF behaviour on the far side is not, and cannot be.
"""
from __future__ import annotations

import logging

from nfcgate.proto import CONTINUATION, READER, TagConfig
from nfcgate.session import DEFAULT_PORT, DEFAULT_SESSION, NFCGateSession, PeerGone
from transport.base import CardTransport

logger = logging.getLogger(__name__)

# A human has to pick the phone up, open the app and hold it to a card. The
# default has to be patient enough for that without being unbounded.
DEFAULT_TAG_WAIT = 60.0

# Once the relay is running, an APDU that takes this long is not coming.
DEFAULT_APDU_TIMEOUT = 15.0


class NFCGateTransport(CardTransport):
    """A card in a phone's RF field, reached through an NFCGate session."""

    def __init__(
        self,
        host: str,
        port: int = DEFAULT_PORT,
        session: int = DEFAULT_SESSION,
        *,
        cafile: str | None = None,
        tag_wait: float = DEFAULT_TAG_WAIT,
        timeout: float = DEFAULT_APDU_TIMEOUT,
    ) -> None:
        self.host = host
        self.port = port
        self.session_number = session
        self.tag_wait = tag_wait
        self.timeout = timeout
        self.tag = TagConfig()
        self._session = NFCGateSession(
            host, port, session, timeout=timeout, cafile=cafile)

    @property
    def secure(self) -> bool:
        return self._session.secure

    # ── lifecycle ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        """
        Join the session and wait for the phone to report a tag.

        Both waits are deliberate. There is no card until the phone says there
        is, and returning a transport that has never seen one would move the
        failure to the first ``transmit`` — where it looks like the card went
        away rather than like it never arrived.
        """
        self._session.connect()
        try:
            self._session.wait_for_peer(self.tag_wait)
            self._await_tag()
        except Exception:
            self._session.close()
            raise

    def disconnect(self) -> None:
        self._session.close()

    def get_atr(self) -> bytes:
        """
        The tag's ATS, rebuilt from the configuration the phone sent.

        Empty when the tag contributed no historical bytes — an ATS invented
        whole would be a claim about a card nobody made.
        """
        return self.tag.ats

    # ── the exchange ─────────────────────────────────────────────────────────

    def transmit(self, apdu: bytes) -> bytes:
        """
        Send a command APDU to the phone and return what the card answered.

        A tag configuration arriving mid-exchange is not a response: the phone
        re-detected a tag, so the record is updated and the wait continues.
        """
        self._session.send_nfcdata(bytes(apdu), data_source=READER,
                                   data_type=CONTINUATION)
        while True:
            message = self._session.recv_nfcdata(self.timeout)
            if message.is_initial:
                self._adopt(message.data, again=True)
                continue
            if not message.data:
                # The phone forwards an empty body when the tag did not answer.
                raise PeerGone(
                    "The phone reported no answer from the card — it probably left "
                    "the field. Hold it back on the tag and try again.")
            return message.data

    # ── internals ────────────────────────────────────────────────────────────

    def _await_tag(self) -> None:
        """Block until the phone sends the tag's configuration."""
        while True:
            message = self._session.recv_nfcdata(self.tag_wait)
            if message.is_initial:
                self._adopt(message.data)
                return
            logger.warning(
                "NFCGate: the phone sent traffic before any tag configuration "
                "(%s) — ignoring it and still waiting for a tag",
                message.data[:8].hex().upper())

    def _adopt(self, config: bytes, *, again: bool = False) -> None:
        self.tag = TagConfig.from_stream(config)
        logger.info("NFCGate: %s tag on the phone — %s",
                    "another" if again else "a", self.tag.describe())
        if self.tag.ats_is_partial:
            logger.info(
                "NFCGate: the ATS is rebuilt from the tag configuration — FSCI is "
                "not sent by NFCGate and TA(1) does not survive the trip, so those "
                "two are not the card's")
        elif not self.tag.historical_bytes:
            logger.warning(
                "NFCGate: the tag sent no historical bytes, so there is no ATS to "
                "report. %s", self.tag.describe())

    def __repr__(self) -> str:                          # pragma: no cover - debugging
        return (f"NFCGateTransport({self.host}:{self.port} "
                f"session {self.session_number})")
