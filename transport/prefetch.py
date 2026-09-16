"""
Answer the predictable part of a transaction without waiting for the card.

Where the time goes is measured, not theoretical.  One relayed exchange on this
rig takes 74-87 ms, of which:

* the card's own answer, over RF, is **~50 ms** — measured two independent ways,
  through the PN532 escape channel and through an ordinary PC/SC card
  connection, which agree to within 0.3 ms;
* the whole CCID bridge is **~2.8 ms per escape**, three of them, about 8 ms.

So the card is the ceiling, not the transport, and no faster route to it exists:
both routes end in the same ``InDataExchange`` inside the reader's own
microcontroller.

**This is a latency win, not a rescue.**  It was written believing the chip
advertised a card-like 38.7 ms frame waiting time, which would have made a live
exchange impossible and a cache the only way through.  ``nfc measure-ats`` then
read the chip's real ATS: FWI 9, **155 ms**.  A live 87 ms exchange fits inside
that, so the firmware path can carry a whole transaction unaided and this is no
longer load-bearing.

What it still does is real: a cache hit does not ask the card at all, so it
costs one escape — about 3 ms — instead of fifty.  On this rig that took a
measured relay from 74 ms to 32 ms.  Worth having on a slow card, a remote one,
or a terminal stricter than this one.  Not worth having on by default.

What is safe to cache, and why so little
----------------------------------------
Two commands in a contactless EMV flow are deterministic *and* free of terminal
input: ``SELECT 2PAY.SYS.DDF01`` and ``SELECT <AID>``.  The AID is discoverable
from the PPSE's own FCI without any terminal involvement, so both can be fetched
during the wait for a terminal — a window measured in minutes.

Everything else is refused by an allowlist rather than a denylist, because a
denylist eventually meets a command nobody thought of:

* **GET PROCESSING OPTIONS** looks cacheable and is not.  For qVSDC and some
  M/Chip profiles the card picks its AIP and AFL from the terminal's TTQ in the
  PDOL, so serving a warm-up's answer to a terminal that asked differently hands
  it a profile the card never authorised for that transaction — and the
  cryptogram that follows is computed over a different context.  That is a
  correctness break wearing a latency win's clothes.
* **GENERATE AC** covers a terminal-chosen unpredictable number.
* **EXCHANGE RELAY RESISTANCE DATA** is timed by the terminal in microseconds
  and is the one command this whole rig exists to be caught by.  Answering it
  from a cache would be forging the measurement it makes.

Only ``9000`` responses are cached.  A cached ``6A82`` would make the emulated
card permanently refuse an application the real one might serve next time.

Where this sits, and why there
------------------------------
It is a ``CardTransport`` that wraps another one, so it goes exactly where the
emulator reaches the card and nowhere else.  Putting the same logic inside
``_relay`` would get three things wrong that this gets right for free: the key
would be the command *before* mutation rather than the bytes that actually reach
the card; a cached response would skip the response-mutation hooks; and the
card-timing counters would record a warm-up read as though a terminal had waited
for it, which is enough to make the relay report a timeout on a run that worked.

It is off by default.  ATRIUM's worth is that a trace says what the card did,
and a cache changes that to what the card said a minute ago — nearly always the
same thing for a SELECT, but "nearly always" is a claim the operator should make
deliberately.
"""
from __future__ import annotations

import logging
import threading

from transport.base import CardTransport

logger = logging.getLogger(__name__)

PPSE_NAME = b"2PAY.SYS.DDF01"

# SELECT by name, and READ RECORD. Nothing else, ever — see the module docstring.
CACHEABLE_INSTRUCTIONS = {
    (0x00, 0xA4, 0x04),      # SELECT by DF name
    (0x00, 0xB2, None),      # READ RECORD — static card data, but see below
}

SW_OK = b"\x90\x00"


def select_by_name(name: bytes, *, le: bool = True) -> bytes:
    """
    A SELECT for a DF name, with or without a trailing Le.

    Kernels differ on whether they send one, and the cache is keyed on exact
    bytes, so a warm-up that guesses wrong is a warm-up that never hits. Both
    forms are cheap in a window this long.
    """
    apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(name)]) + name
    return apdu + b"\x00" if le else apdu


def aids_in_ppse(response: bytes) -> list[bytes]:
    """
    Every AID the PPSE's FCI advertises, in the order it lists them.

    Walks the BER-TLV rather than searching for 4F, so a 4F that happens to
    appear inside some other value is not mistaken for an application
    identifier. Returns nothing rather than raising on a malformed response —
    a warm-up that cannot read the directory simply warms less.
    """
    found: list[bytes] = []

    def walk(data: bytes, depth: int = 0) -> None:
        if depth > 6:
            return
        i = 0
        while i < len(data):
            if data[i] in (0x00, 0xFF):          # padding between objects
                i += 1
                continue
            tag = data[i]
            i += 1
            constructed = bool(tag & 0x20)
            if tag & 0x1F == 0x1F:               # multi-byte tag
                if i >= len(data):
                    return
                tag = (tag << 8) | data[i]
                i += 1
                while data[i - 1] & 0x80:
                    if i >= len(data):
                        return
                    tag = (tag << 8) | data[i]
                    i += 1
            if i >= len(data):
                return
            length = data[i]
            i += 1
            if length & 0x80:                    # long form
                count = length & 0x7F
                if count == 0 or i + count > len(data):
                    return
                length = int.from_bytes(data[i:i + count], "big")
                i += count
            if i + length > len(data):
                return
            value = data[i:i + length]
            i += length
            if tag == 0x4F:
                if value and value not in found:
                    found.append(bytes(value))
            elif constructed:
                walk(value, depth + 1)

    walk(bytes(response[:-2]) if len(response) >= 2 else b"")
    return found


class PrefetchingTransport(CardTransport):
    """
    A card transport that answers deterministic SELECTs from a warm-up.

    Wraps another transport and forwards everything it cannot answer. The
    wrapped transport is the one that talks to hardware; this one only ever
    remembers what it said.
    """

    def __init__(self, inner: CardTransport, *, read_records: bool = False) -> None:
        self.inner = inner
        # READ RECORD responses are static card data and sound to cache, but
        # reaching them needs a warm-up GET PROCESSING OPTIONS, and most cards
        # increment the application transaction counter there. The terminal's
        # real transaction would then present an ATC one higher than the issuer
        # expects, and issuers check that. Off unless asked for.
        self.read_records = read_records
        self._cache: dict[bytes, bytes] = {}
        # ACR122Link has no lock and IsoDepEmulator already relays from a
        # worker thread, so two threads inside one card link is reachable. A
        # torn CCID exchange does not fail cleanly — it returns another
        # command's response.
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        # Which AID the warm-up left the card sitting on, and which one the
        # terminal actually chose. They are usually the same — the terminal
        # picks the top-priority application, which is the last one warmed —
        # and when they are not, the card is on the wrong one.
        self._resting_aid: bytes | None = None
        self._terminal_aid: bytes | None = None
        self._repaired = False

    # ── CardTransport ────────────────────────────────────────────────────────

    def connect(self) -> None:
        self.inner.connect()
        self._warm_up()

    def get_atr(self) -> bytes:
        return self.inner.get_atr()

    def disconnect(self) -> None:
        self.inner.disconnect()

    def __getattr__(self, name):
        # uid, reader_name and anything else a concrete transport offers.
        # Only reached for attributes this class does not define itself.
        return getattr(self.__dict__["inner"], name)

    def transmit(self, apdu: bytes) -> bytes:
        command = bytes(apdu)
        with self._lock:
            cached = (self._cache.get(command)
                      if self.is_cacheable(command, self.read_records) else None)
            if cached is not None:
                self.hits += 1
                # A SELECT answered from memory never reached the card, so the
                # card does not know the terminal made it. Remember what it
                # thinks it selected, because the card has to be put there
                # before anything that depends on the selection.
                aid = self._selected_aid(command)
                if aid is not None:
                    self._terminal_aid = aid
                logger.debug("Served %s from the warm-up", command[:8].hex().upper())
                return cached

            self.misses += 1
            # The warm-up left the card on some application; the terminal may
            # have chosen another. Put it back before the first command that
            # actually reaches the card, which is an exchange already over
            # budget and therefore the cheapest place to pay for it.
            self._repair(command)
            return self.inner.transmit(command)

    # ── the warm-up ──────────────────────────────────────────────────────────

    def _warm_up(self) -> None:
        """
        Fetch what the terminal is certain to ask for, before it arrives.

        Runs inside connect(), which happens before the relay arms, so none of
        this lands in the timing the terminal is measured against.
        """
        ppse = None
        for form in (True, False):
            command = select_by_name(PPSE_NAME, le=form)
            response = self._remember(command)
            if response is not None and ppse is None:
                ppse = response

        if ppse is None:
            logger.info("The card did not answer a PPSE, so there is nothing "
                        "to warm up; every exchange will go to the card")
            return

        aids = aids_in_ppse(ppse)
        if not aids:
            logger.info("Warmed the PPSE; its directory named no AID")
            return

        logger.info("Warmed the PPSE — %d application(s): %s",
                    len(aids), ", ".join(a.hex().upper() for a in aids))
        for aid in aids:
            for form in (True, False):
                if self._remember(select_by_name(aid, le=form)) is not None:
                    self._resting_aid = aid

        logger.info("Warm-up holds %d response(s); the card is resting on %s",
                    len(self._cache),
                    self._resting_aid.hex().upper() if self._resting_aid else "nothing")

    def _remember(self, command: bytes) -> bytes | None:
        """Ask the card once and keep the answer if it is one worth keeping."""
        try:
            response = self.inner.transmit(command)
        except Exception as exc:                       # noqa: BLE001
            logger.debug("Warm-up %s failed: %s", command[:8].hex().upper(), exc)
            return None
        if len(response) < 2 or response[-2:] != SW_OK:
            # A refusal now may not be a refusal later, and a cached one would
            # be permanent.
            return None
        self._cache[bytes(command)] = bytes(response)
        return bytes(response)

    def _repair(self, command: bytes) -> None:
        """
        Re-select the application the warm-up left, if the terminal chose one.

        A cache hit never reaches the card, so after the terminal's SELECTs are
        answered from memory the card is still where the warm-up left it. That
        is the right place in the common case — the terminal picks the
        top-priority AID, which is the last one warmed. When it picks a
        different one, the card is on the wrong application and answers the
        live GET PROCESSING OPTIONS with 6985, which reads as a card fault and
        is not one.
        """
        if self._repaired:
            return
        self._repaired = True
        wanted = self._terminal_aid
        if wanted is None or wanted == self._resting_aid:
            return
        logger.info("The terminal selected %s from cache but the warm-up left "
                    "the card on %s; re-selecting before this command",
                    wanted.hex().upper(),
                    self._resting_aid.hex().upper() if self._resting_aid else "nothing")
        try:
            self.inner.transmit(select_by_name(wanted))
        except Exception:                              # noqa: BLE001
            logger.warning("Could not put the card back on %s",
                           wanted.hex().upper(), exc_info=True)

    @staticmethod
    def _selected_aid(command: bytes) -> bytes | None:
        if len(command) < 6 or command[:4] != b"\x00\xA4\x04\x00":
            return None
        length = command[4]
        if len(command) < 5 + length:
            return None
        name = command[5:5 + length]
        return None if name == PPSE_NAME else bytes(name)

    # ── what may be cached at all ────────────────────────────────────────────

    @classmethod
    def is_cacheable(cls, command: bytes, read_records: bool = False) -> bool:
        """
        Whether a command may ever be answered from memory.

        An allowlist, because a denylist eventually meets a command nobody
        thought of — and on this interface the command nobody thought of is
        the one that measures how long the card took to answer.
        """
        if len(command) < 4:
            return False
        cla, ins, p1 = command[0], command[1], command[2]
        if (cla, ins, p1) in CACHEABLE_INSTRUCTIONS:
            return True
        return read_records and (cla, ins, None) in CACHEABLE_INSTRUCTIONS
