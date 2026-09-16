"""
REST routes — contactless (ACR122U / PN532).

GET  /api/nfc/status          — PN532-capable readers, chip info, emulator state
POST /api/nfc/scan            — UID + ATS of whatever is in the field
POST /api/nfc/emulate/start   — present an emulated card, relaying to a real one
POST /api/nfc/emulate/stop    — end the emulation

The contactless support was command-line only for its first release, which made
it invisible: an ACR122U showed up in the reader picker and nowhere else, so
there was no way to tell from the dashboard whether the vendor escape path even
worked. These routes are the same three things the CLI does — identify the chip,
read a card, emulate one — with no extra capability.

Single-tenant on purpose, exactly like the relay session: one PN532 is one piece
of hardware, and a second caller starting an emulation would be fighting the
first for the same chip.
"""
from __future__ import annotations

import logging
import threading
import time
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from transport.source import open_card_source

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/nfc", tags=["nfc"])

_ROOT = Path(__file__).parent.parent.parent
LOGS_DIR = _ROOT / "logs"
MUTATIONS_YAML = _ROOT / "mutations.yaml"

# Shapes RecordedCardTransport can read. Anything else in logs/ is not offered,
# so the picker cannot suggest a file that will fail on open.
CAPTURE_SUFFIXES = (".hexlog", ".log", ".json", ".jsonl", ".txt", ".apdu")


class _OsShim:
    """
    The ``.execute(apdu)`` shape ``MutationEngine.from_config`` expects.

    Injected commands go to the relayed card, whatever transport is holding it,
    so this adapts a plain transmit callable rather than requiring a RelayOS.
    """

    def __init__(self, transmit) -> None:
        self.execute = transmit


def _capture_path(name: str) -> str:
    """
    Resolve a capture filename inside logs/ and prove it stayed there.

    The CLI takes any path the operator can type, because they already have a
    shell. A browser request is a different thing: this one is reachable by
    anything that can reach the dashboard, so it reads only from logs/ — the
    same rule the host layer's captures follow, checked on the resolved path so
    a symlink out of the tree is caught too.
    """
    if not name or "/" in name or "\\" in name or "\x00" in name:
        raise HTTPException(400, "Invalid capture name")
    base = LOGS_DIR.resolve()
    candidate = (base / name).resolve()
    if candidate == base or base not in candidate.parents:
        raise HTTPException(400, "Invalid capture name")
    if not candidate.is_file():
        raise HTTPException(404, f"No capture named '{name}' in logs/")
    return str(candidate)


# ── emulator state ───────────────────────────────────────────────────────────

_emu_thread: threading.Thread | None = None
_emu = None                       # the CardEmulator, kept so stop() can reach it
_emu_link = None                  # the ACR122 link, closed on stop
_emu_active = False
_emu_error: str | None = None
_emu_started_at: float | None = None
_emu_lock = threading.Lock()


def _pn532_readers() -> tuple[list[dict], str]:
    from core.readers import probe

    readers, problem = probe()
    return [r.to_dict() for r in readers if r.is_pn532], problem


def _suggest_pair(readers: list[dict]) -> dict:
    """
    Which reader should emulate and which should hold the card.

    A two-ACR122U rig is the setup this is for, and picking the assignment is
    the part that is easy to get backwards — so it is proposed here rather than
    left to the operator to work out from two identical device names. The
    emulator must be a PN532; the card side can be anything that is not
    virtual and is not the emulator.
    """
    emulators = [r for r in readers if r["pn532"]]
    if not emulators:
        return {"emulator": None, "emulator_index": None, "card": None,
                "card_index": None,
                "why": "No PN532 reader present — emulation needs an ACR122U."}

    emulator = emulators[0]
    # Excluded by name rather than by index on purpose. A reader is addressed by
    # its PC/SC name, so if two entries share one they are the same device as
    # far as anything here can reach — refusing that pairing is correct, not
    # over-cautious.
    cards = [r for r in readers
             if not r["virtual"] and r["name"] != emulator["name"]]
    if not cards:
        others = [r for r in readers
                  if not r["virtual"] and r["index"] != emulator["index"]]
        why = ("Only one reader — it can emulate, but there is nothing left to "
               "hold the card. Add a second reader, or relay to a recorded "
               "capture.")
        if others:
            why = (f"Two readers report the same PC/SC name "
                   f"({emulator['name']!r}), so they cannot be told apart well "
                   f"enough to use one for each side. Relay to a recorded "
                   f"capture, or to a card on another host, instead.")
        return {"emulator": emulator["name"], "emulator_index": emulator["index"],
                "card": None, "card_index": None, "why": why}

    # Contact first: a card in a contact slot is the steadier side of a relay
    # than one that has to stay in a second reader's RF field.
    contact = [r for r in cards if r["kind"] == "contact"]
    card = (contact or cards)[0]
    return {"emulator": emulator["name"], "emulator_index": emulator["index"],
            "card": card["name"], "card_index": card["index"], "why": ""}


def _resolve_reader(name: str | None) -> str:
    """A named PN532 reader, or the first one present."""
    from core.readers import ReaderError

    if name:
        return name
    found, problem = _pn532_readers()
    if not found:
        raise ReaderError(
            "No PN532-based reader found. This needs an ACR122U on USB. "
            + (problem or ""))
    return found[0]["name"]


# ── routes ───────────────────────────────────────────────────────────────────

@router.get("/status")
def nfc_status(probe_chip: bool = False, reader: str | None = None,
               details: bool = False) -> dict[str, Any]:
    """
    What contactless hardware is present, and what the emulator is doing.

    The chip probe is opt-in because it claims the reader in direct mode: doing
    it on every poll would take the device away from a scan the operator is in
    the middle of.
    """
    from core.readers import probe

    all_readers, problem = probe()
    all_readers = [r.to_dict() for r in all_readers]

    if details:
        # A direct connection per reader, so it is asked for rather than polled.
        from core.readers import describe_location, physical_id

        for entry in all_readers:
            if entry["virtual"]:
                continue
            entry["where"] = describe_location(physical_id(entry["name"]))

    emulators = [r for r in all_readers if r["pn532"]]

    chip: dict | None = None
    chip_error: str | None = None
    if probe_chip and emulators and not _emu_active:
        wanted = reader or emulators[0]["name"]
        try:
            from nfc.acr122 import open_pn532

            device, link = open_pn532(wanted, direct=True)
            try:
                chip = device.firmware_version()
                chip["reader"] = wanted
            finally:
                link.close()
        except Exception as exc:                       # noqa: BLE001
            chip_error = str(exc)

    return {
        "ok": True,
        # Every reader, so the card side can be a contact slot too; "emulators"
        # is the subset that can present a card.
        "all_readers": all_readers,
        "emulators": emulators,
        "readers": emulators,          # kept: the old name for the same list
        "suggested": _suggest_pair(all_readers),
        "problem": problem if not all_readers else "",
        "chip": chip,
        "chip_error": chip_error,
        "emulating": _emu_active,
        "exchanges": getattr(_emu, "exchanges", 0) if _emu else 0,
        # Times target mode has been re-armed with nobody there yet. Zero and
        # emulating means armed and listening; climbing means listening and
        # waiting. Without it the two look the same from the dashboard.
        "arm_attempts": getattr(_emu, "arm_attempts", 0) if _emu else 0,
        # Terminal sessions so far. More than one means a terminal read this
        # card, let go, and came back — which is what several kernels do
        # between discovery and the transaction proper.
        "sessions": getattr(_emu, "sessions", 0) if _emu else 0,
        # Terminals that activated this card and then asked nothing at all.
        # Nothing we answered can explain one, so the objection is to the
        # activation itself — or the terminal was only looking.
        "silent_activations": getattr(_emu, "silent_activations", 0) if _emu else 0,
        # Card responses too big for one Direct Transmit on a chip that will
        # not split them. Each one is a real card answer the terminal never
        # saw, and on this hardware it is the certificate record every EMV
        # transaction turns on.
        "undeliverable": getattr(_emu, "undeliverable", 0) if _emu else 0,
        # Responses handed over as 61 XX for the terminal to collect. Not zero
        # means the trace shows a conversation ATRIUM shaped: the card said it
        # in one APDU and the terminal was told it in several.
        "split_responses": getattr(_emu, "split_responses_used", 0) if _emu else 0,
        # Exchanges answered from the warm-up rather than the card. Zero when
        # prefetch is off, which is the default.
        "prefetch_hits": getattr(getattr(_emu, "transport", None), "hits", 0) if _emu else 0,
        # Times the reader lost the relayed card and it had to be activated
        # again. Should be zero: the transport asks the reader to stop its own
        # polling. Anything else means it refused, and each one reset the card
        # to the master file underneath the transaction.
        "reactivations": getattr(getattr(_emu, "transport", None),
                                 "reactivations", 0) if _emu else 0,
        "mutating": bool(getattr(_emu, "mutations", None)) if _emu_active else False,
        # Responses a rule grew past one exchange, relayed unmutated instead.
        "oversize": getattr(_emu, "oversize", 0) if _emu else 0,
        # Only the ISO-DEP driver reports these; zero on the firmware path.
        "own_isodep": bool(getattr(_emu, "wtxm", None)) if _emu else False,
        "wtx_requests": getattr(_emu, "wtx_requests", 0) if _emu else 0,
        "chained_out": getattr(_emu, "chained_out", 0) if _emu else 0,
        "uptime": (time.time() - _emu_started_at) if (_emu_active and _emu_started_at) else 0,
        "error": _emu_error,
    }


@router.get("/captures")
def list_captures() -> dict[str, Any]:
    """Capture files in logs/ that a recorded card can be built from."""
    if not LOGS_DIR.is_dir():
        return {"ok": True, "captures": []}

    out = []
    for path in sorted(LOGS_DIR.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in CAPTURE_SUFFIXES:
            continue
        try:
            rel = path.relative_to(LOGS_DIR)
        except ValueError:
            continue
        # Only the top level: _capture_path refuses a name with a separator in
        # it, so offering a nested file would offer something unusable.
        if len(rel.parts) != 1:
            continue
        out.append({"name": rel.name, "size": path.stat().st_size})
    return {"ok": True, "captures": out}


class ScanRequest(BaseModel):
    reader: str | None = None


@router.post("/scan")
def nfc_scan(req: ScanRequest) -> dict[str, Any]:
    """UID and ATS of the card in the field, or why there is none."""
    if _emu_active:
        return {"ok": False, "error": "The reader is emulating a card — stop that first."}

    try:
        from transport.contactless import ContactlessTransport

        card = ContactlessTransport(reader_name=req.reader)
        card.connect()
        try:
            return {
                "ok": True,
                "reader": card.reader_name,
                "uid": card.uid.hex().upper(),
                "ats": card.get_atr().hex().upper(),
            }
        finally:
            card.disconnect()
    except Exception as exc:                           # noqa: BLE001
        return {"ok": False, "error": str(exc)}


class IdentifyRequest(BaseModel):
    reader: str | None = None
    buzzer: bool = False
    repeat: int = 3


@router.post("/identify")
def identify_reader(req: IdentifyRequest) -> dict[str, Any]:
    """
    Blink one reader so a human can see which physical device it is.

    This is the answer to two identical ACR122Us on a desk. PC/SC names them
    apart and their USB addresses differ, but neither tells you which of the two
    in front of you it is — and a USB bus address only moves the question to
    which port is which. Making the reader itself light up does not.
    """
    if _emu_active:
        return {"ok": False, "error": "Emulation is running — stop it first."}

    try:
        name = _resolve_reader(req.reader)
    except Exception as exc:                           # noqa: BLE001
        return {"ok": False, "error": str(exc)}

    # The LED command is ACR122-specific. Saying so beats letting the escape
    # fail on a contact reader with an error about pseudo-APDUs.
    known, _ = _pn532_readers()
    if name not in {r["name"] for r in known}:
        return {"ok": False, "reader": name,
                "error": f"'{name}' is not an ACR122 — only its own readers have "
                         f"an LED this can blink."}

    try:
        from nfc.acr122 import identify

        identify(name, repeat=max(1, min(req.repeat, 20)), buzzer=req.buzzer)
    except Exception as exc:                           # noqa: BLE001
        return {"ok": False, "reader": name, "error": str(exc)}

    from core.readers import describe_location, physical_id

    return {"ok": True, "reader": name,
            "where": describe_location(physical_id(name))}


class DetectRequest(BaseModel):
    reader: str | int | None = None


@router.post("/detect-card")
def detect_card(req: DetectRequest) -> dict[str, Any]:
    """
    Confirm a card is readable on the *card* side, whatever interface it is on.

    The scan route drives a PN532 and reports a UID; this one takes any reader,
    because the card being relayed is as likely to be in a contact slot. It
    exists so the two-reader flow has a step that proves the card side works
    before the emulator is armed — otherwise the first evidence of a wrong
    reader is a terminal that will not complete, with two identical device
    names to choose between.
    """
    if _emu_active:
        return {"ok": False, "error": "Emulation is running — stop it first."}

    from core.readers import ReaderError, resolve

    try:
        chosen = resolve(req.reader)
    except ReaderError as exc:
        return {"ok": False, "error": str(exc)}

    if chosen.is_virtual:
        return {"ok": False,
                "error": f"'{chosen.name}' is the virtual reader — ATRIUM's own "
                         f"output side, not a slot holding a card."}

    try:
        if chosen.is_pn532:
            from transport.contactless import ContactlessTransport

            card = ContactlessTransport(reader_name=chosen.name)
            card.connect()
            try:
                return {"ok": True, "reader": chosen.name, "interface": "contactless",
                        "uid": card.uid.hex().upper(),
                        "answer": card.get_atr().hex().upper(),
                        "answer_kind": "ATS"}
            finally:
                card.disconnect()

        from transport.local import LocalCardTransport

        card = LocalCardTransport(chosen.index)
        card.connect()
        try:
            return {"ok": True, "reader": chosen.name, "interface": "contact",
                    "uid": "", "answer": card.get_atr().hex().upper(),
                    "answer_kind": "ATR"}
        finally:
            card.disconnect()
    except Exception as exc:                           # noqa: BLE001
        return {"ok": False, "reader": chosen.name, "error": str(exc)}


class EmulateRequest(BaseModel):
    # The PN532 that presents the emulated card to the terminal.
    reader: str | None = None
    # Where the card being relayed is: a second reader (a second ACR122U
    # works), a remote card proxy, a capture file, or a phone running NFCGate.
    card_reader: int | str | None = None
    from_file: str | None = None
    strict_replay: bool = False
    remote: bool = False
    remote_host: str = "127.0.0.1"
    remote_port: int = 7654
    pairing: str | None = None
    nfcgate: bool = False
    nfcgate_host: str = "127.0.0.1"
    nfcgate_port: int = 5566
    nfcgate_session: int = 1
    # Apply the mutation engine to the relayed traffic. Off unless asked for:
    # mutating a live link is a deliberate act, not a default.
    mutate: bool = False
    # Do ISO-DEP here rather than in the chip. Buys S(WTX), a chosen FWI and
    # chaining; costs the proven-ness of the firmware path, so it is opt-in.
    own_isodep: bool = False
    fwi: int = 12
    wtxm: int = 16
    # Blink and beep the reader when target mode opens. On by default: the
    # window is a few seconds at a time and gives no sign from the outside,
    # so an operator with no cue cannot tell it from a relay that is broken.
    alert: bool = True
    # Answer the deterministic SELECTs from a warm-up rather than the card.
    # Off by default for the same reason as mutate: it changes what a trace
    # means, and that should be a deliberate choice.
    prefetch: bool = False


@router.post("/emulate/start")
def emulate_start(req: EmulateRequest) -> dict[str, Any]:
    """
    Arm card emulation in a background thread.

    Returning immediately is the point: ``CardEmulator.run`` blocks until a
    terminal has finished with it, and the dashboard needs to stay answerable
    while the operator walks the reader over to a terminal.
    """
    global _emu_thread, _emu_active, _emu_error, _emu_started_at

    with _emu_lock:
        if _emu_active:
            return {"ok": False, "error": "Already emulating"}

        # Bad numbers are a malformed request and are answerable without any
        # hardware; a missing reader is the environment. Say which is wrong
        # first, or a typo'd FWI reads as "no reader" on a rig that has none.
        if req.own_isodep:
            if not 0 <= req.fwi <= 14:
                return {"ok": False,
                        "error": f"FWI is 0–14 (15 is reserved), not {req.fwi}"}
            if not 1 <= req.wtxm <= 59:
                return {"ok": False,
                        "error": f"WTXM is 1–59, not {req.wtxm}"}

        try:
            reader_name = _resolve_reader(req.reader)
        except Exception as exc:                       # noqa: BLE001
            return {"ok": False, "error": str(exc)}

        if req.remote and req.pairing:
            try:
                from secure_link import parse_pairing
                parse_pairing(req.pairing)
            except Exception as exc:                   # noqa: BLE001
                return {"ok": False, "error": f"Bad pairing string: {exc}"}

        # Outside the try: a bad capture name is a 400/404 with its own status,
        # not something to fold into an ok:false body.
        capture = _capture_path(req.from_file) if req.from_file else None

        try:
            card, described = open_card_source(
                from_file=capture,
                remote=req.remote,
                remote_host=req.remote_host,
                remote_port=req.remote_port,
                pairing=req.pairing,
                reader=req.card_reader,
                exclude_reader=reader_name,
                strict_replay=req.strict_replay,
                nfcgate=req.nfcgate,
                nfcgate_host=req.nfcgate_host,
                nfcgate_port=req.nfcgate_port,
                nfcgate_session=req.nfcgate_session,
            )
        except Exception as exc:                       # noqa: BLE001
            return {"ok": False, "error": str(exc)}

        engine = None
        if req.mutate:
            try:
                from mutation_engine import MutationEngine

                engine = MutationEngine.from_config(
                    str(MUTATIONS_YAML), os=_OsShim(card.transmit))
            except Exception as exc:                   # noqa: BLE001
                return {"ok": False,
                        "error": f"Could not load mutations.yaml: {exc}"}

        _emu_error = None
        _emu_active = True
        _emu_started_at = time.time()

    def _run() -> None:
        global _emu, _emu_link, _emu_active, _emu_error
        try:
            from nfc.acr122 import open_pn532

            # After the engine has bound _OsShim(card.transmit) above, so an
            # injected command still reaches the card rather than a cache.
            # A separate name: `card` belongs to the enclosing scope and the
            # engine's shim already holds its transmit.
            source = card
            if req.prefetch:
                from transport.prefetch import PrefetchingTransport
                from transport.recorded import RecordedCardTransport

                if isinstance(card, RecordedCardTransport):
                    logger.info("Ignoring prefetch for a recorded capture")
                else:
                    source = PrefetchingTransport(card)

            chip, link = open_pn532(reader_name, direct=True)
            _emu_link = link
            # Before anything is on the clock: the first broadcast would
            # otherwise import mutation_engine mid-relay, which costs ~74 ms.
            _warm_broadcast()
            if req.own_isodep:
                from nfc.emulator import IsoDepEmulator
                from nfc.isodep import Ats

                _emu = IsoDepEmulator(chip, source, on_apdu=_broadcast,
                                      mutations=engine, ats=Ats(fwi=req.fwi),
                                      wtxm=req.wtxm, alert=req.alert)
                logger.info("Card emulation armed on '%s', ISO-DEP ours "
                            "(FWI %d, WTXM %d)", reader_name, req.fwi, req.wtxm)
            else:
                from nfc.emulator import CardEmulator

                _emu = CardEmulator(chip, source, on_apdu=_broadcast,
                                    mutations=engine, alert=req.alert)
                logger.info("Card emulation armed on '%s'", reader_name)
            _emu.run()
        except Exception as exc:                       # noqa: BLE001
            # A stop that had to fall back to closing the link tears the
            # exchange in flight; that is the operator's own request arriving
            # the blunt way, not a fault worth reporting as one.
            if _emu is not None and getattr(_emu, "_stop", False):
                logger.info("Card emulation stopped (%s)", exc)
            else:
                _emu_error = str(exc)
                logger.error("Card emulation failed: %s", exc)
        finally:
            if _emu_link is not None:
                try:
                    _emu_link.close()
                except Exception:                      # noqa: BLE001
                    logger.debug("Ignoring error closing the PN532 link", exc_info=True)
                _emu_link = None
            _emu_active = False

    _emu_thread = threading.Thread(target=_run, daemon=True, name="nfc-emulate")
    _emu_thread.start()
    return {"ok": True, "reader": reader_name, "relaying_to": described,
            "mutating": bool(req.mutate)}


# How long to let the emulation thread notice the stop flag and unwind on its
# own. A re-arm cycle is bounded by the reader's bridge timeout — about five
# seconds — and the flag is checked once per cycle, so this is that plus room
# for the exchange in flight.
STOP_GRACE = 8.0


@router.post("/emulate/stop")
def emulate_stop() -> dict[str, Any]:
    """
    Ask the emulation to finish, and give it time to put the chip back.

    The flag is enough on its own. A session parked waiting for a terminal is
    inside a re-arm cycle that asks ``_still_wanted`` before each attempt, so
    it raises ``Cancelled`` and unwinds through its own ``finally`` — which is
    where ``_return_chip`` restores the parameter byte that target mode had to
    clear.

    Closing the link here instead is what the previous version did, and it took
    that ``finally`` away: the blocked exchange died with "Link is not
    connected" before the flag was ever read, the restore then failed against a
    closed link, and every stop left the reader unable to activate 14443-4
    cards until it was unplugged. So the close is now only a fallback, for a
    thread that did not come back at all.
    """
    global _emu_active

    if not _emu_active:
        return {"ok": False, "error": "Not emulating"}
    if _emu is not None:
        _emu.stop()

    thread, unwound = _emu_thread, True
    if thread is not None and thread.is_alive():
        thread.join(STOP_GRACE)
        unwound = not thread.is_alive()
        if not unwound:
            # Wedged somewhere that does not consult the flag. Closing the link
            # is the only lever left, and it costs the parameter restore.
            logger.warning(
                "Emulation did not stop within %.0fs; closing the link. The "
                "reader may need unplugging before it will read cards again.",
                STOP_GRACE)
            if _emu_link is not None:
                try:
                    _emu_link.close()
                except Exception:                      # noqa: BLE001
                    logger.debug("Ignoring error closing the PN532 link",
                                 exc_info=True)

    _emu_active = False
    return {"ok": True, "chip_restored": unwound}


# ── trace ────────────────────────────────────────────────────────────────────

def _drain_live_records():
    """
    Mutation records for the trace, with the import cost paid up front.

    This used to import mutation_engine inside _broadcast, which runs after the
    response has gone back and before the next read. mutation_engine is not
    imported at module scope anywhere unless mutations are on, so with them off
    the first relayed exchange paid a cold import of the module and its
    dependency graph — measured at 73.8 ms, against a frame waiting time of
    39 ms. It never showed in a trace because the terminal released after the
    first exchange every time; it would have arrived the moment that stopped
    happening, as a lost second command.
    """
    from mutation_engine import drain_live_records

    return drain_live_records()


def _warm_broadcast() -> None:
    """Pay _broadcast's import cost before the relay starts, not during it."""
    try:
        _drain_live_records()
    except Exception:                                  # noqa: BLE001
        logger.debug("Nothing to warm in the trace path", exc_info=True)


def _broadcast(command: bytes, response: bytes) -> None:
    """Put a relayed contactless pair on the Live Trace, like the contact relay."""
    try:
        from api.ws.apdu_stream import broadcast_apdu
    except ImportError:
        return

    now = time.time()
    sw = response[-2:].hex().upper() if len(response) >= 2 else ""
    entry = {
        "ts": now,
        "resp_ts": now,
        "duration_us": 0,
        "cmd": command.hex().upper(),
        "resp": response.hex().upper(),
        "sw": sw,
        "desc": "contactless",
        "session_id": "nfc",
    }
    # Anything a rule changed during this exchange, so the contactless trace
    # shows the card's own bytes beside what the terminal was given — the same
    # before/after the contact relay already renders.
    try:
        records = _drain_live_records()
    except ImportError:
        records = []
    if records:
        entry["mutations"] = [r.to_dict() for r in records]

    try:
        broadcast_apdu(entry)
    except Exception:                                  # noqa: BLE001
        logger.debug("Live Trace broadcast failed; the relay continues", exc_info=True)
