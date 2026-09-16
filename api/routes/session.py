"""
REST routes — relay session control.

POST /api/session/start   — start a new relay session (relay only, no agent)
POST /api/session/stop    — stop the relay and cascade-stop any running agent
GET  /api/session/status  — current status + card ATR
"""
from __future__ import annotations

import logging
import threading
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/session", tags=["session"])

_session_thread: threading.Thread | None = None
_session_active = False
_virtual_card = None          # kept so stop() can close the socket
_card_atr: str | None = None
_last_error: str | None = None


def _format_atr(atr: Any) -> str | None:
    """
    Render an ATR as uppercase hex.

    Transports disagree on the type: pyscard hands back a list of ints, the
    remote transport returns bytes, and older versions return a str of
    char-codes. All three end up as the same hex string here.
    """
    if atr is None:
        return None
    if isinstance(atr, (bytes, bytearray)):
        raw = bytes(atr)
    elif isinstance(atr, str):
        raw = bytes(ord(c) for c in atr)
    else:
        try:
            raw = bytes(atr)
        except (TypeError, ValueError):
            return None
    return raw.hex().upper() or None


class StartRequest(BaseModel):
    reader_index: int | str | None = None
    remote: bool = False
    remote_host: str = "127.0.0.1"
    remote_port: int = 7654
    # Pairing string from `atrium pair` on the card host. When present the link
    # is TLS with a pinned certificate; host/port are taken from it.
    pairing: str | None = None


@router.post("/start")
def start_session(req: StartRequest) -> dict[str, Any]:
    global _session_thread
    if _session_active:
        return {"ok": False, "error": "Session already running"}

    _last_error = None
    _card_atr = None

    if req.remote and req.pairing:
        try:
            from secure_link import parse_pairing
            parse_pairing(req.pairing)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    def _run() -> None:
        global _session_active, _card_atr, _last_error, _virtual_card
        _session_active = True
        try:
            from atrium import _make_virtual_card
            vc = _make_virtual_card(
                req.reader_index,
                remote=req.remote,
                remote_host=req.remote_host,
                remote_port=req.remote_port,
                pairing=req.pairing,
            )
            _virtual_card = vc
            # Read the ATR before run() takes the thread: it is the first
            # evidence the card is actually answering, and the dashboard shows
            # it. Failing to read one is not a reason to abandon the session —
            # the relay works whether or not we could format this for display.
            try:
                _card_atr = _format_atr(vc.os.getATR())
            except Exception as exc:                     # noqa: BLE001
                logger.debug("Could not read the card ATR: %s", exc)
            vc.run()
        except Exception as exc:
            _last_error = str(exc)
            logger.exception("Session error")
        finally:
            _session_active = False
            _virtual_card = None

    _session_thread = threading.Thread(target=_run, daemon=True, name="relay-session")
    _session_thread.start()
    return {"ok": True}


@router.post("/stop")
def stop_session() -> dict[str, Any]:
    global _session_active, _card_atr
    _session_active = False
    _card_atr = None

    # Close the virtual card socket so run() unblocks immediately
    vc = _virtual_card
    if vc is not None:
        try:
            vc.stop()
        except Exception:
            pass

    # Cascade: stop any running agent
    try:
        from api.routes.agent import request_stop as stop_agent
        stop_agent()
    except Exception:
        pass

    return {"ok": True}


@router.get("/status")
def session_status() -> dict[str, Any]:
    return {
        "active": _session_active,
        "atr": _card_atr,
        "error": _last_error,
    }
