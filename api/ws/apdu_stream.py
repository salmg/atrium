"""
WebSocket endpoint — live APDU trace stream.

Clients connect here to receive every APDU pair (command + response) as it
flows through the relay in real-time.  The relay thread calls
``broadcast_apdu()`` which is also importable by the logger.
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)
router = APIRouter()

_clients: set[WebSocket] = set()
_loop: asyncio.AbstractEventLoop | None = None


def set_event_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Called once from api/server.py on startup."""
    global _loop
    _loop = loop


def broadcast_apdu(entry: dict[str, Any]) -> None:
    """
    Thread-safe broadcast from the relay / logger thread.

    ``entry`` should contain at least::

        {
            "cmd":  "00A4...",   # hex string
            "resp": "9000",
            "ts":   1714123456.789,
            "sw":   "9000",
        }
    """
    if not _loop or not _clients:
        return
    payload = json.dumps(entry)
    _loop.call_soon_threadsafe(_async_broadcast, payload)


def _async_broadcast(payload: str) -> None:
    for ws in list(_clients):
        asyncio.ensure_future(ws.send_text(payload))


@router.websocket("/ws/apdu")
async def apdu_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    _clients.add(websocket)
    logger.info("APDU WebSocket client connected (total: %d)", len(_clients))
    try:
        while True:
            await websocket.receive_text()  # keep-alive ping support
    except WebSocketDisconnect:
        pass
    finally:
        _clients.discard(websocket)
        logger.info("APDU WebSocket client disconnected (total: %d)", len(_clients))
