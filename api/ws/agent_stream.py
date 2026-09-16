"""
WebSocket endpoint — streaming agent output.

The agent thread sends tokens/events here; the UI renders them in real time.
Callers use ``broadcast_agent_event()`` which is thread-safe.
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
    global _loop
    _loop = loop


def broadcast_agent_event(event: dict[str, Any]) -> None:
    """
    Thread-safe broadcast from the agent thread.

    ``event`` shape examples::

        {"type": "text",  "text": "Analyzing card…"}
        {"type": "tool",  "name": "read_record",  "input": {…}}
        {"type": "done"}
        {"type": "error", "message": "…"}
    """
    if not _loop or not _clients:
        return
    payload = json.dumps(event)
    _loop.call_soon_threadsafe(_async_broadcast, payload)


def _async_broadcast(payload: str) -> None:
    for ws in list(_clients):
        asyncio.ensure_future(ws.send_text(payload))


@router.websocket("/ws/agent")
async def agent_stream(websocket: WebSocket) -> None:
    await websocket.accept()
    _clients.add(websocket)
    logger.info("Agent WebSocket client connected (total: %d)", len(_clients))
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        _clients.discard(websocket)
