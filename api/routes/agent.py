"""
REST routes — agent control.

POST /api/agent/start   — start an agent session (non-interactive)
POST /api/agent/stop    — request agent stop (exits at next loop iteration)
GET  /api/agent/status  — current agent status
POST /api/agent/message — inject a follow-up user message
GET  /api/agent/providers — which model back ends are installed/configured
"""
from __future__ import annotations

import logging
import threading
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/agent", tags=["agent"])

_agent_thread: threading.Thread | None = None
_agent_active = False
_agent_status = "idle"
_stop_event: threading.Event = threading.Event()


def request_stop() -> None:
    """Signal the agent to stop at its next loop iteration. Safe to call at any time."""
    _stop_event.set()


class StartRequest(BaseModel):
    reader_index: int | str | None = None
    task: str | None = None
    # None = use the provider default / $ATRIUM_LLM_MODEL
    model: str | None = None
    provider: str | None = None
    brute_sfi: bool = False
    system_extra: str | None = None


class MessageRequest(BaseModel):
    text: str


@router.post("/start")
def start_agent(req: StartRequest) -> dict[str, Any]:
    global _agent_thread
    if _agent_active:
        return {"ok": False, "error": "Agent already running"}

    try:
        from llm_provider import ProviderUnavailable, resolve_provider
        resolve_provider(req.provider, req.model)
    except ProviderUnavailable as exc:
        return {"ok": False, "error": str(exc), "needs_setup": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}

    _stop_event.clear()

    def _run() -> None:
        global _agent_active, _agent_status
        _agent_active = True
        _agent_status = "running"
        try:
            from emv_agent import run_agent
            run_agent(
                reader_index=req.reader_index,
                provider=req.provider,
                model=req.model,
                brute_sfi=req.brute_sfi,
                task=req.task,
                non_interactive=True,
                system_extra=req.system_extra,
                stop_event=_stop_event,
            )
        except BaseException as exc:          # SystemExit included
            logger.exception("Agent error")
            _agent_status = f"error: {exc}"
            try:
                from api.ws.agent_stream import broadcast_agent_event
                broadcast_agent_event({"type": "error", "message": str(exc)})
            except Exception:
                pass
        finally:
            _agent_active = False
            _stop_event.clear()
            if not _agent_status.startswith("error"):
                _agent_status = "idle"

    _agent_thread = threading.Thread(target=_run, daemon=True, name="emv-agent")
    _agent_thread.start()
    return {"ok": True}


@router.post("/stop")
def stop_agent() -> dict[str, Any]:
    global _agent_status
    request_stop()
    if _agent_active:
        _agent_status = "stopping"
    return {"ok": True}


@router.get("/status")
def agent_status() -> dict[str, Any]:
    return {"active": _agent_active, "status": _agent_status}


@router.get("/providers")
def agent_providers() -> dict[str, Any]:
    """
    Report which model back ends are installed and configured so the UI can
    populate the model picker and explain what is missing. Never raises.
    """
    try:
        from llm_provider import describe_providers
        return {"ok": True, **describe_providers()}
    except Exception as exc:
        logger.exception("Provider discovery failed")
        return {"ok": False, "error": str(exc), "active": "none",
                "agent_available": False, "providers": []}
