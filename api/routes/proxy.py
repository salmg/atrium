"""
REST routes — remote card proxy daemon control.

POST /api/proxy/start   — launch proxy server {host, port, reader}
POST /api/proxy/stop    — terminate it
GET  /api/proxy/status  — running / pid / tail of recent output
"""
from __future__ import annotations

import logging
import subprocess
import sys
from collections import deque
from pathlib import Path

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/proxy", tags=["proxy"])

_ROOT = Path(__file__).parent.parent.parent
_proc: subprocess.Popen | None = None
_output_buf: deque[str] = deque(maxlen=100)     # last 100 lines of stdout


class ProxyConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 7654
    reader: int | str | None = None


@router.post("/start")
def start_proxy(cfg: ProxyConfig) -> dict:
    global _proc
    if _proc and _proc.poll() is None:
        return {"ok": False, "error": "Proxy already running"}

    _output_buf.clear()
    try:
        _proc = subprocess.Popen(
            [
                sys.executable,
                str(_ROOT / "atrium.py"),
                "proxy",
                "--proxy-host", cfg.host,
                "--proxy-port", str(cfg.port),
                "--reader",     "" if cfg.reader is None else str(cfg.reader),
            ],
            cwd=str(_ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        # Collect output in a background thread so the buffer stays fresh
        import threading

        def _read() -> None:
            assert _proc and _proc.stdout
            for line in _proc.stdout:
                _output_buf.append(line.rstrip())

        threading.Thread(target=_read, daemon=True, name="proxy-stdout").start()
        logger.info("Proxy started (pid=%d) on %s:%d reader=%s",
                    _proc.pid, cfg.host, cfg.port,
                    cfg.reader if cfg.reader is not None else "auto")
        return {"ok": True, "pid": _proc.pid}
    except Exception as exc:
        logger.exception("Failed to start proxy")
        return {"ok": False, "error": str(exc)}


@router.post("/stop")
def stop_proxy() -> dict:
    if _proc and _proc.poll() is None:
        _proc.terminate()
        logger.info("Proxy terminated (pid=%d)", _proc.pid)
        return {"ok": True}
    return {"ok": True, "message": "Proxy was not running"}


@router.get("/status")
def proxy_status() -> dict:
    running = bool(_proc and _proc.poll() is None)
    return {
        "running": running,
        "pid":     _proc.pid if running else None,
        "output":  list(_output_buf),
    }
