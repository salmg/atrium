"""
ATRIUM API server — FastAPI application factory.

Start with:
    uvicorn api.server:app --reload --port 8000

Or via the entry point:
    python3 atrium.py --serve
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

import ipaddress
import os
import secrets

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse

from api.routes import (
    session, fingerprint, mutations, intel,
    agent as agent_routes, playbooks, logs, config, proxy, simtrace, outcomes,
    host as host_routes, readers as reader_routes, nfc as nfc_routes,
)
from api.ws import apdu_stream, agent_stream

logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).parent.parent / "web"

# ── Local-service hardening ──────────────────────────────────────────────────
#
# ATRIUM drives a card relay and can launch privileged helpers, so the API is a
# high-value target even bound to loopback. Two guards:
#
# 1. Host allow-list. A browser enforces same-origin on cross-site fetches, but
#    DNS rebinding defeats that: an attacker's page re-resolves its own domain
#    to 127.0.0.1 and is then treated as same-origin. Checking the Host header
#    breaks that, because the request still arrives with the attacker's name.
#
# 2. Optional shared token. Off for loopback (the OS already restricts who can
#    connect); required when binding anywhere else — see atrium.py serve.

_DEFAULT_HOSTS = {"localhost", "127.0.0.1", "[::1]", "::1", "testserver"}


def _allowed_hosts() -> set[str]:
    extra = os.environ.get("ATRIUM_ALLOWED_HOSTS", "")
    return _DEFAULT_HOSTS | {h.strip().lower() for h in extra.split(",") if h.strip()}


def _host_ok(header: str | None) -> bool:
    if not header:
        return False
    host = header.rsplit(":", 1)[0].lower() if not header.startswith("[") else \
           header.split("]")[0] + "]"
    if host in _allowed_hosts():
        return True
    # Any literal IP that is loopback is fine regardless of how it was written
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def create_app() -> FastAPI:
    app = FastAPI(
        title="ATRIUM — Payment Security Workbench",
        version="2.0.0",
        description="A security research assistant for EMV payment systems — "
                    "APDU relay, card fingerprinting, transaction mutation, and AI-assisted analysis.",
    )

    # ── Security middleware (runs before routing) ────────────────────────────
    @app.middleware("http")
    async def _guard(request: Request, call_next):
        if not _host_ok(request.headers.get("host")):
            return JSONResponse(
                {"ok": False, "error": "Host not allowed. Set ATRIUM_ALLOWED_HOSTS "
                                       "to serve this name."},
                status_code=421,
            )

        token = os.environ.get("ATRIUM_API_TOKEN", "")
        if token and request.url.path.startswith("/api/"):
            supplied = (request.headers.get("x-atrium-token")
                        or request.query_params.get("token", ""))
            if not secrets.compare_digest(supplied, token):
                return JSONResponse(
                    {"ok": False, "error": "Missing or invalid API token."},
                    status_code=401,
                )
        return await call_next(request)

    # ── REST routes ──────────────────────────────────────────────────────────
    app.include_router(session.router)
    app.include_router(fingerprint.router)
    app.include_router(mutations.router)
    app.include_router(intel.router)
    app.include_router(agent_routes.router)
    app.include_router(playbooks.router)
    app.include_router(logs.router)
    app.include_router(config.router)
    app.include_router(proxy.router)
    app.include_router(simtrace.router)
    app.include_router(outcomes.router)
    app.include_router(host_routes.router)
    app.include_router(reader_routes.router)
    app.include_router(nfc_routes.router)

    # ── WebSocket routes ─────────────────────────────────────────────────────
    app.include_router(apdu_stream.router)
    app.include_router(agent_stream.router)

    # ── Static web UI ────────────────────────────────────────────────────────
    if WEB_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(WEB_DIR)), name="static")

        @app.get("/", include_in_schema=False)
        async def serve_index() -> FileResponse:
            return FileResponse(str(WEB_DIR / "index.html"))

    # ── Startup: wire up event loop for thread-safe WebSocket broadcasts ─────
    @app.on_event("startup")
    async def on_startup() -> None:
        loop = asyncio.get_running_loop()
        apdu_stream.set_event_loop(loop)
        agent_stream.set_event_loop(loop)
        logger.info("ATRIUM API server started")

    return app


app = create_app()
