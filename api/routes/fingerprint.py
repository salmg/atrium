"""
REST routes — card fingerprinting.

GET  /api/fingerprint          — return cached fingerprint (if available)
POST /api/fingerprint/run      — trigger a fresh fingerprint scan (reader_index, brute_sfi)
"""
from __future__ import annotations

import dataclasses
import logging
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/fingerprint", tags=["fingerprint"])

_fingerprint_cache: dict[str, Any] | None = None


@router.get("")
def get_fingerprint() -> dict[str, Any]:
    if _fingerprint_cache is None:
        return {"ok": False, "error": "No fingerprint available yet"}
    return {"ok": True, "data": _fingerprint_cache}


class RunRequest(BaseModel):
    reader_index: int | str | None = None
    brute_sfi: bool = False


@router.post("/run")
def run_fingerprint(req: RunRequest) -> dict[str, Any]:
    # Refuse if the web relay session is active — both would hold the same reader.
    # Import the module (not just the variable) so we read the live bool.
    try:
        from api.routes import session as _session_mod
        if _session_mod._session_active:
            return {
                "ok": False,
                "error": "A relay session is active — stop it first, then scan.",
            }
    except Exception:
        pass

    try:
        from card_fingerprint import CardFingerprinter
    except ImportError as exc:
        return {"ok": False, "error": f"card_fingerprint not available: {exc}"}

    fp = None
    try:
        fp = CardFingerprinter(reader_index=req.reader_index, brute_sfi=req.brute_sfi)
        profile = fp.fingerprint()
        safe = _to_json_safe(profile)
        update_fingerprint(safe)

        try:
            from card_intel import CardIntelDB
            idb = CardIntelDB()
            idb.record_card(safe)
            idb.close()
        except Exception:
            pass

        return {"ok": True, "data": safe}
    except Exception as exc:
        logger.exception("Fingerprint scan failed")
        return {"ok": False, "error": str(exc)}
    finally:
        if fp is not None:
            try:
                fp.close()
            except Exception:
                pass


def update_fingerprint(data: dict[str, Any]) -> None:
    """Called by the agent / relay session when a fingerprint scan completes."""
    global _fingerprint_cache
    _fingerprint_cache = data


def _to_json_safe(obj: Any) -> Any:
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex().upper()
    if isinstance(obj, set):
        return sorted(list(obj))
    if isinstance(obj, dict):
        return {k: _to_json_safe(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_to_json_safe(i) for i in obj]
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        try:
            return _to_json_safe(dataclasses.asdict(obj))
        except Exception:
            return f"<{type(obj).__name__}>"
    return obj
