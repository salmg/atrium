"""
REST routes — APDU mutation outcome store.

POST /api/outcomes/mark      — manually flag a trace row as interesting
GET  /api/outcomes           — query outcome patterns (by card or cross-card)
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/outcomes", tags=["outcomes"])


class MarkRequest(BaseModel):
    fingerprint_hash: str = ""
    session_id: str = ""
    cmd_hex: str = ""
    cmd_ins: str = ""
    resp_hex: str = ""
    sw: str = ""
    label: str = "manual_interesting"
    notes: str = ""


@router.post("/mark")
def mark_outcome(req: MarkRequest) -> dict[str, Any]:
    """Manually flag a Live Trace APDU pair as interesting."""
    try:
        from card_intel import CardIntelDB
    except ImportError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        db = CardIntelDB()
        row_id = db.record_outcome(
            label=req.label,
            fingerprint_hash=req.fingerprint_hash,
            session_id=req.session_id,
            cmd_hex=req.cmd_hex,
            cmd_ins=req.cmd_ins,
            resp_hex=req.resp_hex,
            sw=req.sw,
            notes=req.notes,
            source="manual",
        )
        db.close()
        return {"ok": True, "id": row_id}
    except Exception as exc:
        logger.exception("mark_outcome failed")
        return {"ok": False, "error": str(exc)}


@router.get("")
def get_outcomes(
    fingerprint_hash: str = "",
    cross_card: bool = False,
) -> dict[str, Any]:
    """
    Return outcome patterns for a card or across all cards.
    ?fingerprint_hash=<hash>  — patterns for one card
    ?cross_card=true          — global patterns across all cards
    """
    try:
        from card_intel import CardIntelDB
    except ImportError as exc:
        return {"ok": False, "error": str(exc)}
    try:
        db = CardIntelDB()
        if cross_card or not fingerprint_hash:
            data = db.get_cross_card_patterns()
        else:
            data = db.get_outcomes_summary(fingerprint_hash)
        db.close()
        return {"ok": True, **data}
    except Exception as exc:
        logger.exception("get_outcomes failed")
        return {"ok": False, "error": str(exc)}
