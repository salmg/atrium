"""
REST routes — card intelligence (CardIntelDB).

GET    /api/intel/cards              — list all fingerprinted cards (summary)
GET    /api/intel/card/{hash}        — full intel for a card (hash prefix supported)
POST   /api/intel/card/{hash}/note   — append a note to a card
DELETE /api/intel/card/{hash}        — delete card and all its attack records
DELETE /api/intel/attack/{id}        — delete a single attack record
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/intel", tags=["intel"])

_db = None


def _get_db():
    global _db
    if _db is None:
        from card_intel import CardIntelDB
        _db = CardIntelDB()
    return _db


@router.get("/cards")
def list_cards() -> dict:
    try:
        return {"ok": True, "data": _get_db().list_cards()}
    except Exception as exc:
        logger.exception("Failed to list cards")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/card/{hash_prefix}")
def get_card_intel(hash_prefix: str) -> dict:
    try:
        db = _get_db()
        cards = db.list_cards()
        match = next(
            (c for c in cards if c["fingerprint_hash"].startswith(hash_prefix)),
            None,
        )
        if match is None:
            raise HTTPException(status_code=404, detail="Card not found")
        intel = db.get_intel(match["fingerprint_hash"])
        return {"ok": True, "data": intel}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to get card intel")
        raise HTTPException(status_code=500, detail=str(exc))


class NoteBody(BaseModel):
    note: str


@router.post("/card/{hash_prefix}/note")
def add_note(hash_prefix: str, body: NoteBody) -> dict:
    try:
        db = _get_db()
        cards = db.list_cards()
        match = next(
            (c for c in cards if c["fingerprint_hash"].startswith(hash_prefix)),
            None,
        )
        if match is None:
            raise HTTPException(status_code=404, detail="Card not found")
        db.add_note(match["fingerprint_hash"], body.note.strip())
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to add note")
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/card/{hash_prefix}")
def delete_card(hash_prefix: str) -> dict:
    try:
        db = _get_db()
        cards = db.list_cards()
        match = next(
            (c for c in cards if c["fingerprint_hash"].startswith(hash_prefix)),
            None,
        )
        if match is None:
            raise HTTPException(status_code=404, detail="Card not found")
        db.delete_card(match["fingerprint_hash"])
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to delete card")
        raise HTTPException(status_code=500, detail=str(exc))


@router.delete("/attack/{attack_id}")
def delete_attack(attack_id: int) -> dict:
    try:
        db = _get_db()
        found = db.delete_attack(attack_id)
        if not found:
            raise HTTPException(status_code=404, detail="Attack record not found")
        return {"ok": True}
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Failed to delete attack")
        raise HTTPException(status_code=500, detail=str(exc))
