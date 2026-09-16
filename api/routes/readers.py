"""
REST routes — PC/SC reader discovery.

GET /api/readers — every reader, named and classified, with a recommendation.

Exists because a reader index alone is not enough information to choose one.
With vpcd running the virtual reader usually takes index 0, and that is
ATRIUM's own output side rather than a slot a card goes in, so the obvious
default is the wrong one.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/readers", tags=["readers"])


@router.get("")
def list_readers() -> dict:
    from core.readers import pick_default, probe

    readers, problem = probe()
    default = pick_default(readers)
    return {
        "ok": not problem,
        "problem": problem,
        "readers": [r.to_dict() for r in readers],
        "default": default.index if default else None,
        # Relaying a card to the virtual reader means relaying it to itself.
        # The UI says so rather than letting it look like a card fault.
        "only_virtual": bool(readers) and all(r.is_virtual for r in readers),
    }
