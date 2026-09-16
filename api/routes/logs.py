"""
REST routes — log file browser.

GET    /api/logs               — list all files in logs/
GET    /api/logs/{filename}    — read a file (paginated, offset+limit)
DELETE /api/logs/{filename}    — delete a file
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/logs", tags=["logs"])

LOGS_DIR = Path(__file__).parent.parent.parent / "logs"


def _safe_path(name: str) -> Path:
    """
    Resolve a requested log file and prove it stays inside LOGS_DIR.

    Sanitising the string and hoping is fragile; checking the *resolved* path
    against the *resolved* directory is what actually holds, and it also
    catches symlinks pointing outside the tree.
    """
    if not name or "/" in name or "\\" in name or "\x00" in name:
        raise HTTPException(400, "Invalid filename")
    base = LOGS_DIR.resolve()
    candidate = (base / name).resolve()
    if candidate == base or base not in candidate.parents:
        raise HTTPException(400, "Invalid filename")
    return candidate


@router.get("")
def list_logs() -> dict:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    files = []
    for f in sorted(LOGS_DIR.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
        if f.is_file():
            st = f.stat()
            files.append({
                "name": f.name,
                "size": st.st_size,
                "modified": int(st.st_mtime * 1000),
            })
    return {"ok": True, "data": files}


@router.get("/{filename}")
def read_log(filename: str, offset: int = 0, limit: int = 500) -> dict:
    path = _safe_path(filename)
    if not path.is_file():
        raise HTTPException(404, "File not found")
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(lines)
        return {
            "ok": True,
            "name": filename,
            "total_lines": total,
            "offset": offset,
            "lines": lines[offset: offset + limit],
        }
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.delete("/{filename}")
def delete_log(filename: str) -> dict:
    path = _safe_path(filename)
    if not path.is_file():
        raise HTTPException(404, "File not found")
    path.unlink()
    return {"ok": True}
