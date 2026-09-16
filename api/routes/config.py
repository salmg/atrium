"""
REST routes — ATRIUM configuration files.

GET /api/config/logger   — read emv_logger.yaml as text
PUT /api/config/logger   — validate + overwrite emv_logger.yaml
"""
from __future__ import annotations

import logging
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/config", tags=["config"])

_ROOT = Path(__file__).parent.parent.parent
LOGGER_YAML = _ROOT / "emv_logger.yaml"


class ConfigBody(BaseModel):
    content: str


@router.get("/logger")
def get_logger_config() -> dict:
    try:
        content = LOGGER_YAML.read_text(encoding="utf-8") if LOGGER_YAML.exists() else ""
        return {"ok": True, "content": content}
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.put("/logger")
def save_logger_config(body: ConfigBody) -> dict:
    try:
        import yaml
        yaml.safe_load(body.content)        # validate before writing
        LOGGER_YAML.write_text(body.content, encoding="utf-8")
        logger.info("emv_logger.yaml updated via web UI")
        return {"ok": True}
    except Exception as exc:
        raise HTTPException(500, str(exc))
