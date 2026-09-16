"""
REST routes — mutation engine.

GET   /api/mutations           — list loaded mutation rules
POST  /api/mutations/run       — run mutation suite against current session
GET   /api/mutations/results   — last run results
GET   /api/mutations/config    — raw mutations.yaml text
PUT   /api/mutations/config    — overwrite mutations.yaml
PATCH /api/mutations/rule      — toggle / update a single rule field
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/mutations", tags=["mutations"])

_last_results: list[dict[str, Any]] = []

_VALID_SECTIONS = {
    "pdol_mutations",
    "afl_mutations",
    "dol_mutations",
    "response_mutations",
    "injected_commands",
}


@router.get("")
def list_mutations() -> dict[str, Any]:
    try:
        import yaml
        with open("mutations.yaml", encoding="utf-8") as f:
            rules = yaml.safe_load(f)
        return {"ok": True, "count": len(rules or []), "rules": rules}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


@router.post("/run")
def run_mutations() -> dict[str, Any]:
    return {"ok": False, "error": "No active session — start a relay session first"}


@router.get("/results")
def get_results() -> dict[str, Any]:
    return {"ok": True, "results": _last_results}


def update_results(results: list[dict[str, Any]]) -> None:
    global _last_results
    _last_results = results


@router.get("/config")
def get_config() -> dict[str, Any]:
    """Read the active mutations.yaml as raw text."""
    try:
        with open("mutations.yaml", encoding="utf-8") as f:
            return {"ok": True, "content": f.read()}
    except FileNotFoundError:
        return {"ok": True, "content": ""}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


class _ConfigBody(BaseModel):
    content: str


@router.put("/config")
def save_config(body: _ConfigBody) -> dict[str, Any]:
    """Overwrite mutations.yaml with validated YAML text."""
    try:
        import yaml
        yaml.safe_load(body.content)     # validate before writing
        with open("mutations.yaml", "w", encoding="utf-8") as f:
            f.write(body.content)
        return {"ok": True}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


class _RuleUpdate(BaseModel):
    section: str
    index: int
    enabled: bool


@router.patch("/rule")
def toggle_rule(body: _RuleUpdate) -> dict[str, Any]:
    """Enable or disable a single mutation rule by section + index."""
    if body.section not in _VALID_SECTIONS:
        return {"ok": False, "error": f"Unknown section: {body.section}"}
    try:
        import yaml
        with open("mutations.yaml", encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        section = config.get(body.section)
        if not isinstance(section, list):
            return {"ok": False, "error": f"Section '{body.section}' not found"}
        if body.index < 0 or body.index >= len(section):
            return {"ok": False, "error": f"Index {body.index} out of range"}

        section[body.index]["enabled"] = body.enabled

        with open("mutations.yaml", "w", encoding="utf-8") as f:
            yaml.dump(config, f, default_flow_style=False,
                      allow_unicode=True, sort_keys=False)
        return {"ok": True}
    except Exception as exc:
        logger.exception("Failed to toggle rule")
        return {"ok": False, "error": str(exc)}

