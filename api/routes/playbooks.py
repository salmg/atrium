"""
REST routes — playbook management.

GET    /api/playbooks               — list saved playbooks
GET    /api/playbooks/{name}        — get playbook content
POST   /api/playbooks               — create playbook  {name, content}
PUT    /api/playbooks/{name}        — update playbook content
DELETE /api/playbooks/{name}        — delete playbook
POST   /api/playbooks/{name}/apply  — write playbook → mutations.yaml
GET    /api/playbooks/active        — which playbook matches mutations.yaml
POST   /api/playbooks/engine        — arm or disarm the engine  {enabled}
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/playbooks", tags=["playbooks"])

_ROOT = Path(__file__).parent.parent.parent
PLAYBOOKS_DIR = _ROOT / "playbooks"
MUTATIONS_YAML = _ROOT / "mutations.yaml"


# ── helpers ──────────────────────────────────────────────────────────────────

def _slug(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", name.strip())[:64]


def _path(name: str) -> Path:
    slug = _slug(name)
    if not slug:
        raise HTTPException(400, "Invalid playbook name")
    return PLAYBOOKS_DIR / f"{slug}.yaml"


def _first_comment(text: str) -> str:
    for line in text.splitlines():
        stripped = line.lstrip("# ").strip()
        if stripped:
            return stripped
    return ""


# ── routes ───────────────────────────────────────────────────────────────────

@router.get("")
def list_playbooks() -> dict:
    PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
    books = []
    for f in sorted(PLAYBOOKS_DIR.glob("*.yaml")):
        try:
            text = f.read_text(encoding="utf-8")
            books.append({
                "name": f.stem,
                "description": _first_comment(text),
            })
        except Exception:
            pass
    return {"ok": True, "data": books}


# Declared before /{name} on purpose: FastAPI matches in registration
# order, so the parameterised route would otherwise swallow "active"
# and answer "Playbook not found".
@router.get("/active")
def active_playbook() -> dict:
    """
    Which playbook, if any, matches the live mutations.yaml.

    Derived by comparison rather than remembered, which makes it
    self-correcting: edit mutations.yaml by hand and no playbook claims to be
    active, because none is. A stored "last applied" name would keep asserting
    something that stopped being true.
    """
    if not MUTATIONS_YAML.exists():
        return {"ok": True, "active": None, "engine_enabled": False,
                "reason": "no mutations.yaml yet"}

    text = MUTATIONS_YAML.read_text(encoding="utf-8")
    enabled = engine_enabled(text)
    live = _normalise(text)
    PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
    for path in sorted(PLAYBOOKS_DIR.glob("*.yaml")):
        try:
            if _normalise(path.read_text(encoding="utf-8")) == live:
                return {"ok": True, "active": path.stem,
                        "engine_enabled": enabled, "reason": ""}
        except OSError:
            continue
    return {"ok": True, "active": None, "engine_enabled": enabled,
            "reason": "the active config does not match any saved playbook"}


def _normalise(text: str) -> str:
    """
    Compare on content, ignoring layout and the engine's own on/off switch.

    Dropping the top-level ``enabled:`` line is what lets a playbook stay
    *loaded* while the engine is *disarmed* — two facts the dashboard reports
    separately, because "which rules are staged" and "are they being applied"
    are different questions and only one of them has a button.
    """
    return "\n".join(line.rstrip() for line in text.strip().splitlines()
                     if line.strip() and not _TOP_ENABLED_RE.match(line))


@router.get("/{name}")
def get_playbook(name: str) -> dict:
    p = _path(name)
    if not p.exists():
        raise HTTPException(404, "Playbook not found")
    return {"ok": True, "name": p.stem, "content": p.read_text(encoding="utf-8")}


class PlaybookBody(BaseModel):
    name: str
    content: str


@router.post("")
def create_playbook(body: PlaybookBody) -> dict:
    PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
    p = _path(body.name)
    if p.exists():
        raise HTTPException(409, f"Playbook '{p.stem}' already exists")
    _validate_yaml(body.content)
    p.write_text(body.content, encoding="utf-8")
    return {"ok": True, "name": p.stem}


@router.put("/{name}")
def update_playbook(name: str, body: PlaybookBody) -> dict:
    p = _path(name)
    if not p.exists():
        raise HTTPException(404, "Playbook not found")
    _validate_yaml(body.content)
    p.write_text(body.content, encoding="utf-8")
    return {"ok": True}


@router.delete("/{name}")
def delete_playbook(name: str) -> dict:
    p = _path(name)
    if not p.exists():
        raise HTTPException(404, "Playbook not found")
    p.unlink()
    return {"ok": True}


class EngineBody(BaseModel):
    enabled: bool


# Declared before /{name}/... for the same reason /active is: FastAPI matches
# in registration order.
@router.post("/engine")
def set_engine(body: EngineBody) -> dict:
    """
    Arm or disarm the mutation engine without discarding the loaded rules.

    Applying a playbook was a one-way door — there was no way back to a clean
    relay short of hand-editing mutations.yaml, and deleting the file would
    lose the configuration the operator had just staged. Flipping the top-level
    flag leaves every rule where it is, so the same playbook can be switched
    back on without re-applying it.
    """
    if not MUTATIONS_YAML.exists():
        if not body.enabled:
            return {"ok": True, "enabled": False}
        raise HTTPException(404, "No mutations.yaml — apply a playbook first")

    text = MUTATIONS_YAML.read_text(encoding="utf-8")
    MUTATIONS_YAML.write_text(set_engine_enabled(text, body.enabled), encoding="utf-8")
    logger.info("Mutation engine %s", "armed" if body.enabled else "disarmed")
    return {"ok": True, "enabled": body.enabled}


@router.post("/{name}/apply")
def apply_playbook(name: str) -> dict:
    p = _path(name)
    if not p.exists():
        raise HTTPException(404, "Playbook not found")
    content = p.read_text(encoding="utf-8")
    _validate_yaml(content)
    MUTATIONS_YAML.write_text(content, encoding="utf-8")
    logger.info("Applied playbook '%s' → mutations.yaml", name)
    return {"ok": True, "message": f"Playbook '{name}' is now active"}


# ── the engine switch, as text ───────────────────────────────────────────────

# Only the top-level flag: rule-level "enabled:" lines are indented, and
# rewriting one of those would silently arm or disarm a single rule.
_TOP_ENABLED_RE = re.compile(r"^enabled:\s*(\S+)\s*$")


def engine_enabled(text: str) -> bool:
    """Whether a mutations.yaml text has its engine armed. Absent means off."""
    for line in text.splitlines():
        m = _TOP_ENABLED_RE.match(line)
        if m:
            return m.group(1).strip().lower() in ("true", "yes", "on", "1")
    return False


def set_engine_enabled(text: str, enabled: bool) -> str:
    """
    Return ``text`` with the top-level engine flag set.

    Rewritten as text rather than round-tripped through the YAML parser: the
    file is full of comments explaining what each rule does, and a reserialised
    document would throw all of them away.
    """
    want = "true" if enabled else "false"
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if _TOP_ENABLED_RE.match(line):
            lines[i] = f"enabled: {want}"
            return "\n".join(lines) + "\n"
    # No flag at all — the engine defaults to off, so only arming needs one.
    return f"enabled: {want}\n" + text


# ── internal ─────────────────────────────────────────────────────────────────

def _validate_yaml(text: str) -> None:
    try:
        import yaml
        yaml.safe_load(text)
    except Exception as exc:
        raise HTTPException(400, f"Invalid YAML: {exc}") from exc
