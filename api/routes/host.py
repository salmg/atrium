"""
REST routes — the host layer (acquirer / gateway / issuer).

Puts the ISO 8583 half of the toolkit behind the dashboard.  The CLI remains
the primary interface and is what the host/README documents; this exists so an
operator already watching a card session can drive the link above it without
changing terminals.

Three rules carried over from the CLI, because a browser button is an easier
thing to press by accident than a command line is to type
------------------------------------------------------------------------------
* **The target allow-list is mandatory and fails closed.**  It arrives with the
  request and is checked before a socket exists, exactly as ``--allow`` is.
* **Anything that changes or originates traffic needs ``confirm: true``.**  The
  passive proxy observes and needs no confirmation; the mutating proxy rewrites
  live messages and replay originates transactions, so neither happens on a
  single stray click.
* **Issuer master keys never travel through this API.**  A key in a request body
  ends up in access logs, proxy logs and browser history.  Verification reads
  ``$HOST_IMK`` or a server-side file instead, and says so when neither is set.

State is module-level, matching the rest of api/routes: ATRIUM is a
single-operator tool bound to loopback by default.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/host", tags=["host"])

_ROOT = Path(__file__).parent.parent.parent
LOGS_DIR = _ROOT / "logs"

# ── Runtime state ─────────────────────────────────────────────────────────────

_lock = threading.Lock()
_proxy: Any = None
_proxy_capture: Any = None
_proxy_meta: dict = {}

_replay_thread: threading.Thread | None = None
_replay_state: dict = {"running": False, "done": False, "error": "",
                       "sent": 0, "total": 0, "summary": "", "results": []}


def _safe_capture_path(name: str) -> Path:
    """
    Resolve a capture filename inside logs/ and prove it stayed there.

    Same reasoning as api/routes/logs.py: checking the resolved path against
    the resolved directory is what actually holds, and it catches symlinks
    pointing out of the tree too.
    """
    if not name or "/" in name or "\\" in name or "\x00" in name:
        raise HTTPException(400, "Invalid capture name")
    base = LOGS_DIR.resolve()
    candidate = (base / name).resolve()
    if candidate == base or base not in candidate.parents:
        raise HTTPException(400, "Invalid capture name")
    return candidate


def _require_confirm(confirm: bool, what: str) -> None:
    if not confirm:
        raise HTTPException(
            400,
            f"{what} changes traffic on a live link, so it needs an explicit "
            "confirmation. Re-send with confirm: true.",
        )


# ── Models ────────────────────────────────────────────────────────────────────

class ProxyStartBody(BaseModel):
    mode: str = "passive"                 # passive | mutate
    listen: str = "127.0.0.1:8583"
    target: str
    allow: list[str] = []
    dialect: str = "iso8583-1987"
    playbook: str | None = None
    capture: str | None = None            # filename inside logs/
    abort_on_live_pan: bool = False
    confirm: bool = False


class ReplayBody(BaseModel):
    capture: str
    target: str
    allow: list[str] = []
    dialect: str = "iso8583-1987"
    freshen: bool = False
    playbook: str | None = None
    profile: str = "emv-book2"
    resign: bool = False                  # uses $HOST_IMK / server-side file
    psn: str = "00"
    mti: list[str] = []
    limit: int = 0
    delay: float = 0.0
    timeout: float = 30.0
    abort_on_live_pan: bool = False
    confirm: bool = False


class DetectBody(BaseModel):
    capture: str | None = None
    hex: str | None = None
    limit: int = 5


class VerifyBody(BaseModel):
    capture: str
    dialect: str = "iso8583-1987"
    profile: str = "emv-book2"
    psn: str = "00"
    limit: int = 0


# ── Catalogue ─────────────────────────────────────────────────────────────────

@router.get("/catalogue")
def catalogue() -> dict:
    """Everything the UI needs to populate its pickers, in one round trip."""
    out: dict[str, Any] = {"ok": True, "dialects": [], "playbooks": [],
                           "profiles": [], "captures": [], "errors": []}
    try:
        from host.iso8583.dialect import available_dialects, load_dialect
        for name in available_dialects():
            d = load_dialect(name)
            out["dialects"].append({
                "name": name, "fields": len(d.fields),
                "tpdu": d.framing.tpdu_length, "numerics": d.numeric_encoding,
            })
    except Exception as exc:                      # noqa: BLE001
        out["errors"].append(f"dialects: {exc}")

    try:
        from host.mutation import available_playbooks, load_playbook
        for name in available_playbooks():
            pb = load_playbook(name)
            out["playbooks"].append({
                "name": name, "description": pb.description,
                "rules": len([r for r in (*pb.field_mutations, *pb.de55_mutations)
                              if r.enabled]),
            })
    except Exception as exc:                      # noqa: BLE001
        out["errors"].append(f"playbooks: {exc}")

    try:
        from host.crypto import available_profiles, load_profile
        for name in available_profiles():
            p = load_profile(name)
            out["profiles"].append({"name": name, "description": p.description,
                                    "tags": len(p.tags),
                                    "session_key": p.session_key})
    except Exception as exc:                      # noqa: BLE001
        out["errors"].append(f"profiles: {exc}")

    out["captures"] = list_captures()["captures"]
    out["imk_configured"] = _imk_available()
    return out


def _imk_available() -> bool:
    import os
    return bool(os.environ.get("HOST_IMK") or os.environ.get("HOST_IMK_FILE"))


@router.get("/captures")
def list_captures() -> dict:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    files = []
    for f in sorted(LOGS_DIR.glob("*.jsonl"), key=lambda p: p.stat().st_mtime,
                    reverse=True):
        st = f.stat()
        files.append({"name": f.name, "size": st.st_size,
                      "modified": int(st.st_mtime * 1000)})
    return {"ok": True, "captures": files}


@router.get("/capture/{name}")
def read_capture(name: str, offset: int = 0, limit: int = 200) -> dict:
    path = _safe_capture_path(name)
    if not path.is_file():
        raise HTTPException(404, "Capture not found")
    from host.capture import load_capture, summarise

    records = load_capture(path)
    return {
        "ok": True, "name": name, "total": len(records),
        "summary": summarise(records),
        "records": records[offset: offset + limit],
    }


# ── Proxy ─────────────────────────────────────────────────────────────────────

@router.post("/proxy/start")
def start_proxy(body: ProxyStartBody) -> dict:
    global _proxy, _proxy_capture, _proxy_meta

    with _lock:
        if _proxy is not None:
            return {"ok": False, "error": "A host proxy is already running"}

    mode = (body.mode or "passive").lower()
    if mode not in ("passive", "mutate"):
        raise HTTPException(400, f"Unknown mode {body.mode!r}; use passive or mutate")
    if mode == "mutate":
        _require_confirm(body.confirm, "The mutating proxy")

    from host.capture import CaptureLog
    from host.iso8583.dialect import DialectError, load_dialect
    from host.mutation import MutationError, load_playbook
    from host.proxy import MutatingProxy, PassiveProxy
    from host.scoping import Scope, ScopeError, parse_target

    try:
        dialect = load_dialect(body.dialect)
        listen_host, listen_port = parse_target(body.listen)
        target_host, target_port = parse_target(body.target)
        scope = Scope(allowed_targets=tuple(body.allow),
                      on_live_pan="abort" if body.abort_on_live_pan else "warn")
        playbook = load_playbook(body.playbook) if (mode == "mutate" and body.playbook) else None
        if mode == "mutate" and playbook is None:
            raise MutationError("The mutating proxy needs a playbook.")
    except (DialectError, MutationError, ScopeError) as exc:
        return {"ok": False, "error": str(exc)}

    capture_path = _safe_capture_path(body.capture) if body.capture else None
    capture = CaptureLog(capture_path)

    try:
        if mode == "mutate":
            proxy = MutatingProxy(listen_host, listen_port, target_host, target_port,
                                  dialect=dialect, scope=scope, capture=capture,
                                  playbook=playbook)
        else:
            proxy = PassiveProxy(listen_host, listen_port, target_host, target_port,
                                 dialect=dialect, scope=scope, capture=capture)
        proxy.start()
    except (ScopeError, MutationError) as exc:
        capture.close()
        return {"ok": False, "error": str(exc)}
    except Exception as exc:                      # noqa: BLE001
        capture.close()
        logger.exception("Could not start the host proxy")
        return {"ok": False, "error": str(exc)}

    with _lock:
        _proxy = proxy
        _proxy_capture = capture
        _proxy_meta = {
            "mode": mode, "dialect": dialect.name,
            "listen": f"{listen_host}:{proxy.bound_port}",
            "target": f"{target_host}:{target_port}",
            "playbook": playbook.name if playbook else None,
            "capture": body.capture,
        }
    logger.info("Host proxy started (%s) %s -> %s", mode,
                _proxy_meta["listen"], _proxy_meta["target"])
    return {"ok": True, **_proxy_meta}


@router.post("/proxy/stop")
def stop_proxy() -> dict:
    global _proxy, _proxy_capture, _proxy_meta
    with _lock:
        proxy, capture = _proxy, _proxy_capture
        _proxy = _proxy_capture = None
        _proxy_meta = {}
    if proxy is None:
        return {"ok": True, "message": "No host proxy was running"}
    try:
        proxy.stop()
    finally:
        if capture is not None:
            capture.close()
    logger.info("Host proxy stopped")
    return {"ok": True}


@router.get("/proxy/status")
def proxy_status(tail: int = 25) -> dict:
    with _lock:
        proxy, capture, meta = _proxy, _proxy_capture, dict(_proxy_meta)
    if proxy is None:
        return {"ok": True, "running": False, "records": [], "counts": {}}

    records = list(capture.records) if capture else []
    counts = {
        "messages": len(records),
        "mutations": sum(len(r.mutations) for r in records),
        "discrepancies": sum(len(r.discrepancies) for r in records),
        "warnings": sum(len(r.warnings) for r in records),
    }
    return {
        "ok": True, "running": True, **meta, "counts": counts,
        "records": [r.to_dict() if hasattr(r, "to_dict") else r.__dict__
                    for r in records[-tail:]],
    }


# ── Replay ────────────────────────────────────────────────────────────────────

@router.post("/replay/run")
def run_replay(body: ReplayBody) -> dict:
    global _replay_thread, _replay_state

    _require_confirm(body.confirm, "Replay")
    if _replay_state.get("running"):
        return {"ok": False, "error": "A replay is already running"}

    from host.capture import CaptureLog
    from host.iso8583.dialect import DialectError, load_dialect
    from host.mutation import MutationError, load_playbook
    from host.replay import ReplayError, ReplaySession, load_corpus
    from host.scoping import Scope, ScopeError, parse_target

    imk = crypto_profile = None
    try:
        dialect = load_dialect(body.dialect)
        target_host, target_port = parse_target(body.target)
        scope = Scope(allowed_targets=tuple(body.allow),
                      on_live_pan="abort" if body.abort_on_live_pan else "warn")
        playbook = load_playbook(body.playbook) if body.playbook else None
        items = load_corpus(_safe_capture_path(body.capture),
                            mti=tuple(body.mti), limit=body.limit)
        if body.resign:
            imk, crypto_profile = _server_side_imk(body.profile)
    except (DialectError, MutationError, ReplayError, ScopeError, ValueError,
            OSError) as exc:
        return {"ok": False, "error": str(exc)}

    try:
        session = ReplaySession(
            target_host, target_port, dialect=dialect, scope=scope,
            capture=CaptureLog(None), playbook=playbook, freshen=body.freshen,
            timeout=body.timeout, imk=imk, crypto_profile=crypto_profile,
            psn=body.psn)
    except ScopeError as exc:
        return {"ok": False, "error": str(exc)}

    _replay_state = {"running": True, "done": False, "error": "", "sent": 0,
                     "total": len(items), "summary": "", "results": []}

    def _run() -> None:
        import time

        from host.replay import ReplayReport

        report = ReplayReport(
            mode=session.mode,
            playbook=session.playbook.name if session.playbook else "",
            resigned=session.imk is not None and session.crypto_profile is not None)
        try:
            with session:
                for item in items:
                    result = session.send_one(item)
                    # Keep the real result for the verdict, and a flattened
                    # copy for the UI to poll — deriving the verdict from the
                    # flattened copy would mean reconstructing objects it had
                    # already thrown away.
                    report.results.append(result)
                    _replay_state["sent"] += 1
                    _replay_state["results"].append({
                        "seq": item.seq, "mti": item.mti,
                        "changed": bool(result.changes),
                        "rc": result.response_code,
                        "approved": result.approved,
                        "rtt_ms": result.rtt_ms, "error": result.error,
                        "changes": [c.to_dict() for c in result.changes],
                    })
                    if body.delay:
                        time.sleep(body.delay)
        except Exception as exc:                  # noqa: BLE001
            logger.exception("Replay failed")
            _replay_state["error"] = str(exc)
        finally:
            _replay_state["summary"] = report.summary()
            _replay_state["running"] = False
            _replay_state["done"] = True

    _replay_thread = threading.Thread(target=_run, daemon=True, name="host-replay")
    _replay_thread.start()
    return {"ok": True, "total": len(items)}


@router.get("/replay/status")
def replay_status() -> dict:
    return {"ok": True, **_replay_state}


# ── Analysis ──────────────────────────────────────────────────────────────────

@router.post("/detect")
def detect_dialect(body: DetectBody) -> dict:
    from host.capture import load_capture
    from host.iso8583.detect import detect

    if body.hex:
        try:
            data = bytes.fromhex(body.hex.strip().replace(" ", ""))
        except ValueError:
            return {"ok": False, "error": "That is not hex."}
    elif body.capture:
        records = load_capture(_safe_capture_path(body.capture))
        raws = [r["raw"] for r in records if r.get("raw")]
        if not raws:
            return {"ok": False, "error": "This capture holds no raw bytes to "
                                          "analyse. Was it written without them?"}
        data = bytes.fromhex(raws[0])
    else:
        return {"ok": False, "error": "Give a capture or a hex string."}

    return {"ok": True, "candidates": [
        {"dialect": c.dialect.name, "label": c.label, "score": round(c.score, 3),
         "notes": c.notes, "mti": c.message.mti if c.message else ""}
        for c in detect(data, limit=body.limit)
    ]}


def _server_side_imk(profile_name: str):
    """
    Resolve an IMK without it ever passing through a request.

    A key in a request body lands in access logs, reverse-proxy logs and
    browser history; none of those are places an issuer master key should be.
    """
    import os

    from host.crypto import load_imk, load_profile
    path = os.environ.get("HOST_IMK_FILE") or None
    if not path and not os.environ.get("HOST_IMK"):
        raise ValueError(
            "No issuer master key is configured on the server. Set HOST_IMK, or "
            "HOST_IMK_FILE to a file holding it, and restart ATRIUM. Keys are "
            "deliberately not accepted over this API — a key in a request body "
            "ends up in logs and browser history."
        )
    imk, _source = load_imk(None, path)
    return imk, load_profile(profile_name)


@router.post("/verify")
def verify_cryptograms(body: VerifyBody) -> dict:
    from host.crypto import derive_udk, verify_cryptogram
    from host.iso8583.codec import unpack_body
    from host.iso8583.dialect import DialectError, load_dialect
    from host.replay import ReplayError, load_corpus

    try:
        dialect = load_dialect(body.dialect)
        imk, profile = _server_side_imk(body.profile)
        items = load_corpus(_safe_capture_path(body.capture), limit=body.limit)
    except (DialectError, ReplayError, ValueError, OSError) as exc:
        return {"ok": False, "error": str(exc)}

    rows, checked, matched = [], 0, 0
    for item in items:
        try:
            wire, _ = dialect.framing.unwrap(item.raw)
            _tpdu, rest = dialect.framing.split_tpdu(wire)
            msg = unpack_body(dialect, rest)
            pan = msg.fields.get(2)
            if not isinstance(pan, str) or not pan:
                rows.append({"seq": item.seq, "state": "skipped",
                             "detail": "no PAN — cannot derive a key"})
                continue
            result = verify_cryptogram(msg, derive_udk(imk, pan, body.psn).udk,
                                       profile)
        except Exception as exc:                  # noqa: BLE001
            rows.append({"seq": item.seq, "state": "error", "detail": str(exc)})
            continue

        if result.reason:
            rows.append({"seq": item.seq, "state": "unchecked",
                         "detail": result.reason})
        else:
            checked += 1
            matched += int(result.matched)
            rows.append({"seq": item.seq,
                         "state": "verified" if result.matched else "mismatch",
                         "detail": str(result), "atc": result.atc})

    return {"ok": True, "profile": profile.name, "checked": checked,
            "matched": matched, "rows": rows,
            "advice": _verify_advice(checked, matched)}


def _verify_advice(checked: int, matched: int) -> str:
    if not checked:
        return ("Nothing could be checked. The usual causes are a profile that "
                "does not match the card's scheme, or DE55 missing tags the "
                "profile needs — the rows say which.")
    if matched == checked:
        return ("The key and profile are right for this traffic. A mismatch "
                "from here on is evidence about the data, not about the setup.")
    if not matched:
        return ("Nothing verified. Doubt the profile before the key: try "
                "emv-book2-iad or udk-direct, and confirm against your "
                "target's own test vectors.")
    return (f"{matched} of {checked} verified. A partial result usually means "
            "the corpus mixes cards or schemes.")
