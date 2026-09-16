"""
REST routes — SimTrace2 device and daemon discovery.

ATRIUM does not launch simtrace2-remsim.  The daemon needs raw USB access, so
it wants root, and having a web request escalate privileges means either a
password prompt with nowhere to go or a passwordless sudo rule that turns the
API into a root shell for anything that can reach it.  Neither is worth it.

So the operator runs it themselves in a second terminal, and ATRIUM's job is
only to answer "which device, which command, is it up yet":

GET  /api/simtrace/devices   — enumerate SimTrace2 USB devices via sysfs
GET  /api/simtrace/status    — is a simtrace2-remsim running, and on what
GET  /api/simtrace/command   — the exact command to paste into a root shell
GET  /api/simtrace/config    — stored binary-path hint (display only)
PUT  /api/simtrace/config    — update it

Nothing in this module executes anything.  tests/test_security.py enforces
that.
"""
from __future__ import annotations

import json
import logging
import pwd
import re
import shlex
import shutil
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/simtrace", tags=["simtrace"])

_ROOT        = Path(__file__).parent.parent.parent
_CONFIG_FILE = _ROOT / "simtrace_config.json"

_USB_VENDOR  = "1d50"
_USB_PRODUCT = "60e3"
_USB_CONFIG  = "1"

_BINARY_NAME = "simtrace2-remsim"

# /proc/<pid>/comm is truncated to 15 characters, so the name we match on the
# cheap first pass is one short of the real one.
_COMM_NAME = _BINARY_NAME[:15]

# Build trees people actually end up with, checked in order after $PATH.
_COMMON_LOCATIONS = (
    "~/simtrace2/host/src/" + _BINARY_NAME,
    "~/Desktop/elma/simtrace2/host/src/" + _BINARY_NAME,
    "~/src/simtrace2/host/src/" + _BINARY_NAME,
    "/usr/local/bin/" + _BINARY_NAME,
    "/usr/bin/" + _BINARY_NAME,
)

_UDEV_RULE_PATH = "/etc/udev/rules.d/60-simtrace2.rules"
_UDEV_RULE = (
    f'SUBSYSTEM=="usb", ATTR{{idVendor}}=="{_USB_VENDOR}", '
    f'ATTR{{idProduct}}=="{_USB_PRODUCT}", MODE="0660", TAG+="uaccess"'
)

_USB_PATH_RE = re.compile(r"^\d+-[\d.]+$")


# ── Validation ────────────────────────────────────────────────────────────────
#
# The USB path is still validated even though nothing runs here, because it is
# interpolated into a command string the operator will paste into a root shell.
# Rendering something unexpected there is its own kind of injection — just with
# a human in the loop instead of execve.

def _validate_usb_path(usb_path: str) -> str:
    """Only accept a sysfs USB path this host actually reports for a SimTrace2."""
    if not _USB_PATH_RE.match(usb_path or ""):
        raise HTTPException(400, f"Malformed USB path: {usb_path!r}")
    known = {d["usb_path"] for d in list_devices()["devices"]}
    if usb_path not in known:
        raise HTTPException(
            400,
            f"No SimTrace2 device at USB path {usb_path}. "
            f"Detected: {', '.join(sorted(known)) or 'none'}",
        )
    return usb_path


# ── Config helpers ────────────────────────────────────────────────────────────
#
# The stored path is a display hint for the suggested command, nothing more.
# It is never executed, so there is no allow-list to enforce here.

def _load_config() -> dict:
    if _CONFIG_FILE.exists():
        try:
            cfg = json.loads(_CONFIG_FILE.read_text(encoding="utf-8"))
            return {
                "binary_path": str(cfg.get("binary_path", "")),
                "use_sudo": bool(cfg.get("use_sudo", True)),
            }
        except Exception:
            logger.warning("Ignoring unreadable %s", _CONFIG_FILE.name)
    return {"binary_path": "", "use_sudo": True}


def _save_config(cfg: dict) -> None:
    _CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def _resolve_binary(cfg: dict) -> tuple[str, str]:
    """
    Find something plausible to name in the suggested command.

    Returns (path, source).  A miss is not an error: falling back to the bare
    name still gives the operator a runnable line if the binary is on root's
    PATH, and the UI says where the value came from.
    """
    configured = (cfg.get("binary_path") or "").strip()
    if configured:
        return str(Path(configured).expanduser()), "config"

    found = shutil.which(_BINARY_NAME)
    if found:
        return found, "path"

    for candidate in _COMMON_LOCATIONS:
        p = Path(candidate).expanduser()
        if p.is_file():
            return str(p), "search"

    return _BINARY_NAME, "fallback"


# ── Process discovery ─────────────────────────────────────────────────────────

PROC_ROOT = Path("/proc")


def _read_cmdline(pid_dir: Path) -> list[str]:
    try:
        raw = (pid_dir / "cmdline").read_bytes()
    except OSError:
        return []
    return [a for a in raw.decode("utf-8", errors="replace").split("\0") if a]


def _arg_value(argv: list[str], flag: str) -> str:
    """Pull `--flag value` or `--flag=value` out of an argv list."""
    for i, arg in enumerate(argv):
        if arg == flag and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith(flag + "="):
            return arg.split("=", 1)[1]
    return ""


def _owner(pid_dir: Path) -> str:
    try:
        uid = pid_dir.stat().st_uid
    except OSError:
        return ""
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def find_remsim_processes(proc_root: Path | None = None) -> list[dict]:
    """
    Every running simtrace2-remsim on this host.

    Reads /proc directly rather than shelling out to pgrep: no subprocess, and
    /proc/<pid>/cmdline is world-readable, so an unprivileged ATRIUM can still
    see a daemon the operator started under sudo.
    """
    procs: list[dict] = []
    root = proc_root or PROC_ROOT
    if not root.is_dir():
        return procs

    for entry in root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            comm = (entry / "comm").read_text(encoding="utf-8").strip()
        except OSError:
            continue                     # process exited, or not ours to read
        if comm not in (_COMM_NAME, _BINARY_NAME):
            continue

        # comm is truncated, so confirm against argv[0] before believing it.
        argv = _read_cmdline(entry)
        if argv and Path(argv[0]).name != _BINARY_NAME:
            continue

        try:
            started = int(entry.stat().st_ctime * 1000)
        except OSError:
            started = 0

        procs.append({
            "pid":      int(entry.name),
            "user":     _owner(entry),
            "usb_path": _arg_value(argv, "--usb-path"),
            "cmdline":  " ".join(argv),
            "started":  started,
        })

    return sorted(procs, key=lambda p: p["pid"])


# ── Pydantic models ───────────────────────────────────────────────────────────

class SimTraceConfigBody(BaseModel):
    binary_path: str = ""
    use_sudo: bool = True


# ── Routes ────────────────────────────────────────────────────────────────────

@router.get("/devices")
def list_devices() -> dict:
    """Enumerate connected SimTrace2 devices via /sys/bus/usb/devices/."""
    devices = []
    usb_root = Path("/sys/bus/usb/devices")
    if not usb_root.exists():
        return {"ok": True, "devices": []}

    for dev_dir in sorted(usb_root.iterdir()):
        vendor_file  = dev_dir / "idVendor"
        product_file = dev_dir / "idProduct"
        if not (vendor_file.exists() and product_file.exists()):
            continue
        try:
            vendor  = vendor_file.read_text(encoding="utf-8").strip()
            product = product_file.read_text(encoding="utf-8").strip()
        except Exception:
            continue
        if vendor != _USB_VENDOR or product != _USB_PRODUCT:
            continue

        manufacturer = ""
        product_name = ""
        try:
            manufacturer = (dev_dir / "manufacturer").read_text(encoding="utf-8").strip()
        except Exception:
            pass
        try:
            product_name = (dev_dir / "product").read_text(encoding="utf-8").strip()
        except Exception:
            pass

        devices.append({
            "usb_path":     dev_dir.name,
            "manufacturer": manufacturer,
            "product":      product_name,
            "vendor_id":    vendor,
            "product_id":   product,
        })

    return {"ok": True, "devices": devices}


@router.get("/status")
def simtrace_status() -> dict:
    """
    What the operator needs to know at a glance.

    ``state`` collapses the combinations into one thing the UI can switch on:

      no_device      nothing matching 1d50:60e3 on the bus
      device_ready   board is present, no daemon yet — show them the command
      running        a simtrace2-remsim is up on a device we can see
      running_other  a daemon is up but bound to a device we cannot see
    """
    devices = list_devices()["devices"]
    procs   = find_remsim_processes()
    known   = {d["usb_path"] for d in devices}

    if procs:
        proc = next((p for p in procs if p["usb_path"] in known), procs[0])
        matched = proc["usb_path"] in known
        state = "running" if matched else "running_other"
    else:
        proc = None
        state = "device_ready" if devices else "no_device"

    return {
        "ok":        True,
        "state":     state,
        # `running`/`pid` keep the shape the dashboard already reads.
        "running":   proc is not None,
        "pid":       proc["pid"] if proc else None,
        "user":      proc["user"] if proc else None,
        "usb_path":  proc["usb_path"] if proc else None,
        "cmdline":   proc["cmdline"] if proc else "",
        "started":   proc["started"] if proc else None,
        "processes": procs,
        "devices":   devices,
    }


@router.get("/command")
def simtrace_command(usb_path: str = "") -> dict:
    """
    The command to run in a second terminal.

    With no ``usb_path`` and exactly one board attached, that board is assumed.
    With no board attached at all the line still comes back, carrying a
    placeholder, so the UI has something to show while the operator goes and
    plugs it in.
    """
    cfg              = _load_config()
    binary, source   = _resolve_binary(cfg)
    devices          = list_devices()["devices"]

    if usb_path:
        target, resolved = _validate_usb_path(usb_path), True
    elif len(devices) == 1:
        target, resolved = devices[0]["usb_path"], True
    else:
        # Deliberately shell-safe: an operator who pastes the line before
        # plugging the board in gets a clean "no such device", not a redirect.
        target, resolved = "USB-PATH-HERE", False

    argv = [
        binary,
        "--usb-vendor",  _USB_VENDOR,
        "--usb-product", _USB_PRODUCT,
        "--usb-path",    target,
        "--usb-config",  _USB_CONFIG,
    ]
    command = " ".join(shlex.quote(a) for a in argv)
    if cfg["use_sudo"]:
        command = "sudo " + command

    return {
        "ok":            True,
        "command":       command,
        "binary":        binary,
        "binary_source": source,
        "usb_path":      target,
        "resolved":      resolved,
        "udev_rule":     _UDEV_RULE,
        "udev_path":     _UDEV_RULE_PATH,
    }


@router.get("/config")
def get_simtrace_config() -> dict:
    cfg            = _load_config()
    binary, source = _resolve_binary(cfg)
    return {"ok": True, **cfg, "resolved_binary": binary, "binary_source": source}


@router.put("/config")
def save_simtrace_config(body: SimTraceConfigBody) -> dict:
    path = body.binary_path.strip()
    _save_config({"binary_path": path, "use_sudo": body.use_sudo})
    logger.info("SimTrace2 command hint updated: binary_path=%s use_sudo=%s",
                path or "(auto-detect)", body.use_sudo)
    return {"ok": True}


# Kept so a browser tab left open across the upgrade gets an explanation rather
# than a bare 404.
_MOVED = ("ATRIUM no longer starts or stops simtrace2-remsim. Run it yourself "
          "in a second terminal — GET /api/simtrace/command returns the exact "
          "line, and /api/simtrace/status reports when it is up.")


@router.post("/start", deprecated=True)
def start_simtrace_gone() -> dict:
    raise HTTPException(410, _MOVED)


@router.post("/stop", deprecated=True)
def stop_simtrace_gone() -> dict:
    raise HTTPException(410, _MOVED)
