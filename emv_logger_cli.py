#!/usr/bin/env python3
"""
emv_logger_cli.py – Standalone CLI for testing and replaying EMV APDU logs.

Modes
─────
1. LIVE (default): connect directly to vpcd socket and log everything.

       python3 emv_logger_cli.py --mode live [--host localhost] [--port 35963]

2. FILE: read a hex-log file produced by HexlogHandler and re-parse it
   through the logger (useful for offline TLV inspection / format conversion).

       python3 emv_logger_cli.py --mode file --input logs/apdu.hexlog

3. REPLAY: load a saved session JSON and optionally send each command to a
   real card reader via pyscard.

       python3 emv_logger_cli.py --mode replay --input logs/sessions/session_<id>.json
       python3 emv_logger_cli.py --mode replay --input logs/sessions/session_<id>.json \\
               --reader 0 --send

4. STDIN: feed raw hex APDUs from stdin, one per line, prefixed C/R.

       echo "C 00 A4 04 00 07 A0 00 00 00 03 10 10" | python3 emv_logger_cli.py --mode stdin

Common flags
────────────
  --config PATH     YAML/TOML config file (default: emv_logger.yaml if present)
  --format FORMAT   Override output format: console|json|hexlog|sqlite|all
  --no-color        Disable ANSI color
  --filter-ins INS  Only show APDUs with this INS byte (hex), repeatable
"""

from __future__ import annotations

import argparse
import logging
import re
import socket
import struct
import sys
import time
from pathlib import Path

# ── bootstrap logging ─────────────────────────────────────────────────────────
logging.basicConfig(level=logging.WARNING,
                    format="%(levelname)s  %(name)s  %(message)s")

from emv_logger import (
    EMVLogger, Direction, load_config,
    ConsoleHandler, JSONHandler, HexlogHandler, SQLiteHandler,
    _to_bytes, _now,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _build_logger(args: argparse.Namespace) -> EMVLogger:
    cfg_path = args.config if args.config else (
        "emv_logger.yaml" if Path("emv_logger.yaml").exists() else None
    )
    cfg = load_config(cfg_path)

    # CLI format override
    if args.format:
        for key in ("console", "json", "hexlog", "sqlite"):
            cfg["output"][key] = (key == args.format or args.format == "all")

    if args.no_color:
        cfg["console"]["colors"] = False

    # CLI INS filter override
    if args.filter_ins:
        cfg["filters"]["cla_ins"] = [x.upper() for x in args.filter_ins]

    return EMVLogger(cfg)


# ── mode: live (vpcd socket) ──────────────────────────────────────────────────

_SHORT = struct.Struct("!H")

VPCD_CTRL_LEN   = 1
VPCD_CTRL_OFF   = b'\x00'
VPCD_CTRL_ON    = b'\x01'
VPCD_CTRL_RESET = b'\x02'
VPCD_CTRL_ATR   = b'\x04'


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("vpcd disconnected")
        buf += chunk
    return buf


def mode_live(args: argparse.Namespace) -> None:
    """
    Connect to vpcd and log everything – passthrough only, no mutation.
    Useful for verifying the logger works without running the full intercept.
    """
    emv = _build_logger(args)
    host = args.host
    port = args.port

    print(f"Connecting to vpcd at {host}:{port} …")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.settimeout(None)
    print("Connected.  Waiting for APDUs (Ctrl-C to stop).\n")

    try:
        while True:
            size_raw = _recv_exact(sock, 2)
            size = _SHORT.unpack(size_raw)[0]

            if size == 0:
                msg = None
            else:
                msg = _recv_exact(sock, size)

            if size == VPCD_CTRL_LEN:
                # Control messages – passthrough unchanged
                sock.sendall(_SHORT.pack(0))
                continue

            if msg is None:
                continue

            # Log command, echo it back unchanged (pure observer mode)
            emv.on_command(msg)
            # In live mode the logger is passive – send the APDU straight back
            # so vpcd can forward to the real card.  When used alongside the
            # intercept stack this mode is not needed; use it standalone only.
            sock.sendall(_SHORT.pack(len(msg)) + msg)

    except (KeyboardInterrupt, EOFError):
        print("\nStopped.")
    finally:
        emv.close()
        sock.close()


# ── mode: file (parse a hexlog) ───────────────────────────────────────────────

_HEXLOG_LINE = re.compile(
    r"^(\d+)\s+([CR])\s+\[([0-9a-fA-F]+)\]\s+((?:[0-9A-Fa-f]{2}\s*)+)$"
)


def mode_file(args: argparse.Namespace) -> None:
    """Read a .hexlog file and feed every APDU through the logger."""
    emv = _build_logger(args)
    path = Path(args.input)
    if not path.exists():
        sys.exit(f"File not found: {path}")

    lines = path.read_text().splitlines()
    for lineno, line in enumerate(lines, 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _HEXLOG_LINE.match(line)
        if not m:
            logging.warning("line %d: unrecognised format, skipping", lineno)
            continue

        direction = m.group(2)
        raw_bytes = bytes.fromhex(m.group(4).replace(" ", ""))

        if direction == "C":
            emv.on_command(raw_bytes)
        else:
            # For response-only lines we need a dummy cmd to pair with
            emv.on_response(b"", raw_bytes)

    emv.close()


# ── mode: replay ─────────────────────────────────────────────────────────────

def mode_replay(args: argparse.Namespace) -> None:
    """
    Load a saved session JSON, print the command sequence, and optionally
    send each command to a physical card via pyscard.
    """
    emv = _build_logger(args)
    commands = emv.replay_session(args.input)

    if not commands:
        print("No command APDUs found in session file.")
        emv.close()
        return

    print(f"Loaded {len(commands)} command APDUs.\n")

    if not args.send:
        # Dry-run: just print the sequence
        for c in commands:
            spaced = " ".join(
                c["raw_hex"][i:i+2] for i in range(0, len(c["raw_hex"]), 2)
            )
            print(f"  #{c['seq']:03d}  {c['ins_name'] or '?':30s}  {spaced}")
        print("\n(Use --send to replay against a physical card)")
        emv.close()
        return

    # Live replay
    try:
        import smartcard.System
        import smartcard.Session
        from smartcard.util import toHexString
    except ImportError:
        sys.exit("pyscard not installed; cannot replay to physical card.")

    readers = smartcard.System.listReaders()
    if args.reader >= len(readers):
        sys.exit(f"Reader {args.reader} not available (found {len(readers)}).")

    session = smartcard.Session(readers[args.reader])
    print(f"Connected to: {readers[args.reader]}\n")

    for c in commands:
        apdu_list = list(c["raw_bytes"])
        try:
            rapdu, sw1, sw2 = session.sendCommandAPDU(apdu_list)
            resp = bytes(rapdu + [sw1, sw2])
            emv.on_command(c["raw_bytes"])
            emv.on_response(c["raw_bytes"], resp)
        except Exception as exc:
            print(f"  #{c['seq']:03d}  ERROR: {exc}")

    session.close()
    emv.close()


# ── mode: stdin ───────────────────────────────────────────────────────────────

def mode_stdin(args: argparse.Namespace) -> None:
    """
    Read hex APDUs from stdin, one per line.
    Format:  C <hex bytes>   – command (terminal→card)
             R <hex bytes>   – response (card→terminal)

    Example:
        C 00 A4 04 00 07 A0 00 00 00 03 10 10
        R 6F 1F 84 07 A0 00 00 00 03 10 10 A5 14 50 0A 56 49 53 41 20 44 45 42 49 54 90 00
    """
    emv = _build_logger(args)
    last_cmd = b""
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2 or parts[0] not in ("C", "R"):
            continue
        try:
            raw = bytes.fromhex("".join(parts[1:]))
        except ValueError as exc:
            logging.warning("stdin: bad hex on line: %s (%s)", line, exc)
            continue

        if parts[0] == "C":
            last_cmd = raw
            emv.on_command(raw)
        else:
            emv.on_response(last_cmd, raw)

    emv.close()


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="EMV APDU logger CLI – test and replay without running the full intercept stack.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--mode", choices=["live", "file", "replay", "stdin"],
                   default="stdin",
                   help="Operation mode (default: stdin)")
    p.add_argument("--config", metavar="PATH",
                   help="YAML/TOML config file (default: emv_logger.yaml if present)")
    p.add_argument("--format",
                   choices=["console", "json", "hexlog", "sqlite", "all"],
                   help="Override output format from config")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI colour output")
    p.add_argument("--filter-ins", metavar="INS", action="append", default=[],
                   help="Only show APDUs with this INS byte (hex, repeatable)")

    # live mode
    p.add_argument("--host", default="localhost",
                   help="vpcd host (live mode, default localhost)")
    p.add_argument("--port", type=int, default=35963,
                   help="vpcd port (live mode, default 35963)")

    # file / replay mode
    p.add_argument("--input", metavar="PATH",
                   help="Hexlog or session-JSON to read (file/replay mode)")

    # replay mode extras
    p.add_argument("--reader", type=int, default=0,
                   help="pyscard reader index for live replay (default 0)")
    p.add_argument("--send", action="store_true",
                   help="Actually send replayed commands to the card reader")

    args = p.parse_args()

    if args.mode in ("file", "replay") and not args.input:
        p.error(f"--input is required for --mode {args.mode}")

    dispatch = {
        "live":   mode_live,
        "file":   mode_file,
        "replay": mode_replay,
        "stdin":  mode_stdin,
    }
    dispatch[args.mode](args)


if __name__ == "__main__":
    main()
