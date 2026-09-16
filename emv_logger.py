"""
emv_logger.py – Flexible APDU logging layer for the atrium-pentest intercept path.

Insertion points (intercept_attack.py → InterceptAttack.user_execute):

    from emv_logger import EMVLogger
    _emv = EMVLogger.from_config("emv_logger.yaml")

    def user_execute(self, msg):
        msg = _emv.on_command(msg)          # log + optional pre-send mutation
        ans = self.os.execute(msg)
        ans = _emv.on_response(msg, ans)    # log + optional pre-response mutation
        return ans

The logger wraps cleanly around the existing attacker_mitm / CVM-change logic
because it sits at the entry and exit of user_execute, not inside it.
"""

from __future__ import annotations

import binascii
import dataclasses
import datetime
import importlib.util
import json
import logging
import os
import queue
import sqlite3
import sys
import threading
import time
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 1 – EMV tag + INS dictionaries, BER-TLV parser, APDU / session records
# ─────────────────────────────────────────────────────────────────────────────

# ISO 7816-4 / EMVCo tag name dictionary (tag hex → human name)
EMV_TAGS: dict[str, str] = {
    "4F":     "Application Identifier (AID) – Card",
    "50":     "Application Label",
    "57":     "Track 2 Equivalent Data",
    "5A":     "Application Primary Account Number (PAN)",
    "5F20":   "Cardholder Name",
    "5F24":   "Application Expiry Date",
    "5F25":   "Application Effective Date",
    "5F28":   "Issuer Country Code",
    "5F2A":   "Transaction Currency Code",
    "5F2D":   "Language Preference",
    "5F30":   "Service Code",
    "5F34":   "Application PAN Sequence Number",
    "5F36":   "Transaction Currency Exponent",
    "5F50":   "Issuer URL",
    "5F53":   "International Bank Account Number (IBAN)",
    "5F54":   "Bank Identifier Code (BIC)",
    "5F55":   "Issuer Country Code (alpha2)",
    "5F56":   "Issuer Country Code (alpha3)",
    "61":     "Application Template",
    "6F":     "File Control Information (FCI) Template",
    "70":     "EMV Proprietary Template",
    "71":     "Issuer Script Template 1",
    "72":     "Issuer Script Template 2",
    "73":     "Directory Discretionary Template",
    "77":     "Response Message Template Format 2",
    "80":     "Response Message Template Format 1",
    "82":     "Application Interchange Profile (AIP)",
    "83":     "Command Template",
    "84":     "Dedicated File (DF) Name",
    "86":     "Issuer Script Command",
    "87":     "Application Priority Indicator",
    "88":     "Short File Identifier (SFI)",
    "89":     "Authorisation Code",
    "8A":     "Authorisation Response Code",
    "8C":     "Card Risk Management DOL 1 (CDOL1)",
    "8D":     "Card Risk Management DOL 2 (CDOL2)",
    "8E":     "Cardholder Verification Method (CVM) List",
    "8F":     "Certification Authority Public Key Index",
    "90":     "Issuer Public Key Certificate",
    "91":     "Issuer Authentication Data",
    "92":     "Issuer Public Key Remainder",
    "93":     "Signed Static Application Data",
    "94":     "Application File Locator (AFL)",
    "95":     "Terminal Verification Results (TVR)",
    "97":     "Transaction Certificate DOL (TDOL)",
    "98":     "Transaction Certificate (TC) Hash Value",
    "99":     "Transaction PIN Data",
    "9A":     "Transaction Date",
    "9B":     "Transaction Status Information",
    "9C":     "Transaction Type",
    "9D":     "Directory Definition File (DDF) Name",
    "9F02":   "Amount, Authorised (Numeric)",
    "9F03":   "Amount, Other (Numeric)",
    "9F05":   "Application Discretionary Data",
    "9F06":   "Application Identifier (AID) – Terminal",
    "9F07":   "Application Usage Control",
    "9F08":   "Application Version Number – ICC",
    "9F09":   "Application Version Number – Terminal",
    "9F0B":   "Cardholder Name Extended",
    "9F0D":   "Issuer Action Code – Default",
    "9F0E":   "Issuer Action Code – Denial",
    "9F0F":   "Issuer Action Code – Online",
    "9F10":   "Issuer Application Data",
    "9F11":   "Issuer Code Table Index",
    "9F12":   "Application Preferred Name",
    "9F13":   "Last Online ATC Register",
    "9F14":   "Lower Consecutive Offline Limit",
    "9F15":   "Merchant Category Code",
    "9F16":   "Merchant Identifier",
    "9F17":   "PIN Retry Counter",
    "9F18":   "Issuer Script Identifier",
    "9F1A":   "Terminal Country Code",
    "9F1B":   "Terminal Floor Limit",
    "9F1C":   "Terminal Identification",
    "9F1D":   "Terminal Risk Management Data",
    "9F1E":   "IFD Serial Number",
    "9F1F":   "Track 1 Discretionary Data",
    "9F20":   "Track 2 Discretionary Data",
    "9F21":   "Transaction Time",
    "9F22":   "CA Public Key Index – Terminal",
    "9F23":   "Upper Consecutive Offline Limit",
    "9F24":   "Payment Account Reference (PAR)",
    "9F25":   "Last 4 Digits of PAN",
    "9F26":   "Application Cryptogram (AC)",
    "9F27":   "Cryptogram Information Data (CID)",
    "9F2D":   "ICC PIN Encipherment Public Key Certificate",
    "9F2E":   "ICC PIN Encipherment Public Key Exponent",
    "9F2F":   "ICC PIN Encipherment Public Key Remainder",
    "9F32":   "Issuer Public Key Exponent",
    "9F33":   "Terminal Capabilities",
    "9F34":   "CVM Results",
    "9F35":   "Terminal Type",
    "9F36":   "Application Transaction Counter (ATC)",
    "9F37":   "Unpredictable Number",
    "9F38":   "Processing Options DOL (PDOL)",
    "9F39":   "POS Entry Mode",
    "9F3A":   "Amount, Reference Currency",
    "9F3B":   "Application Reference Currency",
    "9F3C":   "Transaction Reference Currency Code",
    "9F3D":   "Transaction Reference Currency Exponent",
    "9F40":   "Additional Terminal Capabilities",
    "9F41":   "Transaction Sequence Counter",
    "9F42":   "Application Currency Code",
    "9F44":   "Application Currency Exponent",
    "9F45":   "Data Authentication Code",
    "9F46":   "ICC Public Key Certificate",
    "9F47":   "ICC Public Key Exponent",
    "9F48":   "ICC Public Key Remainder",
    "9F49":   "Dynamic Data Authentication DOL (DDOL)",
    "9F4A":   "Static Data Authentication Tag List",
    "9F4B":   "Signed Dynamic Application Data",
    "9F4C":   "ICC Dynamic Number",
    "9F4D":   "Log Entry",
    "9F4E":   "Merchant Name and Location",
    "9F4F":   "Log Format",
    "9F50":   "Offline Accumulator Balance",
    "9F51":   "DRDOL",
    "9F52":   "Terminal Compatibility Indicator",
    "9F53":   "Consecutive Transaction Limit (International)",
    "9F54":   "Cumulative Total Transaction Amount Limit",
    "9F55":   "Geographic Indicator",
    "9F56":   "Issuer Authentication Indicator",
    "9F57":   "Issuer Country Code",
    "9F5B":   "Issuer Script Results",
    "9F5D":   "Available Offline Spending Amount (AOSA)",
    "9F60":   "CVC3 (Track1)",
    "9F61":   "CVC3 (Track2)",
    "9F62":   "PCVC3 (Track1)",
    "9F63":   "PUNATC (Track1)",
    "9F64":   "NATC (Track1)",
    "9F65":   "PCVC3 (Track2)",
    "9F66":   "Terminal Transaction Qualifiers (TTQ)",
    "9F67":   "NATC (Track2)",
    "9F69":   "Card Authentication Related Data",
    "9F6B":   "Track 2 Data",
    "9F6C":   "Card Transaction Qualifiers (CTQ)",
    "9F6E":   "Third Party Data",
    "A5":     "FCI Proprietary Template",
    "BF0C":   "FCI Issuer Discretionary Data",
    "DF01":   "Kernel Identifier",
    "9F7C":   "Customer Exclusive Data (CED)",
}

# INS byte → command name (EMVCo Book 1/3 + ISO 7816)
EMV_INS: dict[str, str] = {
    "A4": "SELECT",
    "A8": "GET PROCESSING OPTIONS",
    "B2": "READ RECORD",
    "AE": "GENERATE AC",
    "88": "INTERNAL AUTHENTICATE",
    "CA": "GET DATA",
    "CB": "GET DATA",
    "C0": "GET RESPONSE",
    "20": "VERIFY",
    "21": "VERIFY",
    "82": "EXTERNAL AUTHENTICATE",
    "84": "GET CHALLENGE",
    "D6": "UPDATE BINARY",
    "D7": "UPDATE BINARY",
    "DC": "UPDATE RECORD",
    "DD": "UPDATE RECORD",
    "B0": "READ BINARY",
    "B1": "READ BINARY",
    "E2": "APPEND RECORD",
    "24": "CHANGE PIN",
    "2C": "RESET RETRY COUNTER",
    "70": "MANAGE CHANNEL",
    "22": "MANAGE SECURITY ENVIRONMENT",
    "2A": "PERFORM SECURITY OPERATION",
    "04": "DEACTIVATE FILE",
    "44": "ACTIVATE FILE",
    "C2": "ENVELOPE",
    "86": "GENERAL AUTHENTICATE",
    "F2": "STATUS",
    "F0": "SET STATUS",
    "D8": "PUT KEY",
    "DA": "PUT DATA",
    "E0": "CREATE FILE",
    "E4": "DELETE FILE",
    "EE": "DELETE DATA",
}


# ── Direction constants ───────────────────────────────────────────────────────

class Direction:
    TERMINAL_TO_CARD = "terminal→card"
    CARD_TO_TERMINAL = "card→terminal"


# ── BER-TLV parser ────────────────────────────────────────────────────────────

@dataclasses.dataclass
class TLVNode:
    tag: str                  # uppercase hex, e.g. "9F26"
    tag_name: str             # human name from EMV_TAGS, or "Unknown tag XX"
    length: int
    value: bytes
    constructed: bool
    children: list["TLVNode"] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "tag": self.tag,
            "name": self.tag_name,
            "length": self.length,
            "value": self.value.hex().upper(),
        }
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d


def _parse_tag(data: bytes, pos: int) -> tuple[str, bool, int]:
    """Return (tag_hex, is_constructed, next_pos). Raises ValueError on truncation."""
    if pos >= len(data):
        raise ValueError("truncated tag")
    b0 = data[pos]
    constructed = bool(b0 & 0x20)
    if (b0 & 0x1F) != 0x1F:          # single-byte tag
        return f"{b0:02X}", constructed, pos + 1
    tag_bytes = bytearray([b0])       # multi-byte tag
    pos += 1
    while pos < len(data):
        b = data[pos]
        tag_bytes.append(b)
        pos += 1
        if not (b & 0x80):
            break
    else:
        raise ValueError("truncated multi-byte tag")
    return tag_bytes.hex().upper(), constructed, pos


def _parse_length(data: bytes, pos: int) -> tuple[int, int]:
    """Return (length, next_pos). Raises ValueError on truncation or indefinite form."""
    if pos >= len(data):
        raise ValueError("truncated length")
    b0 = data[pos]
    if b0 < 0x80:
        return b0, pos + 1
    num = b0 & 0x7F
    if num == 0:
        raise ValueError("indefinite-length TLV not supported")
    length = 0
    for _ in range(num):
        pos += 1
        if pos >= len(data):
            raise ValueError("truncated multi-byte length")
        length = (length << 8) | data[pos]
    return length, pos + 1


def parse_tlv(data: bytes, depth: int = 0) -> list[TLVNode]:
    """
    Recursively parse BER-TLV encoded bytes.
    Stops silently on malformed data (never raises).
    """
    nodes: list[TLVNode] = []
    pos = 0
    while pos < len(data):
        if data[pos] in (0x00, 0xFF):   # padding
            pos += 1
            continue
        try:
            tag, constructed, pos = _parse_tag(data, pos)
            length, pos = _parse_length(data, pos)
            if pos + length > len(data):
                break
            value = data[pos: pos + length]
            pos += length
            name = EMV_TAGS.get(tag, f"Unknown tag {tag}")
            node = TLVNode(tag=tag, tag_name=name, length=length,
                           value=value, constructed=constructed)
            if constructed and depth < 8:
                node.children = parse_tlv(value, depth + 1)
            nodes.append(node)
        except Exception:
            break
    return nodes


def maybe_parse_tlv(data: bytes) -> list[TLVNode]:
    """Try TLV parse; return [] for anything that doesn't look like TLV."""
    if len(data) < 2 or data[0] in (0x00, 0xFF):
        return []
    return parse_tlv(data)


# ── APDU record ───────────────────────────────────────────────────────────────

@dataclasses.dataclass
class APDURecord:
    session_id: str
    seq: int
    ts_ms: int            # epoch milliseconds
    ts_str: str           # ISO-8601
    direction: str        # Direction.*
    raw_bytes: bytes
    raw_hex: str          # uppercase, no spaces
    # command fields (None for response APDUs)
    cla: str | None
    ins: str | None
    ins_name: str | None
    p1: str | None
    p2: str | None
    lc: int | None
    le: int | None
    data_hex: str | None
    # response fields (None for command APDUs)
    sw1: str | None
    sw2: str | None
    # parsed TLV
    tlv_nodes: list[TLVNode] = dataclasses.field(default_factory=list)
    # round-trip latency from on_command → on_response (None for command APDUs)
    duration_us: int | None = None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "seq": self.seq,
            "timestamp_ms": self.ts_ms,
            "timestamp": self.ts_str,
            "duration_us": self.duration_us,
            "direction": self.direction,
            "raw_hex": self.raw_hex,
            "cla": self.cla,
            "ins": self.ins,
            "ins_name": self.ins_name,
            "p1": self.p1,
            "p2": self.p2,
            "lc": self.lc,
            "le": self.le,
            "data_hex": self.data_hex,
            "sw1": self.sw1,
            "sw2": self.sw2,
            "tlv": [n.to_dict() for n in self.tlv_nodes],
        }


def _now() -> tuple[int, str]:
    ms = int(time.time() * 1000)
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return ms, ts


def parse_command_apdu(raw: bytes, session_id: str, seq: int) -> APDURecord:
    ts_ms, ts_str = _now()
    raw_hex = raw.hex().upper()
    cla = ins = p1 = p2 = None
    lc = le = None
    data_hex = None
    tlv_nodes: list[TLVNode] = []

    if len(raw) >= 4:
        cla = f"{raw[0]:02X}"
        ins = f"{raw[1]:02X}"
        p1  = f"{raw[2]:02X}"
        p2  = f"{raw[3]:02X}"
    if len(raw) == 5:
        le = raw[4]
    elif len(raw) > 5:
        lc = raw[4]
        body = raw[5: 5 + lc]
        data_hex = body.hex().upper()
        if len(raw) > 5 + lc:
            le = raw[5 + lc]
        # Don't TLV-parse SELECT AID data – it's a raw AID, not TLV
        if body and ins != "A4":
            tlv_nodes = maybe_parse_tlv(body)

    return APDURecord(
        session_id=session_id, seq=seq, ts_ms=ts_ms, ts_str=ts_str,
        direction=Direction.TERMINAL_TO_CARD,
        raw_bytes=raw, raw_hex=raw_hex,
        cla=cla, ins=ins, ins_name=EMV_INS.get(ins, None) if ins else None,
        p1=p1, p2=p2, lc=lc, le=le, data_hex=data_hex,
        sw1=None, sw2=None, tlv_nodes=tlv_nodes,
    )


def parse_response_apdu(raw: bytes, session_id: str, seq: int) -> APDURecord:
    ts_ms, ts_str = _now()
    raw_hex = raw.hex().upper()
    sw1 = sw2 = None
    tlv_nodes: list[TLVNode] = []

    if len(raw) >= 2:
        sw1 = f"{raw[-2]:02X}"
        sw2 = f"{raw[-1]:02X}"
        body = raw[:-2]
        if body:
            tlv_nodes = maybe_parse_tlv(body)

    return APDURecord(
        session_id=session_id, seq=seq, ts_ms=ts_ms, ts_str=ts_str,
        direction=Direction.CARD_TO_TERMINAL,
        raw_bytes=raw, raw_hex=raw_hex,
        cla=None, ins=None, ins_name=None,
        p1=None, p2=None, lc=None, le=None, data_hex=None,
        sw1=sw1, sw2=sw2, tlv_nodes=tlv_nodes,
    )


# ── Session info ──────────────────────────────────────────────────────────────

@dataclasses.dataclass
class SessionInfo:
    session_id: str
    started_at_ms: int
    started_at_str: str
    aid: str | None = None         # hex AID once known from SELECT AID
    records: list[APDURecord] = dataclasses.field(default_factory=list)
    ended: bool = False

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "started_at": self.started_at_str,
            "started_at_ms": self.started_at_ms,
            "aid": self.aid,
            "apdus": [r.to_dict() for r in self.records],
        }


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 2 – Output handlers: Console, JSON, Hexlog, SQLite
# ─────────────────────────────────────────────────────────────────────────────

class BaseHandler(ABC):
    @abstractmethod
    def on_apdu(self, record: APDURecord, session: SessionInfo) -> None: ...

    @abstractmethod
    def on_session_end(self, session: SessionInfo) -> None: ...

    def close(self) -> None:
        pass


# ANSI palette
_RST  = "\033[0m"
_BOLD = "\033[1m"
_DIM  = "\033[2m"
_CYAN = "\033[96m"   # terminal→card
_GRN  = "\033[92m"   # card→terminal / SW 9000
_YLW  = "\033[93m"   # TLV tag names / SW 62-63
_RED  = "\033[91m"   # SW 6x errors
_GRAY = "\033[37m"   # raw hex


def _sw_color(sw1: str, sw2: str) -> str:
    if sw1 == "90" and sw2 == "00":
        return _GRN
    if sw1.startswith("9"):
        return _GRN
    if sw1 in ("62", "63"):
        return _YLW
    if sw1.startswith("6"):
        return _RED
    return _RST


def _tlv_lines(nodes: list[TLVNode], indent: int = 0,
               use_color: bool = True) -> list[str]:
    lines: list[str] = []
    pad = "    " * indent
    tag_c  = _YLW  if use_color else ""
    rst    = _RST   if use_color else ""
    hex_c  = _GRAY  if use_color else ""

    for n in nodes:
        val = n.value.hex().upper()
        lines.append(f"{pad}{tag_c}{n.tag}{rst}  {n.tag_name}  "
                     f"{hex_c}[{val}]{rst}  ({n.length}B)")
        if n.children:
            lines.extend(_tlv_lines(n.children, indent + 1, use_color))
    return lines


# ── ConsoleHandler ────────────────────────────────────────────────────────────

class ConsoleHandler(BaseHandler):
    """Color-coded pretty-print to stdout. Direction, hex dump, inline TLV."""

    def __init__(self, colors: bool = True,
                 show_tlv: bool = True,
                 show_raw: bool = True):
        self.colors   = colors
        self.show_tlv = show_tlv
        self.show_raw = show_raw

    def _c(self, code: str) -> str:
        return code if self.colors else ""

    def on_apdu(self, record: APDURecord, session: SessionInfo) -> None:
        # Timestamp: HH:MM:SS.mmm
        ts = record.ts_str[11:23]

        if record.direction == Direction.TERMINAL_TO_CARD:
            dir_clr = self._c(_CYAN)
            arrow   = "▶ CMD"
            ins_str = (f"{record.cla} {record.ins}"
                       f"  {record.ins_name or '?'}"
                       f"  P1={record.p1} P2={record.p2}"
                       + (f"  Lc={record.lc}" if record.lc is not None else "")
                       + (f"  Le={record.le}" if record.le is not None else ""))
            detail = ins_str
        else:
            dir_clr  = self._c(_GRN)
            arrow    = "◀ RSP"
            sw_clr   = self._c(_sw_color(record.sw1 or "??",
                                         record.sw2 or "??"))
            detail   = f"SW={sw_clr}{record.sw1}{record.sw2}{self._c(_RST)}"

        sid = session.session_id[:8]
        header = (f"{dir_clr}{self._c(_BOLD)}"
                  f"[{ts}] #{record.seq:03d} {arrow}  {detail}"
                  f"  sid={sid}{self._c(_RST)}")
        print(header)

        if self.show_raw:
            spaced = " ".join(
                record.raw_hex[i:i+2] for i in range(0, len(record.raw_hex), 2)
            )
            print(f"  {self._c(_GRAY)}{spaced}{self._c(_RST)}")

        if self.show_tlv and record.tlv_nodes:
            print(f"  {self._c(_DIM)}TLV:{self._c(_RST)}")
            for line in _tlv_lines(record.tlv_nodes, indent=1,
                                   use_color=self.colors):
                print(f"  {line}")
        print()

    def on_session_end(self, session: SessionInfo) -> None:
        aid = session.aid or "unknown AID"
        print(f"{self._c(_BOLD)}{'─'*64}\n"
              f"  Session {session.session_id[:8]} closed"
              f"  AID={aid}  APDUs={len(session.records)}\n"
              f"{'─'*64}{self._c(_RST)}\n")


# ── JSONHandler ───────────────────────────────────────────────────────────────

class JSONHandler(BaseHandler):
    """Writes one JSON file per session (on session end) to a directory."""

    def __init__(self, output_dir: str = "logs/sessions"):
        self._dir = Path(output_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def on_apdu(self, record: APDURecord, session: SessionInfo) -> None:
        pass  # records are stored in SessionInfo.records; flushed at session end

    def on_session_end(self, session: SessionInfo) -> None:
        path = self._dir / f"session_{session.session_id}.json"
        try:
            with open(path, "w") as fh:
                json.dump(session.to_dict(), fh, indent=2)
            log.debug("JSONHandler: wrote %s", path)
        except Exception as exc:
            log.warning("JSONHandler: write failed %s: %s", path, exc)


# ── HexlogHandler ─────────────────────────────────────────────────────────────

class HexlogHandler(BaseHandler):
    """
    PCSC-style hex log, one APDU per line:

        <epoch_ms>  C  [<sid8>]  00 A4 04 00 07 A0 00 00 00 03 10 10
        <epoch_ms>  R  [<sid8>]  6F 1F 84 07 ... 90 00

    C = command (terminal→card), R = response (card→terminal).
    Compatible with replaying via emv_logger_cli.py --replay.
    """

    def __init__(self, path: str = "logs/apdu.hexlog"):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._fh = open(path, "a", buffering=1)   # line-buffered

    def on_apdu(self, record: APDURecord, session: SessionInfo) -> None:
        tag = "C" if record.direction == Direction.TERMINAL_TO_CARD else "R"
        spaced = " ".join(
            record.raw_hex[i:i+2] for i in range(0, len(record.raw_hex), 2)
        )
        self._fh.write(
            f"{record.ts_ms}  {tag}  [{session.session_id[:8]}]  {spaced}\n"
        )

    def on_session_end(self, session: SessionInfo) -> None:
        aid = session.aid or "?"
        self._fh.write(f"# session {session.session_id[:8]} ended  AID={aid}\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()


# ── SQLiteHandler ─────────────────────────────────────────────────────────────

class SQLiteHandler(BaseHandler):
    """
    Writes to SQLite using a background write-queue thread (WAL mode) to
    keep the latency impact below 1 ms on the intercept path.

    Schema
    ──────
    sessions  (session_id, started_at_ms, started_at, aid, ended_at_ms)
    apdus     (id, session_id, seq, ts_ms, ts, direction, raw_hex,
               cla, ins, ins_name, p1, p2, lc, le, data_hex, sw1, sw2)
    tlv_nodes (id, apdu_id, tag, tag_name, length, value_hex,
               constructed, parent_id, depth)
    """

    _SCHEMA = """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id   TEXT PRIMARY KEY,
            started_at_ms INTEGER,
            started_at   TEXT,
            aid          TEXT,
            ended_at_ms  INTEGER
        );
        CREATE TABLE IF NOT EXISTS apdus (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id   TEXT,
            seq          INTEGER,
            ts_ms        INTEGER,
            ts           TEXT,
            direction    TEXT,
            raw_hex      TEXT,
            cla          TEXT,
            ins          TEXT,
            ins_name     TEXT,
            p1           TEXT,
            p2           TEXT,
            lc           INTEGER,
            le           INTEGER,
            data_hex     TEXT,
            sw1          TEXT,
            sw2          TEXT
        );
        CREATE TABLE IF NOT EXISTS tlv_nodes (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            apdu_id      INTEGER,
            tag          TEXT,
            tag_name     TEXT,
            length       INTEGER,
            value_hex    TEXT,
            constructed  INTEGER,
            parent_id    INTEGER,
            depth        INTEGER
        );
        CREATE INDEX IF NOT EXISTS idx_apdus_sid ON apdus(session_id);
        CREATE INDEX IF NOT EXISTS idx_tlv_apdu  ON tlv_nodes(apdu_id);
    """

    def __init__(self, db_path: str = "logs/emv.db"):
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._q: queue.Queue = queue.Queue()
        self._t = threading.Thread(
            target=self._worker, args=(db_path,), daemon=True, name="sqlite-logger"
        )
        self._t.start()

    def _worker(self, db_path: str) -> None:
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(self._SCHEMA)
        conn.commit()

        while True:
            try:
                item = self._q.get(timeout=2)
            except queue.Empty:
                conn.commit()   # periodic flush
                continue
            if item is None:
                conn.commit()
                conn.close()
                return
            try:
                op, payload = item
                if op == "apdu":
                    self._write_apdu(conn, payload)
                elif op == "session_end":
                    conn.execute(
                        "UPDATE sessions SET ended_at_ms=?, aid=? "
                        "WHERE session_id=?",
                        (int(time.time() * 1000),
                         payload["aid"], payload["session_id"])
                    )
                conn.commit()
            except Exception as exc:
                log.warning("SQLiteHandler worker: %s", exc)

    def _write_apdu(self, conn: sqlite3.Connection, p: dict) -> None:
        r: APDURecord = p["record"]
        conn.execute(
            "INSERT OR IGNORE INTO sessions "
            "(session_id,started_at_ms,started_at,aid) VALUES (?,?,?,?)",
            (r.session_id, p["sess_ms"], p["sess_ts"], p["sess_aid"])
        )
        cur = conn.execute(
            "INSERT INTO apdus "
            "(session_id,seq,ts_ms,ts,direction,raw_hex,"
            " cla,ins,ins_name,p1,p2,lc,le,data_hex,sw1,sw2) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (r.session_id, r.seq, r.ts_ms, r.ts_str,
             r.direction, r.raw_hex,
             r.cla, r.ins, r.ins_name,
             r.p1, r.p2, r.lc, r.le, r.data_hex,
             r.sw1, r.sw2)
        )
        self._write_tlv(conn, cur.lastrowid, r.tlv_nodes, None, 0)

    def _write_tlv(self, conn: sqlite3.Connection, apdu_id: int | None,
                   nodes: list[TLVNode], parent_id: int | None, depth: int) -> None:
        for n in nodes:
            cur = conn.execute(
                "INSERT INTO tlv_nodes "
                "(apdu_id,tag,tag_name,length,value_hex,constructed,parent_id,depth) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (apdu_id, n.tag, n.tag_name, n.length,
                 n.value.hex().upper(), int(n.constructed), parent_id, depth)
            )
            if n.children:
                self._write_tlv(conn, apdu_id, n.children, cur.lastrowid, depth + 1)

    def on_apdu(self, record: APDURecord, session: SessionInfo) -> None:
        self._q.put(("apdu", {
            "record": record,
            "sess_ms":  session.started_at_ms,
            "sess_ts":  session.started_at_str,
            "sess_aid": session.aid,
        }))

    def on_session_end(self, session: SessionInfo) -> None:
        self._q.put(("session_end", {
            "session_id": session.session_id,
            "aid": session.aid,
        }))

    def close(self) -> None:
        self._q.put(None)
        self._t.join(timeout=5)
        if self._t.is_alive():
            log.warning("SQLiteHandler: worker thread did not stop within 5 s; DB may be incomplete")


# ── SW auto-labelling (for mutation outcome store) ────────────────────────────

def _auto_label_sw(sw: str) -> str | None:
    """
    Classify an SW code for mutation outcome recording.
    Returns None for routine/success codes that should not be stored.
    """
    if not sw or len(sw) != 4:
        return None
    s = sw.upper()
    if s == "9000":
        return None                              # normal success — skip
    if s[:2] in ("61", "6C"):
        return None                              # GET RESPONSE / Le correction — skip
    if s in ("6983", "6984", "6985", "6986", "6988"):
        return "security_condition"              # card blocked / conditions not met
    if s[0] == "6":
        return "interesting"                     # other 6xxx — unexpected card behaviour
    return None                                  # 9xxx warnings — skip to reduce noise


# ── WebSocketHandler ──────────────────────────────────────────────────────────

class WebSocketHandler(BaseHandler):
    """Broadcasts paired command+response APDU records to the dashboard Live Trace.

    Pairs each TERMINAL→CARD record with the following CARD→TERMINAL record and
    sends one entry per exchange so the trace table shows one row per APDU pair.
    The broadcast is a no-op when no WebSocket clients are connected or when
    running outside the API server (import guarded).
    """

    def __init__(self) -> None:
        self._pending_cmd: "APDURecord | None" = None

    def on_apdu(self, record: "APDURecord", session: "SessionInfo") -> None:
        try:
            from api.ws.apdu_stream import broadcast_apdu
        except ImportError:
            return

        if record.direction == Direction.TERMINAL_TO_CARD:
            self._pending_cmd = record
            return

        # Response: pair with the buffered command
        cmd = self._pending_cmd
        self._pending_cmd = None

        sw = (record.sw1 + record.sw2) if (record.sw1 and record.sw2) else ""
        entry: dict = {
            "ts":          cmd.ts_ms / 1000.0 if cmd else record.ts_ms / 1000.0,
            "resp_ts":     record.ts_ms / 1000.0,
            "duration_us": record.duration_us,
            "cmd":         cmd.raw_hex if cmd else "",
            "resp":        record.raw_hex,
            "sw":          sw,
            "desc":        (cmd.ins_name or "") if cmd else "",
            "session_id":  record.session_id,
        }
        nodes = (cmd.tlv_nodes if cmd else []) + record.tlv_nodes
        if nodes:
            entry["tlv"] = [n.to_dict() for n in nodes]

        # Anything a mutation rule changed during this exchange, so the trace
        # can show the card's own bytes beside what the terminal was given.
        # Drained here because this is the point where the pair is complete.
        try:
            from mutation_engine import drain_live_records
            mutations = drain_live_records()
        except ImportError:
            mutations = []
        if mutations:
            entry["mutations"] = [m.to_dict() for m in mutations]

        broadcast_apdu(entry)

        # Auto-record non-routine SW outcomes into the mutation outcome store
        label = _auto_label_sw(sw)
        if label:
            try:
                from card_intel import CardIntelDB
                fp_hash = ""
                try:
                    from api.routes.fingerprint import _fingerprint_cache
                    if _fingerprint_cache:
                        fp_hash = _fingerprint_cache.get("fingerprint_hash", "")
                except Exception:
                    pass
                odb = CardIntelDB()
                odb.record_outcome(
                    label=label,
                    fingerprint_hash=fp_hash,
                    session_id=record.session_id,
                    cmd_hex=cmd.raw_hex if cmd else "",
                    cmd_ins=cmd.ins or "" if cmd else "",
                    resp_hex=record.raw_hex,
                    sw=sw,
                    source="auto",
                )
                odb.close()
            except Exception:
                pass

    def on_session_end(self, session: "SessionInfo") -> None:
        self._pending_cmd = None


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 3 – APDUFilter, mutation hooks, config loader
# ─────────────────────────────────────────────────────────────────────────────

# ── APDU filter ───────────────────────────────────────────────────────────────

@dataclasses.dataclass
class APDUFilter:
    """
    All non-empty conditions are ANDed.  Empty list = no restriction on that axis.

    directions     – e.g. ["terminal→card"]
    cla_ins        – e.g. ["00A4", "80AE"]   (CLA+INS, no space, uppercase)
    required_tags  – only pass records whose TLV contains ALL listed tags
    suppress_tags  – drop records whose TLV contains ANY listed tag
    """
    directions:    list[str] = dataclasses.field(default_factory=list)
    cla_ins:       list[str] = dataclasses.field(default_factory=list)
    required_tags: list[str] = dataclasses.field(default_factory=list)
    suppress_tags: list[str] = dataclasses.field(default_factory=list)

    def matches(self, record: APDURecord) -> bool:
        if self.directions and record.direction not in self.directions:
            return False

        if self.cla_ins and record.cla and record.ins:
            if (record.cla + record.ins) not in self.cla_ins:
                return False

        if self.required_tags or self.suppress_tags:
            present = {n.tag for n in self._flatten(record.tlv_nodes)}
            if self.required_tags and not all(t in present for t in self.required_tags):
                return False
            if self.suppress_tags and any(t in present for t in self.suppress_tags):
                return False

        return True

    @staticmethod
    def _flatten(nodes: list[TLVNode]) -> list[TLVNode]:
        out: list[TLVNode] = []
        for n in nodes:
            out.append(n)
            out.extend(APDUFilter._flatten(n.children))
        return out


# ── Mutation hooks ────────────────────────────────────────────────────────────
#
# Hook function signatures
# ────────────────────────
# pre_send hook:
#   def my_hook(apdu: bytes, session: SessionInfo) -> tuple[str, bytes]:
#       # action: "passthrough" | "modify" | "drop" | "inject"
#       # "passthrough" – forward unchanged              (return ("passthrough", b""))
#       # "modify"      – replace APDU with new bytes   (return ("modify", new_bytes))
#       # "drop"        – suppress command, return 6D00 (return ("drop", b""))
#       # "inject"      – skip card, reply immediately  (return ("inject", response_bytes))
#       return "passthrough", b""
#
# pre_response hook:
#   def my_hook(cmd: bytes, response: bytes, session: SessionInfo) -> tuple[str, bytes]:
#       # "passthrough" – forward unchanged
#       # "modify"      – replace response
#       # "drop"        – replace with 90 00
#       # "inject"      – replace with custom bytes
#       return "passthrough", b""
#
# Register in emv_logger.yaml:
#   hooks:
#     pre_send:     "hooks/my_hooks.py::pre_send"
#     pre_response: "hooks/my_hooks.py::pre_response"

def _load_hook(spec: str | None):
    """Load a hook callable from a 'path/to/file.py::function_name' spec."""
    if not spec:
        return None
    try:
        file_part, func_name = spec.split("::")
        sp = importlib.util.spec_from_file_location("_emv_hook", file_part)
        mod = importlib.util.module_from_spec(sp)       # type: ignore[arg-type]
        sp.loader.exec_module(mod)                       # type: ignore[union-attr]
        fn = getattr(mod, func_name)
        log.info("Loaded hook %s from %s", func_name, file_part)
        return fn
    except Exception as exc:
        log.warning("Failed to load hook '%s': %s", spec, exc)
        return None


# ── pre_send insertion point ──────────────────────────────────────────────────

def _run_pre_send(hook, raw: bytes,
                  session: SessionInfo) -> tuple[bytes, str]:
    """
    Run the pre_send hook and return (final_bytes, action).
    action is one of: "passthrough", "modify", "drop", "inject".

    # ── INSERT PRE-SEND MUTATION LOGIC HERE ─────────────────────────────────
    # Example: swap GENERATE AC type from TC to ARQC
    #   if raw[1:2] == b'\xAE':
    #       raw = raw[:4] + bytes([raw[4] & ~0x40]) + raw[5:]
    #       return raw, "modify"
    # ────────────────────────────────────────────────────────────────────────
    """
    if hook is None:
        return raw, "passthrough"
    try:
        action, data = hook(raw, session)
        if action == "modify":
            return data, "modify"
        if action == "drop":
            return b"", "drop"
        if action == "inject":
            return data, "inject"
    except Exception as exc:
        log.warning("pre_send hook raised: %s", exc)
    return raw, "passthrough"


# ── pre_response insertion point ─────────────────────────────────────────────

def _run_pre_response(hook, cmd: bytes, response: bytes,
                      session: SessionInfo) -> tuple[bytes, str]:
    """
    Run the pre_response hook and return (final_bytes, action).

    # ── INSERT PRE-RESPONSE MUTATION LOGIC HERE ──────────────────────────────
    # Example: strip CVM list from FCI (tag 8E)
    #   if record reveals tag 8E in TLV, strip it and recalculate length
    # ────────────────────────────────────────────────────────────────────────
    """
    if hook is None:
        return response, "passthrough"
    try:
        action, data = hook(cmd, response, session)
        if action in ("modify", "inject"):
            return data, action
        if action == "drop":
            return b"\x90\x00", "drop"
    except Exception as exc:
        log.warning("pre_response hook raised: %s", exc)
    return response, "passthrough"


# ── Config loader ─────────────────────────────────────────────────────────────

_DEFAULTS: dict[str, Any] = {
    "output": {
        "console":      True,
        "json":         False,
        "hexlog":       False,
        "sqlite":       False,
        "json_dir":     "logs/sessions",
        "sqlite_path":  "logs/emv.db",
        "hexlog_path":  "logs/apdu.hexlog",
    },
    "console": {
        "colors":   True,
        "show_tlv": True,
        "show_raw": True,
    },
    "filters": {
        "directions":    [],
        "cla_ins":       [],
        "required_tags": [],
        "suppress_tags": [],
    },
    "hooks": {
        "pre_send":     None,
        "pre_response": None,
    },
    "session": {
        "timeout_seconds": 30,
        "auto_save":       True,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = dict(base)
    for k, v in override.items():
        if k in out and isinstance(out[k], dict) and isinstance(v, dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(path: str | None = None) -> dict:
    """
    Load YAML (preferred) or TOML config, merged over built-in defaults.
    Returns the defaults unchanged if path is None or the file is missing.
    """
    if path is None:
        return _DEFAULTS

    try:
        text = Path(path).read_text()
    except FileNotFoundError:
        log.warning("emv_logger: config not found at '%s', using defaults", path)
        return _DEFAULTS

    user: dict = {}
    try:
        import yaml                          # pyyaml
        user = yaml.safe_load(text) or {}
    except ImportError:
        try:
            import tomllib                   # stdlib Python ≥ 3.11
            user = tomllib.loads(text)
        except ImportError:
            log.warning("emv_logger: neither pyyaml nor tomllib found; "
                        "install pyyaml or use Python ≥ 3.11 for TOML support")

    return _deep_merge(_DEFAULTS, user)


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 4 – EMVLogger main class
# ─────────────────────────────────────────────────────────────────────────────

def _to_bytes(raw) -> bytes:
    """
    Normalise any APDU representation to bytes.
    Handles: bytes, bytearray, list/tuple of ints,
    and Python-2-era str (each char is chr(byte_value)).
    """
    if isinstance(raw, bytes):
        return raw
    if isinstance(raw, (bytearray, memoryview)):
        return bytes(raw)
    if isinstance(raw, (list, tuple)):
        return bytes(raw)
    if isinstance(raw, str):
        # Python 2-style byte string: "".join(chr(b) for b in rapdu)
        return bytes(ord(c) for c in raw)
    raise TypeError(f"Cannot convert {type(raw).__name__} to bytes")


def _restore_type(data: bytes, original) -> Any:
    """Return data in the same type as original (str / bytes / bytearray / list)."""
    if isinstance(original, bytes):
        return data
    if isinstance(original, bytearray):
        return bytearray(data)
    if isinstance(original, list):
        return list(data)
    if isinstance(original, str):
        return "".join(chr(b) for b in data)
    return data


# ─────────────────────────────────────────────────────────────────────────────
# Cryptogram correlation database
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class CryptogramRecord:
    """One GENERATE AC round-trip captured for offline cryptanalysis."""
    ts_ms: int
    session_id: str
    aid: str
    atc: str           # 9F36 – Application Transaction Counter
    cid: str           # 9F27 – Cryptogram Information Data (ARQC/TC/AAC)
    ac: str            # 9F26 – Application Cryptogram
    iad: str           # 9F10 – Issuer Application Data
    cdol1_data: str    # raw hex of the CDOL1 payload sent in GENERATE AC
    resp_hex: str      # full response hex (for post-hoc re-analysis)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def _extract_tag(nodes: list, target: str) -> str:
    """DFS search for a tag in a TLVNode tree; returns hex value or ''."""
    for n in nodes:
        if n.tag == target:
            v = n.value
            if isinstance(v, (bytes, bytearray)):
                return v.hex().upper()
            if isinstance(v, list):
                return bytes(v).hex().upper()
            return str(v)
        if n.children:
            found = _extract_tag(n.children, target)
            if found:
                return found
    return ""


class CryptogramDB:
    """
    Appends one JSON record to logs/cryptograms.jsonl for every GENERATE AC
    round-trip.  Records contain the full CDOL1 input vector plus the AC,
    ATC, CID, and IAD — sufficient for offline key-diversification analysis
    and pre-play / replay research.

    Enable by passing cryptogram_db=True to EMVLogger (or setting
    cryptogram_db: true in emv_logger.yaml).
    """

    def __init__(self, path: str = "logs/cryptograms.jsonl") -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        try:
            self._fh = open(path, "a", buffering=1, encoding="utf-8")
        except OSError as e:
            log.warning("CryptogramDB: cannot open %s: %s", path, e)
            self._fh = None

    def capture(
        self,
        session_id: str,
        aid: str,
        cmd_bytes: bytes,
        resp_bytes: bytes,
    ) -> CryptogramRecord | None:
        """
        Parse a GENERATE AC command + response and write a record.
        `cmd_bytes` is the raw GENERATE AC APDU (CDOL1 data starts at offset 5).
        """
        if len(resp_bytes) < 4:
            return None
        try:
            nodes = parse_tlv(resp_bytes[:-2])
        except Exception:
            return None

        ac  = _extract_tag(nodes, "9F26")
        cid = _extract_tag(nodes, "9F27")
        atc = _extract_tag(nodes, "9F36")
        iad = _extract_tag(nodes, "9F10")

        if not ac:
            return None   # no cryptogram in response — skip

        # CDOL1 data is the command body (after the 5-byte APDU header)
        cdol1_data = cmd_bytes[5:].hex().upper() if len(cmd_bytes) > 5 else ""

        rec = CryptogramRecord(
            ts_ms=int(time.time() * 1000),
            session_id=session_id,
            aid=aid,
            atc=atc,
            cid=cid,
            ac=ac,
            iad=iad,
            cdol1_data=cdol1_data,
            resp_hex=resp_bytes.hex().upper(),
        )
        if self._fh:
            try:
                self._fh.write(rec.to_json() + "\n")
            except OSError as e:
                log.warning("CryptogramDB write error: %s", e)
        return rec

    def close(self) -> None:
        if self._fh:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass
            self._fh = None


class EMVLogger:
    """
    Flexible APDU logging and mutation facade.

    Typical integration into InterceptAttack (intercept_attack.py)
    ──────────────────────────────────────────────────────────────
    Add to __init__:
        from emv_logger import EMVLogger
        self._emv = EMVLogger.from_config("emv_logger.yaml")

    Wrap user_execute:
        def user_execute(self, msg):
            msg = self._emv.on_command(msg)     # ← log + optional mutation
            # ... existing attacker_mitm logic ...
            ans = self.os.execute(msg)
            # ... existing CVM / response-patch logic ...
            ans = self._emv.on_response(msg, ans)  # ← log + optional mutation
            return ans

    The logger never raises; all exceptions are caught and logged internally
    so the passthrough is never broken.
    """

    def __init__(self, cfg: dict) -> None:
        self._cfg = cfg

        # Build handler list from config
        out = cfg.get("output", {})
        con = cfg.get("console", {})
        self._handlers: list[BaseHandler] = []

        if out.get("console", True):
            self._handlers.append(ConsoleHandler(
                colors=con.get("colors", True),
                show_tlv=con.get("show_tlv", True),
                show_raw=con.get("show_raw", True),
            ))
        if out.get("json", False):
            self._handlers.append(JSONHandler(out.get("json_dir", "logs/sessions")))
        if out.get("hexlog", False):
            self._handlers.append(HexlogHandler(out.get("hexlog_path", "logs/apdu.hexlog")))
        if out.get("sqlite", False):
            self._handlers.append(SQLiteHandler(out.get("sqlite_path", "logs/emv.db")))

        # Always active. Import-guarded inside, so it is a no-op when the logger
        # runs outside the API server (CLI relay, offline replay).
        self._handlers.append(WebSocketHandler())

        # Filter
        fc = cfg.get("filters", {})
        self._filter = APDUFilter(
            directions=[d for d in fc.get("directions", [])],
            cla_ins=[x.upper().replace(" ", "") for x in fc.get("cla_ins", [])],
            required_tags=[t.upper() for t in fc.get("required_tags", [])],
            suppress_tags=[t.upper() for t in fc.get("suppress_tags", [])],
        )

        # Hooks
        hc = cfg.get("hooks", {})
        self._pre_send_hook     = _load_hook(hc.get("pre_send"))
        self._pre_response_hook = _load_hook(hc.get("pre_response"))

        # Session management
        sc = cfg.get("session", {})
        self._timeout_ms = sc.get("timeout_seconds", 30) * 1000
        self._auto_save  = sc.get("auto_save", True)

        self._session:      SessionInfo | None = None
        self._seq:          int = 0
        self._last_cmd:     bytes | None = None   # saved for GENERATE AC detection
        self._cmd_start_us: int | None = None     # perf_counter_ns at on_command

        # Cryptogram correlation database
        crypt_cfg = cfg.get("cryptogram_db", {})
        if crypt_cfg.get("enabled", False):
            self._crypt_db: CryptogramDB | None = CryptogramDB(
                path=crypt_cfg.get("path", "logs/cryptograms.jsonl")
            )
        else:
            self._crypt_db = None

    # ── constructor helpers ───────────────────────────────────────────────────

    @classmethod
    def from_config(cls, path: str | None = None) -> "EMVLogger":
        """Load config from YAML/TOML file (or use defaults) and return instance."""
        return cls(load_config(path))

    # ── session lifecycle ─────────────────────────────────────────────────────

    def _new_session(self) -> SessionInfo:
        ms, ts = _now()
        sid = uuid.uuid4().hex
        self._session = SessionInfo(
            session_id=sid, started_at_ms=ms, started_at_str=ts
        )
        self._seq = 0
        log.debug("EMVLogger: new session %s", sid[:8])
        return self._session

    def _active_session(self) -> SessionInfo:
        """Return current session, creating a new one if timed-out or absent."""
        now_ms = int(time.time() * 1000)
        if self._session is None:
            return self._new_session()
        # Timeout: use last record timestamp if available
        last_ts = (self._session.records[-1].ts_ms
                   if self._session.records
                   else self._session.started_at_ms)
        if (now_ms - last_ts) > self._timeout_ms:
            self._end_session()
            return self._new_session()
        return self._session

    def _end_session(self) -> None:
        if self._session and not self._session.ended:
            self._session.ended = True
            for h in self._handlers:
                try:
                    h.on_session_end(self._session)
                except Exception as exc:
                    log.warning("on_session_end error (%s): %s",
                                type(h).__name__, exc)
            if self._auto_save:
                self._session = None

    # ── public API ────────────────────────────────────────────────────────────

    def on_command(self, raw) -> Any:
        """
        Call at the start of user_execute(), before any mutation or card I/O.

        Logs the incoming command APDU, runs the pre_send hook, and returns
        the (possibly mutated) command in the same type as the input.
        If the hook returns "inject", returns the injected bytes directly
        (caller should treat them as the card response and skip os.execute).
        """
        original = raw
        try:
            raw_b = _to_bytes(raw)
        except Exception as exc:
            log.warning("on_command: cannot convert input: %s", exc)
            return raw

        try:
            # ── Session start detection (SELECT AID: CLA=00 INS=A4 P1=04) ──
            if len(raw_b) >= 3 and raw_b[0] == 0x00 and raw_b[1] == 0xA4 and raw_b[2] == 0x04:
                if self._session is not None:
                    self._end_session()
                session = self._new_session()
                # Extract AID from Lc+data
                if len(raw_b) >= 6:
                    lc = raw_b[4]
                    session.aid = raw_b[5: 5 + lc].hex().upper()
            else:
                session = self._active_session()

            # ── Pre-send mutation hook ─────────────────────────────────────
            # To add a mutation: edit hooks/my_hooks.py and point emv_logger.yaml
            # hooks.pre_send at it.  The stub below does nothing.
            mutated, action = _run_pre_send(self._pre_send_hook, raw_b, session)
            if action == "drop":
                return _restore_type(b"\x6D\x00", original)
            if action == "inject":
                # Caller receives a fake card response; skip os.execute
                return _restore_type(mutated, original)
            if action == "modify":
                raw_b = mutated

            # ── Record ────────────────────────────────────────────────────
            self._seq += 1
            self._cmd_start_us = time.perf_counter_ns() // 1000
            record = parse_command_apdu(raw_b, session.session_id, self._seq)
            session.records.append(record)
            self._last_cmd = raw_b

            if self._filter.matches(record):
                self._dispatch(record, session)

        except Exception as exc:
            log.warning("EMVLogger.on_command: %s", exc)
            return original

        return _restore_type(raw_b, original)

    def on_response(self, cmd, response) -> Any:
        """
        Call at the end of user_execute(), after all mutation logic.

        Logs the outgoing response APDU, runs the pre_response hook, and returns
        the (possibly mutated) response in the same type as the input.
        """
        original = response
        try:
            resp_b = _to_bytes(response)
            cmd_b  = _to_bytes(cmd)
        except Exception as exc:
            log.warning("on_response: cannot convert input: %s", exc)
            return response

        try:
            session = self._active_session()

            # ── Pre-response mutation hook ─────────────────────────────────
            # Insert response mutations here via emv_logger.yaml hooks.pre_response.
            mutated, action = _run_pre_response(
                self._pre_response_hook, cmd_b, resp_b, session
            )
            if action != "passthrough":
                resp_b = mutated

            # ── Record ────────────────────────────────────────────────────
            self._seq += 1
            record = parse_response_apdu(resp_b, session.session_id, self._seq)
            if self._cmd_start_us is not None:
                record.duration_us = (time.perf_counter_ns() // 1000) - self._cmd_start_us
                self._cmd_start_us = None
            session.records.append(record)

            if self._filter.matches(record):
                self._dispatch(record, session)

            # ── Session end: GENERATE AC response (INS=AE) ────────────────
            if (self._last_cmd is not None
                    and len(self._last_cmd) >= 2
                    and self._last_cmd[1] == 0xAE):
                # Capture cryptogram before closing session
                if self._crypt_db is not None:
                    self._crypt_db.capture(
                        session_id=session.session_id,
                        aid=session.aid,
                        cmd_bytes=self._last_cmd,
                        resp_bytes=resp_b,
                    )
                self._end_session()

        except Exception as exc:
            log.warning("EMVLogger.on_response: %s", exc)
            return original

        return _restore_type(resp_b, original)

    def flush(self) -> None:
        """Force-close the current session and flush all handlers."""
        self._end_session()

    def close(self) -> None:
        self.flush()
        for h in self._handlers:
            try:
                h.close()
            except Exception:
                pass
        if self._crypt_db is not None:
            self._crypt_db.close()

    # ── Replay ────────────────────────────────────────────────────────────────

    def replay_session(self, json_path: str) -> list[dict]:
        """
        Load a saved session JSON file and return a list of command APDUs
        ready to replay.

        Actual I/O is the caller's responsibility – wire this into a
        smartcard.Session or feed it to a terminal simulator.

        Returns a list of:
            {"seq": int, "ins_name": str, "raw_hex": str, "raw_bytes": bytes}
        """
        with open(json_path) as fh:
            data = json.load(fh)

        cmds = [a for a in data.get("apdus", [])
                if a["direction"] == Direction.TERMINAL_TO_CARD]
        log.info("replay_session: %d commands from session %s",
                 len(cmds), data.get("session_id", "?")[:8])
        return [
            {
                "seq":       a["seq"],
                "ins_name":  a.get("ins_name"),
                "raw_hex":   a["raw_hex"],
                "raw_bytes": bytes.fromhex(a["raw_hex"]),
            }
            for a in cmds
        ]

    # ── internal ──────────────────────────────────────────────────────────────

    def _dispatch(self, record: APDURecord, session: SessionInfo) -> None:
        for h in self._handlers:
            try:
                h.on_apdu(record, session)
            except Exception as exc:
                log.warning("handler %s.on_apdu: %s", type(h).__name__, exc)
