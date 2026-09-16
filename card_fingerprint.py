#!/usr/bin/env python3
"""
card_fingerprint.py – EMV Card Fingerprinting (Layer 2)

Produces a structured CardProfile for every AID found on a card:
  • AID enumeration via PSE (1PAY.SYS.DDF01) and PPSE (2PAY.SYS.DDF01)
  • Full AFL record map for each AID
  • Off-AFL SFI brute-force (configurable range, default SFI 1-10 / rec 1-10)
  • PDOL decode (tag + length for each terminal data object requested)
  • AIP flag decode (SDA / DDA / CDA / CVM / issuer-auth / on-device CVM)
  • CVM list decode (every rule with method name + condition name)
  • Cryptographic capabilities derived from records and AIP
    (RSA key sizes, CA key index, app version, 9F6E Form Factor Indicator)
  • ATC starting value and PIN retry counter via GET DATA
  • All unique EMV tags collected across every record, flattened

Output: JSON CardProfile + human-readable console summary

Usage
─────
  python3 card_fingerprint.py --reader 0
  python3 card_fingerprint.py --reader 0 --output profile.json
  python3 card_fingerprint.py --reader 0 --brute-sfi
  python3 card_fingerprint.py --list-readers

Integration with relay stack
─────────────────────────────
  from card_fingerprint import CardFingerprinter
  fp = CardFingerprinter(reader_index=0)
  profile = fp.fingerprint()
  print(profile.to_json())
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import json
import logging
import os
import struct
import sys
import time
from pathlib import Path
from typing import Any

# Reuse TLV parser and tag dictionary from emv_logger (no duplication)
try:
    from emv_logger import parse_tlv, maybe_parse_tlv, EMV_TAGS, TLVNode
except ImportError:
    sys.exit("emv_logger.py not found – run from the atrium-pentest directory.")

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 1 – Constants and dataclasses
# ─────────────────────────────────────────────────────────────────────────────

# ── PSE / PPSE names ─────────────────────────────────────────────────────────

PSE_NAME  = b"1PAY.SYS.DDF01"   # contact PSE
PPSE_NAME = b"2PAY.SYS.DDF01"   # contactless PPSE

# ── Fallback AID list (tried when PSE is absent) ─────────────────────────────

FALLBACK_AIDS: list[bytes] = [
    bytes.fromhex("A0000000031010"),   # Visa Credit / Debit
    bytes.fromhex("A0000000032010"),   # Visa Electron
    bytes.fromhex("A0000000033010"),   # Visa Cash
    bytes.fromhex("A0000000038010"),   # Visa Electron (alt)
    bytes.fromhex("A0000000041010"),   # Mastercard
    bytes.fromhex("A0000000043060"),   # Maestro
    bytes.fromhex("A0000000046000"),   # Cirrus
    bytes.fromhex("A000000025010401"), # American Express
    bytes.fromhex("A0000000651010"),   # JCB
    bytes.fromhex("A0000000291010"),   # China UnionPay
    bytes.fromhex("A000000152301C"),   # Discover
    bytes.fromhex("A0000001523010"),   # Discover (alt)
]

# ── PDOL default values (used to build a null-safe GPO command) ──────────────
# Values are chosen to represent a generic contactless-capable terminal.
# Fingerprinting only needs a valid GPO response; amounts are symbolic.

_PDOL_DEFAULTS: dict[str, bytes] = {
    "9F66": bytes.fromhex("B7604000"),     # TTQ – DDA + CDA + fDDA capable
    "9F02": bytes.fromhex("000000000100"), # Amount = $1.00
    "9F03": bytes.fromhex("000000000000"), # Other Amount
    "9F1A": bytes.fromhex("0840"),         # Terminal Country Code – US
    "95":   bytes.fromhex("0000000000"),   # TVR – all clear
    "5F2A": bytes.fromhex("0840"),         # Transaction Currency Code – USD
    "9A":   b"",                           # Transaction Date – filled at runtime
    "9C":   bytes.fromhex("00"),           # Transaction Type – purchase
    "9F37": bytes.fromhex("12345678"),     # Unpredictable Number
    "9F35": bytes.fromhex("22"),           # Terminal Type
    "9F45": bytes.fromhex("0000"),         # Data Authentication Code
    "9F4C": bytes.fromhex("0000000000000000"),  # ICC Dynamic Number
    "9F34": bytes.fromhex("1F0002"),       # CVM Results – no CVM performed
    "9F21": b"",                           # Transaction Time – filled at runtime
    "9F7E": bytes.fromhex("00"),           # Mobile Support Indicator
}

# ── AIP flag decode (tag 82, byte 1) ─────────────────────────────────────────

_AIP_BYTE1_FLAGS: list[tuple[int, str]] = [
    (0x40, "SDA"),
    (0x20, "DDA"),
    (0x10, "CVM"),
    (0x08, "Terminal-Risk-Mgmt"),
    (0x04, "Issuer-Auth"),
    (0x02, "OnDevice-CVM"),
    (0x01, "CDA"),
]

_AIP_BYTE2_FLAGS: list[tuple[int, str]] = [
    (0x80, "MSD-contactless"),
    (0x20, "Relay-Resistance"),
]

# ── CVM code table ────────────────────────────────────────────────────────────

_CVM_CODES: dict[int, str] = {
    0x00: "Fail",
    0x01: "Plaintext offline PIN",
    0x02: "Enciphered online PIN",
    0x03: "Plaintext offline PIN + Signature",
    0x04: "Enciphered offline PIN",
    0x05: "Enciphered offline PIN + Signature",
    0x1E: "Signature",
    0x1F: "No CVM required",
    0x3F: "No CVM required (CDCVM)",
}

# ── CVM condition table ───────────────────────────────────────────────────────

_CVM_CONDITIONS: dict[int, str] = {
    0x00: "Always",
    0x01: "If unattended cash",
    0x02: "If not (unattended cash / manual cash / cashback)",
    0x03: "If terminal supports CVM",
    0x04: "If manual cash",
    0x05: "If purchase with cashback",
    0x06: "If amount < X (app currency)",
    0x07: "If amount >= X (app currency)",
    0x08: "If amount < Y (app currency)",
    0x09: "If amount >= Y (app currency)",
}

# ── GET DATA tags to sweep on every AID ──────────────────────────────────────

GET_DATA_TAGS: list[str] = [
    "9F36",   # ATC
    "9F13",   # Last Online ATC Register
    "9F17",   # PIN Retry Counter
    "9F4D",   # Log Entry
    "9F4F",   # Log Format
    "9F6E",   # Form Factor Indicator (Visa) / Third Party Data (MC)
    "9F7C",   # Customer Exclusive Data (Visa)
    "DF01",   # Kernel Identifier
]

# ─────────────────────────────────────────────────────────────────────────────
# Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class PDOLEntry:
    tag: str
    name: str
    length: int


@dataclasses.dataclass
class AFLEntry:
    sfi: int
    first_record: int
    last_record: int
    offline_auth_records: int


@dataclasses.dataclass
class CVMRule:
    code: int
    code_name: str
    condition: int
    condition_name: str
    continue_if_fail: bool


@dataclasses.dataclass
class SFIRecord:
    sfi: int
    record: int
    in_afl: bool
    raw_hex: str
    sw: str
    tlv: list[dict] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class CryptoCaps:
    """Cryptographic capabilities inferred from card data."""
    aip_sda: bool = False
    aip_dda: bool = False
    aip_cda: bool = False
    ca_key_index: int | None = None         # tag 8F
    issuer_pk_bits: int | None = None       # len(tag 90) * 8 − padding estimate
    icc_pk_bits: int | None = None          # len(tag 9F46) * 8
    app_version: str | None = None          # tag 9F08
    form_factor_indicator: str | None = None  # tag 9F6E (GET DATA)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


@dataclasses.dataclass
class AIDProfile:
    aid: str
    label: str | None
    priority: int | None
    source: str                     # "PSE", "PPSE", "fallback"
    fci_raw: str
    pdol: str | None
    pdol_entries: list[PDOLEntry]
    aip: str | None
    aip_flags: list[str]
    afl_entries: list[AFLEntry]
    afl_records: list[SFIRecord]
    off_afl_records: list[SFIRecord]
    cvm_rules: list[CVMRule]
    crypto: CryptoCaps
    get_data: dict[str, str | None]  # tag → hex value (or None if not supported)
    all_tags: dict[str, str]         # tag → last seen hex value (flattened, all records)
    # CDOL1/CDOL2 — DOL field lists extracted from AFL records (tags 8C / 8D)
    cdol1_entries: list[PDOLEntry] = dataclasses.field(default_factory=list)
    cdol2_entries: list[PDOLEntry] = dataclasses.field(default_factory=list)
    # Service code from Track 2 Equivalent Data (tag 57), e.g. "201"
    service_code: str | None = None

    def to_dict(self) -> dict:
        return {
            "aid": self.aid,
            "label": self.label,
            "priority": self.priority,
            "source": self.source,
            "fci_raw": self.fci_raw,
            "pdol": self.pdol,
            "pdol_entries": [dataclasses.asdict(e) for e in self.pdol_entries],
            "aip": self.aip,
            "aip_flags": self.aip_flags,
            "afl_entries": [dataclasses.asdict(e) for e in self.afl_entries],
            "afl_records": [dataclasses.asdict(r) for r in self.afl_records],
            "off_afl_records": [dataclasses.asdict(r) for r in self.off_afl_records],
            "cvm_rules": [dataclasses.asdict(r) for r in self.cvm_rules],
            "cdol1_entries": [dataclasses.asdict(e) for e in self.cdol1_entries],
            "cdol2_entries": [dataclasses.asdict(e) for e in self.cdol2_entries],
            "service_code": self.service_code,
            "crypto": self.crypto.to_dict(),
            "get_data": self.get_data,
            "all_tags": self.all_tags,
        }


@dataclasses.dataclass
class CardProfile:
    timestamp: str
    reader_name: str
    atr: str
    pse_present: bool
    ppse_present: bool
    aids_from_pse: list[str]
    aids_from_ppse: list[str]
    profiles: list[AIDProfile]
    fingerprint_hash: str            # SHA-256 of stable card identity fields

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "reader": self.reader_name,
            "atr": self.atr,
            "pse_present": self.pse_present,
            "ppse_present": self.ppse_present,
            "aids_from_pse": self.aids_from_pse,
            "aids_from_ppse": self.aids_from_ppse,
            "profiles": [p.to_dict() for p in self.profiles],
            "fingerprint_hash": self.fingerprint_hash,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 2 – CardFingerprinter: init and low-level transport helpers
# ─────────────────────────────────────────────────────────────────────────────

class CardFingerprinter:
    """
    Connects to a physical card via pyscard and runs the full fingerprint
    sequence.  All card I/O is in this class; the dataclass layer above is
    pure data.

    Parameters
    ──────────
    reader_index  – reader index, name fragment, or None to auto-select
    brute_sfi     – also try SFIs not listed in the AFL
    sfi_range     – (min_sfi, max_sfi) for brute-force (default 1-10)
    rec_range     – (min_rec, max_rec) per SFI (default 1-10)
    verbose       – print each APDU exchange to stdout
    """

    def __init__(
        self,
        reader_index: int | str | None = None,
        brute_sfi: bool = False,
        sfi_range: tuple[int, int] = (1, 10),
        rec_range: tuple[int, int] = (1, 10),
        verbose: bool = False,
    ) -> None:
        try:
            import smartcard.System
            import smartcard.Session
        except ImportError:
            raise RuntimeError("pyscard not installed — pip install pyscard")

        from core.readers import ReaderError, resolve

        try:
            chosen = resolve(reader_index)
        except ReaderError as exc:
            raise RuntimeError(str(exc)) from exc

        self._reader_name = chosen.name
        self._session = smartcard.Session(self._reader_name)
        self._brute_sfi = brute_sfi
        self._sfi_min, self._sfi_max = sfi_range
        self._rec_min, self._rec_max = rec_range
        self._verbose = verbose

    # ── ATR ──────────────────────────────────────────────────────────────────

    def _atr_hex(self) -> str:
        try:
            return bytes(self._session.getATR()).hex().upper()
        except Exception:
            return ""

    # ── Core send/receive with 61/6C chaining ────────────────────────────────

    def _send(self, apdu: bytes | list[int]) -> tuple[bytes, int, int]:
        """
        Send an APDU and return (response_data, sw1, sw2).

        Handles transparently:
          SW1=61 → issue GET RESPONSE to collect remaining data
          SW1=6C → resend with correct Le (SW2)
        """
        if isinstance(apdu, bytes):
            cmd = list(apdu)
        else:
            cmd = list(apdu)

        try:
            rapdu, sw1, sw2 = self._session.sendCommandAPDU(cmd)
        except Exception as exc:
            log.debug("_send error: %s  APDU=%s", exc,
                      bytes(cmd).hex().upper())
            return b"", 0x6F, 0x00

        if self._verbose:
            print(f"  >> {bytes(cmd).hex().upper()}")
            print(f"  << {bytes(rapdu).hex().upper()} {sw1:02X}{sw2:02X}")

        # 61 XX – more data; fetch it
        if sw1 == 0x61:
            get_resp = [0x00, 0xC0, 0x00, 0x00, sw2 or 0x00]
            try:
                r2, s1, s2 = self._session.sendCommandAPDU(get_resp)
                data = bytes(rapdu + r2)
                if self._verbose:
                    print(f"  >> {bytes(get_resp).hex().upper()}")
                    print(f"  << {data.hex().upper()} {s1:02X}{s2:02X}")
                return data, s1, s2
            except Exception:
                pass

        # 6C XX – wrong Le; resend with card's preferred length
        if sw1 == 0x6C:
            cmd[-1] = sw2
            try:
                r2, s1, s2 = self._session.sendCommandAPDU(cmd)
                return bytes(r2), s1, s2
            except Exception:
                pass

        return bytes(rapdu), sw1, sw2

    # ── SELECT by name ────────────────────────────────────────────────────────

    def _select_name(self, name: bytes) -> tuple[bytes, int, int]:
        """SELECT file by name (P1=04, P2=00)."""
        apdu = bytes([0x00, 0xA4, 0x04, 0x00, len(name)]) + name
        return self._send(apdu)

    def _select_aid(self, aid: bytes) -> tuple[bytes, int, int]:
        """SELECT application by AID (P1=04, P2=00)."""
        return self._select_name(aid)

    # ── READ RECORD ───────────────────────────────────────────────────────────

    def _read_record(self, sfi: int, record: int) -> tuple[bytes, int, int]:
        """READ RECORD for a given SFI (1-30) and record number (1-255)."""
        p2 = (sfi << 3) | 0x04
        apdu = bytes([0x00, 0xB2, record, p2, 0x00])
        return self._send(apdu)

    # ── GET DATA ─────────────────────────────────────────────────────────────

    def _get_data(self, tag_hex: str) -> bytes | None:
        """
        GET DATA for a 2-byte tag using the CLA=80 form.
        Returns raw response bytes (without SW), or None if not supported.
        """
        tag = bytes.fromhex(tag_hex.replace(" ", ""))
        if len(tag) == 1:
            tag = b"\x00" + tag    # pad to 2 bytes
        if len(tag) != 2:
            return None
        apdu = bytes([0x80, 0xCA, tag[0], tag[1], 0x00])
        data, sw1, sw2 = self._send(apdu)
        if sw1 == 0x90 and sw2 == 0x00:
            return data
        # 9F XX = command successfully executed; XX bytes available
        if sw1 == 0x9F:
            get_resp = [0x00, 0xC0, 0x00, 0x00, sw2]
            data2, s1, s2 = self._send(bytes(get_resp))
            if s1 == 0x90:
                return data2
        return None

    def _get_data_bulk(self, tags: list[str]) -> dict[str, str | None]:
        """GET DATA for a list of tag hex strings. Returns {tag: hex_value}."""
        results: dict[str, str | None] = {}
        for tag in tags:
            raw = self._get_data(tag)
            if raw is not None:
                # The card often wraps the value in a TLV; unwrap if so
                nodes = maybe_parse_tlv(raw)
                if nodes and nodes[0].tag.upper() == tag.upper().replace(" ", ""):
                    results[tag] = nodes[0].value.hex().upper()
                else:
                    results[tag] = raw.hex().upper()
            else:
                results[tag] = None
        return results

    # ── GET PROCESSING OPTIONS ────────────────────────────────────────────────

    def _gpo(self, pdol_data: bytes) -> tuple[bytes, int, int]:
        """
        Send GET PROCESSING OPTIONS.
        pdol_data is wrapped in Command Template tag 83.
        """
        inner = bytes([0x83, len(pdol_data)]) + pdol_data
        apdu  = bytes([0x80, 0xA8, 0x00, 0x00, len(inner)]) + inner
        return self._send(apdu)


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 3 – PSE/PPSE enumeration and AID-level SELECT + GPO
# ─────────────────────────────────────────────────────────────────────────────

    # ── PSE enumeration ───────────────────────────────────────────────────────

    def _enumerate_pse(self, pse_name: bytes) -> list[dict]:
        """
        SELECT the PSE/PPSE, read all directory records, extract AID entries.
        Returns a list of dicts with keys: aid, label, priority, raw_hex.
        """
        aids: list[dict] = []
        data, sw1, sw2 = self._select_name(pse_name)
        if sw1 != 0x90:
            return aids   # PSE not present

        # FCI of PSE contains tag 88 (SFI of the Directory EF)
        fci_nodes = maybe_parse_tlv(data)
        sfi = self._find_tag_value(fci_nodes, "88")
        if not sfi:
            return aids
        dir_sfi = sfi[0]

        # Read all directory records
        for rec in range(1, 256):
            rec_data, sw1, sw2 = self._read_record(dir_sfi, rec)
            if sw1 in (0x6A,) and sw2 in (0x83, 0x82):
                break
            if sw1 != 0x90:
                break

            # Each record is a 70 template containing 61 Application Templates
            nodes = maybe_parse_tlv(rec_data)
            for app_template in self._find_nodes(nodes, "61"):
                entry: dict[str, Any] = {"raw_hex": rec_data.hex().upper()}
                # 4F = AID
                aid_val = self._find_tag_value(app_template.children, "4F")
                if aid_val:
                    entry["aid"] = bytes(aid_val).hex().upper()
                # 50 = Application Label
                lbl = self._find_tag_value(app_template.children, "50")
                if lbl:
                    entry["label"] = bytes(lbl).decode("ascii", errors="replace").strip()
                else:
                    entry["label"] = None
                # 87 = Priority
                pri = self._find_tag_value(app_template.children, "87")
                entry["priority"] = pri[0] if pri else None

                if "aid" in entry:
                    aids.append(entry)

        return aids

    # ── PDOL builder ─────────────────────────────────────────────────────────

    @staticmethod
    def _decode_pdol(pdol_bytes: bytes) -> list[PDOLEntry]:
        """
        Parse a PDOL (Processing Options Data Object List).
        PDOL is a list of (tag, length) pairs – no values, no TLV nesting.
        """
        entries: list[PDOLEntry] = []
        pos = 0
        while pos < len(pdol_bytes):
            try:
                # Read tag (1 or 2 bytes)
                b0 = pdol_bytes[pos]
                if (b0 & 0x1F) == 0x1F:          # multi-byte tag
                    if pos + 1 >= len(pdol_bytes):
                        break
                    tag = f"{b0:02X}{pdol_bytes[pos+1]:02X}"
                    pos += 2
                else:
                    tag = f"{b0:02X}"
                    pos += 1
                # Read length (always 1 byte in a DOL)
                if pos >= len(pdol_bytes):
                    break
                length = pdol_bytes[pos]
                pos += 1
                name = EMV_TAGS.get(tag, f"Unknown {tag}")
                entries.append(PDOLEntry(tag=tag, name=name, length=length))
            except Exception:
                break
        return entries

    def _build_pdol_data(self, pdol_entries: list[PDOLEntry]) -> bytes:
        """
        Build the PDOL response data (what the terminal sends in GPO).
        Uses sensible defaults from _PDOL_DEFAULTS; zero-pads anything unknown.
        """
        today = datetime.date.today()
        # Build a local copy so we don't mutate the module-level defaults dict
        defaults = dict(_PDOL_DEFAULTS)
        defaults["9A"] = bytes([
            int(f"{today.year % 100:02d}", 16),   # BCD year last 2 digits
            int(f"{today.month:02d}", 16),
            int(f"{today.day:02d}", 16),
        ])
        now = datetime.datetime.now()
        defaults["9F21"] = bytes([
            int(f"{now.hour:02d}", 16),
            int(f"{now.minute:02d}", 16),
            int(f"{now.second:02d}", 16),
        ])

        result = b""
        for entry in pdol_entries:
            default = defaults.get(entry.tag, b"")
            if len(default) >= entry.length:
                result += default[:entry.length]
            else:
                result += default + b"\x00" * (entry.length - len(default))
        return result

    # ── Per-AID SELECT + GPO ──────────────────────────────────────────────────

    def _select_and_gpo(
        self, aid: bytes, source: str
    ) -> tuple[bytes, list[PDOLEntry], bytes, list[AFLEntry], str] | None:
        """
        SELECT the AID, parse FCI, call GPO.
        Returns (fci_raw, pdol_entries, aip_bytes, afl_entries, label)
        or None if SELECT failed.
        """
        fci_data, sw1, sw2 = self._select_aid(aid)
        if sw1 != 0x90:
            log.debug("SELECT %s failed: %02X%02X", aid.hex().upper(), sw1, sw2)
            return None

        fci_raw = fci_data.hex().upper()
        fci_nodes = maybe_parse_tlv(fci_data)

        # Application label (tag 50 inside A5)
        label = None
        lbl_val = self._find_tag_value(fci_nodes, "50") or \
                  self._find_tag_deep(fci_nodes, "50")
        if lbl_val:
            label = bytes(lbl_val).decode("ascii", errors="replace").strip()

        # PDOL (tag 9F38, usually inside A5)
        pdol_val = self._find_tag_deep(fci_nodes, "9F38")
        pdol_entries: list[PDOLEntry] = []
        if pdol_val:
            pdol_entries = self._decode_pdol(bytes(pdol_val))

        # GPO
        pdol_data = self._build_pdol_data(pdol_entries)
        gpo_data, sw1, sw2 = self._gpo(pdol_data)

        aip = b""
        afl_entries: list[AFLEntry] = []

        if sw1 == 0x90:
            gpo_nodes = maybe_parse_tlv(gpo_data)

            # Format 1 (tag 80): AIP(2) + AFL(n)
            fmt1 = self._find_tag_value(gpo_nodes, "80")
            if fmt1 and len(fmt1) >= 2:
                aip = bytes(fmt1[:2])
                afl_entries = self._parse_afl(bytes(fmt1[2:]))
            else:
                # Format 2 (tag 77): separate 82 + 94
                aip_val = self._find_tag_deep(gpo_nodes, "82")
                if aip_val:
                    aip = bytes(aip_val[:2])
                afl_val = self._find_tag_deep(gpo_nodes, "94")
                if afl_val:
                    afl_entries = self._parse_afl(bytes(afl_val))

        return fci_raw, pdol_entries, aip, afl_entries, label or ""

    # ── AFL parser ────────────────────────────────────────────────────────────

    @staticmethod
    def _parse_afl(afl_bytes: bytes) -> list[AFLEntry]:
        """
        Parse AFL (tag 94). Format: 4-byte groups:
          byte 0: SFI in bits 7-3, bits 2-0 are RFU
          byte 1: first record
          byte 2: last record
          byte 3: number of records involved in offline data authentication
        """
        entries: list[AFLEntry] = []
        for i in range(0, len(afl_bytes) - 3, 4):
            sfi = (afl_bytes[i] >> 3) & 0x1F
            first = afl_bytes[i + 1]
            last  = afl_bytes[i + 2]
            oda   = afl_bytes[i + 3]
            if sfi and first and last >= first:
                entries.append(AFLEntry(sfi=sfi, first_record=first,
                                        last_record=last,
                                        offline_auth_records=oda))
        return entries


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 4 – Record reading, SFI brute-force, and all decoders
# ─────────────────────────────────────────────────────────────────────────────

    # ── AFL record reader ─────────────────────────────────────────────────────

    def _read_afl_records(self, afl_entries: list[AFLEntry]) -> list[SFIRecord]:
        records: list[SFIRecord] = []
        for entry in afl_entries:
            for rec_num in range(entry.first_record, entry.last_record + 1):
                data, sw1, sw2 = self._read_record(entry.sfi, rec_num)
                sw_str = f"{sw1:02X}{sw2:02X}"
                tlv = [n.to_dict() for n in maybe_parse_tlv(data)] if sw1 == 0x90 else []
                records.append(SFIRecord(
                    sfi=entry.sfi,
                    record=rec_num,
                    in_afl=True,
                    raw_hex=data.hex().upper(),
                    sw=sw_str,
                    tlv=tlv,
                ))
        return records

    # ── SFI brute-force ───────────────────────────────────────────────────────

    def _brute_sfi(self, afl_sfis: set[int]) -> list[SFIRecord]:
        """
        Try every SFI in [sfi_min, sfi_max] not already covered by the AFL.
        For each, read records [rec_min, rec_max] until 6A83 (no more records).
        Stops early on 6A82 (file not found) for a given SFI.
        """
        found: list[SFIRecord] = []
        for sfi in range(self._sfi_min, self._sfi_max + 1):
            if sfi in afl_sfis:
                continue
            for rec_num in range(self._rec_min, self._rec_max + 1):
                data, sw1, sw2 = self._read_record(sfi, rec_num)
                sw_str = f"{sw1:02X}{sw2:02X}"

                if sw1 == 0x6A and sw2 == 0x82:  # file not found → skip SFI
                    break
                if sw1 == 0x6A and sw2 == 0x83:  # record not found → next SFI
                    break
                if sw1 == 0x69 and sw2 == 0x82:  # security condition
                    found.append(SFIRecord(sfi=sfi, record=rec_num, in_afl=False,
                                           raw_hex="", sw=sw_str, tlv=[]))
                    break

                if sw1 == 0x90:
                    tlv = [n.to_dict() for n in maybe_parse_tlv(data)]
                    found.append(SFIRecord(sfi=sfi, record=rec_num, in_afl=False,
                                           raw_hex=data.hex().upper(),
                                           sw=sw_str, tlv=tlv))
                # Any other SW: stop this SFI
                elif sw1 not in (0x90, 0x61, 0x9F):
                    break
        return found

    # ── AIP decoder ───────────────────────────────────────────────────────────

    @staticmethod
    def _decode_aip(aip: bytes) -> list[str]:
        """Return list of enabled flag names from a 2-byte AIP."""
        flags: list[str] = []
        if len(aip) < 1:
            return flags
        b1 = aip[0]
        for mask, name in _AIP_BYTE1_FLAGS:
            if b1 & mask:
                flags.append(name)
        if len(aip) >= 2:
            b2 = aip[1]
            for mask, name in _AIP_BYTE2_FLAGS:
                if b2 & mask:
                    flags.append(name)
        return flags

    # ── DOL decoder (CDOL1 / CDOL2) ──────────────────────────────────────────

    @staticmethod
    def _parse_dol(hex_data: str) -> list[PDOLEntry]:
        """Parse a DOL (Data Object List) hex string into PDOLEntry list."""
        try:
            data = bytes.fromhex(hex_data)
        except ValueError:
            return []
        entries: list[PDOLEntry] = []
        pos = 0
        while pos < len(data):
            b = data[pos]
            tag_bytes = bytes([b])
            pos += 1
            if (b & 0x1F) == 0x1F:
                while pos < len(data):
                    b2 = data[pos]
                    tag_bytes += bytes([b2])
                    pos += 1
                    if not (b2 & 0x80):
                        break
            if pos >= len(data):
                break
            length = data[pos]
            pos += 1
            tag_hex = tag_bytes.hex().upper()
            name = EMV_TAGS.get(tag_hex, f"Unknown({tag_hex})")
            entries.append(PDOLEntry(tag=tag_hex, name=name, length=length))
        return entries

    # ── Track 2 service code extractor ───────────────────────────────────────

    @staticmethod
    def _parse_service_code(track2_hex: str) -> str | None:
        """
        Extract the 3-digit service code from Track 2 Equivalent Data (tag 57).
        Track 2 BCD format: [PAN] D [YYMM] [3-digit service code] [discretionary]
        """
        try:
            nibbles = []
            for i in range(0, len(track2_hex) - 1, 2):
                b = int(track2_hex[i:i + 2], 16)
                nibbles.append(b >> 4)
                nibbles.append(b & 0xF)
            # Find the D separator nibble
            d_idx = next((i for i, n in enumerate(nibbles) if n == 0xD), None)
            if d_idx is None:
                return None
            sc_start = d_idx + 5   # D + 4 YYMM nibbles
            if sc_start + 3 > len(nibbles):
                return None
            return "".join(str(n) for n in nibbles[sc_start: sc_start + 3])
        except Exception:
            return None

    # ── CVM list decoder ──────────────────────────────────────────────────────

    @staticmethod
    def _decode_cvm_list(cvm_bytes: bytes) -> list[CVMRule]:
        """
        Decode tag 8E – CVM List.
        Format: 4-byte X-amount | 4-byte Y-amount | N × 2-byte rules
        Rule byte 1 bits 7-2 = CVM code, bit 1 = continue-if-fail
        Rule byte 2 = condition code
        """
        rules: list[CVMRule] = []
        if len(cvm_bytes) < 8:
            return rules
        # skip 8-byte X/Y amounts
        pos = 8
        while pos + 1 < len(cvm_bytes):
            b1 = cvm_bytes[pos]
            b2 = cvm_bytes[pos + 1]
            pos += 2
            code = b1 & 0x3F
            continue_if_fail = bool(b1 & 0x40)
            cond = b2
            rules.append(CVMRule(
                code=code,
                code_name=_CVM_CODES.get(code, f"Unknown({code:#04x})"),
                condition=cond,
                condition_name=_CVM_CONDITIONS.get(cond, f"Unknown({cond:#04x})"),
                continue_if_fail=continue_if_fail,
            ))
        return rules

    # ── Crypto capability extractor ───────────────────────────────────────────

    @staticmethod
    def _extract_crypto(
        all_records: list[SFIRecord],
        aip_flags: list[str],
        get_data_results: dict[str, str | None],
    ) -> CryptoCaps:
        """
        Infer cryptographic capabilities from collected card data.
        Key sources:
          8F   – CA Public Key Index
          90   – Issuer Public Key Certificate (length ≈ RSA key size)
          9F46 – ICC Public Key Certificate
          9F08 – Application Version Number
          9F6E – Form Factor Indicator / Third Party Data (from GET DATA)
        """
        caps = CryptoCaps(
            aip_sda="SDA" in aip_flags,
            aip_dda="DDA" in aip_flags,
            aip_cda="CDA" in aip_flags,
        )

        def _all_tags_flat() -> dict[str, bytes]:
            seen: dict[str, bytes] = {}
            def _walk(nodes: list[dict]) -> None:
                for n in nodes:
                    seen[n["tag"]] = bytes.fromhex(n["value"])
                    if "children" in n:
                        _walk(n["children"])
            for rec in all_records:
                _walk(rec.tlv)
            return seen

        tags = _all_tags_flat()

        if "8F" in tags:
            caps.ca_key_index = tags["8F"][0]

        # Cert length in bytes ≈ RSA modulus bytes → × 8 = bits
        if "90" in tags:
            caps.issuer_pk_bits = len(tags["90"]) * 8
        if "9F46" in tags:
            caps.icc_pk_bits = len(tags["9F46"]) * 8

        if "9F08" in tags:
            caps.app_version = tags["9F08"].hex().upper()

        ffi = get_data_results.get("9F6E")
        if ffi:
            caps.form_factor_indicator = ffi

        return caps

    # ── TLV search helpers ────────────────────────────────────────────────────

    @staticmethod
    def _find_tag_value(nodes: list[TLVNode], tag: str) -> list[int] | None:
        """First matching node at top level; returns value as byte list."""
        tag_up = tag.upper()
        for n in nodes:
            if n.tag == tag_up:
                return list(n.value)
        return None

    @staticmethod
    def _find_tag_deep(nodes: list[TLVNode], tag: str) -> list[int] | None:
        """Depth-first search across full TLV tree."""
        tag_up = tag.upper()
        for n in nodes:
            if n.tag == tag_up:
                return list(n.value)
            if n.children:
                result = CardFingerprinter._find_tag_deep(n.children, tag_up)
                if result is not None:
                    return result
        return None

    @staticmethod
    def _find_nodes(nodes: list[TLVNode], tag: str) -> list[TLVNode]:
        tag_up = tag.upper()
        return [n for n in nodes if n.tag == tag_up]

    @staticmethod
    def _flatten_tags(records: list[SFIRecord]) -> dict[str, str]:
        """Collect every unique {tag: last_value_hex} across all records."""
        result: dict[str, str] = {}
        def _walk(nodes: list[dict]) -> None:
            for n in nodes:
                result[n["tag"]] = n["value"]
                if "children" in n:
                    _walk(n["children"])
        for rec in records:
            _walk(rec.tlv)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 5 – fingerprint() orchestrator, console printer, CLI
# ─────────────────────────────────────────────────────────────────────────────

    # ── Main orchestrator ─────────────────────────────────────────────────────

    def fingerprint(self) -> CardProfile:
        """
        Run the complete fingerprint sequence and return a CardProfile.
        Safe to call multiple times (re-SELECTs each AID from scratch).
        """
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        atr = self._atr_hex()

        # ── Step 1: PSE / PPSE enumeration ───────────────────────────────────
        print(f"\n[PSE]  Enumerating 1PAY.SYS.DDF01 …")
        pse_entries  = self._enumerate_pse(PSE_NAME)
        print(f"[PPSE] Enumerating 2PAY.SYS.DDF01 …")
        ppse_entries = self._enumerate_pse(PPSE_NAME)

        pse_aid_strs  = [e["aid"] for e in pse_entries]
        ppse_aid_strs = [e["aid"] for e in ppse_entries]

        # Build ordered AID work list (PSE first, then PPSE extras, then fallback)
        seen_aids: set[str] = set()
        aid_work: list[tuple[bytes, str]] = []  # (aid_bytes, source)

        for e in pse_entries:
            key = e["aid"].upper()
            if key not in seen_aids:
                seen_aids.add(key)
                aid_work.append((bytes.fromhex(key), "PSE"))

        for e in ppse_entries:
            key = e["aid"].upper()
            if key not in seen_aids:
                seen_aids.add(key)
                aid_work.append((bytes.fromhex(key), "PPSE"))

        if not aid_work:
            print("[!]    No AIDs found via PSE/PPSE – trying fallback list …")
            for aid_b in FALLBACK_AIDS:
                key = aid_b.hex().upper()
                if key not in seen_aids:
                    seen_aids.add(key)
                    aid_work.append((aid_b, "fallback"))

        # ── Step 2: Per-AID fingerprint ───────────────────────────────────────
        profiles: list[AIDProfile] = []

        for aid_bytes, source in aid_work:
            aid_str = aid_bytes.hex().upper()
            print(f"\n[AID]  {aid_str}  ({source})")

            result = self._select_and_gpo(aid_bytes, source)
            if result is None:
                print(f"       SELECT failed – skipping")
                continue

            fci_raw, pdol_entries, aip_bytes, afl_entries, label = result

            # Pull label from PSE entry if FCI didn't have it
            if not label:
                for e in (pse_entries + ppse_entries):
                    if e["aid"].upper() == aid_str:
                        label = e.get("label") or ""
                        break

            priority = None
            for e in (pse_entries + ppse_entries):
                if e["aid"].upper() == aid_str:
                    priority = e.get("priority")
                    break

            aip_flags = self._decode_aip(aip_bytes)
            pdol_str  = bytes([b for e in pdol_entries
                               for b in bytes.fromhex(e.tag) + bytes([e.length])
                               ]).hex().upper() if pdol_entries else None

            print(f"       Label: {label or '—'}  AIP: {aip_bytes.hex().upper() or '?'}"
                  f"  → {', '.join(aip_flags) or 'none'}")
            print(f"       AFL: {len(afl_entries)} entries, PDOL tags: "
                  f"{[e.tag for e in pdol_entries] or '[]'}")

            # ── Step 3: Read AFL records ──────────────────────────────────────
            print(f"       Reading AFL records …")
            afl_records = self._read_afl_records(afl_entries)
            afl_sfis    = {e.sfi for e in afl_entries}

            # ── Step 4: SFI brute-force ───────────────────────────────────────
            off_afl_records: list[SFIRecord] = []
            if self._brute_sfi:
                print(f"       Brute-forcing off-AFL SFIs "
                      f"{self._sfi_min}–{self._sfi_max} …")
                off_afl_records = self._brute_sfi(afl_sfis)
                if off_afl_records:
                    print(f"       Found {len(off_afl_records)} off-AFL record(s)!")

            # ── Step 5: CVM list ──────────────────────────────────────────────
            all_records = afl_records + off_afl_records
            all_tags_flat = self._flatten_tags(all_records)
            cvm_rules: list[CVMRule] = []
            if "8E" in all_tags_flat:
                cvm_rules = self._decode_cvm_list(bytes.fromhex(all_tags_flat["8E"]))

            # ── Step 5b: CDOL1 / CDOL2 extraction ────────────────────────────
            cdol1_entries: list[PDOLEntry] = []
            cdol2_entries: list[PDOLEntry] = []
            if "8C" in all_tags_flat:
                cdol1_entries = self._parse_dol(all_tags_flat["8C"])
            if "8D" in all_tags_flat:
                cdol2_entries = self._parse_dol(all_tags_flat["8D"])

            # ── Step 5c: Service code from Track 2 ───────────────────────────
            service_code: str | None = None
            if "57" in all_tags_flat:
                service_code = self._parse_service_code(all_tags_flat["57"])

            # ── Step 6: GET DATA sweep ────────────────────────────────────────
            print(f"       GET DATA sweep ({len(GET_DATA_TAGS)} tags) …")
            get_data = self._get_data_bulk(GET_DATA_TAGS)

            # ── Step 7: Crypto capabilities ───────────────────────────────────
            crypto = self._extract_crypto(all_records, aip_flags, get_data)

            # Annotate get_data with tag names for readability
            named_get_data = {
                f"{t} ({EMV_TAGS.get(t, '?')})": v
                for t, v in get_data.items()
            }

            profiles.append(AIDProfile(
                aid=aid_str,
                label=label or None,
                priority=priority,
                source=source,
                fci_raw=fci_raw,
                pdol=pdol_str,
                pdol_entries=pdol_entries,
                aip=aip_bytes.hex().upper() or None,
                aip_flags=aip_flags,
                afl_entries=afl_entries,
                afl_records=afl_records,
                off_afl_records=off_afl_records,
                cvm_rules=cvm_rules,
                cdol1_entries=cdol1_entries,
                cdol2_entries=cdol2_entries,
                service_code=service_code,
                crypto=crypto,
                get_data=named_get_data,
                all_tags=all_tags_flat,
            ))

        # ── Fingerprint hash ──────────────────────────────────────────────────
        hash_input = "|".join(
            f"{p.aid}:{p.aip or ''}:{','.join(p.aip_flags)}"
            for p in sorted(profiles, key=lambda x: x.aid)
        ).encode()
        fp_hash = hashlib.sha256(hash_input).hexdigest()[:16]

        return CardProfile(
            timestamp=ts,
            reader_name=self._reader_name,
            atr=atr,
            pse_present=bool(pse_entries),
            ppse_present=bool(ppse_entries),
            aids_from_pse=pse_aid_strs,
            aids_from_ppse=ppse_aid_strs,
            profiles=profiles,
            fingerprint_hash=fp_hash,
        )

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Console summary printer
# ─────────────────────────────────────────────────────────────────────────────

_B  = "\033[1m"
_R  = "\033[0m"
_C  = "\033[96m"
_G  = "\033[92m"
_Y  = "\033[93m"
_D  = "\033[2m"


def print_profile(profile: CardProfile) -> None:
    w = 66
    print(f"\n{_B}{'═'*w}{_R}")
    print(f"{_B}  EMV Card Fingerprint{_R}")
    print(f"  Reader : {profile.reader_name}")
    print(f"  ATR    : {profile.atr or '(unavailable)'}")
    print(f"  Time   : {profile.timestamp}")
    print(f"  Hash   : {_Y}{profile.fingerprint_hash}{_R}")
    print(f"{_B}{'═'*w}{_R}\n")

    pse_tag  = f"{_G}✓{_R}" if profile.pse_present  else f"{_D}✗{_R}"
    ppse_tag = f"{_G}✓{_R}" if profile.ppse_present else f"{_D}✗{_R}"
    print(f"  PSE  (1PAY) {pse_tag}   PPSE (2PAY) {ppse_tag}")
    if profile.aids_from_pse:
        print(f"  PSE  AIDs: {', '.join(profile.aids_from_pse)}")
    if profile.aids_from_ppse:
        print(f"  PPSE AIDs: {', '.join(profile.aids_from_ppse)}")

    for p in profile.profiles:
        print(f"\n{_B}{'─'*w}{_R}")
        print(f"{_B}{_C}  AID {p.aid}  {p.label or ''}  [{p.source}]{_R}")
        print(f"{'─'*w}")

        # AIP
        aip_str = p.aip or "—"
        flags   = "  ".join(p.aip_flags) if p.aip_flags else "none"
        print(f"  AIP       : {aip_str}  →  {_G}{flags}{_R}")

        # PDOL
        if p.pdol_entries:
            pdol_items = "  ".join(
                f"{e.tag}({e.length}B)" for e in p.pdol_entries
            )
            print(f"  PDOL      : {pdol_items}")
        else:
            print(f"  PDOL      : empty (no terminal data required)")

        # AFL
        if p.afl_entries:
            afl_lines = "  ".join(
                f"SFI{e.sfi}[{e.first_record}-{e.last_record}]"
                + (f"*{e.offline_auth_records}" if e.offline_auth_records else "")
                for e in p.afl_entries
            )
            print(f"  AFL       : {afl_lines}")
            print(f"  Records   : {len(p.afl_records)} read  "
                  f"({len(p.off_afl_records)} off-AFL)")
        else:
            print(f"  AFL       : empty")

        # CVM
        if p.cvm_rules:
            print(f"  CVM List  :")
            for i, rule in enumerate(p.cvm_rules, 1):
                cont = " (cont.)" if rule.continue_if_fail else ""
                print(f"    {i}. {_Y}{rule.code_name}{_R}{cont}"
                      f"  — {rule.condition_name}")
        else:
            print(f"  CVM List  : not found in records")

        # Crypto
        c = p.crypto
        print(f"  Crypto    : "
              f"SDA={'✓' if c.aip_sda else '✗'}  "
              f"DDA={'✓' if c.aip_dda else '✗'}  "
              f"CDA={'✓' if c.aip_cda else '✗'}")
        if c.ca_key_index is not None:
            print(f"    CA Key Index : {c.ca_key_index:#04x}")
        if c.issuer_pk_bits:
            print(f"    Issuer PK    : ~{c.issuer_pk_bits} bits (RSA cert size)")
        if c.icc_pk_bits:
            print(f"    ICC PK       : ~{c.icc_pk_bits} bits (RSA cert size)")
        if c.app_version:
            print(f"    App Version  : {c.app_version}")
        if c.form_factor_indicator:
            print(f"    FFI (9F6E)   : {c.form_factor_indicator}")

        # GET DATA results
        gd_found = {k: v for k, v in p.get_data.items() if v is not None}
        if gd_found:
            print(f"  GET DATA  :")
            for k, v in gd_found.items():
                print(f"    {k} : {v}")

        # Interesting / proprietary tags
        known_tags = set(EMV_TAGS.keys())
        prop_tags  = {t: v for t, v in p.all_tags.items() if t not in known_tags}
        if prop_tags:
            print(f"  Proprietary tags ({len(prop_tags)}):")
            for t, v in list(prop_tags.items())[:10]:
                print(f"    {t} : {v}")
            if len(prop_tags) > 10:
                print(f"    … and {len(prop_tags)-10} more (see JSON output)")

    print(f"\n{_B}{'═'*w}{_R}\n")


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    p = argparse.ArgumentParser(
        description="EMV Card Fingerprinter – Layer 2 research tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--reader", "-r", type=int, default=0,
                   help="PC/SC reader index (default 0)")
    p.add_argument("--list-readers", action="store_true",
                   help="List available readers and exit")
    p.add_argument("--output", "-o", metavar="FILE",
                   help="Write JSON CardProfile to FILE (default: stdout only)")
    p.add_argument("--brute-sfi", action="store_true",
                   help="Brute-force SFIs not listed in the AFL")
    p.add_argument("--sfi-max", type=int, default=10,
                   help="Max SFI to probe in brute-force mode (default 10)")
    p.add_argument("--rec-max", type=int, default=10,
                   help="Max record per SFI in brute-force mode (default 10)")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Print each APDU exchange")
    p.add_argument("--no-color", action="store_true",
                   help="Disable ANSI color in console output")
    args = p.parse_args()

    if args.list_readers:
        try:
            import smartcard.System
            readers = smartcard.System.listReaders()
            if readers:
                for i, r in enumerate(readers):
                    print(f"  [{i}] {r}")
            else:
                print("No readers found.")
        except ImportError:
            print("pyscard not installed.")
        return

    fp = CardFingerprinter(
        reader_index=args.reader,
        brute_sfi=args.brute_sfi,
        sfi_range=(1, args.sfi_max),
        rec_range=(1, args.rec_max),
        verbose=args.verbose,
    )

    try:
        profile = fp.fingerprint()
    finally:
        fp.close()

    print_profile(profile)

    if args.output:
        Path(args.output).write_text(profile.to_json())
        print(f"Profile written to {args.output}")
    else:
        # Always write a timestamped JSON alongside the console output
        ts_safe = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        out_path = Path("logs") / f"fingerprint_{ts_safe}.json"
        out_path.parent.mkdir(exist_ok=True)
        out_path.write_text(profile.to_json())
        print(f"JSON profile saved to {out_path}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.WARNING)
    main()
