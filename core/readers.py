"""
Reader discovery — names, classification, and a sensible default.

Every call site used to enumerate readers itself and index into the list, which
made a reader an opaque number.  That is workable until vpcd is running, at
which point the *virtual* reader usually lands at index 0 — and the virtual
reader is ATRIUM's own output side, the thing presenting a card to the
terminal, not the thing a real card is sitting in.  Defaulting to it is
therefore always wrong on a working setup, and gives an error that looks like
a card fault rather than a wiring mistake.

So readers are named and classified here, once, and everything else asks this
module.  A reader may still be selected by index — the API and CLI keep taking
one — but nothing has to *guess* which index is right.
"""
from __future__ import annotations

import dataclasses
import re

VIRTUAL = "virtual"
CONTACT = "contact"
CONTACTLESS = "contactless"
UNKNOWN = "unknown"

# Matched against the reader's PC/SC name, lowercased. Order matters: the
# virtual patterns win, then contactless, and anything else left over is
# assumed to be a contact slot — which is what an unrecognised EMV reader
# almost always is.
_VIRTUAL_PATTERNS = (
    "virtual pcd", "virtualpcd", "vpcd", "virtual smart card", "vicc",
)

# A dual-interface reader exposes both slots under the *same model name*,
# distinguished only by an interface marker — "PICC" for contactless, "ICC" for
# contact. So the marker has to outrank the model name, and it has to be
# matched on a word boundary, because "PICC" contains "ICC".
_PICC_RE = re.compile(r"\bpicc\b|contactless", re.I)
_ICC_RE = re.compile(r"\bicc\b", re.I)

# Models that have no contact slot at all, so their name alone settles it.
_CONTACTLESS_ONLY_PATTERNS = (
    "acr122", "pn53", "pn 53", "rc-s380", "scl01", "scl3711", "nfc", "prox",
)

# Models known to be a PN532 under the hood, which matters because they can be
# driven into card emulation through the ACR122 escape APDU.
_PN532_PATTERNS = ("acr122", "pn53", "scl3711")


class ReaderError(RuntimeError):
    """No usable reader, or the requested one does not exist. User-facing."""


@dataclasses.dataclass(frozen=True)
class Reader:
    index: int
    name: str
    kind: str

    @property
    def is_virtual(self) -> bool:
        return self.kind == VIRTUAL

    @property
    def is_pn532(self) -> bool:
        """True for readers that are a PN532 behind a CCID bridge."""
        lowered = self.name.lower()
        return any(p in lowered for p in _PN532_PATTERNS)

    @property
    def label(self) -> str:
        return f"[{self.index}] {self.name}"

    def to_dict(self) -> dict:
        return {"index": self.index, "name": self.name, "kind": self.kind,
                "virtual": self.is_virtual, "pn532": self.is_pn532}


# ── Telling two identical readers apart ──────────────────────────────────────
#
# PC/SC names are unique by construction: pcsc-lite appends a reader index and
# slot number to the friendly name, so two ACR122Us arrive as
# "... PICC Interface 00 00" and "... PICC Interface 01 00". They can always be
# *addressed* separately.
#
# The question that is genuinely hard is which of the two black squares on the
# desk is index 00 — and no amount of naming answers that. Two things help:
# these attributes, which pin each reader to a USB bus and device address, and
# nfc.acr122.identify(), which makes the reader itself blink.

# 0xDDDDCCCC, where DDDD names the channel type. 0x0020 is USB, and the low
# half is then (bus << 8) | device address — the same numbers lsusb prints.
_CHANNEL_USB = 0x0020


def physical_id(name: str) -> dict:
    """
    Where a reader physically is, as far as PC/SC will say.

    Best effort by design: every field is optional, because drivers differ in
    what they implement and a missing attribute is not an error. A reader that
    answers nothing still works — it just cannot be pointed at.

    Opening a direct connection is what makes this possible with no card in the
    field, and it is also why this is not folded into probe(): it costs a
    connect per reader, and probe() runs on a poll.
    """
    out: dict = {}
    try:
        from smartcard.scard import (
            SCARD_ATTR_CHANNEL_ID,
            SCARD_ATTR_DEVICE_UNIT,
            SCARD_ATTR_VENDOR_IFD_SERIAL_NO,
            SCARD_PROTOCOL_UNDEFINED,
            SCARD_SHARE_DIRECT,
        )
        from smartcard.System import readers as list_readers
    except ImportError:
        return out

    target = next((r for r in list_readers() if str(r) == name), None)
    if target is None:
        return out

    connection = target.createConnection()
    try:
        connection.connect(mode=SCARD_SHARE_DIRECT, protocol=SCARD_PROTOCOL_UNDEFINED)
    except Exception:                                  # noqa: BLE001
        return out

    try:
        channel = _attrib(connection, SCARD_ATTR_CHANNEL_ID)
        if channel and len(channel) >= 4:
            value = int.from_bytes(bytes(channel[:4]), "little")
            if (value >> 16) == _CHANNEL_USB:
                out["usb_bus"] = (value >> 8) & 0xFF
                out["usb_address"] = value & 0xFF

        serial = _attrib(connection, SCARD_ATTR_VENDOR_IFD_SERIAL_NO)
        if serial:
            text = bytes(serial).split(b"\x00")[0].decode("ascii", "replace").strip()
            if text:
                out["serial"] = text

        unit = _attrib(connection, SCARD_ATTR_DEVICE_UNIT)
        if unit:
            out["unit"] = int.from_bytes(bytes(unit[:4]), "little")
    finally:
        try:
            connection.disconnect()
        except Exception:                              # noqa: BLE001
            pass
    return out


def _attrib(connection, attribute):
    """One reader attribute, or None when the driver does not implement it."""
    try:
        return connection.getAttrib(attribute)
    except Exception:                                  # noqa: BLE001
        return None


def describe_location(details: dict) -> str:
    """A short human phrase for where a reader is, or '' when nothing is known."""
    if not details:
        return ""
    parts = []
    if "usb_bus" in details and "usb_address" in details:
        parts.append(f"USB {details['usb_bus']:03d}:{details['usb_address']:03d}")
    if details.get("serial"):
        parts.append(f"serial {details['serial']}")
    if not parts and "unit" in details:
        parts.append(f"unit {details['unit']}")
    return " · ".join(parts)


def classify(name: str) -> str:
    """
    Work out what a reader is from its PC/SC name.

    Precedence matters. An explicit interface marker beats the model name,
    because a dual-interface reader carries the same model on both slots — so
    "ACR1281U-C1 ICC Reader" is the contact half even though the family is best
    known for contactless.
    """
    lowered = (name or "").lower()
    if not lowered.strip():
        return UNKNOWN
    if any(p in lowered for p in _VIRTUAL_PATTERNS):
        return VIRTUAL
    if _PICC_RE.search(lowered):
        return CONTACTLESS
    if _ICC_RE.search(lowered):
        return CONTACT
    if any(p in lowered for p in _CONTACTLESS_ONLY_PATTERNS):
        return CONTACTLESS
    return CONTACT


def probe() -> tuple[list[Reader], str]:
    """
    Enumerate readers. Returns (readers, problem) — never raises.

    A missing pyscard and a stopped pcscd are ordinary states on a machine
    running only half this toolkit, so they come back as an explanation rather
    than an exception.
    """
    try:
        import smartcard.System
    except ImportError:
        return [], ("pyscard is not installed, so no PC/SC reader can be "
                    "opened: pip install pyscard")
    try:
        names = smartcard.System.listReaders()
    except Exception as exc:                          # noqa: BLE001
        return [], f"Could not list readers ({exc}) — is pcscd running?"

    readers = [Reader(index=i, name=n, kind=classify(n)) for i, n in enumerate(names)]
    if not readers:
        return [], ("No PC/SC readers found. Check that pcscd is running and "
                    "the reader is plugged in.")
    return readers, ""


def list_readers() -> list[Reader]:
    return probe()[0]


def pick_default(readers: list[Reader]) -> Reader | None:
    """
    The reader a card is most likely sitting in.

    Contact first, because this is a contact-EMV tool; then contactless, for an
    ACR122 or similar; then anything unclassified. The virtual reader is chosen
    only when it is the only one there — and even then the caller should say so,
    because relaying a card to itself is not a working configuration.
    """
    for kind in (CONTACT, CONTACTLESS, UNKNOWN):
        for reader in readers:
            if reader.kind == kind:
                return reader
    return readers[0] if readers else None


def resolve(spec: int | str | None = None) -> Reader:
    """
    Turn an index, a name, or nothing at all into a specific reader.

    ``None`` means "pick for me". An integer keeps the old index behaviour so
    existing callers and stored settings still work. A string is matched
    against reader names, exactly first and then as a case-insensitive
    substring, so "ACR122" finds the reader without anyone typing its full
    PC/SC name with the trailing slot number.
    """
    readers, problem = probe()
    if not readers:
        raise ReaderError(problem or "No readers available")

    if spec is None or spec == "":
        chosen = pick_default(readers)
        if chosen is None:
            raise ReaderError("No readers available")
        return chosen

    if isinstance(spec, str) and spec.strip().lstrip("-").isdigit():
        spec = int(spec.strip())

    if isinstance(spec, int):
        if 0 <= spec < len(readers):
            return readers[spec]
        raise ReaderError(
            f"No reader at index {spec}. Found {len(readers)}:\n"
            + "\n".join(f"  {r.label}  ({r.kind})" for r in readers)
        )

    wanted = str(spec).strip()
    for reader in readers:
        if reader.name == wanted:
            return reader
    lowered = wanted.lower()
    matches = [r for r in readers if lowered in r.name.lower()]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise ReaderError(
            f"{wanted!r} matches more than one reader:\n"
            + "\n".join(f"  {r.label}" for r in matches)
        )
    raise ReaderError(
        f"No reader matching {wanted!r}. Found:\n"
        + "\n".join(f"  {r.label}  ({r.kind})" for r in readers)
    )


def describe(readers: list[Reader] | None = None, problem: str = "",
             details: bool = False) -> str:
    """
    Render the reader list for a terminal.

    ``details`` adds each reader's USB address and serial, which costs a direct
    connection per reader — worth it when two of the same model are plugged in
    and the names alone do not say which is which.
    """
    if readers is None:
        readers, problem = probe()
    if not readers:
        return problem or "No readers found."

    default = pick_default(readers)
    lines = []
    for reader in readers:
        marks = []
        if reader is default:
            marks.append("default")
        if reader.is_virtual:
            marks.append("ATRIUM's own output, not where a card goes")
        if reader.is_pn532:
            marks.append("PN532")
        suffix = f"   ← {', '.join(marks)}" if marks else ""
        lines.append(f"  [{reader.index}] {reader.name}  ({reader.kind}){suffix}")
        if details and not reader.is_virtual:
            where = describe_location(physical_id(reader.name))
            lines.append(f"        {where or 'no location reported by the driver'}")
    return "\n".join(lines)
