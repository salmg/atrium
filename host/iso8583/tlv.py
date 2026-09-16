"""
BER-TLV parse / serialise — the encoding DE55 carries.

VENDORED COPY.  This is deliberately a duplicate of the TLV core in ATRIUM's
``emv_logger.parse_tlv`` and ``mutation_engine.serialize_tlv``, kept here so the
host tool has no import dependency on the card-present stack (which pulls in
pyscard and the PC/SC headers to build it).

The duplication is temporary and guarded: ``host/tests/test_tlv_parity.py``
runs both implementations over the same corpus and fails if they ever disagree.
When a second consumer justifies it, both sides collapse into a shared
``paycore.tlv`` and this module goes away.

Display concerns (the EMV_TAGS name table) are intentionally *not* copied — a
codec has no business knowing what a tag is called.
"""
from __future__ import annotations

import dataclasses


@dataclasses.dataclass
class TLVNode:
    tag: str                  # uppercase hex, e.g. "9F26"
    length: int
    value: bytes
    constructed: bool
    children: list["TLVNode"] = dataclasses.field(default_factory=list)

    def to_dict(self) -> dict:
        d: dict = {
            "tag":    self.tag,
            "length": self.length,
            "value":  self.value.hex().upper(),
        }
        if self.children:
            d["children"] = [c.to_dict() for c in self.children]
        return d


# ── Parsing ───────────────────────────────────────────────────────────────────

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

    Stops silently on malformed data rather than raising: a partially readable
    DE55 is still evidence, and one bad tag at the end should not cost you the
    twenty good ones in front of it.
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
            node = TLVNode(tag=tag, length=length, value=value,
                           constructed=constructed)
            if constructed and depth < 8:
                node.children = parse_tlv(value, depth + 1)
            nodes.append(node)
        except Exception:
            break
    return nodes


def maybe_parse_tlv(data: bytes) -> list[TLVNode]:
    """Try a TLV parse; return [] for anything that does not look like TLV."""
    if len(data) < 2 or data[0] in (0x00, 0xFF):
        return []
    return parse_tlv(data)


# ── Serialising ───────────────────────────────────────────────────────────────

def _serialize_tag(tag_hex: str) -> bytes:
    tag_hex = tag_hex.upper().replace(" ", "")
    if len(tag_hex) % 2:
        tag_hex = "0" + tag_hex
    return bytes.fromhex(tag_hex)


def _serialize_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length <= 0xFF:
        return bytes([0x81, length])
    if length <= 0xFFFF:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    raise ValueError(f"TLV length {length} too large to encode")


def serialize_tlv(nodes: list[TLVNode]) -> bytes:
    """Re-serialise a list of TLVNode objects back to BER-TLV bytes."""
    out = bytearray()
    for node in nodes:
        value_bytes = serialize_tlv(node.children) if node.children else bytes(node.value)
        out += _serialize_tag(node.tag)
        out += _serialize_length(len(value_bytes))
        out += value_bytes
    return bytes(out)


# ── Navigation ────────────────────────────────────────────────────────────────

def find_tag(nodes: list[TLVNode], tag: str) -> TLVNode | None:
    """Depth-first search for the first node carrying `tag`."""
    target = tag.upper()
    for node in nodes:
        if node.tag == target:
            return node
        hit = find_tag(node.children, target)
        if hit is not None:
            return hit
    return None
