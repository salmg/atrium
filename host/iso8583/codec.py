"""
Generic ISO 8583 pack / unpack, driven entirely by a Dialect.

There is no dialect-specific code in this module — every deployment difference
lives in the YAML.  Adding support for a new switch should mean writing a
dialect file, never editing this.

Degrade, never crash
--------------------
``unpack`` records a problem and stops rather than raising when a field will
not decode.  Pointed at an unknown dialect that is close but not exact, a
message decoded up to field 43 is real evidence; an exception is not.  Callers
check ``Message.problems``.  This mirrors ``maybe_parse_tlv`` on the card side,
which tries a TLV parse and falls back to raw rather than failing the capture.
"""
from __future__ import annotations

import dataclasses

from host.iso8583.dialect import Dialect, FieldSpec
from host.iso8583.framing import Framing

# EBCDIC: cp500 is the common flavour on the mainframe hosts that still use it.
_EBCDIC = "cp500"


class CodecError(ValueError):
    """A message cannot be encoded or decoded under this dialect."""


@dataclasses.dataclass
class Message:
    """One ISO 8583 message. Values are str for n/an/ans/z, bytes for b."""
    mti: str = ""
    fields: dict[int, str | bytes] = dataclasses.field(default_factory=dict)
    tpdu: bytes = b""
    problems: list[str] = dataclasses.field(default_factory=list)
    trailing: bytes = b""          # bytes left over after the last field

    @property
    def complete(self) -> bool:
        """True when every byte was accounted for and nothing failed to parse."""
        return not self.problems and not self.trailing

    def get(self, number: int, default=None):
        return self.fields.get(number, default)

    def to_dict(self) -> dict:
        return {
            "mti": self.mti,
            "tpdu": self.tpdu.hex().upper() or None,
            "fields": {
                n: (v.hex().upper() if isinstance(v, (bytes, bytearray)) else v)
                for n, v in sorted(self.fields.items())
            },
            "problems": list(self.problems),
            "trailing": self.trailing.hex().upper() or None,
        }


# ── Primitive codecs ──────────────────────────────────────────────────────────

def _text_encode(value: str, body_encoding: str) -> bytes:
    codec = _EBCDIC if body_encoding == "ebcdic" else "ascii"
    try:
        return value.encode(codec)
    except UnicodeEncodeError as exc:
        raise CodecError(f"{value!r} is not encodable as {codec}") from exc


def _text_decode(raw: bytes, body_encoding: str) -> str:
    codec = _EBCDIC if body_encoding == "ebcdic" else "ascii"
    return raw.decode(codec, errors="replace")


def _bcd_encode(digits: str, pad: str) -> bytes:
    """
    Pack digits two-per-byte.

    Odd counts pad per the field's convention: quantities pad left with zero,
    left-justified strings (PAN, track 2) pad right with 0xF.
    """
    if len(digits) % 2:
        digits = ("0" + digits) if pad == "left_zero" else (digits + "F")
    try:
        return bytes.fromhex(digits)
    except ValueError as exc:
        raise CodecError(f"{digits!r} is not BCD-encodable") from exc


def _bcd_decode(raw: bytes, digits: int, pad: str) -> str:
    text = raw.hex().upper()
    if digits and len(text) > digits:
        # Drop the pad nibble from whichever end it was added to.
        text = text[-digits:] if pad == "left_zero" else text[:digits]
    return text


def _numeric_byte_length(digits: int, encoding: str) -> int:
    return (digits + 1) // 2 if encoding == "bcd" else digits


def _pack_value(spec: FieldSpec, dialect: Dialect, value: str | bytes) -> bytes:
    if spec.type == "b":
        if isinstance(value, str):
            try:
                value = bytes.fromhex(value)
            except ValueError as exc:
                raise CodecError(
                    f"Field {spec.number} is binary; {value!r} is not hex"
                ) from exc
        return bytes(value)

    if isinstance(value, (bytes, bytearray)):
        raise CodecError(f"Field {spec.number} is {spec.type}, got raw bytes")

    if spec.type in ("n", "z"):
        encoding = dialect.encoding_for(spec)
        if encoding == "bcd":
            digits = value if spec.is_variable else value.rjust(spec.length, "0")
            return _bcd_encode(digits, spec.pad_mode)
        return _text_encode(value if spec.is_variable else value.rjust(spec.length, "0"),
                            dialect.body_encoding)

    text = value if spec.is_variable else value.ljust(spec.length)[: spec.length]
    return _text_encode(text, dialect.body_encoding)


def _unpack_value(spec: FieldSpec, dialect: Dialect, raw: bytes,
                  declared: int) -> str | bytes:
    if spec.type == "b":
        return raw
    if spec.type in ("n", "z") and dialect.encoding_for(spec) == "bcd":
        return _bcd_decode(raw, declared, spec.pad_mode)
    return _text_decode(raw, dialect.body_encoding)


def _pack_length_prefix(spec: FieldSpec, dialect: Dialect, count: int) -> bytes:
    digits = str(count).rjust(spec.length_digits, "0")
    if len(digits) > spec.length_digits:
        raise CodecError(
            f"Field {spec.number}: length {count} exceeds "
            f"{spec.length_digits}-digit prefix"
        )
    if dialect.length_encoding_for(spec) == "bcd":
        return _bcd_encode(digits, "left_zero")
    return _text_encode(digits, dialect.body_encoding)


def _length_prefix_size(spec: FieldSpec, dialect: Dialect) -> int:
    if dialect.length_encoding_for(spec) == "bcd":
        return (spec.length_digits + 1) // 2
    return spec.length_digits


# ── Bitmap ────────────────────────────────────────────────────────────────────

def build_bitmap(field_numbers) -> bytes:
    """Binary bitmap covering fields 2-128. Bit 1 flags a secondary bitmap."""
    present = {n for n in field_numbers if n >= 2}
    secondary = any(n > 64 for n in present)
    size = 16 if secondary else 8
    bits = bytearray(size)
    if secondary:
        bits[0] |= 0x80
    for n in present:
        if n > size * 8:
            raise CodecError(f"Field {n} is beyond the bitmap this message carries")
        index = n - 1
        bits[index // 8] |= 0x80 >> (index % 8)
    return bytes(bits)


def read_bitmap(raw: bytes) -> list[int]:
    """Field numbers flagged in a bitmap. Field 1 (the indicator) is excluded."""
    present = []
    for index in range(len(raw) * 8):
        if raw[index // 8] & (0x80 >> (index % 8)):
            present.append(index + 1)
    return [n for n in present if n != 1]


# ── Message codec ─────────────────────────────────────────────────────────────

def pack_body(dialect: Dialect, msg: Message) -> bytes:
    """Encode MTI + bitmap + fields (no MLI, no TPDU)."""
    if len(msg.mti) != 4 or not msg.mti.isdigit():
        raise CodecError(f"MTI must be four digits, got {msg.mti!r}")

    out = bytearray()
    if dialect.mti_encoding == "bcd":
        out += _bcd_encode(msg.mti, "left_zero")
    else:
        out += _text_encode(msg.mti, dialect.body_encoding)

    bitmap = build_bitmap(msg.fields)
    out += bitmap.hex().upper().encode("ascii") if dialect.bitmap_encoding == "hex" else bitmap

    for number in sorted(n for n in msg.fields if n >= 2):
        spec = dialect.field(number)
        if spec is None:
            raise CodecError(f"Dialect {dialect.name!r} has no definition for field {number}")
        encoded = _pack_value(spec, dialect, msg.fields[number])

        if spec.is_variable:
            # The prefix counts digits/characters for text types but bytes for
            # binary ones — the classic ISO 8583 foot-gun.
            value = msg.fields[number]
            count = len(encoded) if spec.type == "b" else len(
                value if isinstance(value, str) else value.hex()
            )
            if spec.max and count > spec.max:
                raise CodecError(
                    f"Field {number}: {count} exceeds the dialect maximum {spec.max}"
                )
            out += _pack_length_prefix(spec, dialect, count)
        out += encoded

    return bytes(out)


def pack(dialect: Dialect, msg: Message, framing: Framing | None = None) -> bytes:
    """Encode a full framed message: MLI + TPDU + body."""
    framing = framing or dialect.framing
    body = framing.join_tpdu(msg.tpdu, pack_body(dialect, msg))
    return framing.wrap(body)


def unpack_body(dialect: Dialect, body: bytes) -> Message:
    """Decode MTI + bitmap + fields from an unframed message body."""
    msg = Message()
    pos = 0

    mti_size = 2 if dialect.mti_encoding == "bcd" else 4
    if len(body) < mti_size:
        msg.problems.append("message too short to hold an MTI")
        return msg
    if dialect.mti_encoding == "bcd":
        msg.mti = body[:mti_size].hex().upper()
    else:
        msg.mti = _text_decode(body[:mti_size], dialect.body_encoding)
    pos += mti_size

    if not (len(msg.mti) == 4 and msg.mti.isdigit()):
        msg.problems.append(f"MTI {msg.mti!r} is not four digits")
        return msg

    # Primary bitmap, then the secondary one if bit 1 says so.
    unit = 16 if dialect.bitmap_encoding == "hex" else 8

    def _bitmap_at(offset: int) -> bytes | None:
        chunk = body[offset: offset + unit]
        if len(chunk) < unit:
            return None
        if dialect.bitmap_encoding != "hex":
            return chunk
        try:
            return bytes.fromhex(chunk.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            return None

    primary = _bitmap_at(pos)
    if primary is None:
        msg.problems.append("truncated or unreadable primary bitmap")
        return msg
    pos += unit

    bitmap = primary
    if primary[0] & 0x80:
        secondary = _bitmap_at(pos)
        if secondary is None:
            msg.problems.append("secondary bitmap flagged but truncated")
            return msg
        bitmap += secondary
        pos += unit

    for number in read_bitmap(bitmap):
        spec = dialect.field(number)
        if spec is None:
            msg.problems.append(
                f"field {number} is set in the bitmap but undefined in dialect "
                f"{dialect.name!r} — cannot find where it ends"
            )
            break

        if spec.is_variable:
            prefix_size = _length_prefix_size(spec, dialect)
            prefix = body[pos: pos + prefix_size]
            if len(prefix) < prefix_size:
                msg.problems.append(f"field {number}: truncated length prefix")
                break
            pos += prefix_size
            if dialect.length_encoding_for(spec) == "bcd":
                text = prefix.hex()
            else:
                text = _text_decode(prefix, dialect.body_encoding)
            if not text.isdigit():
                msg.problems.append(f"field {number}: length prefix {text!r} is not numeric")
                break
            declared = int(text)
            if spec.max and declared > spec.max:
                msg.problems.append(
                    f"field {number}: declared length {declared} exceeds maximum {spec.max}"
                )
                break
            size = (declared if spec.type == "b"
                    else _numeric_byte_length(declared, dialect.encoding_for(spec))
                    if spec.type in ("n", "z") else declared)
        else:
            declared = spec.length
            size = (spec.length if spec.type in ("b", "an", "ans")
                    else _numeric_byte_length(spec.length, dialect.encoding_for(spec)))

        raw = body[pos: pos + size]
        if len(raw) < size:
            msg.problems.append(
                f"field {number}: needs {size} bytes, only {len(raw)} left"
            )
            break
        pos += size
        try:
            msg.fields[number] = _unpack_value(spec, dialect, raw, declared)
        except CodecError as exc:
            msg.problems.append(f"field {number}: {exc}")
            break

    msg.trailing = body[pos:]
    return msg


def unpack(dialect: Dialect, buf: bytes,
           framing: Framing | None = None) -> tuple[Message, int]:
    """
    Decode the first framed message in a stream buffer.

    Returns (message, bytes_consumed) so a reader can advance its buffer.
    Raises IncompleteMessage when more bytes are needed.
    """
    framing = framing or dialect.framing
    body, consumed = framing.unwrap(buf)
    tpdu, rest = framing.split_tpdu(body)
    msg = unpack_body(dialect, rest)
    msg.tpdu = tpdu
    return msg, consumed
