"""
ISO 8583 codec — dialect-driven, with no dialect-specific code.

    from host.iso8583 import load_dialect, Message, pack, unpack, detect

    dialect = load_dialect("iso8583-1987")
    msg = Message(mti="0100", fields={2: "4111111111111111", 4: "000000001000"})
    wire = pack(dialect, msg)
    back, consumed = unpack(dialect, wire)
"""
from host.iso8583.codec import CodecError, Message, pack, pack_body, unpack, unpack_body
from host.iso8583.detect import Candidate, describe, detect
from host.iso8583.dialect import (
    Dialect,
    DialectError,
    FieldSpec,
    available_dialects,
    load_dialect,
)
from host.iso8583.framing import Framing, FramingError, IncompleteMessage

__all__ = [
    "Candidate", "CodecError", "Dialect", "DialectError", "FieldSpec",
    "Framing", "FramingError", "IncompleteMessage", "Message",
    "available_dialects", "describe", "detect", "load_dialect",
    "pack", "pack_body", "unpack", "unpack_body",
]
