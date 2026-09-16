"""
Dialect definitions — ISO 8583 as data rather than code.

"ISO 8583" names a family, not a protocol.  Deployments differ on at least
eight independent axes (framing, body character set, MTI encoding, bitmap
representation, numeric packing, length-prefix encoding, odd-digit padding and
the field table itself), and hard-coding any of them is what makes host tools
single-target and disposable.

So a dialect is a YAML file.  ``extends:`` keeps a new one to a short diff
against a base rather than a fresh 128-field table — most real dialects are
ISO 8583:1987 plus a handful of private-use fields.

Note on shipped dialects: the scheme specifications (Visa, Mastercard, Amex)
are confidential, and a reconstruction from public knowledge would be wrong in
ways you would only discover mid-engagement.  This ships the ISO base plus the
switch platforms whose layouts are documented in vendor material.  On a real
engagement the authoritative interface spec comes from the target's owner —
which is exactly why dialects are user-authorable content and not constants.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

from host.iso8583.framing import Framing

DIALECT_DIR = Path(__file__).parent.parent / "dialects"

FIELD_TYPES = ("n", "an", "ans", "b", "z")
VARIABLE_LENGTHS = {"llvar": 2, "lllvar": 3, "llllvar": 4}
PAD_MODES = ("left_zero", "right_f")


class DialectError(ValueError):
    """A dialect file is unusable. Message is user-facing."""


@dataclasses.dataclass(frozen=True)
class FieldSpec:
    """How one data element is encoded on the wire."""
    number: int
    name: str
    type: str                       # n | an | ans | b | z
    length: int | str               # int = fixed, or llvar / lllvar / llllvar
    max: int = 0                    # cap for variable-length fields
    encoding: str = ""              # bcd | ascii — numerics only; "" = dialect default
    length_encoding: str = ""       # bcd | ascii — length prefix; "" = dialect default
    pad: str = ""                   # left_zero | right_f; "" = derived from length
    codec: str = ""                 # "" | ber_tlv

    @property
    def is_variable(self) -> bool:
        return isinstance(self.length, str)

    @property
    def length_digits(self) -> int:
        """How many digits the length prefix carries (variable fields only)."""
        return VARIABLE_LENGTHS[self.length] if self.is_variable else 0

    @property
    def pad_mode(self) -> str:
        """
        Odd-digit padding for packed BCD.

        Fixed numerics are right-justified quantities, so they pad on the left
        with zero.  Variable fields (PAN, track 2) are left-justified strings of
        digits, so they pad on the right with 0xF — the convention every switch
        expects for an odd-length PAN.
        """
        if self.pad:
            return self.pad
        return "right_f" if self.is_variable else "left_zero"

    def __post_init__(self) -> None:
        if self.type not in FIELD_TYPES:
            raise DialectError(
                f"Field {self.number}: unknown type {self.type!r}; "
                f"valid: {', '.join(FIELD_TYPES)}"
            )
        if isinstance(self.length, str):
            if self.length not in VARIABLE_LENGTHS:
                raise DialectError(
                    f"Field {self.number}: unknown length {self.length!r}; "
                    f"use an integer or {'/'.join(VARIABLE_LENGTHS)}"
                )
            if self.max <= 0:
                raise DialectError(
                    f"Field {self.number}: variable-length fields need a 'max'"
                )
        elif self.length <= 0:
            raise DialectError(f"Field {self.number}: length must be positive")
        if self.pad and self.pad not in PAD_MODES:
            raise DialectError(
                f"Field {self.number}: unknown pad {self.pad!r}; "
                f"valid: {', '.join(PAD_MODES)}"
            )

    @classmethod
    def from_dict(cls, number: int, d: dict) -> "FieldSpec":
        length = d.get("length")
        if isinstance(length, str) and length.isdigit():
            length = int(length)
        return cls(
            number=number,
            name=str(d.get("name", f"DE{number}")),
            type=str(d.get("type", "ans")).lower(),
            length=length if isinstance(length, int) else str(length).lower(),
            max=int(d.get("max", 0)),
            encoding=str(d.get("encoding", "")).lower(),
            length_encoding=str(d.get("length_encoding", "")).lower(),
            pad=str(d.get("pad", "")).lower(),
            codec=str(d.get("codec", "")).lower(),
        )


@dataclasses.dataclass(frozen=True)
class Dialect:
    name: str
    framing: Framing
    fields: dict[int, FieldSpec]
    body_encoding: str = "ascii"        # ascii | ebcdic
    mti_encoding: str = "ascii"         # ascii | bcd
    bitmap_encoding: str = "binary"     # binary | hex
    numeric_encoding: str = "bcd"       # default for type-n fields
    length_encoding: str = "bcd"        # default for variable-length prefixes

    def field(self, number: int) -> FieldSpec | None:
        return self.fields.get(number)

    def encoding_for(self, spec: FieldSpec) -> str:
        return spec.encoding or self.numeric_encoding

    def length_encoding_for(self, spec: FieldSpec) -> str:
        return spec.length_encoding or self.length_encoding


# ── Loading ───────────────────────────────────────────────────────────────────

def _read_yaml(path: Path) -> dict:
    import yaml
    try:
        data = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        raise DialectError(f"Cannot read dialect {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise DialectError(f"Dialect {path.name} is not a YAML mapping")
    return data


def _resolve(name: str, directory: Path, seen: tuple[str, ...] = ()) -> dict:
    """Load a dialect file and fold in whatever it extends, base first."""
    if name in seen:
        raise DialectError(
            "Dialect inheritance loops: " + " -> ".join([*seen, name])
        )
    path = directory / f"{name}.yaml"
    if not path.is_file():
        available = ", ".join(sorted(p.stem for p in directory.glob("*.yaml"))) or "none"
        raise DialectError(f"No dialect named {name!r}. Available: {available}")

    raw = _read_yaml(path)
    parent_name = raw.get("extends")
    if not parent_name:
        return raw

    merged = _resolve(str(parent_name), directory, (*seen, name))
    # Scalars override wholesale; the field table merges per field number so a
    # child can redefine DE 62 without restating the other hundred.
    for key, value in raw.items():
        if key == "extends":
            continue
        if key == "fields" and isinstance(value, dict):
            fields = dict(merged.get("fields") or {})
            fields.update(value)
            merged["fields"] = fields
        elif key == "framing" and isinstance(value, dict):
            framing = dict(merged.get("framing") or {})
            for sub, subval in value.items():
                if isinstance(subval, dict):
                    inner = dict(framing.get(sub) or {})
                    inner.update(subval)
                    framing[sub] = inner
                else:
                    framing[sub] = subval
            merged["framing"] = framing
        else:
            merged[key] = value
    return merged


def load_dialect(name: str, directory: Path | None = None) -> Dialect:
    """Load a dialect by name from the dialect directory."""
    directory = directory or DIALECT_DIR
    raw = _resolve(name, Path(directory))

    raw_fields = raw.get("fields") or {}
    if not raw_fields:
        raise DialectError(f"Dialect {name!r} defines no fields")

    fields: dict[int, FieldSpec] = {}
    for key, value in raw_fields.items():
        try:
            number = int(key)
        except (TypeError, ValueError):
            raise DialectError(f"Dialect {name!r}: field key {key!r} is not a number")
        if not 1 <= number <= 192:
            raise DialectError(f"Dialect {name!r}: field {number} out of range 1-192")
        if not isinstance(value, dict):
            raise DialectError(f"Dialect {name!r}: field {number} is not a mapping")
        fields[number] = FieldSpec.from_dict(number, value)

    return Dialect(
        name=str(raw.get("name", name)),
        framing=Framing.from_dict(raw.get("framing")),
        fields=fields,
        body_encoding=str(raw.get("body_encoding", "ascii")).lower(),
        mti_encoding=str((raw.get("mti") or {}).get("encoding", "ascii")).lower(),
        bitmap_encoding=str((raw.get("bitmap") or {}).get("encoding", "binary")).lower(),
        numeric_encoding=str(raw.get("numeric_encoding", "bcd")).lower(),
        length_encoding=str(raw.get("length_encoding", "bcd")).lower(),
    )


def available_dialects(directory: Path | None = None) -> list[str]:
    directory = Path(directory or DIALECT_DIR)
    if not directory.is_dir():
        return []
    return sorted(p.stem for p in directory.glob("*.yaml"))
