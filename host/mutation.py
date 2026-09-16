"""
Mutation engine for host messages.

The card side gates mutations on the command being executed (``on_ins``); here
the equivalents are the message type and the direction of travel, because those
are what identify a moment in a host conversation.  Everything else carries
over deliberately unchanged — the same six modes, the same playbook shape, the
same "spec objects loaded from YAML" structure — so what an operator learns on
one half of the toolkit applies to the other.

Two kinds of target:

* **Data elements** (``field_mutations``) — DE4, DE22, DE39 and friends.
* **DE55 tags** (``de55_mutations``) — BER-TLV inside field 55, handled by the
  same TLV core ATRIUM uses on card responses.

Safety rules, which matter more here than the features
------------------------------------------------------
Mutation means giving up phase 2's byte-exactness guarantee: a mutated message
has to be re-encoded from the decoded form, so a codec bug can now corrupt a
live link.  Three rules keep the blast radius to messages that were actually
targeted:

1. **A message that did not decode cleanly is never mutated.**  Problems or
   trailing bytes mean the dialect is not a perfect fit, and re-encoding would
   silently drop whatever was not understood.
2. **A message no rule touched is forwarded verbatim**, never round-tripped.
   Untargeted traffic keeps the phase 2 guarantee in full.
3. **A re-encode that fails forwards the original** and says so loudly.  A
   failed mutation is a bad experiment; a broken link is a bad afternoon.
"""
from __future__ import annotations

import dataclasses
import logging
from pathlib import Path

from host.iso8583 import de55 as de55_mod
from host.iso8583.codec import CodecError, Message, pack_body
from host.iso8583.dialect import Dialect

log = logging.getLogger(__name__)

PLAYBOOK_DIR = Path(__file__).parent / "playbooks"

# Same vocabulary as the card side, so playbook knowledge transfers.
MUTATION_MODES = frozenset({
    "replace",    # overwrite the value
    "delete",     # remove the field or tag entirely
    "xor",        # XOR the original bytes with value (zero-padded)
    "flip_bit",   # flip one bit; bit_position is 0-based from the MSB
    "prepend",    # value + original
    "append",     # original + value
})

# XOR and bit-flipping are byte operations. On a text field there is no honest
# answer to "which bytes" — the ASCII, the BCD packing, or the digits — so they
# are refused there rather than guessed at.
BINARY_ONLY_MODES = frozenset({"xor", "flip_bit"})

ACQUIRER_TO_ISSUER = "acquirer->issuer"
ISSUER_TO_ACQUIRER = "issuer->acquirer"
BOTH = "both"
DIRECTIONS = (ACQUIRER_TO_ISSUER, ISSUER_TO_ACQUIRER, BOTH)


class MutationError(ValueError):
    """A playbook is unusable, or a mutation cannot be applied. User-facing."""


# ── Value arithmetic ──────────────────────────────────────────────────────────

def _hex_to_bytes(value: str, what: str) -> bytes:
    try:
        return bytes.fromhex(value.strip().replace(" ", ""))
    except ValueError as exc:
        raise MutationError(f"{what}: {value!r} is not hex") from exc


def compute_bytes(mode: str, original: bytes, value: bytes,
                  bit_position: int = 0) -> bytes | None:
    """Apply one mode to a byte value. None means 'delete'."""
    if mode == "delete":
        return None
    if mode == "replace":
        return value
    if mode == "prepend":
        return value + original
    if mode == "append":
        return original + value
    if mode == "xor":
        if not value:
            return original
        padded = value.ljust(len(original), b"\x00")[: len(original)]
        return bytes(a ^ b for a, b in zip(original, padded))
    if mode == "flip_bit":
        if not original:
            return original
        index, offset = divmod(bit_position, 8)
        if index >= len(original):
            raise MutationError(
                f"bit {bit_position} is past the end of a {len(original)}-byte value"
            )
        out = bytearray(original)
        out[index] ^= 0x80 >> offset
        return bytes(out)
    raise MutationError(f"Unknown mutation mode {mode!r}")


def compute_text(mode: str, original: str, value: str) -> str | None:
    if mode == "delete":
        return None
    if mode == "replace":
        return value
    if mode == "prepend":
        return value + original
    if mode == "append":
        return original + value
    raise MutationError(
        f"Mode {mode!r} needs a binary field; {'/'.join(sorted(BINARY_ONLY_MODES))} "
        "cannot be applied to a text or numeric data element."
    )


# ── Specs ─────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class _BaseMutation:
    mode: str
    value: str = ""
    bit_position: int = 0
    enabled: bool = True
    comment: str = ""
    direction: str = BOTH
    on_mti: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        self.mode = self.mode.lower().strip()
        if self.mode not in MUTATION_MODES:
            raise MutationError(
                f"Unknown mutation mode {self.mode!r}; valid: "
                + ", ".join(sorted(MUTATION_MODES))
            )
        self.direction = self.direction.lower().strip()
        if self.direction not in DIRECTIONS:
            raise MutationError(
                f"Unknown direction {self.direction!r}; valid: " + ", ".join(DIRECTIONS)
            )
        self.on_mti = tuple(str(m).strip() for m in self.on_mti if str(m).strip())
        if self.mode in ("replace", "prepend", "append", "xor") and not self.value:
            raise MutationError(f"Mode {self.mode!r} needs a 'value'")

    def applies_to(self, mti: str, direction: str) -> bool:
        if not self.enabled:
            return False
        if self.direction != BOTH and self.direction != direction:
            return False
        return not self.on_mti or mti in self.on_mti


@dataclasses.dataclass
class FieldMutation(_BaseMutation):
    """Mutate one ISO 8583 data element."""
    de: int = 0

    def __post_init__(self) -> None:
        super().__post_init__()
        if not 2 <= self.de <= 192:
            raise MutationError(f"Data element {self.de} is out of range 2-192")

    @property
    def target(self) -> str:
        return f"DE{self.de}"

    @classmethod
    def from_dict(cls, d: dict) -> "FieldMutation":
        return cls(
            de=int(d.get("de", 0)),
            mode=str(d.get("mode", "")),
            value=str(d.get("value", "")),
            bit_position=int(d.get("bit_position", 0)),
            enabled=bool(d.get("enabled", True)),
            comment=str(d.get("comment", "")),
            direction=str(d.get("direction", BOTH)),
            on_mti=tuple(d.get("on_mti", ()) or ()),
        )


@dataclasses.dataclass
class De55Mutation(_BaseMutation):
    """Mutate one BER-TLV tag inside DE55."""
    tag: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        self.tag = self.tag.upper().strip().replace(" ", "")
        if not self.tag:
            raise MutationError("A DE55 mutation needs a 'tag'")
        try:
            bytes.fromhex(self.tag if len(self.tag) % 2 == 0 else "0" + self.tag)
        except ValueError as exc:
            raise MutationError(f"Tag {self.tag!r} is not hex") from exc

    @property
    def target(self) -> str:
        return f"DE55/{self.tag}"

    @classmethod
    def from_dict(cls, d: dict) -> "De55Mutation":
        return cls(
            tag=str(d.get("tag", "")),
            mode=str(d.get("mode", "")),
            value=str(d.get("value", "")),
            bit_position=int(d.get("bit_position", 0)),
            enabled=bool(d.get("enabled", True)),
            comment=str(d.get("comment", "")),
            direction=str(d.get("direction", BOTH)),
            on_mti=tuple(d.get("on_mti", ()) or ()),
        )


@dataclasses.dataclass
class MutationRecord:
    """What one applied rule actually changed."""
    target: str
    mode: str
    before: str
    after: str
    comment: str = ""

    def __str__(self) -> str:
        arrow = f"{self.before or '(absent)'} -> {self.after or '(deleted)'}"
        return f"{self.target} {self.mode}: {arrow}"

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# ── Playbook ──────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class Playbook:
    name: str
    description: str = ""
    enabled: bool = True
    field_mutations: tuple[FieldMutation, ...] = ()
    de55_mutations: tuple[De55Mutation, ...] = ()

    @property
    def active(self) -> bool:
        """True when this playbook could actually change something."""
        if not self.enabled:
            return False
        return any(m.enabled for m in (*self.field_mutations, *self.de55_mutations))

    def summary(self) -> str:
        rules = [m for m in (*self.field_mutations, *self.de55_mutations) if m.enabled]
        lines = [f"{self.name} — {len(rules)} active rule(s)"]
        if self.description:
            lines.append(f"  {self.description.strip()}")
        for rule in rules:
            where = ",".join(rule.on_mti) or "any MTI"
            lines.append(f"  {rule.target:<12} {rule.mode:<9} {where:<12} {rule.direction}")
            if rule.comment:
                lines.append(f"      {rule.comment}")
        return "\n".join(lines)

    @classmethod
    def from_dict(cls, d: dict, name: str = "") -> "Playbook":
        if not isinstance(d, dict):
            raise MutationError(f"Playbook {name or '?'} is not a YAML mapping")
        try:
            fields = tuple(FieldMutation.from_dict(x) for x in (d.get("field_mutations") or ()))
            tags = tuple(De55Mutation.from_dict(x) for x in (d.get("de55_mutations") or ()))
        except (TypeError, AttributeError) as exc:
            raise MutationError(f"Playbook {name or '?'}: malformed rule list — {exc}") from exc
        if not fields and not tags:
            raise MutationError(
                f"Playbook {name or d.get('name', '?')} defines no mutations. "
                "Add field_mutations or de55_mutations, or do not load it at all."
            )
        return cls(
            name=str(d.get("name", name or "unnamed")),
            description=str(d.get("description", "")),
            enabled=bool(d.get("enabled", True)),
            field_mutations=fields,
            de55_mutations=tags,
        )


def load_playbook(name_or_path: str, directory: Path | None = None) -> Playbook:
    """Load a playbook by name from the playbook directory, or by explicit path."""
    import yaml

    candidate = Path(name_or_path)
    if candidate.suffix in (".yaml", ".yml") and candidate.is_file():
        path = candidate
    else:
        directory = Path(directory or PLAYBOOK_DIR)
        path = directory / f"{Path(name_or_path).stem}.yaml"
        if not path.is_file():
            available = ", ".join(available_playbooks(directory)) or "none"
            raise MutationError(
                f"No playbook named {name_or_path!r}. Available: {available}"
            )
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        raise MutationError(f"Cannot read playbook {path.name}: {exc}") from exc
    return Playbook.from_dict(raw, name=path.stem)


def available_playbooks(directory: Path | None = None) -> list[str]:
    directory = Path(directory or PLAYBOOK_DIR)
    if not directory.is_dir():
        return []
    return sorted(p.stem for p in directory.glob("*.yaml"))


# ── Engine ────────────────────────────────────────────────────────────────────

def _apply_field(msg: Message, dialect: Dialect, rule: FieldMutation,
                 records: list[MutationRecord]) -> None:
    spec = dialect.field(rule.de)
    if spec is None:
        raise MutationError(
            f"Dialect {dialect.name!r} has no definition for DE{rule.de}, so a "
            "mutated message could not be re-encoded."
        )

    current = msg.fields.get(rule.de)
    absent = current is None

    if absent and rule.mode != "replace":
        # Nothing to xor, append to or delete. Only an outright replace can
        # meaningfully invent a field that was not there.
        raise MutationError(
            f"DE{rule.de} is not present in this message, so {rule.mode!r} has "
            "nothing to act on. Use 'replace' to add it."
        )

    if isinstance(current, (bytes, bytearray)) or (absent and spec.type == "b"):
        original = bytes(current or b"")
        value = _hex_to_bytes(rule.value, rule.target) if rule.value else b""
        result = compute_bytes(rule.mode, original, value, rule.bit_position)
        before, after = original.hex().upper(), ("" if result is None else result.hex().upper())
    else:
        original = str(current or "")
        result = compute_text(rule.mode, original, rule.value)
        before, after = original, ("" if result is None else result)

    if result is None:
        msg.fields.pop(rule.de, None)
    else:
        msg.fields[rule.de] = result

    records.append(MutationRecord(target=rule.target, mode=rule.mode,
                                  before=before, after=after, comment=rule.comment))


def _apply_de55(msg: Message, rule: De55Mutation,
                records: list[MutationRecord]) -> None:
    nodes = de55_mod.from_message(msg)
    if not nodes:
        raise MutationError(
            f"This message carries no readable DE55, so {rule.target} has "
            "nothing to act on."
        )

    node = None
    from host.iso8583.tlv import find_tag
    node = find_tag(nodes, rule.tag)

    if node is None and rule.mode != "replace":
        raise MutationError(
            f"Tag {rule.tag} is not present in DE55, so {rule.mode!r} has "
            "nothing to act on. Use 'replace' to add it."
        )

    original = bytes(node.value) if node is not None else b""
    value = _hex_to_bytes(rule.value, rule.target) if rule.value else b""
    result = compute_bytes(rule.mode, original, value, rule.bit_position)

    if result is None:
        de55_mod.remove_tag(nodes, rule.tag)
    elif node is not None:
        node.value = result
        node.length = len(result)
    else:
        from host.iso8583.tlv import TLVNode
        nodes.append(TLVNode(tag=rule.tag, length=len(result),
                             value=result, constructed=False))

    msg.fields[de55_mod.DE_ICC_DATA] = de55_mod.serialize(nodes)
    records.append(MutationRecord(
        target=rule.target, mode=rule.mode,
        before=original.hex().upper(),
        after="" if result is None else result.hex().upper(),
        comment=rule.comment,
    ))


def apply_playbook(playbook: Playbook, dialect: Dialect, msg: Message,
                   direction: str) -> tuple[Message, list[MutationRecord]]:
    """
    Apply every matching rule to a copy of `msg`.

    Returns (mutated_message, records).  An empty record list means nothing
    matched and the caller should forward the original bytes untouched rather
    than re-encode an identical message.
    """
    if not playbook.active:
        return msg, []

    working = Message(mti=msg.mti, fields=dict(msg.fields), tpdu=msg.tpdu)
    records: list[MutationRecord] = []

    for rule in playbook.field_mutations:
        if rule.applies_to(msg.mti, direction):
            _apply_field(working, dialect, rule, records)

    for rule in playbook.de55_mutations:
        if rule.applies_to(msg.mti, direction):
            _apply_de55(working, rule, records)

    return working, records


def mutate_wire(playbook: Playbook, dialect: Dialect, msg: Message,
                direction: str, framing) -> tuple[bytes | None, list[MutationRecord], str]:
    """
    Produce replacement wire bytes for one message.

    Returns (raw_or_None, records, note).  ``None`` means "forward the original
    bytes" and is the answer whenever mutation would be unsafe or pointless:
    nothing matched, the message did not decode cleanly, or re-encoding failed.
    The note explains which, for the capture.
    """
    if not msg.complete:
        reason = "; ".join(msg.problems) or f"{len(msg.trailing)} trailing bytes"
        return None, [], (
            f"not mutated — message did not decode cleanly ({reason}); "
            "re-encoding would drop whatever was not understood"
        )

    try:
        mutated, records = apply_playbook(playbook, dialect, msg, direction)
    except MutationError as exc:
        return None, [], f"not mutated — {exc}"

    if not records:
        return None, [], ""

    try:
        body = pack_body(dialect, mutated)
        raw = framing.wrap(framing.join_tpdu(mutated.tpdu, body))
    except (CodecError, Exception) as exc:      # noqa: BLE001 — never break the link
        return None, records, f"mutation computed but re-encode failed ({exc}); original forwarded"

    return raw, records, ""
