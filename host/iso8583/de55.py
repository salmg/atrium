"""
DE55 ⇄ BER-TLV bridge.

Field 55 carries ICC data as BER-TLV — the same encoding a card emits on the
wire — so this module is deliberately thin.  It hands the bytes to the TLV core
and gets nodes back; every mutation primitive that works on a card response
works here unchanged.  That is the whole integration story between the two
halves of the toolkit.

The cross-checks at the bottom are the reason this layer is interesting.  A
gateway sees the same quantity twice — once as an ISO 8583 data element it
routes on, once inside DE55 where the cryptogram covers it — and anything that
trusts one while forwarding the other is a finding.
"""
from __future__ import annotations

import dataclasses

from host.iso8583.codec import Message
from host.iso8583.tlv import TLVNode, find_tag, parse_tlv, serialize_tlv

# EMV tags whose value is mirrored by an ISO 8583 data element.
TAG_AMOUNT_AUTHORISED = "9F02"
TAG_TRANSACTION_CURRENCY = "5F2A"
TAG_ATC = "9F36"
TAG_CRYPTOGRAM = "9F26"
TAG_CID = "9F27"
TAG_CVM_RESULTS = "9F34"
TAG_TVR = "95"

DE_AMOUNT = 4
DE_CURRENCY = 49
DE_ICC_DATA = 55


def parse(raw: bytes | str) -> list[TLVNode]:
    """Parse a DE55 value into TLV nodes. Accepts raw bytes or a hex string."""
    if isinstance(raw, str):
        raw = bytes.fromhex(raw.strip().replace(" ", ""))
    return parse_tlv(raw)


def serialize(nodes: list[TLVNode]) -> bytes:
    return serialize_tlv(nodes)


def from_message(msg: Message) -> list[TLVNode]:
    """Pull DE55 out of a decoded message and parse it. [] when absent."""
    raw = msg.fields.get(DE_ICC_DATA)
    if raw is None:
        return []
    return parse(raw)


def tag_value(nodes: list[TLVNode], tag: str) -> str:
    """Hex value of a tag, or "" when it is not present."""
    node = find_tag(nodes, tag)
    return node.value.hex().upper() if node else ""


def set_tag(nodes: list[TLVNode], tag: str, value: bytes | str) -> bool:
    """
    Replace a tag's value in place. Returns False when the tag is absent.

    Length is recomputed from the new value, so a shorter or longer replacement
    re-serialises correctly.
    """
    if isinstance(value, str):
        value = bytes.fromhex(value.strip().replace(" ", ""))
    node = find_tag(nodes, tag)
    if node is None:
        return False
    node.value = value
    node.length = len(value)
    return True


def remove_tag(nodes: list[TLVNode], tag: str) -> bool:
    """
    Delete a tag wherever it sits in the tree. Returns False when absent.

    Recurses into constructed nodes because the interesting tags often live
    inside a template rather than at the top level.
    """
    target = tag.upper()
    for i, node in enumerate(nodes):
        if node.tag == target:
            nodes.pop(i)
            return True
        if node.children and remove_tag(node.children, target):
            return True
    return False


# ── Cross-layer consistency ───────────────────────────────────────────────────

@dataclasses.dataclass
class Discrepancy:
    """One place where the 8583 layer and DE55 disagree."""
    what: str
    de_number: int
    de_value: str
    tag: str
    tag_value: str

    def __str__(self) -> str:
        return (f"{self.what}: DE{self.de_number}={self.de_value} but "
                f"tag {self.tag}={self.tag_value}")


def _normalise_amount(value: str) -> str:
    return value.lstrip("0") or "0"


def cross_check(msg: Message, nodes: list[TLVNode] | None = None) -> list[Discrepancy]:
    """
    Compare the quantities that appear both as data elements and inside DE55.

    A mismatch is not automatically a vulnerability — it is the signal worth
    chasing, because the cryptogram covers the DE55 copy while the switch
    routes and authorises on the data element.  Whichever side a downstream
    system trusts, disagreeing copies mean somebody is deciding on numbers the
    cardholder never approved.
    """
    nodes = from_message(msg) if nodes is None else nodes
    if not nodes:
        return []

    found: list[Discrepancy] = []

    amount_de = msg.fields.get(DE_AMOUNT)
    amount_tag = tag_value(nodes, TAG_AMOUNT_AUTHORISED)
    if isinstance(amount_de, str) and amount_tag:
        if _normalise_amount(amount_de) != _normalise_amount(amount_tag):
            found.append(Discrepancy(
                what="amount mismatch", de_number=DE_AMOUNT, de_value=amount_de,
                tag=TAG_AMOUNT_AUTHORISED, tag_value=amount_tag,
            ))

    currency_de = msg.fields.get(DE_CURRENCY)
    currency_tag = tag_value(nodes, TAG_TRANSACTION_CURRENCY)
    if isinstance(currency_de, str) and currency_tag:
        if currency_de.lstrip("0") != currency_tag.lstrip("0"):
            found.append(Discrepancy(
                what="currency mismatch", de_number=DE_CURRENCY,
                de_value=currency_de, tag=TAG_TRANSACTION_CURRENCY,
                tag_value=currency_tag,
            ))

    return found


def summary(nodes: list[TLVNode]) -> dict[str, str]:
    """The authorisation-relevant tags, for logging a captured message."""
    return {
        tag: tag_value(nodes, tag)
        for tag in (TAG_CRYPTOGRAM, TAG_CID, TAG_ATC, TAG_CVM_RESULTS,
                    TAG_TVR, TAG_AMOUNT_AUTHORISED, TAG_TRANSACTION_CURRENCY)
        if tag_value(nodes, tag)
    }
