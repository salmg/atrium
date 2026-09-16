"""
Application cryptograms — compute, verify, and answer them.

The MAC itself is fixed by EMV: ISO 9797-1 Algorithm 3 under a session key.
What varies between schemes is *which bytes get MACed*, and that is exactly the
part the scheme specifications keep confidential.

So the data build is a profile — an ordered list of EMV tags in a YAML file,
the same treatment dialects get for the same reason.  Ships the recommended
EMV Book 2 composition; a scheme CVN profile is a short file the operator
writes from the spec their client hands them.

The useful direction is verification, not generation
----------------------------------------------------
``verify`` answers "is the cryptogram in this captured message genuine?", which
closes the loop with phases 2-4: you already have captures, and this tells you
whether what is in them was really signed by the card it claims to come from.
It also tells you when your own key or profile is wrong, which is the far more
common outcome and worth distinguishing clearly.
"""
from __future__ import annotations

import dataclasses
import hmac
from pathlib import Path

from host.crypto.des import CryptoError, des3_encrypt, mac_iso9797_alg3, xor
from host.crypto.keys import CSK, derive_session_key
from host.iso8583 import de55 as de55_mod
from host.iso8583.codec import Message
from host.iso8583.tlv import TLVNode, find_tag

PROFILE_DIR = Path(__file__).parent.parent / "cryptograms"

TAG_ATC = "9F36"
TAG_ARQC = "9F26"
TAG_IAD = "9F10"

# Where a tag can be recovered from the 8583 layer when DE55 omits it. Used
# only as a fallback, and reported when it happens: if the two copies disagree
# the cryptogram was computed over the other one, so silently substituting
# would produce a mismatch with no explanation.
DE_FALLBACK = {"9F02": 4, "5F2A": 49}


class CryptogramError(CryptoError):
    """A cryptogram cannot be computed or checked. User-facing."""


# ── Profile ───────────────────────────────────────────────────────────────────

@dataclasses.dataclass(frozen=True)
class CryptogramProfile:
    """Which tags are MACed, in what order, with what padding."""
    name: str
    tags: tuple[str, ...]
    padding: str = "iso9797-2"
    session_key: str = CSK
    description: str = ""

    @classmethod
    def from_dict(cls, d: dict, name: str = "") -> "CryptogramProfile":
        tags = tuple(str(t).upper().replace(" ", "") for t in (d.get("tags") or ()))
        if not tags:
            raise CryptogramError(
                f"Profile {name or '?'} lists no tags, so there is nothing to MAC."
            )
        return cls(
            name=str(d.get("name", name or "unnamed")),
            tags=tags,
            padding=str(d.get("padding", "iso9797-2")),
            session_key=str(d.get("session_key", CSK)),
            description=str(d.get("description", "")),
        )


def load_profile(name: str, directory: Path | None = None) -> CryptogramProfile:
    import yaml

    directory = Path(directory or PROFILE_DIR)
    path = directory / f"{Path(name).stem}.yaml"
    if not path.is_file():
        available = ", ".join(available_profiles(directory)) or "none"
        raise CryptogramError(
            f"No cryptogram profile named {name!r}. Available: {available}")
    try:
        raw = yaml.safe_load(path.read_text()) or {}
    except Exception as exc:
        raise CryptogramError(f"Cannot read profile {path.name}: {exc}") from exc
    return CryptogramProfile.from_dict(raw, name=path.stem)


def available_profiles(directory: Path | None = None) -> list[str]:
    directory = Path(directory or PROFILE_DIR)
    if not directory.is_dir():
        return []
    return sorted(p.stem for p in directory.glob("*.yaml"))


# ── Data build ────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class CryptogramData:
    data: bytes
    used: dict[str, str] = dataclasses.field(default_factory=dict)
    missing: tuple[str, ...] = ()
    substituted: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.missing


def build_data(profile: CryptogramProfile, nodes: list[TLVNode],
               msg: Message | None = None) -> CryptogramData:
    """
    Concatenate the profile's tags into the block that gets MACed.

    Missing tags are reported rather than silently skipped or zero-filled:
    a cryptogram computed over the wrong data fails identically to a forged
    one, and telling those two apart is the entire value of the exercise.
    """
    chunks: list[bytes] = []
    used: dict[str, str] = {}
    missing: list[str] = []
    substituted: list[str] = []

    for tag in profile.tags:
        node = find_tag(nodes, tag)
        if node is not None:
            chunks.append(bytes(node.value))
            used[tag] = node.value.hex().upper()
            continue

        de = DE_FALLBACK.get(tag)
        value = msg.fields.get(de) if (msg is not None and de) else None
        if isinstance(value, str) and value:
            try:
                raw = bytes.fromhex(value if len(value) % 2 == 0 else "0" + value)
            except ValueError:
                raw = None
            if raw is not None:
                chunks.append(raw)
                used[tag] = raw.hex().upper()
                substituted.append(tag)
                continue

        missing.append(tag)

    return CryptogramData(data=b"".join(chunks), used=used,
                          missing=tuple(missing), substituted=tuple(substituted))


# ── Compute and verify ────────────────────────────────────────────────────────

def compute_arqc(session_key: bytes, data: bytes, padding: str = "iso9797-2") -> bytes:
    """The AC itself: an 8-byte retail MAC over the transaction data."""
    return mac_iso9797_alg3(session_key, data, padding=padding)


@dataclasses.dataclass
class VerifyResult:
    matched: bool
    expected: str = ""
    found: str = ""
    atc: str = ""
    reason: str = ""
    data: CryptogramData | None = None

    def __str__(self) -> str:
        if self.matched:
            return f"ARQC verified (ATC {self.atc})"
        if self.reason:
            return f"ARQC not checked — {self.reason}"
        return (f"ARQC MISMATCH (ATC {self.atc}): "
                f"found {self.found}, computed {self.expected}")


def verify_cryptogram(msg: Message, udk: bytes, profile: CryptogramProfile,
                      nodes: list[TLVNode] | None = None) -> VerifyResult:
    """
    Check the ARQC in a message against one derived from the card's key.

    A mismatch is not by itself proof of forgery — a wrong profile, a wrong
    key, or a missing tag produces exactly the same failure. The result carries
    enough context to tell those apart, and refuses to compute at all when the
    inputs are incomplete rather than reporting a mismatch it cannot stand
    behind.
    """
    nodes = de55_mod.from_message(msg) if nodes is None else nodes
    if not nodes:
        return VerifyResult(matched=False, reason="the message carries no DE55")

    found = de55_mod.tag_value(nodes, TAG_ARQC)
    if not found:
        return VerifyResult(matched=False, reason=f"no tag {TAG_ARQC} in DE55")

    atc_hex = de55_mod.tag_value(nodes, TAG_ATC)
    if len(atc_hex) != 4:
        return VerifyResult(matched=False, found=found,
                            reason=f"no usable tag {TAG_ATC} (ATC) in DE55")

    built = build_data(profile, nodes, msg)
    if not built.complete:
        return VerifyResult(
            matched=False, found=found, atc=atc_hex, data=built,
            reason=("DE55 is missing " + ", ".join(built.missing) +
                    f" — profile '{profile.name}' needs them, so any result "
                    "would be meaningless"),
        )

    try:
        session_key = derive_session_key(udk, bytes.fromhex(atc_hex),
                                         method=profile.session_key)
        expected = compute_arqc(session_key, built.data, profile.padding)
    except CryptoError as exc:
        return VerifyResult(matched=False, found=found, atc=atc_hex,
                            data=built, reason=str(exc))

    expected_hex = expected.hex().upper()
    # Constant time, on principle: this runs beside code that talks to a host,
    # and a verifier that leaks its comparison is a bad example to set.
    matched = hmac.compare_digest(expected_hex, found[:len(expected_hex)])
    return VerifyResult(matched=matched, expected=expected_hex, found=found,
                        atc=atc_hex, data=built)


def resign(msg: Message, udk: bytes, profile: CryptogramProfile) -> tuple[Message, str]:
    """
    Recompute the ARQC over the message as it now stands and write it back.

    This is what makes a freshened replay interesting rather than futile: with
    a valid cryptogram over the *new* ATC and amount, an approval no longer
    tells you the host skipped cryptogram checking — it tells you what the host
    does or does not enforce *besides* the cryptogram.
    """
    nodes = de55_mod.from_message(msg)
    if not nodes:
        raise CryptogramError("Cannot re-sign a message with no DE55")

    atc_hex = de55_mod.tag_value(nodes, TAG_ATC)
    if len(atc_hex) != 4:
        raise CryptogramError(f"Cannot re-sign without tag {TAG_ATC} (ATC)")

    built = build_data(profile, nodes, msg)
    if not built.complete:
        raise CryptogramError(
            "Cannot re-sign: DE55 is missing " + ", ".join(built.missing))

    session_key = derive_session_key(udk, bytes.fromhex(atc_hex),
                                     method=profile.session_key)
    arqc = compute_arqc(session_key, built.data, profile.padding)
    if not de55_mod.set_tag(nodes, TAG_ARQC, arqc):
        nodes.append(TLVNode(tag=TAG_ARQC, length=len(arqc), value=arqc,
                             constructed=False))
    msg.fields[de55_mod.DE_ICC_DATA] = de55_mod.serialize(nodes)
    return msg, arqc.hex().upper()


# ── ARPC ──────────────────────────────────────────────────────────────────────

def arpc_method_1(session_key: bytes, arqc: bytes, arc: bytes) -> bytes:
    """
    EMV Book 2 §8.2.1 — the issuer's answer to a cryptogram.

    ARPC = 3DES(SK, ARQC XOR (ARC padded right with zeros)).
    """
    if len(arqc) != 8:
        raise CryptogramError(f"An ARQC is 8 bytes, got {len(arqc)}")
    if len(arc) != 2:
        raise CryptogramError(f"An ARC is 2 bytes, got {len(arc)}")
    return des3_encrypt(session_key, xor(arqc, arc + b"\x00" * 6))


def arpc_method_2(session_key: bytes, arqc: bytes, csu: bytes,
                  proprietary: bytes = b"") -> bytes:
    """
    EMV Book 2 §8.2.2 — the CSU-based variant, truncated to 4 bytes.
    """
    if len(arqc) != 8:
        raise CryptogramError(f"An ARQC is 8 bytes, got {len(arqc)}")
    if len(csu) != 4:
        raise CryptogramError(f"A CSU is 4 bytes, got {len(csu)}")
    return mac_iso9797_alg3(session_key, arqc + csu + proprietary,
                            padding="iso9797-2", length=4)
