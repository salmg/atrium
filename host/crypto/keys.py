"""
EMV key derivation — issuer master key down to the session key that signs an AC.

    IMK  ──(card: PAN + PSN)──►  UDK  ──(transaction: ATC)──►  SK

Both steps are EMV Book 2 Annex A1 and are the same everywhere; what differs
between schemes is which data gets MACed under the result, and that lives in a
profile rather than here (see ``host/cryptograms/``).

Handling of issuer master keys
------------------------------
An IMK derives every card key in its range, so it is the most valuable secret
this toolkit can touch.  Nothing in this module logs one, puts one in a
``repr``, or writes one to a capture, and ``load_imk`` prefers an environment
variable or a file over an argv value that any other process on the box could
read out of ``ps``.
"""
from __future__ import annotations

import dataclasses
import os
from pathlib import Path

from host.crypto.des import CryptoError, adjust_parity, des3_encrypt, xor

# Derivation methods for UDK, EMV Book 2 A1.4
OPTION_A = "option-a"
OPTION_B = "option-b"

# Session key derivation, EMV Book 2 A1.3
CSK = "csk"          # EMV Common Session Key — ATC-diversified
NONE = "none"        # No session key: the AC is MACed under the UDK itself

SESSION_METHODS = (CSK, NONE)

_ENV_IMK = "HOST_IMK"


class KeyError_(CryptoError):
    """Key derivation failed. User-facing."""


@dataclasses.dataclass(frozen=True)
class CardKeys:
    """Keys for one card. Never rendered — see __repr__."""
    udk: bytes
    pan: str
    psn: str

    def __repr__(self) -> str:                # noqa: D105
        return f"CardKeys(pan=***{self.pan[-4:]}, psn={self.psn}, udk=<16 bytes>)"


def _pan_psn_block(pan: str, psn: str = "00") -> bytes:
    """
    The 8-byte diversification value: rightmost 16 digits of PAN||PSN, packed.

    Short PANs are padded on the left with zeros rather than refused — a
    13-digit PAN is perfectly legal and still has to derive.
    """
    pan_digits = "".join(c for c in pan if c.isdigit())
    if not pan_digits:
        # Checked on the PAN alone, not on PAN||PSN: the PSN defaults to "00",
        # so an empty PAN would otherwise derive a real-looking key out of
        # nothing at all — worse than refusing, because it verifies nothing and
        # looks like it should.
        raise KeyError_("PAN is empty, so no key can be derived from it")
    digits = pan_digits + "".join(c for c in psn if c.isdigit())
    return bytes.fromhex(digits[-16:].rjust(16, "0"))


def derive_udk(imk: bytes, pan: str, psn: str = "00",
               method: str = OPTION_A) -> CardKeys:
    """
    Derive a card's unique key from the issuer master key.

    Option A is implemented. Option B — for PANs whose PAN||PSN exceeds 16
    digits — needs a SHA-1 decimalisation step, and a half-correct
    implementation of it would produce keys that look plausible and verify
    nothing. It raises rather than guessing.
    """
    if len(imk) not in (8, 16):
        raise KeyError_(f"An IMK is 8 or 16 bytes, got {len(imk)}")
    if method == OPTION_B:
        raise KeyError_(
            "UDK derivation Option B is not implemented. It applies when "
            "PAN||PSN exceeds 16 digits and needs a SHA-1 decimalisation step; "
            "an approximation of it would produce keys that verify nothing. "
            "Use Option A, or supply the UDK directly with --udk."
        )
    if method != OPTION_A:
        raise KeyError_(f"Unknown UDK derivation method {method!r}")

    y = _pan_psn_block(pan, psn)
    left = des3_encrypt(imk, y)
    right = des3_encrypt(imk, xor(y, b"\xFF" * 8))
    return CardKeys(udk=adjust_parity(left + right), pan=pan, psn=psn)


def derive_session_key(udk: bytes, atc: bytes, method: str = CSK) -> bytes:
    """
    Derive the session key that signs one transaction's AC.

    CSK diversifies on the ATC, so a session key is good for exactly one
    transaction — which is the mechanism a replay is meant to defeat, and the
    reason phase 4's freshened replay is an interesting experiment.

    ``none`` returns the UDK unchanged, matching the older schemes that MAC
    directly under it.
    """
    if len(udk) != 16:
        raise KeyError_(f"A UDK is 16 bytes, got {len(udk)}")
    if method == NONE:
        return udk
    if method != CSK:
        raise KeyError_(
            f"Unknown session key method {method!r}; valid: "
            + ", ".join(SESSION_METHODS))
    if len(atc) != 2:
        raise KeyError_(f"An ATC is 2 bytes, got {len(atc)}")

    left = des3_encrypt(udk, atc + b"\xF0" + b"\x00" * 5)
    right = des3_encrypt(udk, atc + b"\x0F" + b"\x00" * 5)
    return adjust_parity(left + right)


# ── Loading secrets ───────────────────────────────────────────────────────────

def parse_key(text: str, what: str = "key") -> bytes:
    raw = (text or "").strip().replace(" ", "").replace(":", "")
    if not raw:
        raise KeyError_(f"No {what} supplied")
    try:
        key = bytes.fromhex(raw)
    except ValueError as exc:
        raise KeyError_(f"{what} is not hex") from exc
    if len(key) not in (8, 16, 24):
        raise KeyError_(f"{what} is {len(key)} bytes; expected 8, 16 or 24")
    return key[:16] if len(key) == 24 else key


def load_imk(value: str | None = None, path: str | None = None) -> tuple[bytes, str]:
    """
    Resolve an issuer master key, most private source first.

    Returns (key, source).  A key passed on the command line is accepted but
    reported as such, because argv is readable by every other process on the
    machine — the caller should say so out loud.
    """
    if path:
        try:
            text = Path(path).read_text()
        except OSError as exc:
            raise KeyError_(f"Cannot read key file {path}: {exc}") from exc
        return parse_key(text, "IMK"), f"file {path}"

    env = os.environ.get(_ENV_IMK, "")
    if env:
        return parse_key(env, "IMK"), f"${_ENV_IMK}"

    if value:
        return parse_key(value, "IMK"), "command line (visible in ps)"

    raise KeyError_(
        "No issuer master key supplied. Give one as a file (--imk-file), in "
        f"${_ENV_IMK}, or — least privately — with --imk."
    )
