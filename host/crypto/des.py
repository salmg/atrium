"""
DES primitives — 3DES and the ISO 9797-1 MAC that EMV builds cryptograms from.

Two-key 3DES is implemented here as explicit E-D-E over the DES primitive
rather than through ``Crypto.Cipher.DES3``, for one practical reason: the
library refuses a key where K1 equals K2, calling it degenerate.  It is right
that such a key is weak, but EMV test material sometimes contains one, and a
tool that cannot process a test key is useless for testing.  Doing E-D-E
directly also makes the ordering visible instead of implied.

Nothing here chooses keys or judges them.  Weak keys are the target's problem
to have and this tool's job to reveal.
"""
from __future__ import annotations

BLOCK = 8


class CryptoError(ValueError):
    """A key or block is the wrong shape. User-facing."""


def _des(key: bytes):
    from Crypto.Cipher import DES
    if len(key) != 8:
        raise CryptoError(f"A DES key is 8 bytes, got {len(key)}")
    return DES.new(key, DES.MODE_ECB)


def des_encrypt(key: bytes, block: bytes) -> bytes:
    return _des(key).encrypt(block)


def des_decrypt(key: bytes, block: bytes) -> bytes:
    return _des(key).decrypt(block)


def _split(key: bytes) -> tuple[bytes, bytes]:
    if len(key) == 16:
        return key[:8], key[8:]
    if len(key) == 8:                 # single-length key used as 3DES
        return key, key
    raise CryptoError(f"A 3DES key is 8 or 16 bytes, got {len(key)}")


def des3_encrypt(key: bytes, data: bytes) -> bytes:
    """Two-key 3DES in ECB. Data must be a whole number of blocks."""
    k1, k2 = _split(key)
    if len(data) % BLOCK:
        raise CryptoError(f"3DES needs whole 8-byte blocks, got {len(data)}")
    out = bytearray()
    for i in range(0, len(data), BLOCK):
        block = data[i:i + BLOCK]
        out += des_encrypt(k1, des_decrypt(k2, des_encrypt(k1, block)))
    return bytes(out)


def des3_decrypt(key: bytes, data: bytes) -> bytes:
    k1, k2 = _split(key)
    if len(data) % BLOCK:
        raise CryptoError(f"3DES needs whole 8-byte blocks, got {len(data)}")
    out = bytearray()
    for i in range(0, len(data), BLOCK):
        block = data[i:i + BLOCK]
        out += des_decrypt(k1, des_encrypt(k2, des_decrypt(k1, block)))
    return bytes(out)


# ── Padding ───────────────────────────────────────────────────────────────────

def pad_method_1(data: bytes) -> bytes:
    """
    ISO 9797-1 padding method 1 — zeros to the next block boundary.

    Ambiguous by construction (trailing zeros in the message are
    indistinguishable from padding), which is why EMV uses method 2. Provided
    because some hosts use it anyway.
    """
    if not data:
        return b"\x00" * BLOCK
    return data + b"\x00" * (-len(data) % BLOCK)


def pad_method_2(data: bytes) -> bytes:
    """ISO 9797-1 padding method 2 — 0x80 then zeros. What EMV uses."""
    return data + b"\x80" + b"\x00" * (-(len(data) + 1) % BLOCK)


PADDING = {"iso9797-1": pad_method_1, "iso9797-2": pad_method_2, "none": lambda d: d}


# ── MAC ───────────────────────────────────────────────────────────────────────

def mac_iso9797_alg3(key: bytes, data: bytes, padding: str = "iso9797-2",
                     length: int = 8) -> bytes:
    """
    ISO 9797-1 MAC Algorithm 3 — the "retail MAC" EMV computes an AC with.

    Single-DES CBC across the message under the left key half, then one final
    3DES pass over the last block: decrypt with the right half, encrypt with
    the left.  That last step is the whole difference from a plain DES CBC-MAC
    and is what makes the result a 3DES-strength tag.
    """
    if padding not in PADDING:
        raise CryptoError(
            f"Unknown padding {padding!r}; valid: {', '.join(PADDING)}")
    kl, kr = _split(key)
    padded = PADDING[padding](data)
    if len(padded) % BLOCK:
        raise CryptoError("Padded data is not a whole number of blocks")

    h = b"\x00" * BLOCK
    for i in range(0, len(padded), BLOCK):
        block = bytes(a ^ b for a, b in zip(h, padded[i:i + BLOCK]))
        h = des_encrypt(kl, block)

    h = des_encrypt(kl, des_decrypt(kr, h))
    return h[:length]


# ── Key hygiene ───────────────────────────────────────────────────────────────

def adjust_parity(key: bytes) -> bytes:
    """
    Force odd parity in the low bit of every byte, as DES keys carry.

    EMV requires derived keys be parity-adjusted. The bit is not secret and
    carries no strength — it is a legacy integrity check — but a host that
    checks it will reject a key that skips this.
    """
    out = bytearray()
    for byte in key:
        out.append(byte ^ 1 if bin(byte).count("1") % 2 == 0 else byte)
    return bytes(out)


def has_odd_parity(key: bytes) -> bool:
    return all(bin(b).count("1") % 2 == 1 for b in key)


def xor(a: bytes, b: bytes) -> bytes:
    """XOR two equal-length byte strings."""
    if len(a) != len(b):
        raise CryptoError(f"Cannot XOR {len(a)} bytes with {len(b)}")
    return bytes(x ^ y for x, y in zip(a, b))
