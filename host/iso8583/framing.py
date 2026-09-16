"""
Wire framing — the envelope around an ISO 8583 message on a TCP link.

Two things sit in front of the MTI and neither is part of ISO 8583 itself,
which is why they vary so much between deployments:

* the **MLI** (message length indicator), a length prefix so the reader knows
  where the message ends on a stream socket;
* an optional **TPDU**, a 5-byte source/destination header that terminal→host
  links almost always carry and host→host links almost never do.

Both are described by data (see ``dialects/*.yaml``) rather than hard-coded,
because getting either one wrong is the single most common reason a decoder
produces garbage against a real link.
"""
from __future__ import annotations

import dataclasses

MLI_ENCODINGS = ("binary", "ascii", "bcd")

# Every framing shape worth trying when the target is unknown. Ordered by how
# often they turn up in the wild, so detection reports the likeliest first.
COMMON_FRAMINGS: tuple[dict, ...] = (
    {"mli_bytes": 2, "mli_encoding": "binary", "mli_includes_self": False},
    {"mli_bytes": 2, "mli_encoding": "binary", "mli_includes_self": True},
    {"mli_bytes": 4, "mli_encoding": "ascii",  "mli_includes_self": False},
    {"mli_bytes": 2, "mli_encoding": "bcd",    "mli_includes_self": False},
    {"mli_bytes": 4, "mli_encoding": "binary", "mli_includes_self": False},
)


class IncompleteMessage(Exception):
    """The buffer does not yet hold a whole message. Read more and retry."""


class FramingError(ValueError):
    """The buffer cannot be framed under this configuration."""


@dataclasses.dataclass(frozen=True)
class Framing:
    mli_bytes: int = 2
    mli_encoding: str = "binary"      # binary | ascii | bcd
    mli_includes_self: bool = False
    tpdu_length: int = 0              # 0 = no TPDU

    def __post_init__(self) -> None:
        if self.mli_encoding not in MLI_ENCODINGS:
            raise FramingError(
                f"Unknown MLI encoding {self.mli_encoding!r}; "
                f"valid: {', '.join(MLI_ENCODINGS)}"
            )
        if self.mli_bytes < 0 or self.mli_bytes > 8:
            raise FramingError(f"Implausible MLI width: {self.mli_bytes}")
        if self.mli_encoding == "bcd" and self.mli_bytes % 1:
            raise FramingError("BCD MLI needs a whole number of bytes")

    # ── length codec ─────────────────────────────────────────────────────────

    def _encode_length(self, n: int) -> bytes:
        if self.mli_encoding == "binary":
            return n.to_bytes(self.mli_bytes, "big")
        if self.mli_encoding == "ascii":
            digits = str(n).rjust(self.mli_bytes, "0")
            if len(digits) > self.mli_bytes:
                raise FramingError(f"Length {n} does not fit {self.mli_bytes} ASCII digits")
            return digits.encode("ascii")
        digits = str(n).rjust(self.mli_bytes * 2, "0")   # bcd
        if len(digits) > self.mli_bytes * 2:
            raise FramingError(f"Length {n} does not fit {self.mli_bytes} BCD bytes")
        return bytes.fromhex(digits)

    def _decode_length(self, raw: bytes) -> int:
        if self.mli_encoding == "binary":
            return int.from_bytes(raw, "big")
        if self.mli_encoding == "ascii":
            text = raw.decode("ascii", errors="replace")
            if not text.isdigit():
                raise FramingError(f"MLI {text!r} is not ASCII decimal")
            return int(text)
        digits = raw.hex()                                # bcd
        if any(c not in "0123456789" for c in digits):
            raise FramingError(f"MLI {digits!r} is not valid BCD")
        return int(digits)

    # ── public API ───────────────────────────────────────────────────────────

    def wrap(self, body: bytes) -> bytes:
        """Prepend the MLI to a complete message body."""
        n = len(body) + (self.mli_bytes if self.mli_includes_self else 0)
        return self._encode_length(n) + body

    def unwrap(self, buf: bytes) -> tuple[bytes, int]:
        """
        Pull the first whole message out of a stream buffer.

        Returns (body, bytes_consumed).  Raises IncompleteMessage when the
        buffer is short — the caller reads more and tries again — and
        FramingError when the buffer cannot be this framing at all.
        """
        if self.mli_bytes == 0:                    # no MLI: buffer is one message
            return buf, len(buf)
        if len(buf) < self.mli_bytes:
            raise IncompleteMessage("MLI not yet complete")

        declared = self._decode_length(buf[: self.mli_bytes])
        body_len = declared - self.mli_bytes if self.mli_includes_self else declared

        if body_len < 0:
            raise FramingError(f"MLI declares {declared}, shorter than the MLI itself")
        if body_len == 0:
            raise FramingError("MLI declares an empty message")

        total = self.mli_bytes + body_len
        if len(buf) < total:
            raise IncompleteMessage(
                f"need {total} bytes, buffer holds {len(buf)}"
            )
        return buf[self.mli_bytes: total], total

    def split_tpdu(self, body: bytes) -> tuple[bytes, bytes]:
        """Separate the TPDU header (if this link has one) from the message."""
        if self.tpdu_length <= 0:
            return b"", body
        if len(body) < self.tpdu_length:
            raise FramingError(
                f"Message is {len(body)} bytes, too short for a "
                f"{self.tpdu_length}-byte TPDU"
            )
        return body[: self.tpdu_length], body[self.tpdu_length:]

    def join_tpdu(self, tpdu: bytes, body: bytes) -> bytes:
        if self.tpdu_length <= 0:
            return body
        if len(tpdu) != self.tpdu_length:
            raise FramingError(
                f"TPDU is {len(tpdu)} bytes, dialect expects {self.tpdu_length}"
            )
        return tpdu + body

    @classmethod
    def from_dict(cls, d: dict | None) -> "Framing":
        d = d or {}
        mli = d.get("mli", {}) or {}
        tpdu = d.get("tpdu", {}) or {}
        return cls(
            mli_bytes=int(mli.get("bytes", 2)),
            mli_encoding=str(mli.get("encoding", "binary")).lower(),
            mli_includes_self=bool(mli.get("includes_self", False)),
            tpdu_length=int(tpdu.get("length", 5)) if tpdu.get("present") else 0,
        )


def iter_common_framings(tpdu_lengths: tuple[int, ...] = (0, 5)):
    """Every framing shape detection should try, likeliest first."""
    for base in COMMON_FRAMINGS:
        for tpdu in tpdu_lengths:
            yield Framing(**base, tpdu_length=tpdu)
