"""
Dialect detection — work out what a link speaks from bytes alone.

Walking into an unknown environment, you do not know the MLI width, whether
there is a TPDU, or whose field table the switch uses.  Guessing wrong produces
plausible-looking garbage, which is worse than an obvious failure.

The way out is that a *correct* configuration is strongly self-verifying: the
MLI predicts exactly where the message ends, the MTI is four decimal digits of
a valid class, the bitmap names fields the dialect defines, and decoding those
fields lands precisely on the final byte.  Wrong configurations almost never
satisfy all four at once, and the scoring below is arranged so that consuming
the message exactly dominates everything else.

Pair this with capture-first operation: record traffic passively, run
``detect`` over it, then refine the dialect file by hand.
"""
from __future__ import annotations

import dataclasses

from host.iso8583.codec import Message, unpack_body
from host.iso8583.dialect import Dialect, available_dialects, load_dialect
from host.iso8583.framing import Framing, FramingError, IncompleteMessage, iter_common_framings

# Message classes that actually occur on an authorisation link. A first digit
# outside this set means we are almost certainly misaligned.
PLAUSIBLE_MTI_CLASSES = ("0", "1", "2", "4", "6", "8", "9")


@dataclasses.dataclass
class Candidate:
    dialect: Dialect
    framing: Framing
    score: float
    message: Message | None
    notes: list[str] = dataclasses.field(default_factory=list)

    @property
    def label(self) -> str:
        mli = (f"{self.framing.mli_bytes}-byte {self.framing.mli_encoding}"
               f"{' incl. self' if self.framing.mli_includes_self else ''}")
        tpdu = f", {self.framing.tpdu_length}-byte TPDU" if self.framing.tpdu_length else ""
        return f"{self.dialect.name} [{mli}{tpdu}]"

    def __str__(self) -> str:
        return f"{self.label}  score={self.score:.2f}  " + "; ".join(self.notes)


# A flawless decode scores this, leaving deliberate headroom above it for the
# framing tie-break in detect(). Nothing reaches 1.0: two dialects that differ
# only in private-use fields really are indistinguishable from a plain message,
# and the score should not pretend otherwise.
PERFECT_DECODE = 0.90


def _score(msg: Message, body_len: int) -> tuple[float, list[str]]:
    """
    Rate one decode attempt from 0 to PERFECT_DECODE.

    Weighted so the strongest evidence dominates: consuming the message exactly
    with no problems is near-proof, while a syntactically valid MTI on its own
    is nearly worthless — random bytes produce one about 1 time in 300.
    """
    score = 0.0
    notes: list[str] = []

    if not msg.mti:
        return 0.0, ["no MTI"]
    if not (msg.mti.isdigit() and len(msg.mti) == 4):
        return 0.0, [f"MTI {msg.mti!r} is not four digits"]

    score += 0.15
    if msg.mti[0] in PLAUSIBLE_MTI_CLASSES:
        score += 0.10
        notes.append(f"MTI {msg.mti}")
    else:
        notes.append(f"MTI {msg.mti} has an unusual class")

    if msg.fields:
        # Recovering many fields is much stronger evidence than recovering one.
        score += min(0.25, 0.05 * len(msg.fields))
        notes.append(f"{len(msg.fields)} fields")
    else:
        notes.append("no fields decoded")

    if msg.problems:
        # A decode that broke partway has not "consumed" anything, however
        # empty the remainder looks — the loop stopped early, it did not finish.
        score -= min(0.25, 0.08 * len(msg.problems))
        notes.append(f"{len(msg.problems)} problem(s): {msg.problems[0]}")
    else:
        score += 0.10
        if not msg.trailing:
            score += 0.30
            notes.append("consumed exactly")
        else:
            # A little slack is normal (padding); a lot means misalignment.
            if len(msg.trailing) / max(body_len, 1) < 0.05:
                score += 0.10
            notes.append(f"{len(msg.trailing)} trailing bytes")

    return max(0.0, min(PERFECT_DECODE, score)), notes


def detect(capture: bytes,
           dialects: list[str] | None = None,
           directory=None,
           limit: int = 5) -> list[Candidate]:
    """
    Rank (dialect, framing) combinations against captured bytes.

    `capture` is raw bytes straight off the wire, starting at a message
    boundary.  Returns the best `limit` candidates, highest score first; an
    empty list means nothing decoded plausibly.
    """
    names = dialects if dialects is not None else available_dialects(directory)
    loaded: list[Dialect] = []
    for name in names:
        try:
            loaded.append(load_dialect(name, directory))
        except Exception:
            continue          # a broken dialect file should not stop detection

    results: list[Candidate] = []
    for framing in iter_common_framings():
        try:
            body, consumed = framing.unwrap(capture)
        except (IncompleteMessage, FramingError):
            continue
        try:
            tpdu, rest = framing.split_tpdu(body)
        except FramingError:
            continue
        if not rest:
            continue

        for dialect in loaded:
            msg = unpack_body(dialect, rest)
            msg.tpdu = tpdu
            score, notes = _score(msg, len(rest))
            if score <= 0:
                continue
            # Dialects that differ only in private-use fields decode a plain
            # message identically, so the field table alone cannot separate
            # them. What can: the dialect's own declared framing. A dialect
            # that says "my links carry a TPDU" is a worse explanation for a
            # capture with no TPDU than one that says they do not.
            if framing == dialect.framing:
                score += 0.05
                notes.append("framing matches the dialect default")

            results.append(Candidate(dialect=dialect, framing=framing,
                                     score=score, message=msg, notes=notes))

    results.sort(key=lambda c: c.score, reverse=True)
    return results[:limit]


def describe(candidates: list[Candidate]) -> str:
    """Render a detection result for a terminal or a log."""
    if not candidates:
        return ("No dialect decoded this capture. Check that it starts on a "
                "message boundary, then hand-write a dialect file for the "
                "target's interface spec.")
    lines = ["Ranked dialect candidates:"]
    for i, c in enumerate(candidates, 1):
        lines.append(f"  {i}. {c}")
    best = candidates[0]
    if best.score < 0.5:
        lines.append("")
        lines.append("Low confidence — treat this as a starting point, not an answer.")
    return "\n".join(lines)
