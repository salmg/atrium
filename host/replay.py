"""
Replay — drive messages from a captured corpus, with no acquirer in front.

Phases 2 and 3 need a real terminal or acquirer feeding the link.  This does
not: it plays the acquirer itself, reading messages out of a capture and
sending them to the host.  That is why phase 2 keeps raw bytes.

Two modes, and the difference is the whole point
------------------------------------------------
**Verbatim** resends exactly what was captured.  Most hosts should decline it,
because the STAN and RRN have been seen before — and a host that *approves* a
byte-identical replay has no duplicate detection at all.  Nothing clever is
needed to ask that question, which is why it is the default.

**Freshen** rewrites only the volatile routing fields — STAN, RRN, transmission
and local date-time — so the message looks like a new transaction, while
leaving DE55 and its cryptogram exactly as captured.  That asks the sharper
question: is the ARQC actually *bound* to those fields, or can a real
cryptogram be reused under a new STAN?  DE55 is never touched here; reusing it
untouched is the experiment.

Both compose with a phase 3 playbook, so a captured transaction can be run
through ``cryptogram-tamper`` with no live acquirer involved.

Replay is the most active thing in this toolkit: it originates transactions
rather than observing somebody else's.  The scoping guard applies in full, and
the PAN check matters more here than anywhere else — a corpus captured from a
live link would resend real cardholder data.
"""
from __future__ import annotations

import dataclasses
import logging
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from host.capture import (
    ACQUIRER_TO_ISSUER,
    DE_PAN,
    DE_RESPONSE_CODE,
    DE_STAN,
    CaptureLog,
    Record,
    load_capture,
    masked_fields,
)
from host.iso8583.codec import Message, pack_body, unpack_body
from host.iso8583.dialect import Dialect
from host.iso8583.framing import Framing
from host.crypto import CryptogramProfile, CryptogramError, derive_udk, resign
from host.mutation import MutationRecord, Playbook, apply_playbook
from host.scoping import Scope, ScopeError, mask_pan
from host.transport.link import TcpLink

log = logging.getLogger(__name__)

# Fields that identify *this* transaction rather than what was authorised.
# Freshening rewrites these and nothing else — DE55 in particular is left
# exactly as captured, because reusing it untouched is the experiment.
DE_TRANSMISSION_DATETIME = 7
DE_TIME_LOCAL = 12
DE_DATE_LOCAL = 13
DE_RRN = 37
FRESHEN_FIELDS = (DE_TRANSMISSION_DATETIME, DE_STAN, DE_TIME_LOCAL,
                  DE_DATE_LOCAL, DE_RRN)

# "00" is approved everywhere. 10 and 11 are partial and VIP approvals; the
# rest of the code space is scheme-specific, so anything else counts as
# not-approved rather than being guessed at.
APPROVAL_CODES = frozenset({"00", "10", "11"})


class ReplayError(RuntimeError):
    """Replay cannot proceed. User-facing."""


# ── Corpus ────────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class ReplayItem:
    """One message from a capture, ready to send again."""
    seq: int
    ts: float
    mti: str
    raw: bytes

    @property
    def hex(self) -> str:
        return self.raw.hex().upper()


def load_corpus(path: str | Path, leg: str = ACQUIRER_TO_ISSUER,
                mti: tuple[str, ...] = (), limit: int = 0) -> list[ReplayItem]:
    """
    Read replayable messages out of a capture.

    Defaults to the acquirer-to-issuer leg: replay plays the acquirer, so the
    issuer's own replies are not ours to send.
    """
    if not Path(path).is_file():
        raise ReplayError(f"No such capture: {path}")

    items: list[ReplayItem] = []
    for record in load_capture(path):
        if leg and record.get("leg") != leg:
            continue
        if mti and record.get("mti") not in mti:
            continue
        raw = record.get("raw")
        if not raw:
            continue
        try:
            data = bytes.fromhex(raw)
        except ValueError:
            continue
        items.append(ReplayItem(seq=int(record.get("seq", 0)),
                                ts=float(record.get("ts", 0.0)),
                                mti=str(record.get("mti", "")),
                                raw=data))
        if limit and len(items) >= limit:
            break

    if not items:
        raise ReplayError(
            f"No replayable messages in {path}. Captures written with --no-raw "
            "hold no bytes to resend, and only the acquirer-to-issuer leg is "
            "replayable by default."
        )
    return items


# ── Freshening ────────────────────────────────────────────────────────────────

class Freshener:
    """
    Rewrites the fields that identify a transaction, leaving what was
    authorised — and the cryptogram over it — alone.

    STANs come from a random base rather than starting at 1: replaying into a
    host that has seen this corpus before should not collide with the original
    traffic by construction, or the duplicate-detection result becomes
    ambiguous.
    """

    def __init__(self, fields: tuple[int, ...] = FRESHEN_FIELDS,
                 seed: int | None = None) -> None:
        self.fields = tuple(fields)
        rng = random.Random(seed)
        self._stan = rng.randrange(1, 999_999)
        self._rrn_base = rng.randrange(0, 10 ** 8)
        self._n = 0

    def _next_stan(self) -> str:
        self._stan = (self._stan % 999_999) + 1
        return f"{self._stan:06d}"

    def _next_rrn(self) -> str:
        self._n += 1
        return f"{(self._rrn_base + self._n) % 10 ** 12:012d}"

    def apply(self, dialect: Dialect, msg: Message) -> list[MutationRecord]:
        """Freshen in place. Returns records in the same shape as mutations."""
        now = datetime.now(timezone.utc)
        values = {
            DE_TRANSMISSION_DATETIME: now.strftime("%m%d%H%M%S"),
            DE_STAN: self._next_stan(),
            DE_TIME_LOCAL: now.strftime("%H%M%S"),
            DE_DATE_LOCAL: now.strftime("%m%d"),
            DE_RRN: self._next_rrn(),
        }

        records: list[MutationRecord] = []
        for number in self.fields:
            if number not in msg.fields:
                continue          # only refresh what the message already carries
            if dialect.field(number) is None:
                continue
            new = values.get(number)
            if new is None:
                continue
            before = msg.fields[number]
            if not isinstance(before, str):
                continue          # never reinterpret a binary field as a date
            msg.fields[number] = new
            records.append(MutationRecord(
                target=f"DE{number}", mode="freshen", before=before, after=new,
                comment="replay freshening — routing field only",
            ))
        return records


def _arqc_of(msg: Message) -> str:
    """Current ARQC in a message, for before/after reporting."""
    from host.iso8583 import de55 as de55_mod
    try:
        return de55_mod.tag_value(de55_mod.from_message(msg), "9F26")
    except Exception:                                  # noqa: BLE001
        return ""


# ── Results ───────────────────────────────────────────────────────────────────

@dataclasses.dataclass
class ReplayResult:
    item: ReplayItem
    sent: bytes
    changes: list[MutationRecord] = dataclasses.field(default_factory=list)
    response: Message | None = None
    response_raw: bytes = b""
    rtt_ms: float | None = None
    error: str = ""

    @property
    def response_code(self) -> str:
        if self.response is None:
            return ""
        rc = self.response.fields.get(DE_RESPONSE_CODE)
        return rc if isinstance(rc, str) else ""

    @property
    def approved(self) -> bool:
        return self.response_code in APPROVAL_CODES

    @property
    def answered(self) -> bool:
        return self.response is not None


@dataclasses.dataclass
class ReplayReport:
    mode: str
    results: list[ReplayResult] = dataclasses.field(default_factory=list)
    playbook: str = ""
    resigned: bool = False

    @property
    def approved(self) -> list[ReplayResult]:
        return [r for r in self.results if r.approved]

    @property
    def unanswered(self) -> list[ReplayResult]:
        return [r for r in self.results if not r.answered]

    def by_response_code(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self.results:
            if r.answered:
                counts[r.response_code or "(none)"] = counts.get(r.response_code or "(none)", 0) + 1
        return counts

    def verdict(self) -> str:
        """
        What the result set suggests — stated as a lead to verify, not a
        conclusion. Approval codes are scheme-specific and a test host may be
        configured to approve everything, so the tool reports what it saw and
        says what would confirm it.
        """
        if not self.results:
            return "Nothing was replayed."
        approved = len(self.approved)
        if not approved:
            return ("Nothing was approved. The host rejected every replayed "
                    "message, which is the expected result.")

        # Order matters: a playbook rewrites the bytes, so such a run is not
        # byte-identical however it was launched. Claiming otherwise would
        # report the wrong finding.
        if self.playbook:
            return (
                f"** {approved} of {len(self.results)} replays were APPROVED with "
                f"the '{self.playbook}' playbook applied.\n"
                "   The host accepted messages this playbook deliberately "
                "corrupted. Check the\n"
                "   mutation records to see exactly what it tolerated."
            )
        if self.resigned:
            return (
                f"** {approved} of {len(self.results)} replays were APPROVED "
                f"with a recomputed cryptogram.\n"
                "   The ARQC was valid over the modified data, so this says "
                "nothing about whether\n"
                "   the host verifies cryptograms — it says the host accepted "
                "the *content* the\n"
                "   playbook changed. Compare against the same run without "
                "--imk to separate the two."
            )
        if self.mode == "verbatim":
            return (
                f"** {approved} of {len(self.results)} byte-identical replays were "
                f"APPROVED.\n"
                "   The host answered the same STAN and RRN twice without "
                "objecting, which\n"
                "   points at absent duplicate detection. Confirm by checking "
                "whether the\n"
                "   original transactions also cleared — two settlements for one "
                "purchase is\n"
                "   the impact worth reporting."
            )
        return (
            f"** {approved} of {len(self.results)} freshened replays were APPROVED.\n"
            "   The routing fields were rewritten but DE55 and its cryptogram were "
            "reused\n"
            "   verbatim, so an approval suggests the ARQC is not bound to the "
            "transaction\n"
            "   identity — a captured cryptogram can be spent again under a new STAN."
        )

    def summary(self) -> str:
        # "verbatim" describes the routing fields, not the whole message — a
        # playbook rewrites content on top. Say so, rather than leaving a
        # reader to conclude the bytes went out untouched.
        routing = "freshened" if self.mode == "freshened" else "as-captured"
        how = (f"with {routing} routing fields, playbook '{self.playbook}'"
               if self.playbook else f"in {self.mode} mode")
        lines = [f"Replayed {len(self.results)} message(s) {how}."]
        codes = self.by_response_code()
        if codes:
            lines.append("  response codes: " + ", ".join(
                f"{c}×{n}" for c, n in sorted(codes.items())))
        if self.unanswered:
            lines.append(f"  {len(self.unanswered)} unanswered")
        errors = [r for r in self.results if r.error]
        if errors:
            lines.append(f"  {len(errors)} error(s): {errors[0].error}")
        lines.append("")
        lines.append(self.verdict())
        return "\n".join(lines)


# ── Session ───────────────────────────────────────────────────────────────────

class ReplaySession:
    """
    Sends messages from a corpus to a host and collects the answers.

    Built on TcpLink rather than on the proxy's upstream leg: the proxy uses a
    raw socket precisely so pass-through stays byte-exact, which is the
    opposite of what replay needs. Replay constructs what it sends.
    """

    def __init__(self, target_host: str, target_port: int, dialect: Dialect,
                 scope: Scope, framing: Framing | None = None,
                 capture: CaptureLog | None = None,
                 playbook: Playbook | None = None,
                 freshen: bool = False,
                 timeout: float = 30.0,
                 freshen_seed: int | None = None,
                 imk: bytes | None = None,
                 crypto_profile: CryptogramProfile | None = None,
                 psn: str = "00") -> None:
        scope.check_target(target_host, target_port)

        self.target_host = target_host
        self.target_port = target_port
        self.dialect = dialect
        self.scope = scope
        self.framing = framing or dialect.framing
        self.capture = capture or CaptureLog(None)
        self.playbook = playbook if (playbook and playbook.active) else None
        self.freshener = Freshener(seed=freshen_seed) if freshen else None
        self.timeout = timeout
        # Re-signing turns a tampered message from "does the host check the
        # cryptogram?" into "what does the host check *besides* the
        # cryptogram?" — a different and usually more interesting question.
        self.imk = imk
        self.crypto_profile = crypto_profile
        self.psn = psn
        self._link: TcpLink | None = None

    @property
    def mode(self) -> str:
        return "freshened" if self.freshener else "verbatim"

    # ── lifecycle ────────────────────────────────────────────────────────────

    def connect(self) -> None:
        self._link = TcpLink(self.target_host, self.target_port,
                             framing=self.framing, timeout=self.timeout)
        self._link.connect()
        log.info("Replay connected to %s:%d (%s mode)",
                 self.target_host, self.target_port, self.mode)

    def close(self) -> None:
        if self._link:
            self._link.close()
            self._link = None

    def __enter__(self) -> "ReplaySession":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── the work ─────────────────────────────────────────────────────────────

    def _prepare(self, item: ReplayItem) -> tuple[bytes, list[MutationRecord], str]:
        """
        Decide what to actually send.

        Verbatim with no playbook needs no decode at all — the captured bytes go
        back out untouched, which is both the point and the safest path. Any
        transform needs a clean decode first, the same rule mutation follows:
        re-encoding a message the dialect only half understood would silently
        drop the rest.
        """
        if self.freshener is None and self.playbook is None:
            return item.raw, [], ""

        body, _ = self.framing.unwrap(item.raw)
        tpdu, rest = self.framing.split_tpdu(body)
        msg = unpack_body(self.dialect, rest)
        msg.tpdu = tpdu

        if not msg.complete:
            reason = "; ".join(msg.problems) or f"{len(msg.trailing)} trailing bytes"
            return item.raw, [], (
                f"sent verbatim — could not decode cleanly to transform it ({reason})"
            )

        if self.scope is not None:
            pan = msg.fields.get(DE_PAN)
            if isinstance(pan, str) and pan:
                warning = self.scope.check_pan(pan)      # may raise ScopeError
                if warning:
                    log.warning("seq=%d %s", item.seq, warning)

        changes: list[MutationRecord] = []
        if self.freshener is not None:
            changes.extend(self.freshener.apply(self.dialect, msg))
        if self.playbook is not None:
            msg, mutations = apply_playbook(self.playbook, self.dialect, msg,
                                            ACQUIRER_TO_ISSUER)
            changes.extend(mutations)

        if not changes:
            return item.raw, [], ""

        note = ""
        if self.imk is not None and self.crypto_profile is not None:
            pan = msg.fields.get(DE_PAN)
            if isinstance(pan, str) and pan:
                before = _arqc_of(msg)
                try:
                    keys = derive_udk(self.imk, pan, self.psn)
                    _msg, arqc = resign(msg, keys.udk, self.crypto_profile)
                    changes.append(MutationRecord(
                        target="DE55/9F26", mode="resign", before=before,
                        after=arqc, comment=f"recomputed under profile "
                                            f"'{self.crypto_profile.name}'"))
                except CryptogramError as exc:
                    note = f"not re-signed — {exc}"
            else:
                note = "not re-signed — no PAN in the message to derive a key from"

        try:
            raw = self.framing.wrap(
                self.framing.join_tpdu(msg.tpdu, pack_body(self.dialect, msg)))
        except Exception as exc:                       # noqa: BLE001
            return item.raw, [], f"sent verbatim — re-encode failed ({exc})"
        return raw, changes, note

    def send_one(self, item: ReplayItem) -> ReplayResult:
        if self._link is None:
            raise ReplayError("Not connected — call connect() first")

        try:
            outbound, changes, note = self._prepare(item)
        except ScopeError:
            raise
        except Exception as exc:                       # noqa: BLE001
            log.exception("seq=%d could not be prepared", item.seq)
            return ReplayResult(item=item, sent=item.raw,
                                error=f"preparation failed: {exc}")

        result = ReplayResult(item=item, sent=outbound, changes=changes)
        started = time.time()
        try:
            self._link.send_raw(outbound)
            answer = self._link.receive_framed(timeout=self.timeout)
        except Exception as exc:                       # noqa: BLE001
            result.error = str(exc)
            self._record(result, note)
            return result

        if answer is None:
            result.error = "no response before the timeout"
            self._record(result, note)
            return result

        body, raw = answer
        result.response_raw = raw
        result.rtt_ms = round((time.time() - started) * 1000, 2)
        try:
            _tpdu, rest = self.framing.split_tpdu(body)
            result.response = unpack_body(self.dialect, rest)
        except Exception as exc:                       # noqa: BLE001
            result.error = f"response did not decode: {exc}"

        self._record(result, note)
        return result

    def run(self, items: list[ReplayItem], delay: float = 0.0,
            preserve_timing: bool = False) -> ReplayReport:
        report = ReplayReport(
            mode=self.mode,
            playbook=self.playbook.name if self.playbook else "",
            resigned=self.imk is not None and self.crypto_profile is not None)
        previous_ts = None
        for item in items:
            if preserve_timing and previous_ts is not None:
                gap = item.ts - previous_ts
                if 0 < gap < 60:            # ignore clock jumps and idle stretches
                    time.sleep(gap)
            elif delay:
                time.sleep(delay)
            previous_ts = item.ts

            report.results.append(self.send_one(item))
        return report

    # ── capture ──────────────────────────────────────────────────────────────

    def _record(self, result: ReplayResult, note: str) -> None:
        """Write both legs of the exchange into the capture, as the proxy does."""
        now = time.time()
        sent_msg = None
        try:
            body, _ = self.framing.unwrap(result.sent)
            _tpdu, rest = self.framing.split_tpdu(body)
            sent_msg = unpack_body(self.dialect, rest)
        except Exception:                              # noqa: BLE001
            pass

        request = Record(
            ts=now, conn="replay", leg=ACQUIRER_TO_ISSUER, seq=result.item.seq,
            raw=result.item.hex, mti=result.item.mti,
            fields=masked_fields(sent_msg) if sent_msg else {},
            mutations=[c.to_dict() for c in result.changes],
            sent=result.sent.hex().upper() if result.sent != result.item.raw else "",
            note=note,
            problems=[result.error] if result.error else [],
        )
        self.capture.write(request)

        if result.response is not None:
            self.capture.write(Record(
                ts=now, conn="replay", leg="issuer->acquirer", seq=result.item.seq,
                raw=result.response_raw.hex().upper(),
                mti=result.response.mti,
                fields=masked_fields(result.response),
                rtt_ms=result.rtt_ms,
            ))


def describe_results(report: ReplayReport, limit: int = 20) -> str:
    """A per-message table, for a terminal."""
    lines = ["  seq  MTI   sent        rc   rtt      note"]
    for r in report.results[:limit]:
        changed = "changed" if r.changes else "verbatim"
        rc = r.response_code or ("—" if not r.error else "err")
        rtt = f"{r.rtt_ms:.0f}ms" if r.rtt_ms is not None else "—"
        flag = "  <-- APPROVED" if r.approved else ""
        lines.append(f"  {r.item.seq:<4} {r.item.mti:<5} {changed:<11} "
                     f"{rc:<4} {rtt:<8} {r.error}{flag}")
    if len(report.results) > limit:
        lines.append(f"  … {len(report.results) - limit} more")
    return "\n".join(lines)


def pan_of(dialect: Dialect, framing: Framing, raw: bytes) -> str:
    """Masked PAN from a raw message, for pre-flight scope reporting."""
    try:
        body, _ = framing.unwrap(raw)
        _tpdu, rest = framing.split_tpdu(body)
        pan = unpack_body(dialect, rest).fields.get(DE_PAN)
        return mask_pan(pan) if isinstance(pan, str) and pan else ""
    except Exception:                                  # noqa: BLE001
        return ""
