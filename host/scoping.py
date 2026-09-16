"""
Scoping guard — the mirror image of ATRIUM's inbound hardening.

ATRIUM is built so nothing reaches *in*: loopback by default, no privilege
escalation, Host-header allow-listing.  This half of the toolkit reaches *out*
by design, so it needs the opposite guard.  Two rules do the work:

* **Target allow-list.**  The proxy refuses to connect anywhere that was not
  named up front.  A typo in a hostname should fail closed, not quietly open a
  tunnel into something that was never in scope.
* **Test-PAN awareness.**  Authorisation testing belongs against certification
  hosts with test cards.  Seeing a PAN outside the configured test ranges is
  the loudest available signal that the link is pointed at production, and the
  tool says so — or refuses to continue, if told to.

Cardholder data never reaches a log in full regardless of policy: PANs and
track data are masked at the point of capture, not on the way out.
"""
from __future__ import annotations

import dataclasses
import logging

log = logging.getLogger(__name__)

# The card numbers published in every payment API's documentation. They are a
# convenience, not a substitute for the target's own test ranges — a real
# engagement gets those from the host's owner along with the interface spec.
WELL_KNOWN_TEST_BINS: tuple[str, ...] = (
    "411111",   # Visa
    "444433",
    "400000",
    "555555",   # Mastercard
    "510510",
    "222100",
    "378282",   # American Express
    "371449",
    "601111",   # Discover
    "353011",   # JCB
    "305693",   # Diners Club
)

ON_LIVE_PAN = ("warn", "abort")


class ScopeError(RuntimeError):
    """A target or a PAN falls outside the configured scope. User-facing."""


def mask_pan(pan: str) -> str:
    """
    First six and last four, the rest masked — the standard PCI-DSS display.

    Short values are masked entirely rather than partially: a 10-digit string
    would otherwise show almost all of itself.
    """
    digits = "".join(c for c in pan if c.isalnum())
    if len(digits) < 13:
        return "*" * len(digits)
    return f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}"


def mask_track2(track: str) -> str:
    """
    Mask the PAN inside track 2 and drop everything after the separator.

    "=" has to survive normalisation: it is not alphanumeric, and stripping it
    first would hide the separator, leaving the expiry and service code to be
    masked as though they were part of the PAN — which lets the tail of the
    track data through.
    """
    raw = "".join(c for c in track if c.isalnum() or c == "=")
    for sep in ("D", "="):
        if sep in raw:
            pan, _, _rest = raw.partition(sep)
            return f"{mask_pan(pan)}{sep}..."
    return mask_pan(raw)


@dataclasses.dataclass
class Scope:
    """What this run is permitted to touch."""
    allowed_targets: tuple[str, ...] = ()
    test_bins: tuple[str, ...] = WELL_KNOWN_TEST_BINS
    on_live_pan: str = "warn"

    def __post_init__(self) -> None:
        if self.on_live_pan not in ON_LIVE_PAN:
            raise ScopeError(
                f"on_live_pan must be one of {', '.join(ON_LIVE_PAN)}, "
                f"got {self.on_live_pan!r}"
            )
        self.allowed_targets = tuple(t.strip().lower() for t in self.allowed_targets if t.strip())
        self.test_bins = tuple(b.strip() for b in self.test_bins if b.strip())

    # ── targets ──────────────────────────────────────────────────────────────

    def check_target(self, host: str, port: int) -> None:
        """Raise unless this exact host:port was allow-listed."""
        if not self.allowed_targets:
            raise ScopeError(
                "No target has been allow-listed, so there is nowhere this may "
                "connect. Name the host explicitly (--allow host:port) — the "
                "guard is what stops a typo from opening a link to something "
                "that was never in scope."
            )
        target = f"{host.strip().lower()}:{port}"
        if target not in self.allowed_targets:
            raise ScopeError(
                f"Target {target} is not in scope.\n"
                f"Allowed: {', '.join(sorted(self.allowed_targets))}\n"
                "Add it with --allow if it genuinely belongs to this engagement."
            )

    # ── cardholder data ──────────────────────────────────────────────────────

    def is_test_pan(self, pan: str) -> bool:
        digits = "".join(c for c in pan if c.isdigit())
        return any(digits.startswith(bin_) for bin_ in self.test_bins)

    def check_pan(self, pan: str) -> str | None:
        """
        Classify a PAN seen on the wire.

        Returns a warning string when it looks live, None when it is a known
        test number.  Raises ScopeError when the policy is to abort.
        """
        if not pan or self.is_test_pan(pan):
            return None
        message = (
            f"PAN {mask_pan(pan)} is outside the configured test ranges. "
            "If this link carries real cardholder data, stop: authorisation "
            "testing belongs against a certification host with test cards."
        )
        if self.on_live_pan == "abort":
            raise ScopeError(message)
        return message


def parse_target(text: str, default_port: int = 8583) -> tuple[str, int]:
    """Split "host:port" — IPv6 literals in brackets are handled."""
    raw = (text or "").strip()
    if not raw:
        raise ScopeError("Empty target")
    if raw.startswith("["):                       # [::1]:8583
        host, _, rest = raw.partition("]")
        host = host[1:]
        port = rest.lstrip(":")
        return host, int(port) if port else default_port
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        if not port.isdigit():
            raise ScopeError(f"Port {port!r} in {raw!r} is not a number")
        return host, int(port)
    return raw, default_port
