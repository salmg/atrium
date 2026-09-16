"""
Host-link transport interface.

Deliberately **not** modelled on ``transport.CardTransport`` from the card side.
That interface is ``transmit(apdu) -> response``: strict lockstep, one answer
per question, which is exactly right for a card.

A host link is not lockstep.  Several authorisations are in flight at once,
correlated by STAN and RRN rather than by arrival order, and unsolicited
traffic — network-management echoes, reversal advices — arrives with no request
to pair it against.  So ``send`` and ``receive`` are independent here, and
correlation is somebody else's job (see ``host.capture.Correlator``).

Forcing this into the card interface would have looked tidy and then quietly
mis-paired every response on a busy link.
"""
from __future__ import annotations

from abc import ABC, abstractmethod


class HostTransport(ABC):
    """Minimal interface for a framed message link to a payment host."""

    @abstractmethod
    def connect(self) -> None:
        """Open the link."""

    @abstractmethod
    def send(self, body: bytes) -> None:
        """Frame and write one message body."""

    @abstractmethod
    def receive(self, timeout: float | None = None) -> bytes | None:
        """
        Read one complete message body.

        Returns None when the peer closed cleanly or the timeout expired with
        nothing to deliver — both are ordinary on an idle link, neither is an
        error.
        """

    def close(self) -> None:
        """Close the link. Override if the transport needs clean-up."""
