"""
Abstract card transport interface.

Any concrete transport (local pyscard, remote TCP proxy, …) must subclass
``CardTransport`` and implement the three methods below.  The rest of the
application only depends on this interface so the backend can be swapped
without changing any higher-level logic.
"""
from abc import ABC, abstractmethod


class CardTransport(ABC):
    """Minimal interface for communicating with an EMV card."""

    @abstractmethod
    def connect(self) -> None:
        """Open the connection to the card (reader, socket, …)."""

    @abstractmethod
    def get_atr(self) -> bytes:
        """Return the card's Answer-To-Reset bytes."""

    @abstractmethod
    def transmit(self, apdu: bytes) -> bytes:
        """
        Send a command APDU and return the full response APDU (data + SW).

        Parameters
        ----------
        apdu:
            Raw command APDU bytes (CLA INS P1 P2 [Lc data] [Le]).

        Returns
        -------
        bytes
            Response data followed by two status-word bytes (SW1 SW2).
        """

    def disconnect(self) -> None:
        """Close the connection.  Override if the transport needs clean-up."""
