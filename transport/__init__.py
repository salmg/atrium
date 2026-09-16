"""
transport — card I/O backend abstraction.

A uniform interface for talking to an EMV card wherever it is: in a local
reader, behind the remote card proxy, or in an ACR122U's RF field.

Imports are lazy on purpose.  Each backend pulls in a dependency the others do
not need — pyscard for the local reader, the TLS machinery for the remote one —
and the machine running card_proxy.py must be able to import ``transport.remote``
without the rest.
"""
from transport.base import CardTransport  # noqa: F401

__all__ = ["CardTransport", "ContactlessTransport", "LocalCardTransport",
           "NFCGateTransport", "RemoteCardTransport"]


def __getattr__(name: str):
    """PEP 562 lazy attributes — resolved only when actually referenced."""
    if name == "LocalCardTransport":
        from transport.local import LocalCardTransport
        return LocalCardTransport
    if name == "RemoteCardTransport":
        from transport.remote import RemoteCardTransport
        return RemoteCardTransport
    if name == "ContactlessTransport":
        from transport.contactless import ContactlessTransport
        return ContactlessTransport
    if name == "NFCGateTransport":
        from transport.nfcgate import NFCGateTransport
        return NFCGateTransport
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
