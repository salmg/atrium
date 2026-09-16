"""
transport — host-link I/O.

Lazy imports so ``HostTransport`` can be referenced for typing without opening
a socket module path that the caller may not need.
"""
from host.transport.base import HostTransport  # noqa: F401

__all__ = ["HostTransport", "TcpLink"]


def __getattr__(name: str):
    if name == "TcpLink":
        from host.transport.link import TcpLink
        return TcpLink
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
