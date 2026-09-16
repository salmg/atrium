"""
nfcgate — speaking NFCGate's relay protocol, so a phone can be a card source.

`NFCGate <https://github.com/nfcgate/nfcgate>`_ is an Android app that relays
NFC traffic between two devices through a `server
<https://github.com/nfcgate/server>`_: one phone reads a tag, the other presents
it over Host Card Emulation.  Both are Apache-2.0, from TU Darmstadt's Secure
Mobile Networking Lab.

The server turns out not to understand NFC at all — it reads a length-prefixed
frame, notes a one-byte session number, and forwards the payload verbatim to
every *other* client in that session.  It never parses what it carries.  So
anything that speaks the framing is indistinguishable from a phone, and ATRIUM
can be one of the two peers rather than bolting onto a pair of them.

That is what this package is: the wire format (``proto``) and a client for one
side of a session (``session``).  ``transport.nfcgate`` builds a
``CardTransport`` on top, which is the part the rest of ATRIUM sees.

Imports are lazy for the same reason as ``transport``: nothing here should drag
in a socket for a caller that only wants to decode a captured frame.

See ``doc/nfcgate-android.md`` for the protocol notes this was written from.
"""
from nfcgate.proto import (  # noqa: F401
    CARD,
    CONTINUATION,
    INITIAL,
    READER,
    NFCData,
    TagConfig,
    decode_nfcdata,
    decode_serverdata,
    encode_nfcdata,
    encode_serverdata,
    parse_config_stream,
)

__all__ = [
    "CARD", "CONTINUATION", "INITIAL", "READER",
    "NFCData", "TagConfig",
    "decode_nfcdata", "decode_serverdata",
    "encode_nfcdata", "encode_serverdata",
    "parse_config_stream",
    "NFCGateSession", "NFCGateError",
]


def __getattr__(name: str):
    """PEP 562 lazy attributes — the socket layer only when it is used."""
    if name in ("NFCGateSession", "NFCGateError"):
        from nfcgate import session
        return getattr(session, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
