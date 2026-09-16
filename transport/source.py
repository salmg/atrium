"""
Choosing what an emulated card relays to.

Card emulation needs a card on the other side, and there are five places it can
be — including, since NFCGate, an Android phone holding one in its RF field.
Resolving that in one place keeps the CLI and the dashboard offering the
same choices and refusing the same mistakes — chiefly the one that looks like a
hardware fault: pointing the relay at the very reader that is presenting the
emulated card. One ACR122U cannot be a target and an initiator at the same
time, and the failure that comes out of trying is a timeout, not a message.
"""
from __future__ import annotations

import logging

from transport.base import CardTransport

logger = logging.getLogger(__name__)


class CardSourceError(ValueError):
    """No usable card source. User-facing."""


def open_card_source(
    *,
    from_file: str | None = None,
    remote: bool = False,
    remote_host: str = "127.0.0.1",
    remote_port: int = 7654,
    pairing: str | None = None,
    reader: int | str | None = None,
    exclude_reader: str | None = None,
    strict_replay: bool = False,
    nfcgate: bool = False,
    nfcgate_host: str = "127.0.0.1",
    nfcgate_port: int = 5566,
    nfcgate_session: int = 1,
    nfcgate_cafile: str | None = None,
) -> tuple[CardTransport, str]:
    """
    Build the transport the emulator relays to, and a phrase describing it.

    ``exclude_reader`` is the reader doing the emulating; it is never chosen as
    the card side, and naming it explicitly is an error rather than a silent
    substitution.
    """
    if from_file:
        from transport.recorded import RecordedCardTransport

        return RecordedCardTransport(from_file, strict=strict_replay), f"recorded capture {from_file}"

    if remote:
        from transport.remote import RemoteCardTransport

        return (RemoteCardTransport(host=remote_host, port=remote_port, pairing=pairing),
                "remote card")

    if nfcgate:
        from nfcgate.session import NFCGateError
        from transport.nfcgate import NFCGateTransport

        try:
            card = NFCGateTransport(
                nfcgate_host, nfcgate_port, nfcgate_session, cafile=nfcgate_cafile)
        except NFCGateError as exc:
            # A bad session number is caught here rather than at connect time,
            # so the message lands next to the field that is wrong.
            raise CardSourceError(str(exc)) from exc

        return card, f"a card on a phone, in NFCGate session {nfcgate_session}"

    chosen = _pick_card_reader(reader, exclude_reader)

    if chosen.is_pn532:
        from transport.contactless import ContactlessTransport

        return ContactlessTransport(reader_name=chosen.name), f"contactless card on {chosen.name}"

    from transport.local import LocalCardTransport

    return LocalCardTransport(chosen.index), f"card in {chosen.name}"


def _pick_card_reader(spec, exclude_reader: str | None):
    """The reader holding the card, honouring a spec or choosing sensibly."""
    from core.readers import CONTACT, ReaderError, probe, resolve

    if spec is not None and spec != "":
        try:
            chosen = resolve(spec)
        except ReaderError as exc:
            raise CardSourceError(str(exc)) from exc
        if exclude_reader and chosen.name == exclude_reader:
            raise CardSourceError(
                f"'{chosen.name}' is the reader presenting the emulated card, so it "
                f"cannot also hold the card being relayed. Use a second reader — a "
                f"second ACR122U works — or relay to a recorded capture instead.")
        if chosen.is_virtual:
            raise CardSourceError(
                f"'{chosen.name}' is the virtual reader — ATRIUM's own output side, "
                f"not a slot holding a card.")
        return chosen

    readers, problem = probe()
    candidates = [r for r in readers
                  if not r.is_virtual and r.name != exclude_reader]
    if not candidates:
        raise CardSourceError(
            "No reader is available to hold the card being relayed. "
            + (f"{problem} " if problem else "")
            + "Plug in a second reader — a second ACR122U works — or relay to a "
              "recorded capture with a capture file instead.")

    # Contact first: it is the interface ATRIUM knows best, and a contactless
    # card sitting in a second ACR122U's field is the fallback rather than the
    # assumption.
    contact = [r for r in candidates if r.kind == CONTACT]
    return (contact or candidates)[0]
