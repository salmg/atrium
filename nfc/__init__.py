"""
nfc — contactless support, via the PN532 inside an ACR122U.

    from nfc import ACR122Link, PN532, open_pn532

The ACR122U is the only supported hardware, and it is always reached over USB
through PC/SC: as an ordinary reader for contactless cards, and — through the
vendor escape that carries the chip's own commands — as a card emulator.

Contactless is a different transaction shape from the contact relay the rest of
ATRIUM does. The APDUs are the same currency, so fingerprinting, mutation and
logging all apply, but a contactless card answers with an ATS rather than an
ATR and the terminal kernel differs.
"""
from nfc.acr122 import ACR122Error, ACR122Link, open_pn532
from nfc.emulator import CardEmulator, EmulatedCard
from nfc.pn532 import PN532, PN532Error, Target, build_command, parse_frame

__all__ = [
    "ACR122Error", "ACR122Link", "CardEmulator", "EmulatedCard", "PN532",
    "PN532Error", "Target", "build_command", "open_pn532", "parse_frame",
]
