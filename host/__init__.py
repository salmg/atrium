"""
Host-layer payment security testing — the acquirer/gateway/issuer link.

Sibling to ATRIUM, which works the card-present layer (card ⇄ terminal).  This
half works the message layer above it (acquirer ⇄ gateway ⇄ issuer), and the
two meet at DE55: field 55 of an ISO 8583 authorisation carries ICC data as
BER-TLV, the same encoding a card emits, so the TLV core is shared.

Deliberately independent of ATRIUM's root modules — nothing here imports
pyscard or virtualsmartcard, so this runs on a machine with no card reader.

Phase 1 (this package) is codec only: framing, dialects, pack/unpack, the DE55
bridge and dialect detection.  No sockets, no mutation engine, no crypto.
"""
