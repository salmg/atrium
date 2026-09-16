#!/usr/bin/env python3
"""
A/B the two ways of reaching the card in reader B's field.

Path 1 — what ContactlessTransport does today: SCARD_SHARE_DIRECT plus
         PN532 InDataExchange tunnelled through the CCID escape channel.
Path 2 — an ordinary PC/SC card connection: SCardConnect(T=1) + SCardTransmit,
         the ACR122U's own firmware ISO-DEP, no escape, no PN532 wrapper.

Both send the same SELECT PPSE the relay sends, N times, and print the
distribution. This is the measurement the 56-60 ms number needs before any
refactor is justified.

    python3 tools/bench_card_path.py --reader "ACS ACR122U PICC Interface 00 00"

It also prints, for path 2, the pseudo-ATR PC/SC synthesises and the answers to
FF CA 00 00 00 (UID) and FF CA 01 00 00 (real ATS) — the two questions the
transport's uid/get_atr depend on.
"""
from __future__ import annotations

import argparse
import statistics
import sys
import time

SELECT_PPSE = bytes.fromhex("00A404000E325041592E5359532E444446303100")

GET_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
GET_ATS = [0xFF, 0xCA, 0x01, 0x00, 0x00]


def _stats(label, samples):
    if not samples:
        print(f"  {label}: no samples")
        return
    ms = sorted(s * 1000 for s in samples)
    print(f"  {label}: n={len(ms)} min={ms[0]:.1f} med={statistics.median(ms):.1f} "
          f"p90={ms[int(len(ms) * 0.9) - 1]:.1f} max={ms[-1]:.1f} ms")


def path_direct(name, rounds):
    from nfc.acr122 import open_pn532

    chip, link = open_pn532(name, direct=True)
    try:
        chip.set_retries(2)
        targets = chip.list_passive_targets(limit=1)
        if not targets:
            print("  no card in the field")
            return []
        target = targets[0]
        print(f"  target: {target}")
        print(f"  ATS from InListPassiveTarget: {target.ats.hex().upper() or '(none)'}")
        samples = []
        for _ in range(rounds):
            began = time.monotonic()
            resp = chip.data_exchange(SELECT_PPSE, target=target.number)
            samples.append(time.monotonic() - began)
        print(f"  last response: {resp[:12].hex().upper()}… ({len(resp)} bytes)")
        chip.release(target.number)
        return samples
    finally:
        link.close()


def path_pcsc(name, rounds, exclusive):
    from smartcard.CardConnection import CardConnection
    from smartcard.scard import SCARD_SHARE_EXCLUSIVE, SCARD_SHARE_SHARED
    from smartcard.System import readers as list_readers

    target = next((r for r in list_readers() if str(r) == name), None)
    if target is None:
        print(f"  reader '{name}' not present")
        return []
    connection = target.createConnection()
    connection.connect(
        protocol=CardConnection.T1_protocol,
        mode=SCARD_SHARE_EXCLUSIVE if exclusive else SCARD_SHARE_SHARED)
    try:
        atr = bytes(connection.getATR())
        print(f"  pseudo-ATR: {atr.hex().upper()}")
        for label, apdu in (("UID  (FF CA 00 00 00)", GET_UID),
                            ("ATS  (FF CA 01 00 00)", GET_ATS)):
            data, sw1, sw2 = connection.transmit(apdu)
            print(f"  {label}: {bytes(data).hex().upper() or '(empty)'} "
                  f"SW {sw1:02X}{sw2:02X}")
        samples = []
        for _ in range(rounds):
            began = time.monotonic()
            data, sw1, sw2 = connection.transmit(list(SELECT_PPSE))
            samples.append(time.monotonic() - began)
        print(f"  last response: {bytes(data)[:12].hex().upper()}… "
              f"({len(data) + 2} bytes) SW {sw1:02X}{sw2:02X}")
        return samples
    finally:
        connection.disconnect()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reader", required=True, help="PC/SC name of reader B")
    ap.add_argument("--rounds", type=int, default=20)
    ap.add_argument("--exclusive", action="store_true",
                    help="take the card connection SCARD_SHARE_EXCLUSIVE")
    ap.add_argument("--both-at-once", action="store_true",
                    help="hold the direct connection open while card-connecting, "
                         "to see whether pcsc-lite allows it")
    args = ap.parse_args()

    print("\n── PN532 escape path (what the transport does now) ──")
    direct = path_direct(args.reader, args.rounds)
    _stats("InDataExchange via SCardControl", direct)

    print("\n── ordinary PC/SC card path ──")
    pcsc = path_pcsc(args.reader, args.rounds, args.exclusive)
    _stats("SCardTransmit T=1", pcsc)

    if direct and pcsc:
        saved = (statistics.median(direct) - statistics.median(pcsc)) * 1000
        print(f"\n  median difference: {saved:+.1f} ms per exchange")

    if args.both_at_once:
        print("\n── can one reader hold both connections? ──")
        from nfc.acr122 import ACR122Link
        link = ACR122Link(args.reader, direct=True)
        link.connect()
        try:
            try:
                path_pcsc(args.reader, 1, args.exclusive)
                print("  both connections coexisted")
            except Exception as exc:              # noqa: BLE001
                print(f"  card connection refused while direct is open: {exc}")
        finally:
            link.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
