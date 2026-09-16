"""
Command line for the host layer.

    # Watch a link and record everything that crosses it
    python3 -m host.cli proxy --listen 127.0.0.1:8583 --target sim.test:5000 \
        --allow sim.test:5000 --dialect base24 --capture logs/host.jsonl

    # Work out what a capture speaks
    python3 -m host.cli detect --capture logs/host.jsonl
    python3 -m host.cli detect --hex 0023303130307020...

    # Summarise what was recorded
    python3 -m host.cli inspect --capture logs/host.jsonl

    # List what dialects are available
    python3 -m host.cli dialects

    # Rewrite messages in flight per a playbook (changes the link!)
    python3 -m host.cli mutate --listen 127.0.0.1:8583 --target sim.test:5000 \
        --allow sim.test:5000 --playbook amount-mismatch --capture logs/host.jsonl

    # See what playbooks ship
    python3 -m host.cli playbooks

    # Replay a captured corpus at a host, with no acquirer in front
    python3 -m host.cli replay --capture logs/host.jsonl --target sim.test:5000 \
        --allow sim.test:5000                      # verbatim: duplicate detection
    python3 -m host.cli replay --capture logs/host.jsonl --target sim.test:5000 \
        --allow sim.test:5000 --freshen            # is the ARQC bound to the STAN?

    # Are the cryptograms in a capture genuine?
    HOST_IMK=0123... python3 -m host.cli verify --capture logs/host.jsonl

    # What the crypto has and has not been validated against
    python3 -m host.cli selftest
"""
from __future__ import annotations

import argparse
import logging
import sys
import time

from host.capture import CaptureLog, load_capture, summarise
from host.iso8583.detect import describe, detect
from host.iso8583.dialect import DialectError, available_dialects, load_dialect
from host.mutation import MutationError, available_playbooks, load_playbook
from host.scoping import Scope, ScopeError, parse_target

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
)
log = logging.getLogger("host")


def _setup(args: argparse.Namespace):
    """Shared preparation for both proxy modes. Returns (dialect, scope, ends)."""
    dialect = load_dialect(args.dialect)
    listen = parse_target(args.listen)
    target = parse_target(args.target)
    scope = Scope(
        allowed_targets=tuple(args.allow or ()),
        test_bins=(tuple(args.test_bin) if args.test_bin
                   else Scope.__dataclass_fields__["test_bins"].default),
        on_live_pan="abort" if args.abort_on_live_pan else "warn",
    )
    if listen[0] not in ("127.0.0.1", "localhost", "::1"):
        log.warning("Listening on %s — reachable beyond this machine. Anything "
                    "that can reach this port can drive the link.", listen[0])
    return dialect, scope, listen, target


def _run(proxy, capture, banner: str) -> int:
    print(banner)
    try:
        with proxy:
            while True:
                time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n  Stopping…")
    finally:
        capture.close()
    if capture.records:
        print()
        print(summarise([r.__dict__ for r in capture.records]))
    return 0


def cmd_proxy(args: argparse.Namespace) -> int:
    from host.proxy import PassiveProxy

    try:
        dialect, scope, listen, target = _setup(args)
    except (DialectError, ScopeError) as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 2

    capture = CaptureLog(args.capture, include_raw=not args.no_raw)
    try:
        proxy = PassiveProxy(*listen, *target, dialect=dialect, scope=scope,
                             capture=capture)
    except ScopeError as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        capture.close()
        return 2

    return _run(proxy, capture,
                f"\n  Passive proxy — observing only, nothing is modified.\n"
                f"    listen : {listen[0]}:{listen[1]}\n"
                f"    target : {target[0]}:{target[1]}\n"
                f"    dialect: {dialect.name}\n"
                f"    capture: {args.capture or '(memory only)'}\n\n"
                f"  Point the acquirer or terminal simulator at the listen address.\n"
                f"  Ctrl-C to stop.\n")


def cmd_mutate(args: argparse.Namespace) -> int:
    from host.proxy import MutatingProxy

    try:
        dialect, scope, listen, target = _setup(args)
        playbook = load_playbook(args.playbook)
    except (DialectError, MutationError, ScopeError) as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 2

    capture = CaptureLog(args.capture, include_raw=not args.no_raw)
    try:
        proxy = MutatingProxy(*listen, *target, dialect=dialect, scope=scope,
                              capture=capture, playbook=playbook)
    except (MutationError, ScopeError) as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        capture.close()
        return 2

    return _run(proxy, capture,
                f"\n  ** MUTATING PROXY — messages will be rewritten in flight. **\n\n"
                f"    listen : {listen[0]}:{listen[1]}\n"
                f"    target : {target[0]}:{target[1]}\n"
                f"    dialect: {dialect.name}\n"
                f"    capture: {args.capture or '(memory only)'}\n\n"
                f"  {playbook.summary()}\n\n"
                f"  Only messages a rule matches are re-encoded; everything else\n"
                f"  is forwarded byte for byte. Ctrl-C to stop.\n")


def cmd_playbooks(args: argparse.Namespace) -> int:
    names = available_playbooks()
    if not names:
        print("No playbooks found.")
        return 1
    for name in names:
        try:
            print(load_playbook(name).summary())
        except MutationError as exc:
            print(f"{name} ** unusable: {exc}")
        print()
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    from host.replay import (
        ReplayError, ReplaySession, describe_results, load_corpus, pan_of,
    )

    try:
        dialect = load_dialect(args.dialect)
        target = parse_target(args.target)
        playbook = load_playbook(args.playbook) if args.playbook else None
        scope = Scope(
            allowed_targets=tuple(args.allow or ()),
            test_bins=(tuple(args.test_bin) if args.test_bin
                       else Scope.__dataclass_fields__["test_bins"].default),
            on_live_pan="abort" if args.abort_on_live_pan else "warn",
        )
        items = load_corpus(args.capture, mti=tuple(args.mti or ()), limit=args.limit)
        imk = crypto_profile = None
        if args.imk or args.imk_file:
            imk, crypto_profile, _src = _load_keys(args)
    except (DialectError, MutationError, ReplayError, ScopeError) as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 2

    capture = CaptureLog(args.out, include_raw=not args.no_raw)
    try:
        session = ReplaySession(
            *target, dialect=dialect, scope=scope, capture=capture,
            playbook=playbook, freshen=args.freshen, timeout=args.timeout,
            imk=imk, crypto_profile=crypto_profile, psn=args.psn)
    except ScopeError as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        capture.close()
        return 2

    pans = {p for p in (pan_of(dialect, session.framing, i.raw) for i in items) if p}
    print(f"\n  ** REPLAY — this originates transactions against a live host. **\n\n"
          f"    target  : {target[0]}:{target[1]}\n"
          f"    corpus  : {args.capture} ({len(items)} message(s))\n"
          f"    mode    : {session.mode}"
          + (f" + playbook '{playbook.name}'" if playbook else "")
          + (f" + re-signed ({crypto_profile.name})" if imk else "") + "\n"
          f"    cards   : {', '.join(sorted(pans)) or 'none decoded'}\n")

    try:
        with session:
            report = session.run(items, delay=args.delay,
                                 preserve_timing=args.preserve_timing)
    except ScopeError as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"\n  Cannot reach {target[0]}:{target[1]} — {exc}\n", file=sys.stderr)
        return 1
    finally:
        capture.close()

    print(describe_results(report))
    print()
    print(report.summary())
    return 0


def _load_keys(args):
    """Resolve an IMK and profile, reporting how private the source was."""
    from host.crypto import load_imk, load_profile
    imk, source = load_imk(getattr(args, "imk", None), getattr(args, "imk_file", None))
    if "command line" in source:
        log.warning("The issuer master key was passed on the command line, where "
                    "any other process on this machine can read it out of ps. "
                    "Prefer --imk-file or $HOST_IMK.")
    return imk, load_profile(args.profile), source


def cmd_verify(args: argparse.Namespace) -> int:
    from host.crypto import CryptoError, derive_udk, verify_cryptogram
    from host.iso8583.codec import unpack_body
    from host.replay import ReplayError, load_corpus

    try:
        dialect = load_dialect(args.dialect)
        imk, profile, source = _load_keys(args)
        items = load_corpus(args.capture, limit=args.limit)
    except (CryptoError, DialectError, ReplayError) as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 2

    print(f"\n  Verifying cryptograms in {args.capture}\n"
          f"    profile: {profile.name} ({profile.session_key} session key)\n"
          f"    key     : IMK from {source}\n")

    checked = matched = skipped = 0
    for item in items:
        try:
            body, _ = dialect.framing.unwrap(item.raw)
            _tpdu, rest = dialect.framing.split_tpdu(body)
            msg = unpack_body(dialect, rest)
            pan = msg.fields.get(2)
            if not isinstance(pan, str) or not pan:
                print(f"  seq={item.seq:<4} no PAN — cannot derive a key")
                skipped += 1
                continue
            keys = derive_udk(imk, pan, args.psn)
            result = verify_cryptogram(msg, keys.udk, profile)
        except Exception as exc:                       # noqa: BLE001
            print(f"  seq={item.seq:<4} error: {exc}")
            skipped += 1
            continue

        if result.reason:
            skipped += 1
        else:
            checked += 1
            matched += int(result.matched)
        print(f"  seq={item.seq:<4} {result}")

    print()
    if not checked:
        print("Nothing could be checked. The most common causes are a profile "
              "that does not\nmatch the card's scheme, or DE55 missing tags the "
              "profile needs — the lines\nabove say which.")
        return 1
    print(f"{matched} of {checked} cryptogram(s) verified"
          + (f", {skipped} skipped" if skipped else "") + ".")
    if matched and matched == checked:
        print("The key and profile are right for this traffic — a mismatch from "
              "here on is\nevidence about the data, not about the setup.")
    elif not matched:
        print("Nothing verified. Doubt the profile before the key: try "
              "--profile emv-book2-iad\nor --profile udk-direct, and confirm "
              "against your target's own test vectors.")
    return 0


def cmd_selftest(args: argparse.Namespace) -> int:
    """Run the structural checks and be explicit about their limits."""
    from Crypto.Cipher import DES

    from host.crypto import (adjust_parity, arpc_method_1, compute_arqc,
                             derive_session_key, derive_udk, des3_encrypt,
                             has_odd_parity, mac_iso9797_alg3)

    checks: list[tuple[str, bool]] = []

    k = bytes.fromhex("0123456789ABCDEF")
    pt = bytes.fromhex("4E6F772069732074")
    single = DES.new(k, DES.MODE_ECB).encrypt(pt)
    checks.append(("3DES with K1==K2 reduces to single DES",
                   des3_encrypt(k + k, pt) == single))

    imk = bytes.fromhex("0123456789ABCDEFFEDCBA9876543210")
    a = derive_udk(imk, "4111111111111111").udk
    b = derive_udk(imk, "4111111111111112").udk
    checks.append(("UDK is deterministic", a == derive_udk(imk, "4111111111111111").udk))
    checks.append(("UDK differs per PAN", a != b))
    checks.append(("UDK is parity-adjusted", has_odd_parity(a)))

    sk1 = derive_session_key(a, bytes.fromhex("0001"))
    sk2 = derive_session_key(a, bytes.fromhex("0002"))
    checks.append(("session key differs per ATC", sk1 != sk2))
    checks.append(("session key is parity-adjusted", has_odd_parity(sk1)))

    data = bytes.fromhex("00" * 16)
    mac = mac_iso9797_alg3(a, data)
    checks.append(("MAC is 8 bytes", len(mac) == 8))
    checks.append(("MAC changes with the key",
                   mac != mac_iso9797_alg3(b, data)))
    checks.append(("MAC changes with the data",
                   mac != mac_iso9797_alg3(a, data[:-1] + b"\x01")))

    arqc = compute_arqc(sk1, data)
    checks.append(("ARPC differs per response code",
                   arpc_method_1(sk1, arqc, b"\x30\x30")
                   != arpc_method_1(sk1, arqc, b"\x30\x35")))
    checks.append(("parity adjustment is idempotent",
                   adjust_parity(adjust_parity(b"\x00" * 8)) == adjust_parity(b"\x00" * 8)))

    print()
    for name, ok in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")
    failed = [n for n, ok in checks if not ok]
    print()
    print("What this does and does not establish\n"
          "-------------------------------------\n"
          "Checked: the DES primitive against pycryptodome, and that derivation,\n"
          "MACing and ARPC generation are self-consistent and correctly\n"
          "diversified.\n\n"
          "NOT checked: that any profile matches a particular scheme's CVN. That\n"
          "data composition is confidential and ships here only as an editable\n"
          "profile. Before treating a verification result as evidence in a report,\n"
          "validate against test vectors from the target's own specification.")
    return 1 if failed else 0


def cmd_profiles(args: argparse.Namespace) -> int:
    from host.crypto import available_profiles, load_profile
    names = available_profiles()
    if not names:
        print("No cryptogram profiles found.")
        return 1
    print("Cryptogram profiles:")
    for name in names:
        p = load_profile(name)
        print(f"  {p.name:<16} {len(p.tags):>2} tags · {p.session_key} session key "
              f"· {p.padding}")
        if p.description:
            print(f"      {p.description}")
    return 0


def cmd_detect(args: argparse.Namespace) -> int:
    if args.hex:
        data = bytes.fromhex(args.hex.strip().replace(" ", ""))
    elif args.capture:
        records = load_capture(args.capture)
        raws = [r["raw"] for r in records if r.get("raw")]
        if not raws:
            print("Capture holds no raw bytes to analyse. Was it written with "
                  "--no-raw?", file=sys.stderr)
            return 1
        data = bytes.fromhex(raws[0])
    else:
        print("Give either --capture or --hex", file=sys.stderr)
        return 2

    print(describe(detect(data, limit=args.limit)))
    return 0


def cmd_inspect(args: argparse.Namespace) -> int:
    try:
        records = load_capture(args.capture)
    except OSError as exc:
        print(f"\nCannot read {args.capture}: {exc}\n", file=sys.stderr)
        return 1
    print(summarise(records))

    mutated = [r for r in records if r.get("mutations")]
    if mutated:
        print("\nMutations applied:")
        for r in mutated:
            for m in r["mutations"]:
                print(f"  seq={r.get('seq')} {r.get('leg','')} {m['target']} "
                      f"{m['mode']}: {m['before'] or '(absent)'} -> "
                      f"{m['after'] or '(deleted)'}")

    noted = [r for r in records if r.get("note")]
    if noted:
        print("\nMessages left alone:")
        for r in noted:
            print(f"  seq={r.get('seq')} {r['note']}")

    flagged = [r for r in records if r.get("discrepancies")]
    if flagged:
        print("\nDE55 discrepancies:")
        for r in flagged:
            for line in r["discrepancies"]:
                print(f"  seq={r.get('seq')} mti={r.get('mti')}  {line}")
    return 0


def cmd_dialects(args: argparse.Namespace) -> int:
    names = available_dialects()
    if not names:
        print("No dialects found.")
        return 1
    print("Available dialects:")
    for name in names:
        try:
            d = load_dialect(name)
        except DialectError as exc:
            print(f"  {name:<16} ** unusable: {exc}")
            continue
        tpdu = f", {d.framing.tpdu_length}-byte TPDU" if d.framing.tpdu_length else ""
        print(f"  {name:<16} {len(d.fields):>3} fields · {d.framing.mli_bytes}-byte "
              f"{d.framing.mli_encoding} MLI{tpdu} · {d.numeric_encoding} numerics")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="host",
        description="Host-layer payment testing — ISO 8583 codec, proxies and playbooks",
    )
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    def _proxy_args(parser_):
        parser_.add_argument("--listen", default="127.0.0.1:8583",
                             help="Where the acquirer or terminal connects (default %(default)s)")
        parser_.add_argument("--target", required=True, help="The real host, as host:port")
        parser_.add_argument("--allow", action="append", metavar="HOST:PORT",
                             help="Allow-list a target. Required; repeatable.")
        parser_.add_argument("--dialect", default="iso8583-1987")
        parser_.add_argument("--capture", default=None, metavar="FILE",
                             help="JSONL capture path")
        parser_.add_argument("--no-raw", action="store_true",
                             help="Omit raw bytes from the capture (loses replay value)")
        parser_.add_argument("--test-bin", action="append", metavar="PREFIX",
                             help="BIN prefix to treat as test data; repeatable")
        parser_.add_argument("--abort-on-live-pan", action="store_true",
                             help="Stop if a PAN outside the test ranges appears")
        return parser_

    p = _proxy_args(sub.add_parser(
        "proxy", help="Relay a link and record what crosses it, changing nothing"))
    p.set_defaults(func=cmd_proxy)

    p = _proxy_args(sub.add_parser(
        "mutate", help="Relay a link and rewrite messages per a playbook"))
    p.add_argument("--playbook", required=True,
                   help="Playbook name or path to a YAML file")
    p.set_defaults(func=cmd_mutate)

    p = sub.add_parser("playbooks", help="List available playbooks")
    p.set_defaults(func=cmd_playbooks)

    p = sub.add_parser("replay", help="Replay a captured corpus at a host")
    p.add_argument("--capture", required=True, metavar="FILE",
                   help="Capture to replay from")
    p.add_argument("--target", required=True, help="The host, as host:port")
    p.add_argument("--allow", action="append", metavar="HOST:PORT",
                   help="Allow-list a target. Required; repeatable.")
    p.add_argument("--dialect", default="iso8583-1987")
    p.add_argument("--freshen", action="store_true",
                   help="Rewrite STAN/RRN/date-time; DE55 and its cryptogram "
                        "are reused as captured")
    p.add_argument("--playbook", default=None,
                   help="Also apply a mutation playbook to each message")
    p.add_argument("--mti", action="append", metavar="MTI",
                   help="Only replay these MTIs; repeatable")
    p.add_argument("--limit", type=int, default=0, metavar="N")
    p.add_argument("--delay", type=float, default=0.0, metavar="SECONDS")
    p.add_argument("--preserve-timing", action="store_true",
                   help="Reproduce the gaps between the captured messages")
    p.add_argument("--timeout", type=float, default=30.0, metavar="SECONDS")
    p.add_argument("--out", default=None, metavar="FILE",
                   help="Write a capture of the replay itself")
    p.add_argument("--no-raw", action="store_true")
    p.add_argument("--test-bin", action="append", metavar="PREFIX")
    p.add_argument("--abort-on-live-pan", action="store_true",
                   help="Stop if a PAN outside the test ranges appears")
    p.add_argument("--imk-file", default=None, metavar="FILE",
                   help="Recompute the ARQC after transforming, using this key")
    p.add_argument("--imk", default=None, metavar="HEX")
    p.add_argument("--profile", default="emv-book2")
    p.add_argument("--psn", default="00", metavar="NN")
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("verify", help="Check the cryptograms in a capture")
    p.add_argument("--capture", required=True, metavar="FILE")
    p.add_argument("--dialect", default="iso8583-1987")
    p.add_argument("--profile", default="emv-book2",
                   help="Cryptogram data profile (default %(default)s)")
    p.add_argument("--imk-file", default=None, metavar="FILE",
                   help="File holding the issuer master key in hex")
    p.add_argument("--imk", default=None, metavar="HEX",
                   help="Issuer master key. Visible in ps — prefer --imk-file "
                        "or $HOST_IMK.")
    p.add_argument("--psn", default="00", metavar="NN")
    p.add_argument("--limit", type=int, default=0, metavar="N")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("selftest", help="Check the crypto and state its limits")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("profiles", help="List cryptogram profiles")
    p.set_defaults(func=cmd_profiles)

    p = sub.add_parser("detect", help="Work out what dialect a capture speaks")
    p.add_argument("--capture", default=None, metavar="FILE")
    p.add_argument("--hex", default=None, metavar="HEX")
    p.add_argument("--limit", type=int, default=5)
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("inspect", help="Summarise a capture")
    p.add_argument("--capture", required=True, metavar="FILE")
    p.set_defaults(func=cmd_inspect)

    p = sub.add_parser("dialects", help="List available dialects")
    p.set_defaults(func=cmd_dialects)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
