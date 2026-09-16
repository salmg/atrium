"""
atrium.py — ATRIUM command-line entry point.

Usage
-----
  # Start the web UI + API server
  python3 atrium.py serve [--port 8000] [--host 127.0.0.1]

  # Run the relay (virtual card <-> physical card)
  python3 atrium.py relay [--reader 0]

  # Run the AI agent
  python3 atrium.py agent [--reader 0] [--task "..."] [--model ...]
                        [--brute-sfi] [--non-interactive]

  # Start the remote card proxy (run on the machine with the physical reader)
  python3 atrium.py proxy [--proxy-host 127.0.0.1] [--proxy-port 7654] [--reader 0]

  # Start relay + web server together
  python3 atrium.py all [--reader 0] [--port 8000]
"""
from __future__ import annotations

import argparse
import logging
import os
import sys


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(name)s — %(message)s",
)
logger = logging.getLogger("atrium")


def _guard_bind(host: str) -> None:
    """
    Binding beyond loopback exposes card control to the network. The API has no
    login, so require a shared token before allowing it rather than silently
    serving an open control plane.
    """
    import ipaddress
    try:
        loopback = ipaddress.ip_address(host).is_loopback
    except ValueError:
        loopback = host in ("localhost",)
    if loopback:
        return
    if not os.environ.get("ATRIUM_API_TOKEN"):
        sys.exit(
            f"\nRefusing to bind {host} without authentication.\n\n"
            "This would let anyone who can reach this port drive the card relay.\n"
            "Either bind loopback (--host 127.0.0.1, the default), or set a token:\n\n"
            "    export ATRIUM_API_TOKEN=\"$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')\"\n\n"
            "Also set ATRIUM_ALLOWED_HOSTS to the name or address you serve on.\n"
        )
    logging.getLogger("atrium").warning(
        "Serving on %s — reachable beyond this machine. Token auth is enabled.", host
    )


def cmd_serve(args: argparse.Namespace) -> None:
    _guard_bind(args.host)
    try:
        import uvicorn
    except ImportError:
        print("uvicorn is required: pip install uvicorn[standard]", file=sys.stderr)
        sys.exit(1)
    uvicorn.run(
        "api.server:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


VPCD_HOST = "0.0.0.0"
VPCD_PORT = 35963


def _make_virtual_card(
    reader_index: int,
    brute_sfi: bool = False,
    remote: bool = False,
    remote_host: str = "127.0.0.1",
    remote_port: int = 7654,
    pairing: str | None = None,
):
    """
    Build the relay stack. The card is either in a local reader or behind a
    card_proxy.py instance on another host; everything above the transport is
    identical either way.
    """
    from virtual_card import VirtualCard
    from intercept_attack import InterceptAttack

    if remote:
        from remote_relay_os import RemoteRelayOS
        os_ = RemoteRelayOS(remote_host, remote_port, pairing=pairing)
    else:
        from relay_os import RelayOS
        os_ = RelayOS(reader_index)
    attack = InterceptAttack(
        os=os_,
        response=None,
        allresponse=None,
        allcommand="0",
        command=None,
        cvm="0",
        brutef=1 if brute_sfi else 0,
        chkcounter="0",
    )
    return VirtualCard(VPCD_HOST, VPCD_PORT, os_, attack)


def cmd_relay(args: argparse.Namespace) -> None:
    logger.info("Starting relay (reader: %s) — waiting for terminal…",
                args.reader if args.reader is not None else "auto")
    _make_virtual_card(args.reader).run()


def cmd_agent(args: argparse.Namespace) -> None:
    from llm_provider import ProviderUnavailable, resolve_provider
    # Fail fast with setup guidance rather than deep inside the agent loop
    try:
        resolve_provider(args.provider, args.model)
    except ProviderUnavailable as exc:
        sys.exit(f"\n{exc}\n")

    from emv_agent import run_agent
    run_agent(
        reader_index=args.reader,
        provider=args.provider,
        model=args.model,
        brute_sfi=args.brute_sfi,
        task=args.task,
        task_file=getattr(args, 'task_file', None),
        non_interactive=args.non_interactive,
        system_extra=getattr(args, 'system_extra', None),
    )


def cmd_pair(args: argparse.Namespace) -> None:
    """Print the pairing string a rig operator needs to reach this card."""
    from secure_link import load_or_create_identity, make_pairing

    _, _, fingerprint, token = load_or_create_identity(rotate=args.rotate)
    pairing = make_pairing(args.advertise_host, args.port, fingerprint, token)

    if args.rotate:
        print("\n  Identity rotated — every previously issued pairing string is "
              "now invalid.\n")

    print("\n  Pairing string for this host:\n")
    print("    " + pairing)
    print("\n  Certificate fingerprint (SHA-256):")
    print("    " + fingerprint)
    print("\n  Give the string to the rig operator over a channel you trust —")
    print("  it carries the access token. Then serve the card with:\n")
    print(f"    python3 card_proxy.py --secure --host 0.0.0.0 "
          f"--port {args.port} --reader {args.reader}\n")


def cmd_nfc(args: argparse.Namespace) -> None:
    """Contactless: read a card, or emulate one, through an ACR122U."""
    from core.readers import ReaderError

    try:
        if args.nfc_action == "scan":
            from transport.contactless import ContactlessTransport

            card = ContactlessTransport(reader_name=args.reader)
            card.connect()
            try:
                print(f"\n  UID : {card.uid.hex().upper()}")
                print(f"  ATS : {card.get_atr().hex().upper() or '(none)'}\n")
            finally:
                card.disconnect()
            return

        if args.nfc_action == "info":
            from nfc.acr122 import open_pn532
            from core.readers import probe

            name = args.reader
            if not name:
                readers, problem = probe()
                pn532s = [r for r in readers if r.is_pn532]
                if not pn532s:
                    sys.exit(f"\nNo PN532-based reader found. {problem}\n")
                name = pn532s[0].name
            chip, link = open_pn532(name, direct=True)
            try:
                info = chip.firmware_version()
                print(f"\n  {name}")
                print(f"  chip {info['chip']} firmware {info['version']}\n")
            finally:
                link.close()
            return

        if args.nfc_action == "identify":
            from nfc.acr122 import identify
            from core.readers import describe_location, physical_id, probe

            name = args.reader
            if not name:
                readers, problem = probe()
                pn532s = [r for r in readers if r.is_pn532]
                if not pn532s:
                    sys.exit(f"\nNo PN532-based reader found. {problem}\n")
                name = pn532s[0].name

            identify(name, repeat=args.repeat, buzzer=args.buzzer)
            where = describe_location(physical_id(name))
            print(f"\n  Blinking '{name}'.")
            if where:
                print(f"  {where}")
            print("  Watch the readers — the one that lit up is this one.\n")
            return

        if args.nfc_action == "probe":
            from nfc.probe import probe as probe_reader
            from core.readers import probe as probe_readers

            name = args.reader
            if not name:
                readers, problem = probe_readers()
                pn532s = [r for r in readers if r.is_pn532]
                if not pn532s:
                    sys.exit(f"\nNo PN532-based reader found. {problem}\n")
                name = pn532s[0].name
            probe_reader(name, wait=args.wait)
            return

        if args.nfc_action == "measure-ats":
            from nfc.probe import measure_emulated_ats
            from core.readers import probe as probe_readers

            readers, problem = probe_readers()
            pn532s = [r for r in readers if r.is_pn532]
            if len(pn532s) < 2 and not (args.reader and args.with_reader):
                sys.exit("\nThis needs two PN532 readers: one to arm as a card "
                         "and one to read it.\n" + (problem or ""))
            target = args.reader or pn532s[0].name
            other = args.with_reader or next(
                r.name for r in pn532s if r.name != target)
            measure_emulated_ats(target, other, wait=args.wait)
            return

        if args.nfc_action == "transmit-limit":
            from nfc.probe import measure_transmit_limit
            from core.readers import probe as probe_readers

            name = args.reader
            if not name:
                readers, problem = probe_readers()
                pn532s = [r for r in readers if r.is_pn532]
                if not pn532s:
                    sys.exit(f"\nNo PN532-based reader found. {problem}\n")
                name = pn532s[0].name
            measure_transmit_limit(name)
            return

        if args.nfc_action == "emulate":
            _run_emulator(args)
            return
    except ReaderError as exc:
        sys.exit(f"\n{exc}\n")


def _run_emulator(args: argparse.Namespace) -> None:
    """Present an emulated card to a terminal, relaying to a real one."""
    from nfc.acr122 import open_pn532
    from nfc.emulator import CardEmulator
    from core.readers import probe

    name = args.reader
    if not name:
        readers, problem = probe()
        pn532s = [r for r in readers if r.is_pn532]
        if not pn532s:
            sys.exit(f"\nNo PN532-based reader to emulate with. {problem}\n")
        name = pn532s[0].name

    from transport.source import CardSourceError, open_card_source

    try:
        card, described = open_card_source(
            from_file=args.from_file,
            remote=args.remote,
            remote_host=args.remote_host,
            remote_port=args.remote_port,
            pairing=args.pairing,
            reader=args.card_reader,
            exclude_reader=name,
            strict_replay=args.strict_replay,
            nfcgate=args.nfcgate,
            nfcgate_host=args.nfcgate_host,
            nfcgate_port=args.nfcgate_port,
            nfcgate_session=args.nfcgate_session,
            nfcgate_cafile=args.nfcgate_cafile,
        )
    except CardSourceError as exc:
        sys.exit(f"\n{exc}\n")

    engine = None
    if args.mutate:
        try:
            from mutation_engine import MutationEngine

            engine = MutationEngine.from_config(
                args.mutations, os=_OsShim(card.transmit))
        except Exception as exc:                       # noqa: BLE001
            sys.exit(f"\nCould not load {args.mutations}: {exc}\n")

    def _log(command: bytes, response: bytes) -> None:
        logger.info("%s -> %s", command.hex().upper(), response.hex().upper())

    # After the mutation engine has bound _OsShim(card.transmit), never before:
    # an injected command's whole value is the card's real answer to something
    # the terminal never sent, so it must reach the card rather than a cache.
    # A recorded capture is excluded too — it answers from deques that a
    # warm-up would consume, shifting every later loose match.
    if args.prefetch:
        from transport.prefetch import PrefetchingTransport
        from transport.recorded import RecordedCardTransport

        if isinstance(card, RecordedCardTransport):
            print("\n  --prefetch does nothing for a recorded capture, which "
                  "already answers instantly. Ignoring it.\n")
        else:
            card = PrefetchingTransport(card)

    chip, link = open_pn532(name, direct=True)

    if args.own_isodep:
        from nfc.emulator import IsoDepEmulator
        from nfc.isodep import Ats, fwt_seconds

        ats = Ats(fwi=args.fwi)
        emulator = IsoDepEmulator(chip, card, on_apdu=_log, mutations=engine,
                                  ats=ats, wtxm=args.wtxm,
                                  alert=not args.no_alert)
        layer = (f"ours — FWI {args.fwi} ({fwt_seconds(args.fwi) * 1000:.0f} ms), "
                 f"S(WTX) x{args.wtxm}, chaining on")
    else:
        emulator = CardEmulator(chip, card, on_apdu=_log, mutations=engine,
                                alert=not args.no_alert,
                                split_responses=args.split_responses)
        layer = "the chip's — no S(WTX), one frame per response"
        if args.split_responses:
            layer += "; long answers offered as 61 XX"

    from util import build_stamp

    if getattr(args, "trace_chip", False):
        import logging as _logging

        from nfc.acr122 import wire
        wire.setLevel(_logging.INFO)

    print(f"\n  ** CARD EMULATION — presenting a card on '{name}'. **\n\n"
          f"  Relaying to: {described}\n"
          f"  Mutations:   {args.mutations if engine else 'off'}\n"
          f"  ISO-DEP:     {layer}\n"
          f"  Prefetch:    {'PPSE and AIDs served from memory' if args.prefetch else 'off — every exchange is live'}\n"
          f"  Build:       {build_stamp()}\n"
          f"  Hold the reader to a terminal. It stays armed after each one\n"
          f"  lets go, because terminals often read a card and come back.\n"
          f"  Ctrl-C to stop.\n")
    try:
        emulator.run()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    finally:
        sessions = getattr(emulator, "sessions", 0)
        if sessions > 1:
            print(f"\n  {sessions} terminal session(s) — it let go and came "
                  f"back, which one exchange on its own would have hidden.")
        hits = getattr(card, "hits", 0)
        if hits:
            print(f"\n  {hits} exchange(s) answered from the warm-up, "
                  f"{getattr(card, 'misses', 0)} went to the card.")
        if emulator.oversize:
            print(f"\n  {emulator.oversize} mutated response(s) did not fit one "
                  f"exchange and were relayed unmutated — see the log.\n")
        if getattr(emulator, "wtx_requests", 0):
            print(f"\n  Asked the terminal for more time {emulator.wtx_requests} "
                  f"time(s); {emulator.chained_out} response(s) were chained.\n")
        link.close()


class _OsShim:
    """
    The ``.execute(apdu)`` shape MutationEngine.from_config expects.

    Injected commands go to the relayed card, whatever kind of transport is
    holding it, so this adapts a plain transmit callable rather than requiring
    a RelayOS.
    """

    def __init__(self, transmit) -> None:
        self.execute = transmit


def cmd_readers(args: argparse.Namespace) -> None:
    """Show every reader, what kind it is, and which one would be chosen."""
    from core.readers import describe

    print()
    print(describe(details=args.details))
    print()


def cmd_proxy(args: argparse.Namespace) -> None:
    import card_proxy
    sys.argv = [
        'card_proxy',
        '--host', args.proxy_host,
        '--port', str(args.proxy_port),
        '--reader', str(args.reader if args.reader is not None else ''),
    ]
    if args.secure:
        sys.argv.append('--secure')
    if args.insecure_plaintext:
        sys.argv.append('--insecure-plaintext')
    card_proxy.main()


def cmd_all(args: argparse.Namespace) -> None:
    import threading

    relay_thread = threading.Thread(target=cmd_relay, args=(args,), daemon=True, name="relay")
    relay_thread.start()
    logger.info("Relay started in background thread")

    cmd_serve(args)


def build_parser() -> argparse.ArgumentParser:
    """
    Every command and flag ATRIUM accepts.

    Separate from main() so it can be parsed in a test. It was inside
    main() and therefore unreachable from one, which is how a flag shipped
    with its two uses wired up and its definition missing: pyflakes cannot
    see an argparse attribute and six hundred tests never ran the parser.
    """
    parser = argparse.ArgumentParser(
        prog="atrium",
        description="ATRIUM — Payment Security: a research assistant for EMV payment systems",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--debug", action="store_true",
                        help="Enable DEBUG logging")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    # serve
    p_serve = sub.add_parser("serve", help="Start the web UI + API server")
    p_serve.add_argument("--host",   default="127.0.0.1")
    p_serve.add_argument("--port",   type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true")

    # relay
    p_relay = sub.add_parser("relay", help="Start the APDU relay (virtual card <-> physical card)")
    p_relay.add_argument("--reader", "-r", default=None, metavar="INDEX|NAME",
                         help="Reader index or name fragment; auto-selected when omitted")

    # agent
    p_agent = sub.add_parser("agent", help="Run the AI research agent")
    p_agent.add_argument("--reader", "-r", default=None, metavar="INDEX|NAME")
    p_agent.add_argument("--task",            "-t", default=None, metavar="TEXT")
    p_agent.add_argument("--task-file",             default=None, metavar="FILE")
    p_agent.add_argument("--model",                 default=None,
                         help="Model id; defaults to the provider default or $ATRIUM_LLM_MODEL")
    p_agent.add_argument("--provider", "-P",        default=None,
                         choices=["anthropic", "openai", "local"],
                         help="Model back end; auto-detected from the environment when omitted")
    p_agent.add_argument("--brute-sfi",             action="store_true")
    p_agent.add_argument("--non-interactive", "--auto", action="store_true")
    p_agent.add_argument("--system-extra",          default=None, metavar="TEXT")

    # pair
    p_pair = sub.add_parser(
        "pair", help="Print the pairing string for sharing this card securely")
    p_pair.add_argument("--advertise-host", default="",
                        metavar="HOST",
                        help="Address the rig operator will dial (public IP or DNS name)")
    p_pair.add_argument("--port",   type=int, default=7654)
    p_pair.add_argument("--reader", default=None, metavar="INDEX|NAME")
    p_pair.add_argument("--rotate", action="store_true",
                        help="Generate a new identity, invalidating old pairing strings")

    # readers
    p_readers = sub.add_parser(
        "readers", help="List PC/SC readers and which one is used by default")
    p_readers.add_argument("--details", action="store_true",
                           help="Also show each reader's USB address and serial — "
                                "what tells two of the same model apart")

    # nfc — contactless, via an ACR122U
    p_nfc = sub.add_parser("nfc", help="Contactless: read or emulate a card (ACR122U)")
    nfc_sub = p_nfc.add_subparsers(dest="nfc_action", metavar="ACTION")

    p_info = nfc_sub.add_parser("info", help="Show the PN532 firmware version")
    p_info.add_argument("--reader", default=None, metavar="NAME")

    p_scan = nfc_sub.add_parser("scan", help="Read the UID and ATS of a card in the field")
    p_scan.add_argument("--reader", default=None, metavar="NAME")

    p_ident = nfc_sub.add_parser(
        "identify", help="Blink a reader's LED so you can see which one it is")
    p_ident.add_argument("--reader", default=None, metavar="NAME")
    p_ident.add_argument("--repeat", type=int, default=3, metavar="N",
                         help="How many times to blink (default 3)")
    p_ident.add_argument("--buzzer", action="store_true",
                         help="Sound the buzzer too")

    p_probe = nfc_sub.add_parser(
        "probe", help="Dump the raw reader traffic for target mode (diagnostic)")
    p_probe.add_argument("--reader", default=None, metavar="NAME")
    p_probe.add_argument("--wait", type=float, default=8.0, metavar="SECONDS",
                         help="How long to poll after TgInitAsTarget — present "
                              "a terminal during this window (default 8)")

    p_ats = nfc_sub.add_parser(
        "measure-ats",
        help="Arm one reader as a card and read its ATS with another, to find "
             "out what frame waiting time the chip really advertises")
    p_ats.add_argument("--reader", default=None, metavar="NAME",
                       help="The reader to arm as a card")
    p_ats.add_argument("--with-reader", default=None, metavar="NAME",
                       help="The reader that reads it")
    p_ats.add_argument("--wait", type=float, default=20.0, metavar="SECONDS")

    p_limit = nfc_sub.add_parser(
        "transmit-limit",
        help="Find how large a Direct Transmit the reader answers — the number "
             "that decides whether a certificate record can reach the chip")
    p_limit.add_argument("--reader", default=None, metavar="NAME")

    p_emu = nfc_sub.add_parser(
        "emulate", help="Present an emulated card to a terminal, relaying to a real card")
    p_emu.add_argument("--reader", default=None, metavar="NAME",
                       help="The ACR122U that will present the card")
    p_emu.add_argument("--card-reader", default=None, metavar="INDEX|NAME",
                       help="Where the relayed card is — a second ACR122U works; "
                            "auto-selected when omitted")
    p_emu.add_argument("--from-file", default=None, metavar="PATH",
                       help="Relay to a recorded capture instead of a card "
                            "(hexlog, session JSON, JSONL, or '> cmd' / '< resp' lines)")
    p_emu.add_argument("--strict-replay", action="store_true",
                       help="With --from-file, answer 6D00 rather than serving a "
                            "loosely-matched response")
    p_emu.add_argument("--prefetch", action="store_true",
                       help="Read the PPSE and its AIDs from the card before a "
                            "terminal arrives, and answer those from memory. "
                            "Removes the card's round trip from the exchanges "
                            "that are identical every time, which is what gets "
                            "them inside a frame waiting time. Off by default: "
                            "the trace then shows what the card said a moment "
                            "earlier rather than right then")
    p_emu.add_argument("--no-alert", action="store_true",
                       help="Do not blink and beep the reader when target mode "
                            "opens. The cue is on by default, once per run, "
                            "because the first window is a few seconds and "
                            "invisible from the desk; it is not repeated on a "
                            "re-arm, where the 800 ms the reader spends "
                            "blinking is 800 ms the card is not presented")
    p_emu.add_argument("--split-responses", action="store_true",
                       help="When the card answers more than one exchange can "
                            "carry, tell the terminal 61 XX and hand the rest "
                            "over as it asks with GET RESPONSE. The last route "
                            "left on an ACR122U: below the APDU layer one "
                            "TgSetData is too small, the chip will not answer "
                            "TgSetMetaData, and a transmit big enough for the "
                            "whole response damages the reader. Off by default "
                            "because it changes what the card appears to have "
                            "said — one APDU becomes three")
    p_emu.add_argument("--trace-chip", action="store_true",
                       help="Log every byte to and from the reader — the "
                            "pseudo-APDU out, the reply in, and how long it "
                            "was held. This is the only record of what the "
                            "hardware was actually told rather than what a "
                            "layer above made of it, and it is what to send "
                            "when a relay is dropping commands")
    p_emu.add_argument("--mutate", action="store_true",
                       help="Apply the mutation engine to the relayed traffic")
    p_emu.add_argument("--mutations", default="mutations.yaml", metavar="PATH",
                       help="Config for --mutate (default: mutations.yaml)")
    p_emu.add_argument("--remote", action="store_true",
                       help="Relay to a card behind card_proxy instead")
    p_emu.add_argument("--remote-host", default="127.0.0.1")
    p_emu.add_argument("--remote-port", type=int, default=7654)
    p_emu.add_argument("--pairing", default=None,
                       help="Pairing string from 'atrium pair' on the card host")
    p_emu.add_argument("--nfcgate", action="store_true",
                       help="Relay to a card held by an Android phone running "
                            "NFCGate in reader mode, through an NFCGate server")
    p_emu.add_argument("--nfcgate-host", default="127.0.0.1", metavar="HOST",
                       help="Where the NFCGate server is (default: 127.0.0.1)")
    p_emu.add_argument("--nfcgate-port", type=int, default=5566)
    p_emu.add_argument("--nfcgate-session", type=int, default=1, metavar="1-255",
                       help="Session number; must match the phone's (default: 1)")
    p_emu.add_argument("--nfcgate-cafile", default=None, metavar="PATH",
                       help="CA certificate for a TLS NFCGate server. Without it "
                            "the link is plaintext, so keep it on a network you own")
    p_emu.add_argument("--own-isodep", action="store_true",
                       help="Do ISO-DEP here instead of letting the PN532 do it. "
                            "Buys S(WTX) — asking the terminal for more time, the "
                            "only thing that keeps a slow relay alive — plus a "
                            "chosen FWI and response chaining. The chip's own "
                            "layer is the default, and on an ACR122U it is the "
                            "one that activates: answering RATS from the host "
                            "costs a USB round trip against the 8.5 ms ISO "
                            "14443-4 allows, which this bridge does not make")
    p_emu.add_argument("--fwi", type=int, default=12, metavar="0-14",
                       help="With --own-isodep: frame waiting time index for the "
                            "ATS. 12 is ~1.24 s, 14 the ~4.9 s maximum "
                            "(default: 12)")
    p_emu.add_argument("--wtxm", type=int, default=16, metavar="1-59",
                       help="With --own-isodep: how many frame waiting times each "
                            "S(WTX) asks for (default: 16)")

    # proxy
    p_proxy = sub.add_parser("proxy", help="Run the remote card proxy server")
    p_proxy.add_argument("--reader", "-r", default=None, metavar="INDEX|NAME")
    p_proxy.add_argument("--proxy-host", default="127.0.0.1")
    p_proxy.add_argument("--proxy-port", type=int, default=7654)
    p_proxy.add_argument("--secure", action="store_true",
                         help="Require TLS + token; share the string from 'atrium pair'")
    p_proxy.add_argument("--insecure-plaintext", action="store_true",
                         help="Permit an unauthenticated bind beyond loopback")

    # all
    p_all = sub.add_parser("all", help="Start relay + web server together")
    p_all.add_argument("--reader", "-r", default=None, metavar="INDEX|NAME")
    p_all.add_argument("--host",   default="127.0.0.1")
    p_all.add_argument("--port",   type=int, default=8000)
    p_all.add_argument("--reload", action="store_true")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    dispatch = {
        "serve": cmd_serve,
        "relay": cmd_relay,
        "agent": cmd_agent,
        "pair":  cmd_pair,
        "readers": cmd_readers,
        "nfc":     cmd_nfc,
        "proxy": cmd_proxy,
        "all":   cmd_all,
    }

    if args.command is None:
        parser.print_help()
        return

    dispatch[args.command](args)


if __name__ == "__main__":
    main()
