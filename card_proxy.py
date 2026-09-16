"""
card_proxy.py — lightweight card-access server.

Run this on the machine that has the physical card reader.  The ATRIUM host
connects to it via ``transport.remote.RemoteCardTransport``.

Wire protocol:
    Request:  2-byte big-endian length + APDU bytes
              OR single byte b'A' (→ return ATR)
              OR single byte b'R' (→ reset card, return b'OK')
    Response: 2-byte big-endian length + data bytes

Usage
-----
    python3 card_proxy.py [--host 127.0.0.1] [--port 7654] [--reader 0]

Security note
-------------
There is NO authentication on this plain-TCP server.  Bind to localhost or a
trusted private network, or add TLS + client certificates before exposing to
an untrusted network.
"""
from __future__ import annotations

import argparse
import logging
import socket
import struct
import sys

# pyscard is needed to talk to a reader, but not to parse arguments, print
# --help, or refuse an unsafe configuration. Exiting at import time meant the
# plaintext-exposure refusal below could never run on a host without it, so the
# requirement is deferred to the point a reader is actually opened.
try:
    from smartcard.System import readers
    from smartcard.util import toBytes, toHexString  # noqa: F401
except ImportError:                                   # pragma: no cover
    readers = None

    def toHexString(data):                            # minimal stand-in
        return " ".join(f"{b:02X}" for b in data)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(levelname)-7s  %(message)s")
logger = logging.getLogger("card_proxy")


def get_reader(index=None):
    """
    Open a reader by index, by name fragment, or by letting core.readers pick.
    """
    if readers is None:
        raise RuntimeError("pyscard is required to open a reader: pip install pyscard")
    from core.readers import ReaderError, resolve

    try:
        chosen = resolve(index)
    except ReaderError as exc:
        raise RuntimeError(str(exc)) from exc

    for reader in readers():
        if str(reader) == chosen.name:
            return reader
    raise RuntimeError(f"Reader '{chosen.name}' vanished between listing and opening")


def handle_client(conn: socket.socket, reader_index=None) -> None:
    reader = get_reader(reader_index)
    logger.info("Using reader: %s", reader)
    connection = reader.createConnection()
    connection.connect()
    atr = connection.getATR()
    logger.info("ATR: %s", toHexString(atr))

    try:
        while True:
            header = _recv_exact(conn, 2)
            if not header:
                break

            # Special single-byte commands encoded as 2-byte frames where
            # length == 1 and the single payload byte is 'A' or 'R'.
            length = struct.unpack("!H", header)[0]
            payload = _recv_exact(conn, length)

            if payload == b"A":
                _send_framed(conn, bytes(atr))
                continue

            if payload == b"R":
                connection.disconnect()
                connection.connect()
                atr = connection.getATR()
                logger.info("Card reset — new ATR: %s", toHexString(atr))
                _send_framed(conn, b"OK")
                continue

            apdu = list(payload)
            logger.info(">> %s", toHexString(apdu))
            response, sw1, sw2 = connection.transmit(apdu)
            resp_bytes = bytes(response) + bytes([sw1, sw2])
            logger.info("<< %s", toHexString(list(resp_bytes)))
            _send_framed(conn, resp_bytes)

    except (ConnectionError, struct.error):
        pass
    finally:
        try:
            connection.disconnect()
        except Exception:
            pass
        conn.close()
        logger.info("Client disconnected")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return buf
        buf += chunk
    return buf


def _send_framed(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack("!H", len(data)) + data)


def main() -> None:
    parser = argparse.ArgumentParser(description="ATRIUM remote card proxy")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7654)
    parser.add_argument("--reader", default=None, metavar="INDEX|NAME",
                        help="Reader index or name fragment; auto-selected when omitted")
    parser.add_argument("--secure", action="store_true",
                        help="Require TLS + token (needed to serve a card across "
                             "networks). Print the pairing string with: atrium pair")
    parser.add_argument("--insecure-plaintext", action="store_true",
                        help="Permit an unauthenticated plaintext bind beyond loopback. "
                             "Only when the path is already encrypted and access "
                             "controlled (e.g. WireGuard).")
    args = parser.parse_args()

    # Crossing a network without --secure would publish the card in the clear,
    # so make that combination impossible rather than merely discouraged.
    exposed = args.host not in ("127.0.0.1", "localhost", "::1")
    if exposed and args.insecure_plaintext and not args.secure:
        print(
            f"\n  WARNING: serving {args.host} in plaintext with no authentication.\n"
            "  Anyone who can reach this port can transact with the inserted card.\n"
            "  Only do this when the network path is already encrypted and access\n"
            "  controlled (WireGuard, an isolated lab segment).\n",
            file=sys.stderr,
        )
    elif exposed and not args.secure:
        sys.exit(
            f"\nRefusing to serve {args.host} in plaintext.\n\n"
            "Anyone who can reach this port could transact with the inserted card.\n"
            "Either run with --secure (TLS + token; share the string from\n"
            "'atrium pair' with the rig operator), or keep it on loopback and\n"
            "forward it over SSH:\n\n"
            f"    ssh -L {args.port}:127.0.0.1:{args.port} user@this-host\n"
        )

    tls_ctx = None
    token = ""
    if args.secure:
        from secure_link import load_or_create_identity, make_pairing, server_context
        cert_path, key_path, fingerprint, token = load_or_create_identity()
        tls_ctx = server_context(cert_path, key_path)
        print("\n  Secure mode. Give the rig operator this pairing string:\n")
        print("    " + make_pairing(args.host, args.port, fingerprint, token))
        print("\n  It carries the access token — send it over a channel you trust.")
        print("  Revoke it any time with: atrium pair --rotate\n")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(1)
    logger.info("Listening on %s:%d  (reader %s, %s)", args.host, args.port,
                args.reader if args.reader else "auto",
                "TLS + token" if args.secure else "plaintext")

    try:
        while True:
            conn, addr = server.accept()
            logger.info("Connection from %s:%d", *addr)
            if tls_ctx is not None:
                from secure_link import LinkError, accept_authenticated
                try:
                    conn = accept_authenticated(conn, tls_ctx, token)
                except LinkError as exc:
                    # Log and keep serving: a failed probe must not take the
                    # proxy down while an operator is mid-session.
                    logger.warning("Rejected %s:%d — %s", addr[0], addr[1], exc)
                    continue
                logger.info("Client authenticated")
            handle_client(conn, args.reader)
    except KeyboardInterrupt:
        logger.info("Shutting down")
    finally:
        server.close()


if __name__ == "__main__":
    main()
