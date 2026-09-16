"""
secure_link — authenticated, encrypted transport between two ATRIUM hosts.

Lets a card sitting in one network be driven by a SimTrace2 rig in another,
without a broker or any hosted service.  Both ends run ATRIUM locally.

Trust model (SSH-like, deliberately)
------------------------------------
The card host generates a long-lived identity once: a self-signed certificate
plus an access token.  It prints a *pairing string* carrying the address, the
certificate fingerprint and the token.  The rig operator pastes that string.

    card host                                 rig host
    ─────────                                 ────────
    atrium pair            ──(out of band)──> paste into ATRIUM
    card_proxy --secure                       relay connects

That gives mutual authentication:

* **server → client** by certificate pinning.  The client compares the
  SHA-256 of the presented certificate against the fingerprint in the pairing
  string, so a man in the middle with a different key is rejected even though
  the certificate is self-signed.
* **client → server** by the token, sent only *after* the pin matches, so an
  impostor never sees it.  Compared in constant time.

Public CAs are not involved, which is the point: there is no domain to
validate and no third party to trust.  It is the same reasoning as an SSH host
key — trust is pinned on first exchange, out of band, by the two operators.

Note that transport encryption protects the link, not the endpoints.  Whoever
holds the pairing string can transact with the card, so treat it like an SSH
private key: send it over a channel you trust, and rotate it with
``atrium pair --rotate`` when a collaboration ends.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import ssl
import struct
from pathlib import Path

log = logging.getLogger(__name__)

PAIRING_PREFIX = "atrium1:"
DEFAULT_IDENTITY_DIR = Path(os.environ.get("ATRIUM_HOME", Path.home() / ".atrium"))

_CERT_NAME = "link-cert.pem"
_KEY_NAME = "link-key.pem"
_TOKEN_NAME = "link-token"

# Handshake limits — a peer that cannot authenticate should cost us nothing
_HANDSHAKE_TIMEOUT = 15.0
_MAX_TOKEN_LEN = 512


class LinkError(RuntimeError):
    """Handshake, pinning or authentication failure. Message is user-facing."""


# ─────────────────────────────────────────────────────────────────────────────
# Identity
# ─────────────────────────────────────────────────────────────────────────────

def fingerprint_of(cert_der: bytes) -> str:
    """Lowercase hex SHA-256 of a DER certificate — what we pin on."""
    return hashlib.sha256(cert_der).hexdigest()


def _generate_identity(cert_path: Path, key_path: Path) -> None:
    """
    Create a self-signed P-256 identity.

    Prefers the openssl binary, which is present on every platform this project
    supports and needs no Python dependency, then falls back to the
    `cryptography` package.  Runs once per host.
    """
    if _generate_identity_openssl(cert_path, key_path):
        return

    try:
        _generate_identity_cryptography(cert_path, key_path)
        return
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as exc:        # noqa: BLE001
        # Broader than Exception on purpose: a broken cryptography install can
        # surface as a Rust pyo3 PanicException, which derives from
        # BaseException and would otherwise escape this handler.
        log.debug("cryptography backend unusable: %s", exc)

    raise LinkError(
        "Could not generate a link identity: neither the 'openssl' binary nor a "
        "working 'cryptography' package is available.\n"
        "Install either one:  apt install openssl   |   pip install cryptography"
    )


def _generate_identity_openssl(cert_path: Path, key_path: Path) -> bool:
    import shutil
    import subprocess

    openssl = shutil.which("openssl")
    if not openssl:
        return False
    try:
        subprocess.run(
            [openssl, "req", "-x509", "-nodes", "-newkey", "ec",
             "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-keyout", str(key_path), "-out", str(cert_path),
             "-days", "825", "-subj", "/CN=atrium-link"],
            check=True, capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError) as exc:
        log.debug("openssl identity generation failed: %s", exc)
        return False
    key_path.chmod(0o600)
    return True


def _generate_identity_cryptography(cert_path: Path, key_path: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "atrium-link")])
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    key_path.chmod(0o600)


def load_or_create_identity(
    directory: Path | None = None, rotate: bool = False
) -> tuple[Path, Path, str, str]:
    """
    Return (cert_path, key_path, fingerprint, token), creating them on first use.

    ``rotate=True`` discards the existing identity, which invalidates every
    pairing string previously handed out.
    """
    d = Path(directory or DEFAULT_IDENTITY_DIR)
    d.mkdir(parents=True, exist_ok=True)
    try:
        d.chmod(0o700)
    except OSError:
        pass

    cert_path, key_path, token_path = d / _CERT_NAME, d / _KEY_NAME, d / _TOKEN_NAME

    if rotate:
        for p in (cert_path, key_path, token_path):
            p.unlink(missing_ok=True)

    if not (cert_path.exists() and key_path.exists()):
        _generate_identity(cert_path, key_path)
        log.info("Generated new link identity in %s", d)

    if not token_path.exists():
        token_path.write_text(secrets.token_urlsafe(32))
        token_path.chmod(0o600)

    import ssl as _ssl
    der = _ssl.PEM_cert_to_DER_cert(cert_path.read_text())
    return cert_path, key_path, fingerprint_of(der), token_path.read_text().strip()


# ─────────────────────────────────────────────────────────────────────────────
# Pairing string
# ─────────────────────────────────────────────────────────────────────────────

def make_pairing(host: str, port: int, fingerprint: str, token: str) -> str:
    blob = json.dumps({"h": host, "p": port, "f": fingerprint, "t": token},
                      separators=(",", ":")).encode()
    return PAIRING_PREFIX + base64.urlsafe_b64encode(blob).decode().rstrip("=")


def parse_pairing(pairing: str) -> dict:
    raw = (pairing or "").strip()
    if not raw.startswith(PAIRING_PREFIX):
        raise LinkError("Not an ATRIUM pairing string (expected it to start with "
                        f"'{PAIRING_PREFIX}').")
    b64 = raw[len(PAIRING_PREFIX):]
    # Decode failures here are almost always a truncated or re-wrapped copy
    # paste, so say that rather than surfacing a codec or JSON traceback.
    try:
        blob = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
        data = json.loads(blob)
        out = {"host": data["h"], "port": int(data["p"]),
               "fingerprint": data["f"], "token": data["t"]}
    except Exception as exc:
        log.debug("pairing string decode failed: %s", exc)
        raise LinkError(
            "This pairing string is damaged — it looks truncated or altered. "
            "Copy the whole line from 'atrium pair' on the card host, including "
            "the 'atrium1:' prefix and with no line breaks."
        ) from exc
    if len(out["fingerprint"]) != 64:
        raise LinkError("Pairing string carries a malformed fingerprint.")
    return out


# ─────────────────────────────────────────────────────────────────────────────
# Framing (shared with the plaintext protocol)
# ─────────────────────────────────────────────────────────────────────────────

def send_framed(sock, data: bytes) -> None:
    sock.sendall(struct.pack("!H", len(data)) + data)


def recv_exact(sock, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise LinkError("Peer closed the connection during handshake.")
        buf += chunk
    return buf


def recv_framed(sock) -> bytes:
    return recv_exact(sock, struct.unpack("!H", recv_exact(sock, 2))[0])


# ─────────────────────────────────────────────────────────────────────────────
# Server side
# ─────────────────────────────────────────────────────────────────────────────

def server_context(cert_path: Path, key_path: Path) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    return ctx


def accept_authenticated(raw_sock: socket.socket, ctx: ssl.SSLContext,
                         token: str) -> ssl.SSLSocket:
    """
    Wrap an accepted socket in TLS and require the client's token.

    Raises LinkError without leaking which half failed, and never echoes the
    supplied value back to the caller.
    """
    raw_sock.settimeout(_HANDSHAKE_TIMEOUT)
    try:
        tls = ctx.wrap_socket(raw_sock, server_side=True)
    except ssl.SSLError as exc:
        raise LinkError(f"TLS handshake failed: {exc}") from exc

    try:
        supplied = recv_framed(tls)
    except LinkError:
        tls.close()
        raise

    if len(supplied) > _MAX_TOKEN_LEN or not hmac.compare_digest(
        supplied, token.encode()
    ):
        try:
            send_framed(tls, b"DENY")
        finally:
            tls.close()
        raise LinkError("Client presented an invalid token — connection refused.")

    send_framed(tls, b"OK")
    tls.settimeout(None)
    return tls


# ─────────────────────────────────────────────────────────────────────────────
# Client side
# ─────────────────────────────────────────────────────────────────────────────

def connect_authenticated(host: str, port: int, fingerprint: str, token: str,
                          timeout: float = 10.0) -> ssl.SSLSocket:
    """
    Connect, pin the server certificate, then authenticate.

    The certificate is self-signed, so the usual chain validation is switched
    off and replaced with an exact fingerprint match.  That is strictly
    stronger here: a MITM presenting its own certificate fails the pin even
    though it could satisfy a public CA.  The token is sent only after the pin
    matches, so an impostor never receives it.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = False          # no domain to validate; we pin instead
    ctx.verify_mode = ssl.CERT_NONE     # chain is irrelevant for a pinned key

    raw = socket.create_connection((host, port), timeout=timeout)
    try:
        tls = ctx.wrap_socket(raw, server_hostname=None)
    except ssl.SSLError as exc:
        raw.close()
        raise LinkError(f"TLS handshake with {host}:{port} failed: {exc}") from exc

    presented = tls.getpeercert(binary_form=True)
    if not presented:
        tls.close()
        raise LinkError("Server presented no certificate.")

    actual = fingerprint_of(presented)
    if not hmac.compare_digest(actual, fingerprint.lower()):
        tls.close()
        raise LinkError(
            "Certificate fingerprint mismatch — refusing to send the token.\n"
            f"  expected {fingerprint.lower()}\n"
            f"  got      {actual}\n"
            "Either the card host rotated its identity (ask for a fresh pairing "
            "string) or something is intercepting the connection."
        )

    send_framed(tls, token.encode())
    if recv_framed(tls) != b"OK":
        tls.close()
        raise LinkError("Card host rejected the token from this pairing string.")

    tls.settimeout(None)
    return tls
