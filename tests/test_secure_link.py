"""
Secure link tests.

Cover the cross-network card link: certificate pinning, token auth, pairing
string handling, and the refusal to serve a card in plaintext across a network.
"""
from __future__ import annotations

import socket
import sys
import tempfile
import threading
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import secure_link as sl  # noqa: E402


@pytest.fixture(scope="module")
def identity():
    d = Path(tempfile.mkdtemp())
    return sl.load_or_create_identity(d)          # cert, key, fingerprint, token


@pytest.fixture(scope="module")
def rogue_identity():
    """A second identity standing in for a machine-in-the-middle."""
    d = Path(tempfile.mkdtemp())
    return sl.load_or_create_identity(d)


def _serve_once(cert, key, token, payload=b"SECRET"):
    """Run one authenticated server exchange; report whether it got that far."""
    state = {"ready": threading.Event(), "served": False, "error": None}
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    state["port"] = srv.getsockname()[1]

    def run():
        state["ready"].set()
        try:
            conn, _ = srv.accept()
            tls = sl.accept_authenticated(conn, sl.server_context(cert, key), token)
            sl.send_framed(tls, payload)
            state["served"] = True
        except sl.LinkError as exc:
            state["error"] = str(exc)
        finally:
            srv.close()

    threading.Thread(target=run, daemon=True).start()
    state["ready"].wait(timeout=5)
    return state


class TestPinning:
    def test_matching_fingerprint_and_token_connects(self, identity):
        cert, key, fp, token = identity
        st = _serve_once(cert, key, token)
        s = sl.connect_authenticated("127.0.0.1", st["port"], fp, token, timeout=5)
        assert sl.recv_framed(s) == b"SECRET"
        s.close()

    def test_mitm_with_different_certificate_is_rejected(self, identity, rogue_identity):
        """
        The attacker holds a valid TLS certificate and even knows the token;
        only the pin stops them.
        """
        _, _, real_fp, token = identity
        rogue_cert, rogue_key, _, _ = rogue_identity
        st = _serve_once(rogue_cert, rogue_key, token)
        with pytest.raises(sl.LinkError, match="fingerprint mismatch"):
            sl.connect_authenticated("127.0.0.1", st["port"], real_fp, token, timeout=5)

    def test_token_is_never_sent_to_an_impostor(self, identity, rogue_identity):
        """The pin is checked before the token leaves the client."""
        _, _, real_fp, token = identity
        rogue_cert, rogue_key, _, _ = rogue_identity
        st = _serve_once(rogue_cert, rogue_key, token)
        with pytest.raises(sl.LinkError):
            sl.connect_authenticated("127.0.0.1", st["port"], real_fp, token, timeout=5)
        assert st["served"] is False

    def test_wrong_token_is_rejected(self, identity):
        cert, key, fp, _ = identity
        st = _serve_once(cert, key, "the-real-token")
        with pytest.raises(sl.LinkError):
            sl.connect_authenticated("127.0.0.1", st["port"], fp, "guess", timeout=5)
        assert st["served"] is False


class TestPairingString:
    def test_round_trip(self):
        s = sl.make_pairing("203.0.113.9", 7654, "a" * 64, "tok")
        got = sl.parse_pairing(s)
        assert got == {"host": "203.0.113.9", "port": 7654,
                       "fingerprint": "a" * 64, "token": "tok"}

    @pytest.mark.parametrize("bad", [
        "", "hello", "atrium1:!!!!", "atrium1:", "http://example.com",
    ])
    def test_malformed_input_is_rejected(self, bad):
        with pytest.raises(sl.LinkError):
            sl.parse_pairing(bad)

    def test_short_fingerprint_is_rejected(self):
        with pytest.raises(sl.LinkError, match="fingerprint"):
            sl.parse_pairing(sl.make_pairing("h", 1, "abc", "t"))


class TestIdentity:
    def test_is_stable_across_calls(self):
        d = Path(tempfile.mkdtemp())
        a = sl.load_or_create_identity(d)
        b = sl.load_or_create_identity(d)
        assert a[2] == b[2] and a[3] == b[3]

    def test_rotation_invalidates_the_old_pairing(self):
        d = Path(tempfile.mkdtemp())
        _, _, fp1, tok1 = sl.load_or_create_identity(d)
        _, _, fp2, tok2 = sl.load_or_create_identity(d, rotate=True)
        assert fp1 != fp2 and tok1 != tok2

    def test_private_key_is_not_world_readable(self):
        d = Path(tempfile.mkdtemp())
        _, key_path, _, _ = sl.load_or_create_identity(d)
        assert (key_path.stat().st_mode & 0o077) == 0


class TestProxyRefusesPlaintextExposure:
    def test_help_documents_secure_flag(self):
        import subprocess
        out = subprocess.run(
            [sys.executable, "card_proxy.py", "--help"],
            capture_output=True, text=True,
            cwd=str(Path(__file__).parent.parent),
        ).stdout
        assert "--secure" in out

    def test_non_loopback_without_secure_exits(self):
        """Serving a card across a network in the clear must be impossible."""
        import subprocess
        r = subprocess.run(
            [sys.executable, "card_proxy.py", "--host", "0.0.0.0", "--port", "0"],
            capture_output=True, text=True,
            cwd=str(Path(__file__).parent.parent), timeout=30,
        )
        assert r.returncode != 0
        assert "Refusing to serve" in (r.stdout + r.stderr)


class TestPlaintextEscapeHatch:
    """
    --insecure-plaintext existed as a declared flag that nothing read, so it
    silently did nothing. It is now the explicit opt-out, and the refusal it
    bypasses still fires by default.
    """

    def _run(self, *extra):
        import subprocess
        return subprocess.run(
            [sys.executable, "card_proxy.py", "--host", "0.0.0.0", "--port", "0", *extra],
            capture_output=True, text=True, timeout=30,
            cwd=str(Path(__file__).parent.parent),
        )

    def test_default_refuses(self):
        r = self._run()
        assert r.returncode != 0
        assert "Refusing to serve" in (r.stdout + r.stderr)

    def test_explicit_opt_out_warns_instead_of_refusing(self):
        # With the opt-out the proxy proceeds to listen, so it never exits on
        # its own — start it, read the warning, then stop it.
        import subprocess
        proc = subprocess.Popen(
            [sys.executable, "card_proxy.py", "--host", "0.0.0.0", "--port", "0",
             "--insecure-plaintext"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        try:
            out, err = proc.communicate(timeout=6)
        except subprocess.TimeoutExpired:
            proc.terminate()
            out, err = proc.communicate(timeout=6)
        combined = out + err
        assert "Refusing to serve" not in combined
        assert "WARNING" in combined and "no authentication" in combined


class TestProxySubcommandParity:
    def test_atrium_proxy_can_reach_secure_mode(self):
        """
        `atrium proxy` builds a card_proxy argv. It used to drop --secure, so
        the documented entry point could not serve a card across a network.
        """
        import inspect
        import atrium
        src = inspect.getsource(atrium.cmd_proxy)
        assert "--secure" in src
        assert "--insecure-plaintext" in src


class TestEndToEnd:
    def test_relay_over_a_pinned_link(self, identity, monkeypatch):
        """The real proxy handler and the real client, over TLS, fake reader."""
        sysmod = types.ModuleType("smartcard.System"); sysmod.readers = lambda: []
        util = types.ModuleType("smartcard.util")
        util.toHexString = lambda b: " ".join(f"{x:02X}" for x in b)
        util.toBytes = lambda s: [int(x, 16) for x in s.split()]
        root = types.ModuleType("smartcard"); root.System = sysmod; root.util = util
        for n, m in {"smartcard": root, "smartcard.System": sysmod,
                     "smartcard.util": util}.items():
            monkeypatch.setitem(sys.modules, n, m)

        import card_proxy
        from transport.remote import RemoteCardTransport

        class FakeConn:
            def connect(self): pass
            def disconnect(self): pass
            def getATR(self): return [0x3B, 0x6F, 0x00, 0x00]
            def transmit(self, apdu): return ([0x6F, 0x1A], 0x90, 0x00)

        class FakeReader:
            def createConnection(self): return FakeConn()
            def __str__(self): return "FakeReader"

        monkeypatch.setattr(card_proxy, "get_reader", lambda i: FakeReader())

        cert, key, fp, token = identity
        ctx = sl.server_context(cert, key)
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        threading.Thread(
            target=lambda: card_proxy.handle_client(
                sl.accept_authenticated(srv.accept()[0], ctx, token), 0),
            daemon=True,
        ).start()

        t = RemoteCardTransport(pairing=sl.make_pairing("127.0.0.1", port, fp, token),
                                timeout=5)
        assert t.secure
        t.connect()
        assert t.get_atr() == bytes([0x3B, 0x6F, 0x00, 0x00])
        assert t.transmit(bytes([0x00, 0xA4, 0x04, 0x00])) == bytes([0x6F, 0x1A, 0x90, 0x00])
        t.disconnect()
        srv.close()

    def test_transport_requires_an_address_or_pairing(self):
        from transport.remote import RemoteCardTransport
        with pytest.raises(ValueError):
            RemoteCardTransport()
