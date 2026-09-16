"""
Remote relay tests.

The remote path had two independent faults: the UI toggle was never wired
through to the transport, and the client framed its ATR request differently
from what card_proxy.py reads. Both are covered here.
"""
from __future__ import annotations

import socket
import sys
import threading
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def stub_pyscard(monkeypatch):
    """card_proxy imports pyscard at module scope; CI has no reader."""
    sysmod = types.ModuleType("smartcard.System"); sysmod.readers = lambda: []
    util = types.ModuleType("smartcard.util")
    util.toHexString = lambda b: " ".join(f"{x:02X}" for x in b)
    util.toBytes = lambda s: [int(x, 16) for x in s.split()]
    root = types.ModuleType("smartcard"); root.System = sysmod; root.util = util
    for name, mod in {"smartcard": root, "smartcard.System": sysmod,
                      "smartcard.util": util}.items():
        monkeypatch.setitem(sys.modules, name, mod)


class _FakeConn:
    ATR = [0x3B, 0x6F, 0x00, 0x00]
    def connect(self): pass
    def disconnect(self): pass
    def getATR(self): return self.ATR
    def transmit(self, apdu): return ([0x6F, 0x1A], 0x90, 0x00)


class _FakeReader:
    def createConnection(self): return _FakeConn()
    def __str__(self): return "FakeReader"


@pytest.fixture
def proxy_port(stub_pyscard, monkeypatch):
    """Run the real card_proxy handler over a real socket, fake hardware."""
    import card_proxy
    monkeypatch.setattr(card_proxy, "get_reader", lambda i: _FakeReader())
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0)); srv.listen(1)
    port = srv.getsockname()[1]
    threading.Thread(
        target=lambda: card_proxy.handle_client(srv.accept()[0], 0), daemon=True
    ).start()
    yield port
    srv.close()


class TestWireProtocol:
    """The client and the proxy must frame requests identically."""

    def test_atr_request_is_length_framed(self, proxy_port):
        from transport.remote import RemoteCardTransport
        c = RemoteCardTransport("127.0.0.1", proxy_port, timeout=5)
        c.connect()
        assert c.get_atr() == bytes(_FakeConn.ATR)
        c.disconnect()

    def test_apdu_round_trip_appends_status_word(self, proxy_port):
        from transport.remote import RemoteCardTransport
        c = RemoteCardTransport("127.0.0.1", proxy_port, timeout=5)
        c.connect()
        c.get_atr()
        assert c.transmit(bytes([0x00, 0xA4, 0x04, 0x00])) == bytes([0x6F, 0x1A, 0x90, 0x00])
        c.disconnect()


class TestTransportPackage:
    def test_remote_imports_without_virtualsmartcard(self, monkeypatch):
        """
        card_proxy runs on the machine with the reader, which need not have
        virtualsmartcard installed. Eager imports in transport/__init__ used to
        make that impossible.
        """
        monkeypatch.setitem(sys.modules, "virtualsmartcard", None)
        import importlib
        mod = importlib.import_module("transport.remote")
        assert hasattr(mod, "RemoteCardTransport")


class TestRemoteWiring:
    def test_make_virtual_card_accepts_remote_parameters(self):
        """The Remote toggle used to be accepted and then silently ignored."""
        import inspect
        import atrium
        params = inspect.signature(atrium._make_virtual_card).parameters
        assert {"remote", "remote_host", "remote_port"} <= set(params)

    def test_session_route_forwards_remote_settings(self):
        import inspect
        from api.routes import session
        src = inspect.getsource(session.start_session)
        assert "remote=req.remote" in src
        assert "remote_host=req.remote_host" in src
