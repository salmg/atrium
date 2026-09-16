"""
Host-layer API tests.

A browser button is an easier thing to press by accident than a command line is
to type, so most of these cover the guards rather than the features: the
allow-list still fails closed over HTTP, mutation and replay still need an
explicit confirmation, capture names cannot escape logs/, and an issuer master
key cannot be pushed in through a request body.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))


@pytest.fixture
def client(monkeypatch):
    monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
    from api.server import create_app
    return TestClient(create_app())


@pytest.fixture(autouse=True)
def _no_proxy_left_running():
    yield
    from api.routes import host
    try:
        host.stop_proxy()
    except Exception:
        pass


class TestCatalogue:
    def test_lists_what_the_ui_needs_in_one_call(self, client):
        body = client.get("/api/host/catalogue").json()
        assert body["ok"]
        assert {d["name"] for d in body["dialects"]} >= {"iso8583-1987", "base24"}
        assert {p["name"] for p in body["playbooks"]} >= {"amount-mismatch"}
        assert {p["name"] for p in body["profiles"]} >= {"emv-book2"}
        assert body["errors"] == []

    def test_reports_whether_a_key_is_configured_without_revealing_it(
            self, client, monkeypatch):
        monkeypatch.setenv("HOST_IMK", "00" * 16)
        body = client.get("/api/host/catalogue").json()
        assert body["imk_configured"] is True
        assert "00000000" not in client.get("/api/host/catalogue").text


class TestScopeGuardOverHttp:
    def test_proxy_without_an_allow_list_is_refused(self, client):
        r = client.post("/api/host/proxy/start",
                        json={"mode": "passive", "target": "10.0.0.1:5000"})
        assert r.status_code == 200
        assert r.json()["ok"] is False
        assert "allow-listed" in r.json()["error"]

    def test_proxy_target_outside_the_allow_list_is_refused(self, client):
        r = client.post("/api/host/proxy/start", json={
            "mode": "passive", "target": "10.0.0.1:5000",
            "allow": ["other.test:5000"]})
        assert r.json()["ok"] is False
        assert "not in scope" in r.json()["error"]

    def test_replay_without_an_allow_list_is_refused(self, client, tmp_path):
        r = client.post("/api/host/replay/run", json={
            "capture": "nope.jsonl", "target": "10.0.0.1:5000", "confirm": True})
        assert r.json()["ok"] is False


class TestConfirmationRequired:
    def test_mutating_proxy_needs_confirmation(self, client):
        r = client.post("/api/host/proxy/start", json={
            "mode": "mutate", "target": "sim.test:5000",
            "allow": ["sim.test:5000"], "playbook": "amount-mismatch"})
        assert r.status_code == 400
        assert "confirm: true" in r.json()["detail"]

    def test_replay_needs_confirmation(self, client):
        r = client.post("/api/host/replay/run", json={
            "capture": "x.jsonl", "target": "sim.test:5000",
            "allow": ["sim.test:5000"]})
        assert r.status_code == 400
        assert "confirm: true" in r.json()["detail"]

    def test_passive_proxy_needs_no_confirmation(self, client):
        """Observing changes nothing, so it should not nag."""
        r = client.post("/api/host/proxy/start", json={
            "mode": "passive", "target": "10.0.0.1:5000",
            "allow": ["other.test:1"]})
        # Refused on scope, not on confirmation — which is the point.
        assert r.status_code == 200
        assert "confirm" not in r.json()["error"]

    def test_mutating_proxy_still_needs_a_playbook(self, client):
        r = client.post("/api/host/proxy/start", json={
            "mode": "mutate", "target": "sim.test:5000",
            "allow": ["sim.test:5000"], "confirm": True})
        assert r.json()["ok"] is False
        assert "needs a playbook" in r.json()["error"]


class TestCapturePathTraversal:
    @pytest.mark.parametrize("bad", [
        "../../etc/passwd", "../mutations.yaml", "/etc/passwd", "..", ".",
        "sub/dir.jsonl", "a\x00b",
    ])
    def test_rejects_names_escaping_the_log_directory(self, bad):
        from api.routes.host import _safe_capture_path
        from fastapi import HTTPException
        with pytest.raises(HTTPException):
            _safe_capture_path(bad)

    def test_accepts_a_plain_name(self):
        from api.routes.host import LOGS_DIR, _safe_capture_path
        assert _safe_capture_path("host.jsonl").parent == LOGS_DIR.resolve()

    @pytest.mark.parametrize("encoded", ["..%2f..%2fetc%2fpasswd", "%2e%2e%2fmutations.yaml"])
    def test_traversal_blocked_over_http(self, client, encoded):
        r = client.get(f"/api/host/capture/{encoded}")
        assert r.status_code in (400, 404)
        assert "root:" not in r.text


class TestKeysNeverTravelThroughTheApi:
    def test_no_route_accepts_a_key_field(self):
        """
        A key in a request body lands in access logs and browser history, so no
        model here may carry one.
        """
        from api.routes import host
        for model in (host.ProxyStartBody, host.ReplayBody, host.VerifyBody,
                      host.DetectBody):
            fields = set(model.model_fields)
            assert not fields & {"imk", "imk_file", "key", "udk"}, model.__name__

    def test_verify_without_a_configured_key_explains_where_to_put_one(
            self, client, monkeypatch):
        monkeypatch.delenv("HOST_IMK", raising=False)
        monkeypatch.delenv("HOST_IMK_FILE", raising=False)
        body = client.post("/api/host/verify", json={"capture": "x.jsonl"}).json()
        assert body["ok"] is False
        assert "HOST_IMK" in body["error"]
        assert "logs and browser history" in body["error"]


class TestProxyLifecycle:
    def test_status_is_quiet_when_nothing_runs(self, client):
        body = client.get("/api/host/proxy/status").json()
        assert body["running"] is False and body["records"] == []

    def test_start_stop_and_double_start(self, client, tmp_path):
        """Against a real listener, so the whole path is exercised."""
        import socket
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            payload = {"mode": "passive", "listen": "127.0.0.1:0",
                       "target": f"127.0.0.1:{port}",
                       "allow": [f"127.0.0.1:{port}"]}
            assert client.post("/api/host/proxy/start", json=payload).json()["ok"]

            status = client.get("/api/host/proxy/status").json()
            assert status["running"] is True and status["mode"] == "passive"

            again = client.post("/api/host/proxy/start", json=payload).json()
            assert again["ok"] is False and "already running" in again["error"]

            assert client.post("/api/host/proxy/stop", json={}).json()["ok"]
            assert client.get("/api/host/proxy/status").json()["running"] is False
        finally:
            srv.close()

    def test_stopping_when_idle_is_not_an_error(self, client):
        assert client.post("/api/host/proxy/stop", json={}).json()["ok"] is True


class TestAnalysis:
    def test_detect_from_hex(self, client):
        from host.iso8583 import Message, load_dialect, pack
        iso = load_dialect("iso8583-1987")
        wire = pack(iso, Message(mti="0100", fields={
            2: "4111111111111111", 3: "000000", 4: "000000001000", 11: "000123"}))
        body = client.post("/api/host/detect",
                           json={"hex": wire.hex()}).json()
        assert body["ok"]
        assert body["candidates"][0]["dialect"] == "iso8583-1987"
        assert body["candidates"][0]["score"] < 1.0

    def test_detect_needs_an_input(self, client):
        assert client.post("/api/host/detect", json={}).json()["ok"] is False

    def test_detect_rejects_non_hex(self, client):
        body = client.post("/api/host/detect", json={"hex": "zzzz"}).json()
        assert body["ok"] is False and "not hex" in body["error"]
