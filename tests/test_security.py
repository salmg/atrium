"""
Security regression tests.

These cover the guards that stop ATRIUM's control plane from being turned
against the operator.  Each test names the specific attack it blocks; if one
starts failing, that attack is live again.

Run with:  python3 -m pytest tests/ -q
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

sys.path.insert(0, str(Path(__file__).parent.parent))


# ─────────────────────────────────────────────────────────────────────────────
# SimTrace2 launches nothing  (api/routes/simtrace.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestSimtraceRunsNothing:
    """
    The daemon needs root.  Rather than escalate from an HTTP request — which
    means either a dead-end password prompt or a passwordless sudo rule that
    turns the API into a root shell — the operator runs it themselves and this
    module only observes.  These tests keep it that way.
    """

    def test_module_imports_nothing_that_can_execute(self):
        """Checked over the AST, so a mention in a comment does not count."""
        import ast
        import inspect
        from api.routes import simtrace

        tree = ast.parse(inspect.getsource(simtrace))
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(a.name.split(".")[0] for a in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])

        assert not imported & {"subprocess", "pty", "multiprocessing", "asyncio"}

    def test_module_calls_nothing_that_can_execute(self):
        import ast
        import inspect
        from api.routes import simtrace

        forbidden = {"Popen", "run", "call", "check_output", "system", "popen",
                     "spawnv", "spawnl", "fork", "posix_spawn"} | {
                     f"exec{s}" for s in ("l", "le", "lp", "v", "ve", "vp", "vpe")}

        called = set()
        for node in ast.walk(ast.parse(inspect.getsource(simtrace))):
            if not isinstance(node, ast.Call):
                continue
            fn = node.func
            called.add(fn.attr if isinstance(fn, ast.Attribute) else
                       fn.id if isinstance(fn, ast.Name) else "")

        assert not called & forbidden, called & forbidden

    def test_no_route_starts_or_stops_the_daemon(self):
        from api.routes import simtrace
        live = {
            (m, r.path)
            for r in simtrace.router.routes
            for m in getattr(r, "methods", set())
            if not getattr(r, "deprecated", False)
        }
        assert all(m == "GET" for m, _ in live if not _.endswith("/config")), live
        assert ("POST", "/api/simtrace/start") not in live
        assert ("POST", "/api/simtrace/stop") not in live

    def test_legacy_start_and_stop_answer_410(self, monkeypatch):
        """A browser tab left open from before the change gets an explanation."""
        from fastapi.testclient import TestClient
        monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
        from api.server import create_app
        c = TestClient(create_app())
        for path in ("/api/simtrace/start", "/api/simtrace/stop"):
            r = c.post(path, json={})
            assert r.status_code == 410, path
            assert "second terminal" in r.text

    def test_config_is_a_display_hint_and_never_executed(self, tmp_path, monkeypatch):
        """
        Storing /bin/sh is harmless now — nothing runs it — but it must still
        only ever come back as text inside the suggested command.
        """
        from api.routes import simtrace
        monkeypatch.setattr(simtrace, "_CONFIG_FILE", tmp_path / "cfg.json")
        simtrace.save_simtrace_config(
            simtrace.SimTraceConfigBody(binary_path="/bin/sh", use_sudo=True)
        )
        res = simtrace.simtrace_command()
        assert res["command"].startswith("sudo /bin/sh --usb-vendor")
        assert res["binary_source"] == "config"

    @pytest.mark.parametrize("hostile", [
        "/tmp/x; rm -rf /tmp/y", "/tmp/x && id", "/tmp/$(id)", "/tmp/x|tee /etc/shadow",
    ])
    def test_command_quotes_a_hostile_binary_hint(self, hostile, tmp_path, monkeypatch):
        """
        The line is pasted into a root shell, so a metacharacter in the stored
        path must not survive as syntax.  Splitting the rendered command the
        way a shell would has to yield the path as one single word.
        """
        import shlex
        from api.routes import simtrace
        monkeypatch.setattr(simtrace, "_CONFIG_FILE", tmp_path / "cfg.json")
        simtrace.save_simtrace_config(
            simtrace.SimTraceConfigBody(binary_path=hostile, use_sudo=False)
        )
        res = simtrace.simtrace_command()
        assert shlex.split(res["command"])[0] == res["binary"]


class TestSimtraceUsbPath:
    @pytest.mark.parametrize("bad", [
        "../../etc", "2-2.2; rm -rf /", "$(id)", "2-2.2 --foo", "/dev/sda",
    ])
    def test_rejects_malformed_usb_paths(self, bad):
        from api.routes import simtrace
        with pytest.raises(HTTPException):
            simtrace._validate_usb_path(bad)

    def test_rejects_wellformed_path_with_no_such_device(self):
        from api.routes import simtrace
        with pytest.raises(HTTPException) as ei:
            simtrace._validate_usb_path("99-99.9")
        assert "No SimTrace2 device" in ei.value.detail


class TestSimtraceProcessDiscovery:
    """A fake /proc tree stands in for a root-owned simtrace2-remsim."""

    def _fake_proc(self, root, pid, comm, argv):
        d = root / str(pid)
        d.mkdir()
        (d / "comm").write_text(comm + "\n", encoding="utf-8")
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        return d

    def test_finds_a_daemon_and_reads_its_usb_path(self, tmp_path):
        from api.routes import simtrace
        self._fake_proc(tmp_path, 4242, simtrace._COMM_NAME,
                        ["/usr/local/bin/simtrace2-remsim", "--usb-path", "1-1.2"])
        found = simtrace.find_remsim_processes(tmp_path)
        assert [p["pid"] for p in found] == [4242]
        assert found[0]["usb_path"] == "1-1.2"

    def test_ignores_a_process_whose_argv0_is_something_else(self, tmp_path):
        """comm is truncated to 15 chars, so it alone is not proof of identity."""
        from api.routes import simtrace
        self._fake_proc(tmp_path, 99, simtrace._COMM_NAME,
                        ["/bin/sh", "-c", "simtrace2-remsimulator"])
        assert simtrace.find_remsim_processes(tmp_path) == []

    def test_ignores_unrelated_processes(self, tmp_path):
        from api.routes import simtrace
        self._fake_proc(tmp_path, 7, "sshd", ["/usr/sbin/sshd"])
        (tmp_path / "self").mkdir()          # non-numeric entries are skipped
        assert simtrace.find_remsim_processes(tmp_path) == []

    def test_missing_proc_is_not_an_error(self, tmp_path):
        from api.routes import simtrace
        assert simtrace.find_remsim_processes(tmp_path / "nope") == []

    @pytest.mark.parametrize("argv,expected", [
        (["x", "--usb-path", "2-1"], "2-1"),
        (["x", "--usb-path=2-1"],    "2-1"),
        (["x", "--usb-path"],        ""),
        (["x"],                      ""),
    ])
    def test_arg_value_handles_both_flag_spellings(self, argv, expected):
        from api.routes import simtrace
        assert simtrace._arg_value(argv, "--usb-path") == expected


# ─────────────────────────────────────────────────────────────────────────────
# Log file access  (api/routes/logs.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestLogPathTraversal:
    @pytest.mark.parametrize("bad", [
        "../../../etc/passwd", "../mutations.yaml", "/etc/passwd",
        "", "..", ".", "sub/dir", "a\x00b",
    ])
    def test_rejects_paths_escaping_the_log_directory(self, bad):
        from api.routes import logs
        with pytest.raises(HTTPException):
            logs._safe_path(bad)

    def test_accepts_a_plain_filename(self):
        from api.routes import logs
        resolved = logs._safe_path("session_2024.log")
        assert resolved.parent == logs.LOGS_DIR.resolve()

    @pytest.mark.parametrize("encoded", [
        "..%2f..%2fetc%2fpasswd", "..%2F..%2Fmutations.yaml", "%2e%2e%2fetc%2fpasswd",
    ])
    def test_percent_encoded_traversal_blocked_over_http(self, encoded, monkeypatch):
        """The server decodes %2f before the handler sees it, so assert here."""
        from fastapi.testclient import TestClient
        monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
        from api.server import create_app
        r = TestClient(create_app()).get(f"/api/logs/{encoded}")
        assert r.status_code in (400, 404), r.status_code
        assert "root:" not in r.text


# ─────────────────────────────────────────────────────────────────────────────
# Host allow-list — DNS rebinding  (api/server.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestHostAllowList:
    def test_accepts_loopback_names_and_addresses(self):
        from api import server
        for good in ["localhost", "localhost:8000", "127.0.0.1",
                     "127.0.0.1:8000", "127.0.0.2:8000", "[::1]:8000"]:
            assert server._host_ok(good), good

    def test_rejects_attacker_controlled_names(self):
        """The core DNS-rebinding defence: the Host header still says evil.com."""
        from api import server
        for bad in ["evil.com", "evil.com:8000", "attacker.rebind.network",
                    "192.168.1.50:8000", None, ""]:
            assert not server._host_ok(bad), bad

    def test_operator_can_opt_in_to_extra_hosts(self, monkeypatch):
        from api import server
        monkeypatch.setenv("ATRIUM_ALLOWED_HOSTS", "atrium.lab.internal")
        assert server._host_ok("atrium.lab.internal:8000")
        assert not server._host_ok("evil.com")


# ─────────────────────────────────────────────────────────────────────────────
# Bind guard  (atrium.py)
# ─────────────────────────────────────────────────────────────────────────────

class TestBindGuard:
    def test_loopback_needs_no_token(self, monkeypatch):
        import atrium
        monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
        atrium._guard_bind("127.0.0.1")
        atrium._guard_bind("localhost")

    def test_public_bind_without_token_is_refused(self, monkeypatch):
        import atrium
        monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
        with pytest.raises(SystemExit) as ei:
            atrium._guard_bind("0.0.0.0")
        assert "without authentication" in str(ei.value)

    def test_public_bind_allowed_once_a_token_is_set(self, monkeypatch):
        import atrium
        monkeypatch.setenv("ATRIUM_API_TOKEN", "s3cret")
        atrium._guard_bind("0.0.0.0")


# ─────────────────────────────────────────────────────────────────────────────
# Token enforcement, end to end
# ─────────────────────────────────────────────────────────────────────────────

class TestTokenMiddleware:
    def _client(self, monkeypatch, token=None):
        from fastapi.testclient import TestClient
        if token:
            monkeypatch.setenv("ATRIUM_API_TOKEN", token)
        else:
            monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
        from api.server import create_app
        return TestClient(create_app())

    def test_no_token_configured_means_open_loopback_access(self, monkeypatch):
        c = self._client(monkeypatch)
        assert c.get("/api/session/status").status_code == 200

    def test_configured_token_is_required(self, monkeypatch):
        c = self._client(monkeypatch, token="s3cret")
        assert c.get("/api/session/status").status_code == 401
        assert c.get("/api/session/status",
                     headers={"X-Atrium-Token": "wrong"}).status_code == 401
        assert c.get("/api/session/status",
                     headers={"X-Atrium-Token": "s3cret"}).status_code == 200

    def test_rebinding_host_is_refused_before_routing(self, monkeypatch):
        c = self._client(monkeypatch)
        r = c.get("/api/session/status", headers={"Host": "evil.com"})
        assert r.status_code == 421


# ─────────────────────────────────────────────────────────────────────────────
# Agent degrades safely with no model configured
# ─────────────────────────────────────────────────────────────────────────────

class TestAgentWithoutModel:
    @pytest.fixture(autouse=True)
    def _clear_env(self, monkeypatch):
        for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "ATRIUM_LLM_BASE_URL",
                  "ATRIUM_LLM_MODEL", "ATRIUM_LLM_PROVIDER"):
            monkeypatch.delenv(k, raising=False)

    def test_discovery_reports_unavailable_without_raising(self):
        from llm_provider import describe_providers
        info = describe_providers()
        assert info["active"] == "none"
        assert info["agent_available"] is False

    def test_resolve_raises_with_setup_guidance(self):
        from llm_provider import ProviderUnavailable, resolve_provider
        with pytest.raises(ProviderUnavailable) as ei:
            resolve_provider()
        msg = str(ei.value)
        assert "ANTHROPIC_API_KEY" in msg and "ATRIUM_LLM_BASE_URL" in msg

    def test_importing_the_agent_does_not_kill_the_process(self):
        """It used to sys.exit() at import time when the SDK was absent."""
        import importlib
        import emv_agent
        importlib.reload(emv_agent)

    def test_start_refuses_cleanly_instead_of_crashing(self):
        from api.routes.agent import StartRequest, start_agent
        r = start_agent(StartRequest(reader_index=0))
        assert r["ok"] is False and r.get("needs_setup") is True
