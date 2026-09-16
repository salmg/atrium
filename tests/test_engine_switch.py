"""
Arming and disarming the mutation engine.

Applying a playbook used to be a one-way door: the dashboard could copy a
playbook over mutations.yaml and nothing could turn it back off, so the only
way back to a clean relay was to hand-edit the file. These cover the switch and
the distinction it introduces — a playbook can be *loaded* (its rules are in
mutations.yaml) while the engine is *disarmed* (nothing is being changed on the
wire), and the dashboard reports those as two separate facts.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).parent.parent))

from api.routes.playbooks import engine_enabled, set_engine_enabled


COMMENTED = """\
# my playbook — CVM bypass
enabled: true
log_mutations: true

pdol_mutations:
  # a rule that is off on purpose
  - tag: "9F02"
    value: "000000000001"
    enabled: false
    comment: "Amount: 1 cent"
"""


class TestReadingTheFlag:
    def test_reads_the_top_level_flag(self):
        assert engine_enabled(COMMENTED) is True
        assert engine_enabled(COMMENTED.replace("enabled: true", "enabled: false")) is False

    def test_a_missing_flag_means_off(self):
        assert engine_enabled("pdol_mutations: []\n") is False

    def test_an_indented_rule_flag_is_not_the_engine_flag(self):
        """
        The regression this guards: a rule-level ``enabled: true`` is indented,
        and a pattern that allowed leading whitespace reported the engine as
        armed while the top-level flag said false.
        """
        text = COMMENTED.replace("enabled: true", "enabled: false", 1)
        text = text.replace('    enabled: false\n', '    enabled: true\n')
        assert engine_enabled(text) is False


class TestWritingTheFlag:
    def test_disarming_keeps_every_rule_and_comment(self):
        out = set_engine_enabled(COMMENTED, False)
        assert "enabled: false\n" in out
        assert "# my playbook — CVM bypass" in out
        assert '- tag: "9F02"' in out
        assert '# a rule that is off on purpose' in out
        assert engine_enabled(out) is False

    def test_the_rule_level_flag_is_left_alone(self):
        out = set_engine_enabled(COMMENTED, False)
        assert "    enabled: false\n" in out          # the rule, still off
        assert out.count("enabled: false") == 2       # engine + that one rule

    def test_arming_is_the_inverse(self):
        off = set_engine_enabled(COMMENTED, False)
        assert engine_enabled(set_engine_enabled(off, True)) is True

    def test_a_file_with_no_flag_gains_one(self):
        out = set_engine_enabled("pdol_mutations: []\n", True)
        assert engine_enabled(out) is True
        assert "pdol_mutations: []" in out

    def test_still_parses_as_yaml(self):
        yaml = pytest.importorskip("yaml")
        doc = yaml.safe_load(set_engine_enabled(COMMENTED, False))
        assert doc["enabled"] is False
        assert doc["pdol_mutations"][0]["tag"] == "9F02"


@pytest.fixture
def client(monkeypatch, tmp_path):
    """An app whose playbook directory and live config are throwaway files."""
    monkeypatch.delenv("ATRIUM_API_TOKEN", raising=False)
    from api.routes import playbooks

    books = tmp_path / "playbooks"
    books.mkdir()
    monkeypatch.setattr(playbooks, "PLAYBOOKS_DIR", books)
    monkeypatch.setattr(playbooks, "MUTATIONS_YAML", tmp_path / "mutations.yaml")

    from api.server import create_app
    client = TestClient(create_app())
    client.books = books                                # for the tests to write into
    client.live = tmp_path / "mutations.yaml"
    return client


class TestTheRoute:
    def test_disarming_leaves_the_playbook_loaded(self, client):
        (client.books / "cvm_bypass.yaml").write_text(COMMENTED, encoding="utf-8")
        assert client.post("/api/playbooks/cvm_bypass/apply").json()["ok"]

        before = client.get("/api/playbooks/active").json()
        assert before["active"] == "cvm_bypass"
        assert before["engine_enabled"] is True

        assert client.post("/api/playbooks/engine", json={"enabled": False}).json()["ok"]

        after = client.get("/api/playbooks/active").json()
        # Still the loaded playbook — disarming is not unloading.
        assert after["active"] == "cvm_bypass"
        assert after["engine_enabled"] is False
        assert '- tag: "9F02"' in client.live.read_text(encoding="utf-8")

    def test_arming_again_needs_no_re_apply(self, client):
        (client.books / "cvm_bypass.yaml").write_text(COMMENTED, encoding="utf-8")
        client.post("/api/playbooks/cvm_bypass/apply")
        client.post("/api/playbooks/engine", json={"enabled": False})
        client.post("/api/playbooks/engine", json={"enabled": True})

        body = client.get("/api/playbooks/active").json()
        assert body["active"] == "cvm_bypass"
        assert body["engine_enabled"] is True

    def test_arming_with_no_config_at_all_is_a_404_not_a_silent_success(self, client):
        assert not client.live.exists()
        assert client.post("/api/playbooks/engine", json={"enabled": True}).status_code == 404

    def test_disarming_with_no_config_is_already_true(self, client):
        body = client.post("/api/playbooks/engine", json={"enabled": False}).json()
        assert body["ok"] and body["enabled"] is False

    def test_engine_is_not_read_as_a_playbook_name(self, client):
        """
        Route ordering: POST /engine must be matched before /{name}/apply, the
        same trap /active fell into.
        """
        (client.books / "engine.yaml").write_text(COMMENTED, encoding="utf-8")
        assert client.post("/api/playbooks/engine", json={"enabled": False}).json()["ok"]

    def test_a_hand_edited_config_still_claims_no_playbook(self, client):
        (client.books / "cvm_bypass.yaml").write_text(COMMENTED, encoding="utf-8")
        client.post("/api/playbooks/cvm_bypass/apply")
        client.live.write_text(COMMENTED + '\nafl_mutations: []\n', encoding="utf-8")

        body = client.get("/api/playbooks/active").json()
        assert body["active"] is None
        assert "does not match" in body["reason"]
