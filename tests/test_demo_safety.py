"""
tests/test_demo_safety.py
SHENRON — Safety and QA Tests

Run: pytest tests/test_demo_safety.py -v

Tests:
  - No subprocess usage in generator
  - No socket/network usage in generator
  - No file execution in generator
  - Generated JSONL schema compliance
  - All events carry simulation_only: true
  - All events carry payload_present: false
  - All events carry executable: false
  - All events carry portable_adversarial_procedure: false
  - All events carry subprocess_spawned: false
  - All events carry network_connection: false
  - No events reference real system paths
  - Report file existence after generation
  - JSONL line count >= 20
"""

import ast
import inspect
import json
import os
import subprocess
import sys
import tempfile
import textwrap

import pytest

# ---------------------------------------------------------------------------
# Locate the generator script
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.join(os.path.dirname(__file__), "..", "scripts")
GENERATOR = os.path.join(SCRIPT_DIR, "generate_demo_artifacts.py")

REQUIRED_SAFETY_FIELDS = {
    "simulation_only":                True,
    "executable":                     False,
    "payload_present":                False,
    "portable_adversarial_procedure": False,
    "subprocess_spawned":             False,
    "network_connection":             False,
    "real_file_written":              False,
    "shell_invoked":                  False,
}

FORBIDDEN_MODULES = {"subprocess", "socket", "ctypes", "os.system", "pty", "pty.spawn"}

FORBIDDEN_SOURCE_PATTERNS = [
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "os.system(",
    "os.popen(",
    "socket.socket",
    "socket.connect",
    "pty.spawn",
    "exec(",
    "eval(",
    "__import__(",
]

FORBIDDEN_STRINGS_IN_ARTIFACTS = [
    "/etc/passwd",
    "/etc/shadow",
    "crontab -e",
    "bash -i",
    "/bin/sh",
    "chmod +x",
    "wget http",
    "curl http",
]


# ---------------------------------------------------------------------------
# Helper: run the generator and return artifact dir
# ---------------------------------------------------------------------------
def _run_generator():
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [sys.executable, GENERATOR, "--out-dir", tmpdir],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, (
            f"Generator exited non-zero:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        jsonl_path = os.path.join(tmpdir, "shenron_demo_run.jsonl")
        report_path = os.path.join(tmpdir, "shenron_demo_report.md")
        events = []
        with open(jsonl_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
        report_text = open(report_path).read() if os.path.exists(report_path) else ""
        return events, report_text


# ---------------------------------------------------------------------------
# Static source analysis
# ---------------------------------------------------------------------------
class TestSourceSafety:

    def _get_source(self):
        assert os.path.exists(GENERATOR), f"Generator not found: {GENERATOR}"
        return open(GENERATOR).read()

    def test_no_subprocess_import(self):
        source = self._get_source()
        assert "import subprocess" not in source, \
            "SAFETY: subprocess import found in generator source"

    def test_no_socket_import(self):
        source = self._get_source()
        assert "import socket" not in source, \
            "SAFETY: socket import found in generator source"

    def test_no_ctypes_import(self):
        source = self._get_source()
        assert "import ctypes" not in source, \
            "SAFETY: ctypes import found in generator source"

    def test_no_forbidden_patterns(self):
        source = self._get_source()
        for pattern in FORBIDDEN_SOURCE_PATTERNS:
            assert pattern not in source, \
                f"SAFETY: forbidden pattern '{pattern}' found in generator source"

    def test_no_exec_eval(self):
        source = self._get_source()
        # Allow 'executable' as a field name but not exec( or eval(
        for bad in ["exec(", "eval("]:
            assert bad not in source, \
                f"SAFETY: '{bad}' found in generator source"

    def test_source_is_valid_python(self):
        source = self._get_source()
        try:
            ast.parse(source)
        except SyntaxError as e:
            pytest.fail(f"Generator source has syntax error: {e}")


# ---------------------------------------------------------------------------
# Runtime output tests
# ---------------------------------------------------------------------------
class TestGeneratedArtifacts:

    @pytest.fixture(scope="class")
    def artifacts(self):
        return _run_generator()

    def test_minimum_event_count(self, artifacts):
        events, _ = artifacts
        assert len(events) >= 20, \
            f"Expected >= 20 events, got {len(events)}"

    def test_all_phases_present(self, artifacts):
        events, _ = artifacts
        phases = {ev["phase"] for ev in events}
        for p in ["OBSERVE", "SIMULATE", "EXECUTE", "ADAPT"]:
            assert p in phases, f"Phase {p} missing from events"

    def test_all_events_have_safety_block(self, artifacts):
        events, _ = artifacts
        for i, ev in enumerate(events):
            assert "safety" in ev, f"Event {i} (seq={ev.get('sequence')}) missing 'safety' block"

    def test_simulation_only_true(self, artifacts):
        events, _ = artifacts
        for ev in events:
            assert ev["safety"].get("simulation_only") is True, \
                f"Event seq={ev.get('sequence')} has simulation_only != true"

    def test_executable_false(self, artifacts):
        events, _ = artifacts
        for ev in events:
            assert ev["safety"].get("executable") is False, \
                f"Event seq={ev.get('sequence')} has executable != false"

    def test_payload_present_false(self, artifacts):
        events, _ = artifacts
        for ev in events:
            assert ev["safety"].get("payload_present") is False, \
                f"Event seq={ev.get('sequence')} has payload_present != false"

    def test_portable_adversarial_procedure_false(self, artifacts):
        events, _ = artifacts
        for ev in events:
            assert ev["safety"].get("portable_adversarial_procedure") is False, \
                f"Event seq={ev.get('sequence')} has portable_adversarial_procedure != false"

    def test_subprocess_spawned_false(self, artifacts):
        events, _ = artifacts
        for ev in events:
            assert ev["safety"].get("subprocess_spawned") is False, \
                f"Event seq={ev.get('sequence')} has subprocess_spawned != false"

    def test_network_connection_false(self, artifacts):
        events, _ = artifacts
        for ev in events:
            assert ev["safety"].get("network_connection") is False, \
                f"Event seq={ev.get('sequence')} has network_connection != false"

    def test_no_forbidden_strings_in_artifacts(self, artifacts):
        events, _ = artifacts
        raw = json.dumps(events)
        for bad in FORBIDDEN_STRINGS_IN_ARTIFACTS:
            assert bad not in raw, \
                f"Forbidden string '{bad}' found in generated artifact data"

    def test_all_events_have_run_id(self, artifacts):
        events, _ = artifacts
        for ev in events:
            assert "run_id" in ev and ev["run_id"], \
                f"Event seq={ev.get('sequence')} missing run_id"

    def test_all_events_have_mitre_technique(self, artifacts):
        events, _ = artifacts
        for ev in events:
            t = ev.get("mitre_technique", "")
            assert t.startswith("T"), \
                f"Event seq={ev.get('sequence')} has invalid MITRE technique: '{t}'"

    def test_report_exists_and_has_verdict(self, artifacts):
        _, report = artifacts
        assert "PASS" in report or "Verdict" in report, \
            "Report does not contain verdict section"

    def test_report_has_safety_disclaimer(self, artifacts):
        _, report = artifacts
        assert "SYNTHETIC" in report or "simulation_only" in report, \
            "Report missing safety disclaimer"

    def test_no_events_have_payload_content(self, artifacts):
        events, _ = artifacts
        for ev in events:
            desc = ev.get("description", "").lower()
            # description should be shape/descriptor language, not functional code
            for bad in ["shellcode", "meterpreter", "reverse_shell", "exec(", "system("]:
                assert bad not in desc, \
                    f"Event seq={ev.get('sequence')} description contains '{bad}'"

    def test_unique_run_id_per_run(self, artifacts):
        events, _ = artifacts
        run_ids = {ev["run_id"] for ev in events}
        assert len(run_ids) == 1, \
            f"Expected single run_id per run, got: {run_ids}"


# ---------------------------------------------------------------------------
# Article QA tests (if article file exists locally)
# ---------------------------------------------------------------------------
ARTICLE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "docs", "devto_launch_article.md"
)


class TestArticle:

    def _get_article(self):
        if not os.path.exists(ARTICLE_PATH):
            pytest.skip(f"Article not found at {ARTICLE_PATH}")
        return open(ARTICLE_PATH).read()

    def test_article_has_safety_boundary_section(self):
        article = self._get_article()
        assert "safety boundary" in article.lower() or "safety_boundary" in article.lower(), \
            "Article missing safety boundary section"

    def test_article_does_not_claim_real_execution(self):
        article = self._get_article()
        BAD_PHRASES = ["real execution occurred", "actual network traffic", "live payload"]
        for phrase in BAD_PHRASES:
            assert phrase not in article.lower(), \
                f"Article contains overclaiming phrase: '{phrase}'"

    def test_article_has_what_this_does_not_prove(self):
        article = self._get_article()
        assert "does not" in article.lower() or "cannot" in article.lower(), \
            "Article missing 'what this does not prove' or limitation language"

    def test_article_has_synthetic_label(self):
        article = self._get_article()
        assert "synthetic" in article.lower(), \
            "Article never uses the word 'synthetic'"


# ---------------------------------------------------------------------------
# Image existence checks
# ---------------------------------------------------------------------------
CHART_DIR = os.path.join(
    os.path.dirname(__file__), "..", "docs", "assets", "shenron-demo"
)
EXPECTED_CHARTS = [
    "phase_frequency.png",
    "technique_frequency.png",
    "signal_frequency.png",
    "event_timeline.png",
    "safety_boundary.png",
]


class TestChartFiles:

    def test_chart_dir_exists(self):
        assert os.path.isdir(CHART_DIR), f"Chart dir missing: {CHART_DIR}"

    @pytest.mark.parametrize("chart", EXPECTED_CHARTS)
    def test_chart_exists(self, chart):
        path = os.path.join(CHART_DIR, chart)
        assert os.path.isfile(path), f"Chart missing: {path}"

    @pytest.mark.parametrize("chart", EXPECTED_CHARTS)
    def test_chart_is_nonzero(self, chart):
        path = os.path.join(CHART_DIR, chart)
        if os.path.isfile(path):
            assert os.path.getsize(path) > 1024, \
                f"Chart suspiciously small: {path}"
