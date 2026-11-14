"""Issue #65: real HTML CLI routes disclose exclusions and fail closed on edits.

All evidence is generated synthetic demo telemetry. Each process runs against
an isolated source/input copy, with no writes to the working tree or user home.
"""
from html.parser import HTMLParser
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest
import yaml

from scripts.generate_demo_artifacts import generate_events, write_jsonl


ROOT = Path(__file__).resolve().parents[1]
LEGACY = ("assumption_dependency_confusion.yaml", "c2_lateral_coverage.yaml")
EXCLUDED = "EXCLUDED — NOT VALIDATED"
VERDICTS = {"SUPPORTED", "PARTIALLY_SUPPORTED", "UNSUPPORTED", "OUT_OF_SCOPE_VIOLATION"}


class ReportTables(HTMLParser):
    """Read visible heading/table cells without depending on CSS or whitespace."""

    def __init__(self, html):
        super().__init__(convert_charrefs=True)
        self.tables = {}
        self.heading = ""
        self.capture = None
        self.parts = []
        self.row = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        if tag in ("h2", "td", "th"):
            self.capture = tag
            self.parts = []
        elif tag == "table":
            self.tables[self.heading] = []
        elif tag == "tr":
            self.row = []

    def handle_data(self, data):
        if self.capture:
            self.parts.append(data)

    def handle_endtag(self, tag):
        if tag == self.capture:
            text = " ".join("".join(self.parts).split())
            if tag == "h2":
                self.heading = text
            else:
                self.row.append(text)
            self.capture = None
        elif tag == "tr":
            self.tables[self.heading].append(self.row)


@pytest.fixture(params=[("report", "html"), ("--report-html",)], ids=["subcommand", "legacy"])
def cli(tmp_path, request):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    for name in ("core", "assumptions", "sigma"):
        shutil.copytree(ROOT / name, checkout / name,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    shutil.copy2(ROOT / "shenron.py", checkout / "shenron.py")
    events = tmp_path / "known_demo.jsonl"
    write_jsonl(generate_events("html-cli-contract"), str(events))
    reports = tmp_path / "reports"
    env = os.environ.copy()
    env.update(HOME=str(tmp_path / "home"), SHENRON_HOME=str(tmp_path / "home"), SHENRON_REPORT_DIR=str(reports),
               PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(checkout))

    def run(cwd=checkout):
        return subprocess.run(
            [sys.executable, str(checkout / "shenron.py"), *request.param,
             "--events", str(events)],
            cwd=cwd, env=env, text=True, capture_output=True, timeout=30, check=False,
        )

    return checkout, reports, run


def _report(cli, *, evaluated=17):
    checkout, reports, run = cli
    outcome = run()
    assert outcome.returncode == 0, outcome.stdout + outcome.stderr
    files = list(reports.glob("*.html"))
    assert len(files) == 1, outcome.stdout + outcome.stderr
    assert str(files[0]) in outcome.stdout
    html = files[0].read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html
    tables = ReportTables(html).tables
    rows = tables[f"Assumption Validation ({evaluated} assumptions)"][1:]
    assert len(rows) == evaluated
    expected_ids = {
        yaml.safe_load(path.read_text(encoding="utf-8"))["id"]
        for path in (checkout / "assumptions/examples").glob("*.yaml")
        if path.name not in LEGACY
    }
    assert {row[0] for row in rows} == expected_ids
    assert all(row[1] in VERDICTS for row in rows)
    assert all(EXCLUDED not in cell for row in rows for cell in row)
    exclusion_tables = [table for heading, table in tables.items() if "exclusion" in heading.lower()]
    assert len(exclusion_tables) == 1, "Exclusions need a dedicated table, separate from verdicts"
    exclusions = exclusion_tables[0][1:]
    assert len(exclusions) == 2
    assert {row[0] for row in exclusions} == set(LEGACY)
    assert all(EXCLUDED in row for row in exclusions)
    assert html.count(EXCLUDED) == 2
    return rows


def _fails_without_report(cli, diagnostic, *, cwd=None):
    _, reports, run = cli
    outcome = run() if cwd is None else run(cwd)
    assert outcome.returncode != 0, outcome.stdout + outcome.stderr
    assert diagnostic in outcome.stdout + outcome.stderr
    assert "HTML report:" not in outcome.stdout
    assert not list(reports.glob("*.html"))


def test_both_html_clis_report_17_evaluations_and_two_nonvalidated_exclusions(cli):
    _report(cli)


@pytest.mark.parametrize("filename", LEGACY)
@pytest.mark.parametrize("edit", ["comment", "canonical_replacement"])
def test_edited_pinned_legacy_fails_closed_even_if_replaced_with_valid_canonical(cli, filename, edit):
    checkout, _, _ = cli
    path = checkout / "assumptions/examples" / filename
    if edit == "comment":
        path.write_text(path.read_text(encoding="utf-8") + "\n# edited\n", encoding="utf-8")
    else:
        path.write_text(_canonical_yaml("replacement", "periodic_beacon"), encoding="utf-8")
    _fails_without_report(cli, "pinned legacy example changed")


@pytest.mark.parametrize("filename", LEGACY)
def test_unknown_legacy_document_is_not_silently_skipped(cli, filename):
    checkout, _, _ = cli
    examples = checkout / "assumptions/examples"
    shutil.copy2(examples / filename, examples / "zzz_unknown_legacy.yaml")
    _fails_without_report(cli, "zzz_unknown_legacy.yaml")


@pytest.mark.parametrize("filename", LEGACY)
def test_unchanged_legacy_outside_builtin_directory_is_not_excluded(cli, tmp_path, filename):
    checkout, _, _ = cli
    external = tmp_path / "external"
    examples = external / "assumptions/examples"
    examples.mkdir(parents=True)
    shutil.copy2(checkout / "assumptions/examples" / filename, examples / filename)
    _fails_without_report(cli, "unknown top-level key", cwd=external)


@pytest.mark.parametrize("malformation", ["document_key", "claim_key"])
def test_malformed_canonical_yaml_is_not_silently_skipped(cli, malformation):
    checkout, _, _ = cli
    path = checkout / "assumptions/examples/zzz_invalid_canonical.yaml"
    text = _canonical_yaml("invalid_control", "periodic_beacon")
    if malformation == "document_key":
        text += "claim: typo\n"
        diagnostic = "unknown top-level key"
    else:
        text = text.replace("requires_signals:", "requires_signal:")
        diagnostic = "unknown claim key"
    path.write_text(text, encoding="utf-8")
    _fails_without_report(cli, diagnostic)


def _canonical_yaml(assumption_id, signal):
    return yaml.safe_dump({
        "schema_version": "1.0", "id": assumption_id,
        "claims": [{"id": "control", "type": "positive_evidence", "requires_signals": [signal]}],
    })


@pytest.mark.parametrize("signal,verdict,counts", [
    ("periodic_beacon", "SUPPORTED", ["1", "0"]),
    ("absent_html_control_signal", "UNSUPPORTED", ["0", "1"]),
])
def test_valid_canonical_file_keeps_its_real_verdict(cli, signal, verdict, counts):
    checkout, _, _ = cli
    path = checkout / "assumptions/examples/zzz_valid_control.yaml"
    path.write_text(_canonical_yaml("html_control", signal), encoding="utf-8")
    rows = _report(cli, evaluated=18)
    control = next(row for row in rows if row[0] == "html_control")
    assert control[1:4] == [verdict, *counts]
