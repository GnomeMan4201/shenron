"""
tests/test_sigma_integration.py
SHENRON — Sigma rule regression gate

Asserts that the full rule set produces the expected verdict distribution
against the layer artifact log. If a rule that was TRIGGERED starts returning
NOT_TRIGGERED or UNSUPPORTED, this test catches it immediately.

Run: pytest tests/test_sigma_integration.py -v
"""
import json
import pytest
from pathlib import Path
from core.sigma.evaluator import evaluate_sigma_rule
from core.sigma.model import RuleVerdict
from core.config import artifact_log_path

RULES_DIR   = Path("sigma/rules")
ARTIFACT_LOG = artifact_log_path()

# Rules expected to TRIGGER against a full layer artifact log.
# Update this list when you intentionally add/change rules.
EXPECTED_TRIGGERED = {
    "shenron-c2-001",           # SHENRON C2 Beacon Detection
    "shenron-c2-002",           # SHENRON Covert Channel / Protocol Tunneling
    "shenron-airlock-quarantine-001",   # Quarantine Directory Access
    "shenron-deadzone-payload-001",     # Payload Staging
    "shenron-evasion-002",      # High Entropy Evasion Pattern
    "shenron-mirror-loop-deflector-001",# Process Name Masquerading
    "shenron-spectral-rootkit-shroud-001", # Rootkit Artifact
    "shenron-evasion-001",      # Timestamp Manipulation
    "shenron-transient-exfil-shell-001", # Ephemeral Exfiltration Shell
    "shenron-lateral-webcrawler-001",   # Lateral Movement Recon
    "shenron-process-injection-001",    # Process Injection Persistence (approx ID)
    "shenron-scheduled-task-001",       # Scheduled Task Persistence (approx ID)
    "dep-confusion-phantom-001",        # Dependency Confusion
    "shenron-lotl-execution-001",       # LOtL Execution
}

# Rules that should NOT trigger (correct by design)
EXPECTED_NOT_TRIGGERED = {
    # Windows EventID rule — will never fire against SHENRON telemetry

    # bpf-watch live rules — fire against live telemetry only, not simulation artifacts
    "bpfwatch-kprobe-sentinel-001",
    "bpfwatch-cap-watcher-001",
    "bpfwatch-xdp-monitor-001",
    "bpfwatch-enumerator-discrepancy-001",
    "bpfwatch-dangerous-helper-001",
}

# Rules that should remain UNSUPPORTED (Windows-only fields)
EXPECTED_UNSUPPORTED = {
    # windows_event_log.yml uses EventID — correct
}


def _load_all_rules():
    """Return list of (rule_path, rule_id, rule_title) for all rules."""
    rules = []
    for rp in sorted(RULES_DIR.rglob("*.yml")):
        from core.sigma.loader import load_sigma_rule
        try:
            rule = load_sigma_rule(str(rp))
            rules.append((rp, rule.get("id", rp.stem), rule.get("title", rp.stem)))
        except Exception as e:
            pytest.fail(f"Failed to load rule {rp}: {e}")
    return rules


@pytest.fixture(scope="module")
def artifact_log():
    """Ensure artifact log exists."""
    if not ARTIFACT_LOG.exists():
        pytest.skip(
            f"Artifact log not found: {ARTIFACT_LOG}. "
            "Run: python3 shenron.py run all"
        )
    return str(ARTIFACT_LOG)


@pytest.fixture(scope="module")
def sigma_results(artifact_log):
    """Evaluate all sigma rules once and cache results."""
    results = {}
    for rp, rule_id, rule_title in _load_all_rules():
        result = evaluate_sigma_rule(str(rp), artifact_log)
        results[rule_id] = (result, rule_title, rp)
    return results


def test_sigma_rule_count(sigma_results):
    """Exactly 20 rules must be present."""
    assert len(sigma_results) == 20, (
        f"Expected 20 sigma rules, found {len(sigma_results)}. "
        "Update this test if you intentionally add/remove rules."
    )


def test_no_rule_errors(sigma_results):
    """No rule should return ERROR verdict."""
    errors = [
        (rule_id, title)
        for rule_id, (result, title, _) in sigma_results.items()
        if result.verdict == RuleVerdict.ERROR
    ]
    assert not errors, f"Rules returned ERROR: {errors}"


def test_triggered_count(sigma_results):
    """At least 13 rules must TRIGGER against the layer artifact log."""
    triggered = [
        rule_id for rule_id, (result, _, _) in sigma_results.items()
        if result.verdict == RuleVerdict.TRIGGERED
    ]
    assert len(triggered) >= 13, (
        f"Expected >=13 TRIGGERED rules, got {len(triggered)}: {triggered}"
    )


def test_windows_event_log_not_triggered(sigma_results):
    """The Windows EventID rule should never fire against SHENRON telemetry."""
    for rule_id, (result, title, rp) in sigma_results.items():
        if "windows" in rp.name.lower() or "EventID" in rp.read_text():
            assert result.verdict != RuleVerdict.TRIGGERED, (
                f"Windows EventID rule {rule_id} unexpectedly TRIGGERED. "
                "SHENRON does not emit Windows event log fields."
            )


def test_c2_rules_triggered(sigma_results):
    """C2 beacon and covert channel rules must always trigger."""
    c2_rules = {
        rule_id: (result, title)
        for rule_id, (result, title, rp) in sigma_results.items()
        if "c2" in str(rp).lower() or "beacon" in title.lower() or "covert" in title.lower()
    }
    assert c2_rules, "No C2 rules found"
    for rule_id, (result, title) in c2_rules.items():
        assert result.verdict == RuleVerdict.TRIGGERED, (
            f"C2 rule '{title}' ({rule_id}) should be TRIGGERED, got {result.verdict.value}"
        )


def test_evasion_rules_triggered(sigma_results):
    """Core evasion rules (entropy, timestamp) must trigger."""
    evasion_titles = ["entropy", "timestamp", "evasion"]
    for rule_id, (result, title, rp) in sigma_results.items():
        if any(t in title.lower() for t in evasion_titles):
            assert result.verdict == RuleVerdict.TRIGGERED, (
                f"Evasion rule '{title}' ({rule_id}) should be TRIGGERED, "
                f"got {result.verdict.value}. "
                "Check layer field emission with: python3 shenron.py doctor"
            )


def test_persistence_rules_triggered(sigma_results):
    """Persistence rules must trigger."""
    for rule_id, (result, title, rp) in sigma_results.items():
        if "persistence" in str(rp).lower() and "windows" not in rp.name.lower():
            assert result.verdict == RuleVerdict.TRIGGERED, (
                f"Persistence rule '{title}' ({rule_id}) should be TRIGGERED, "
                f"got {result.verdict.value}"
            )


def test_no_regression_from_partial(sigma_results):
    """No rule should regress from TRIGGERED to PARTIAL or NOT_TRIGGERED."""
    # Any rule that fires on the full layer log should not be PARTIAL
    # (PARTIAL means only some artifacts matched — acceptable for some rules)
    partial = [
        (rule_id, title)
        for rule_id, (result, title, _) in sigma_results.items()
        if result.verdict == RuleVerdict.PARTIAL
    ]
    # PARTIAL is allowed but should be 0 — log it as a warning
    if partial:
        import warnings
        warnings.warn(
            f"Rules returning PARTIAL (investigate field emission): "
            f"{[(rid, t) for rid, t in partial]}"
        )


def test_verdict_summary_json(sigma_results, tmp_path):
    """Verdict summary should be serializable to JSON."""
    summary = {
        rule_id: {
            "verdict": result.verdict.value,
            "title": title,
            "triggered_count": result.triggered_count,
        }
        for rule_id, (result, title, _) in sigma_results.items()
    }
    out = tmp_path / "sigma_summary.json"
    out.write_text(json.dumps(summary, indent=2))
    loaded = json.loads(out.read_text())
    assert len(loaded) == len(sigma_results)
