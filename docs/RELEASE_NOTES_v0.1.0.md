# SHENRON v0.1.0 Release Notes

**Release date:** 2026-05-16
**Tag:** `v0.1.0`
**Commit:** `2dffe06`
**Author:** gnomeman4201 / badBANANA Research Collective

---

## Summary

SHENRON v0.1.0 is the first public release of a defensive adversarial telemetry simulation platform. It generates structured, synthetic JSONL telemetry representing adversarial behavior patterns across 50 simulation layers, organized into a four-phase campaign model (OBSERVE, SIMULATE, EXECUTE, ADAPT), with full detector validation scoring and report generation. SHENRON does not contain payloads, exploit code, real network calls, subprocess execution, or operational malware logic. Every artifact is synthetic. Every layer carries an explicit safety contract.

**Core principle:** Observable adversarial behavior, not portable adversarial procedure.

---

## Verified release state

| Check | Result |
|-------|--------|
| Test suite | 117 passed, 0 failed |
| Layer dry-run | 50 ok, 0 failed |
| Hardcoded paths | 0 remaining |
| Safety failures (latest run) | 0 |
| SHENRON_HOME configurable | yes |
| SHENRON_REPORT_DIR configurable | yes |
| Working tree | clean |
| Tag | v0.1.0 at HEAD |

---

## What shipped

### 50 canonical simulation layers

All 50 layers produce defender-observable synthetic telemetry. No layer executes real capability.

| Category | bananaTREE phase | Layers |
|----------|-----------------|--------|
| c2 | OBSERVE | 8 |
| entropy | OBSERVE | 8 |
| identity | OBSERVE | 4 |
| evasion | SIMULATE | 6 |
| payload | SIMULATE | 8 |
| llm | SIMULATE | 4 |
| persistence | EXECUTE | 6 |
| meta | ADAPT | 6 |

Three layers (`dark_signature_morpher`, `polymorph_chain_stats`, `mutation_history`) are operational infrastructure rather than simulators and are documented as such.

### bananaTREE campaign model

Four-phase defensive simulation lifecycle in `core/bananatree/`:

- **OBSERVE** — enumerate adversarial signal surface
- **SIMULATE** — generate synthetic telemetry for detector training
- **EXECUTE** — produce full artifact timelines
- **ADAPT** — score detection coverage, identify gaps

### Report generator v2

Ten-section markdown reports from JSONL evidence: Executive Summary, bananaTREE Cycle, Scenario Metadata, Layer Execution Summary, MITRE Coverage, Synthetic Telemetry Timeline, Detection Opportunities, Defensive Runbook, Safety Contract Verification, Evidence Appendix. Optional Detector Validation section via `--include-validation`.

### Detector validation scoring

PASS / PARTIAL / MISS per expected detection. Coverage: PASS x 1.0 + PARTIAL x 0.5. Verdicts: PASS >=80%, PARTIAL >=50%, FAIL <50%, UNSAFE on any safety violation.

### Safety contract enforcement

Every artifact carries `simulation_only: true`, `executable: false`, `no_payload_present: true`. Any violation degrades verdict to UNSAFE regardless of coverage score.

### Configurable paths

```bash
mkdir -p docs

cat > docs/RELEASE_NOTES_v0.1.0.md << 'ENDOFFILE'
# SHENRON v0.1.0 Release Notes

**Release date:** 2026-05-16
**Tag:** `v0.1.0`
**Commit:** `2dffe06`
**Author:** gnomeman4201 / badBANANA Research Collective

---

## Summary

SHENRON v0.1.0 is the first public release of a defensive adversarial telemetry simulation platform. It generates structured, synthetic JSONL telemetry representing adversarial behavior patterns across 50 simulation layers, organized into a four-phase campaign model (OBSERVE, SIMULATE, EXECUTE, ADAPT), with full detector validation scoring and report generation. SHENRON does not contain payloads, exploit code, real network calls, subprocess execution, or operational malware logic. Every artifact is synthetic. Every layer carries an explicit safety contract.

**Core principle:** Observable adversarial behavior, not portable adversarial procedure.

---

## Verified release state

| Check | Result |
|-------|--------|
| Test suite | 117 passed, 0 failed |
| Layer dry-run | 50 ok, 0 failed |
| Hardcoded paths | 0 remaining |
| Safety failures (latest run) | 0 |
| SHENRON_HOME configurable | yes |
| SHENRON_REPORT_DIR configurable | yes |
| Working tree | clean |
| Tag | v0.1.0 at HEAD |

---

## What shipped

### 50 canonical simulation layers

All 50 layers produce defender-observable synthetic telemetry. No layer executes real capability.

| Category | bananaTREE phase | Layers |
|----------|-----------------|--------|
| c2 | OBSERVE | 8 |
| entropy | OBSERVE | 8 |
| identity | OBSERVE | 4 |
| evasion | SIMULATE | 6 |
| payload | SIMULATE | 8 |
| llm | SIMULATE | 4 |
| persistence | EXECUTE | 6 |
| meta | ADAPT | 6 |

Three layers (`dark_signature_morpher`, `polymorph_chain_stats`, `mutation_history`) are operational infrastructure rather than simulators and are documented as such.

### bananaTREE campaign model

Four-phase defensive simulation lifecycle in `core/bananatree/`:

- **OBSERVE** — enumerate adversarial signal surface
- **SIMULATE** — generate synthetic telemetry for detector training
- **EXECUTE** — produce full artifact timelines
- **ADAPT** — score detection coverage, identify gaps

### Report generator v2

Ten-section markdown reports from JSONL evidence: Executive Summary, bananaTREE Cycle, Scenario Metadata, Layer Execution Summary, MITRE Coverage, Synthetic Telemetry Timeline, Detection Opportunities, Defensive Runbook, Safety Contract Verification, Evidence Appendix. Optional Detector Validation section via `--include-validation`.

### Detector validation scoring

PASS / PARTIAL / MISS per expected detection. Coverage: PASS x 1.0 + PARTIAL x 0.5. Verdicts: PASS >=80%, PARTIAL >=50%, FAIL <50%, UNSAFE on any safety violation.

### Safety contract enforcement

Every artifact carries `simulation_only: true`, `executable: false`, `no_payload_present: true`. Any violation degrades verdict to UNSAFE regardless of coverage score.

### Configurable paths

```bash
### Test suite: 117 tests

- tests/test_bananatree.py    — 35 tests
- tests/test_reports.py       — 31 tests
- tests/test_validation.py    — 35 tests
- tests/test_config_paths.py  — 16 tests

### Documentation

README.md, docs/SAFETY_CONTRACT.md, docs/FIELD_GUIDE.md, docs/BANANATREE_MODEL.md,
docs/BLUE_TEAM_USE_CASES.md, docs/SCENARIO_AUTHORING.md, docs/DETECTOR_VALIDATION.md,
docs/EXAMPLE_REPORT.md, docs/RELEASE_CHECKLIST.md

---

## CLI reference

```bash
python3 shenron.py --list
python3 shenron.py --run all --dry-run
python3 shenron.py --run c2
python3 shenron.py --stats
python3 shenron.py --scenarios
python3 shenron.py --scenario apt_kill_chain --dry-run
python3 shenron.py --validate latest
python3 shenron.py --report-v2 latest --include-validation
---

## Known limitations

1. **Dry-run default** — `run_scenario()` defaults to `dry_run=True`. CLI does not yet expose this for custom scenario paths.
2. **No validation history persistence** — `--validate` reads the live JSONL log. Historical comparison requires manual run_id tracking.
3. **Medium fidelity** — All 50 layers emit structured telemetry at medium fidelity. Higher-fidelity timing models planned for v0.2.0.
4. **Single-host** — No distributed campaign support.
5. **No kernel-level telemetry** — Tests the log/SIEM pipeline, not EDR behavioral detection.

---

## Next milestone

See docs/ROADMAP_v0.2.0.md.
