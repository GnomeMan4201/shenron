# CHANGELOG

All notable changes to SHENRON are documented here.

---

## [Unreleased] — current main

### Added
- Reproducible CI dependency constraints with `pip check` across test, safety, drift, assumption, wheel-install, and release-validation paths
- A Python 3.10 minimum-dependency compatibility lane that installs the declared dependency floors explicitly and runs the full test suite

### Changed
- GitHub Actions checkout/setup-python workflows now use the current v7 action majors and release validation uses the same constrained dependency snapshot as CI
- Raised the PyYAML minimum from 6.0 to 6.0.3 and Requests from 2.28.0 to 2.32.5, the minimum versions required by the declared `pysigma>=1.3.0` floor

### Removed
- Committed `frontend/node_modules/` dependencies and stale frontend ignore conflicts from the active tree
- Unused `export` optional dependency surface whose Jinja2 extra was not referenced by SHENRON code or documentation

## [v0.4.4] — 2026-08-10

### Added
- Tag-driven GitHub release workflow with version/changelog validation and wheel/source-distribution artifacts
- Release consistency checker and regression tests
- Security policy, release process, and automated dependency-update configuration
- Live release badge in the README

### Changed
- Contributor setup now uses the supported Python floor and the package's declared development dependencies
- Navigator exports now report the package version dynamically instead of a frozen v0.2.0 label

### Fixed
- Restored the assumption-coverage CI gate by classifying `covert_socket_relay` under command-and-control and aligning entropy claims with current emitted signal names
- Raised the supported Python floor from 3.9 to 3.10 to match `pysigma>=1.3.0`; CI now tests Python 3.10–3.12 without matrix fail-fast cancellation
- Removed the stale fixed layer count from the safety-job label
- Made Sigma integration tests generate an isolated full-corpus artifact instead of depending on test-order side effects, and aligned the timestamp rule with current layer telemetry
- Removed a random-vector dependency from the mandatory entropy coverage gate

## [v0.4.3] — 2026-06-02

### Fixed
- `mutation_history`, `polymorph_chain_stats`, `llm_shroud_writer`, `scripts/generate_report.py`: `datetime.UTC` import replaced with `timezone.utc` — fixes `ImportError` on Python 3.9/3.10
- `encrypted_echo_chamber`: rewritten as proper simulation layer — removed real `cryptography.fernet` key generation and file writes; now emits synthetic inert telemetry only
- `polymorph_chain_stats`: added missing `@register_payload(name="polymorph_chain_stats")` decorator — layer was silently unrunnable

### Added
- 6 new Sigma rules covering previously uncovered layer families:
  - `sigma/rules/lateral/shenron_lateral_webcrawler.yml` (T1021, T1046, T1135)
  - `sigma/rules/evasion/shenron_sandbox_evasion_sim.yml` (T1564, T1036)
  - `sigma/rules/evasion/shenron_traffic_reflection_sim.yml` (T1036.005, T1070)
  - `sigma/rules/evasion/shenron_rootkit_evasion_sim.yml` (T1014, T1564)
  - `sigma/rules/evasion/shenron_deadzone_payload.yml` (T1027, T1140)
  - `sigma/rules/exfiltration/shenron_transient_exfil_sim.yml` (T1041, T1048)
- `schema_version` field added to all 16 assumption YAMLs; loader now emits `UserWarning` on missing or mismatched version
- Demo artifact (`artifacts/demo/shenron_demo_run.jsonl`) expanded to include `sandbox_evasion_sim`, `traffic_reflection_sim`, `rootkit_evasion_sim`, `deadzone_payload`, `transient_exfil_sim`, `anti_forensics_molt`, `encrypted_echo_chamber`, `antiforensic_wipe_sim`
- CI bumped to `actions/setup-python@v6`

### Changed
- Sigma rule count: 8 → 14
- Demo artifact event count: 102 → expanded
- All tracked generated output under `reports/` untracked from git; `.gitignore` now correctly excludes them

---

## [v0.4.2] — 2026-05-18

### Security
- Purged `basic_windows_keylogger.ps1`, `windows_reverse_shell.bat`, `mirror_module.sh` from all git history via `git filter-repo`
- Rewrote `signature_mutation_sim.py` as simulation-only — no real file writes, no subprocess
- Removed 4402 unsafe mutation variant files from git tracking; added `.gitignore` rule
- Identified generation-time safety constraint gap in mutation engine — variants were synthesizing real capability from canonical layer patterns

### Added
- CLI subcommand grammar (`shenron run`, `shenron sigma`, `shenron assumption`, etc.) — legacy `--flags` preserved for backward compatibility
- `shenron quickstart` — one-command evidence bundle in 60 seconds
- `shenron assumption diff` — claim-level diff of two assumption YAMLs against the same artifact
- `shenron schema validate` — stdlib-only JSON schema validation against 4 schemas (`shenron_event`, `assumption`, `sigma_result`, `safety_contract`)
- `shenron export ecs` / `shenron export hec` — export to Elastic ECS (array or bulk) and Splunk HEC (ndjson)
- Golden demo regression test — 5 pinned assertions against committed demo artifact
- `broad_detection_claim.yaml` — fixture demonstrating overclaim detection (same artifact, different truth status)
- 4 JSON schemas in `schemas/` — stdlib validator, no external deps

### Fixed
- `obfuscated_skinwalker_dropper` rewritten as simulation layer — removed real `shutil.copy2`, `os.chmod`, shell script writes; now emits synthetic telemetry only
- ECS and Splunk HEC adapter field mapping aligned to real SHENRON event schema (flat safety fields, `mitre_techniques` array, `behavior_class`)
- Pre-rewrite backup layers removed from `core/layers/backups/` — contained real subprocess and filesystem operations

### Changed
- README updated to subcommand grammar, accurate test count (350), new commands documented
- Safety contract wording made precise: generated telemetry never represents real subprocess execution; CLI utility commands may invoke local helper scripts only

---

## [v0.3.3] — 2026-05-16

### Added
- Coverage history tracking — `record_validation`, `--history`, `--history-compare` with delta tracking
- Mutation engine — signature_mutation_sim logs layer mutation events to SQLite
- Enhanced release bundle — `--release-demo` produces complete evidence package

### Changed
- 10 new assumption YAMLs added (14 total)
- Sigma rule validation integrated into HTML report output
- Validation history persists per run for delta comparison

---

## [v0.3.2] — 2026-05-16

### Added
- Defensive narration engine (`core/narration/`) — generates human-readable interpretation of simulation runs
- Narration covers all 8 layer categories with phase-aware language

---

## [v0.3.1] — 2026-05-16

### Added
- ECS format export — `write_ecs_array`, `write_ecs_bulk` (Elastic bulk API ndjson)
- Splunk HEC format export — `write_splunk_hec` (newline-delimited JSON)
- MITRE → ECS field mapping for all techniques in the 50-layer corpus
- Import instructions for both Elastic and Splunk in CLI summary output

---

## [v0.3.0] — 2026-05-16

### Added
- Assumption auditing engine (`core/assumptions/`) — validates whether a JSONL artifact supports, partially supports, or violates a claim
- Out-of-scope violation detection — flags when an artifact is being used to support claims it cannot honestly back
- `--validate-assumption` and `--compare-assumptions` CLI flags
- `safe_conclusion` — deterministic, scope-bounded conclusion string per validation result
- Assumption audit index — persists results per assumption ID
- Committed demo artifact (`artifacts/demo/shenron_demo_run.jsonl`) — works from fresh clone, no setup required
- Sigma rule validation engine (`core/sigma/`) — TRIGGERED / PARTIAL / NOT_TRIGGERED / UNSUPPORTED verdicts
- HTML report output (`--report-html`) — standalone, no external dependencies

### Architecture
- BANANA_TREE four-phase campaign model: OBSERVE → SIMULATE → EXECUTE → ADAPT
- Evidence discipline framing established as core design principle

---

## [v0.2.0] — 2026-05-16

### Added
- `--demo` — generates a complete evidence bundle from a single command
- `--verify-safety` — checks safety contract on any JSONL artifact
- `--compare` — side-by-side comparison of two simulation runs
- `--navigator` — exports ATT&CK Navigator layer JSON
- `--release-demo` — produces a complete release bundle
- Shared safety contract (`core/safety/contract.py`) — `simulation_only`, `executable`, `no_payload_present` enforced across all layers

### Fixed
- Portability: all hardcoded `/home/gnomeman4201/SHENRON` paths removed; `core/config.py` with `SHENRON_HOME`/`SHENRON_REPORT_DIR` env vars
- All 50 layers patched for cross-platform path resolution

---

## [v0.1.0] — 2026-05-16

### Initial release

- 50 canonical simulation layers across 8 categories: c2, entropy, identity, evasion, payload, llm, persistence, meta
- Layer loader with mutation variant filtering (`discover_canonical()`)
- bananaTREE scenario engine — chain layers into kill chain timelines
- `--run` CLI with single layer, category, and all targets; `--dry-run` support
- Payload registry — `@register_payload` decorator, `payload_registry.run()`
- MITRE ATT&CK metadata on all 50 layers
- Detector validation scoring — expectations loader, scorer, coverage report
- Safety contract: `executable: false`, `no_payload_present: true` on all layer output
- 116 tests at release

---

## Design principles

**Observable adversarial behavior, not portable adversarial procedure.**

SHENRON generates synthetic telemetry that represents the *shape* of adversarial behavior — what a defender would observe — without containing the procedure that would make it executable or portable. Every artifact carries an explicit safety contract. No payloads, no exploit code, no real subprocess execution, no real network connections.

**Evidence discipline over coverage theater.**

The assumption engine exists to prevent overclaiming. A TRIGGERED Sigma verdict means your rule matches the shape of the simulated behavior. It does not mean your detection stack would catch a real attacker. SHENRON tells you exactly what claims your artifact can and cannot honestly support.

**What SHENRON is not.**
- Not a red team tool
- Not a payload generator
- Not a substitute for live red team artifacts or production telemetry validation
- Not a claim that your detection stack is effective

---

## Roadmap considerations

Areas where SHENRON could be extended by contributors:

- **Real artifact ingestion** — import live EDR/SIEM JSONL and validate assumptions against it
- **Sigma rule authoring assistant** — given a layer's detection opportunities, suggest a Sigma rule skeleton
- **Coverage gap analysis** — given a set of assumptions, identify which MITRE techniques have no simulation coverage
- **Multi-artifact assumption diff** — diff the same assumption across two different artifacts (v1 vs v2 of a detection stack)
- **STIX/TAXII export** — map simulation output to STIX 2.1 bundle format
- **CI integration** — run assumption validation as a pipeline gate

*gnomeman4201 / badBANANA Research Collective*
