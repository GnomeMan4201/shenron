---
title: Observable Adversarial Behavior, Not Portable Adversarial Procedure
published: true
tags: security, blueteam, python, opensource
cover_image: https://dev-to-uploads.s3.amazonaws.com/uploads/articles/zbsteotk0ldx8yzwfr3u.png
---

*How I built SHENRON as a defensive telemetry simulation lab for blue-team validation without shipping the attack.*

**Repo:** https://github.com/GnomeMan4201/shenron

---

There is a specific problem that comes up when you are building detection systems without a red team budget, a dedicated lab environment, or a controlled range: you cannot safely generate realistic adversarial telemetry on demand.

You can read ATT&CK. You can study threat intelligence reports. You can look at PCAP samples from controlled captures. But actually producing a continuous, structured stream of adversarial-shaped events — the kind your SIEM rules are supposed to fire on — without introducing real malware into your environment is harder than it sounds.

That is the problem I built SHENRON to solve.

> **Note on history:** Earlier articles about SHENRON described an earlier architecture with different goals. The current codebase is a ground-up rewrite as a telemetry simulation harness. The older articles describe that prior architecture. This article describes what SHENRON is now.

---

## The safety boundary first

Before anything else, because this matters more than the feature list:

SHENRON does not contain:

- Executable payloads or shellcode
- Real network connections or socket bindings
- Subprocess spawning or shell command execution
- Real file writes outside its own log directory
- Exploit code of any kind

This is not a disclaimer. It is an architectural constraint.

Every layer is structured so that the real behavior it represents is described in the artifact metadata, not performed by the code. A C2 beaconing layer contains data structures describing timing intervals, entropy patterns, and protocol shapes. Not socket calls. A persistence layer describes what cron modification looks like as a log event sequence. It does not write to cron.

The safety verifier scans every artifact and flags violations. A single violation produces `VERDICT: UNSAFE` regardless of coverage score.

---

## What it is

SHENRON is a Python-based defensive adversarial telemetry simulation platform. It has 50 simulation layers, each representing a different adversarial technique or behavior class, organized through a four-phase campaign model called bananaTREE: OBSERVE, SIMULATE, EXECUTE, ADAPT.

Every layer emits structured JSONL artifacts. Every artifact carries an explicit safety contract:

```json
{
  "run_id": "demo-dca95fa7a6aa",
  "sequence": 1,
  "phase": "OBSERVE",
  "layer": "beacon_emitter_cloak",
  "event_type": "synthetic_telemetry",
  "signal": "periodic_beacon",
  "mitre_technique": "T1071.001",
  "description": "C2 beaconing shape — timing interval model",
  "entropy": 5.1859,
  "safety": {
    "simulation_only": true,
    "executable": false,
    "payload_present": false,
    "portable_adversarial_procedure": false,
    "network_connection": false,
    "subprocess_spawned": false,
    "real_file_written": false,
    "shell_invoked": false
  },
  "note": "SYNTHETIC RECORD — not produced by real adversarial execution"
}
```

The core principle:
> **Observable adversarial behavior, not portable adversarial procedure.**

SHENRON documents what adversarial activity looks like from a defender's perspective. It does not implement that activity.

---

## Why I built it this way

I have been doing independent security research for a few years, self-taught, working primarily in Python and bash on a mid-grade laptop and an Android smartphone. I am interested in the defensive side — specifically in the gap between "we have detection rules" and "we have validated that our detection rules fire on realistic telemetry."

That gap is large. Most SIEM rules have never been tested against realistic adversarial event sequences. You find out they do not work when something real happens.

The usual answer is: run an adversarial emulation platform. These are good tools. They also require real process execution, real network activity, and in many cases a dedicated lab environment that many practitioners do not have.

I wanted something that worked at the telemetry layer. That could generate the structural shape of adversarial event sequences without requiring any of those prerequisites.

---

## bananaTREE: the campaign model

bananaTREE organizes SHENRON campaigns into four phases:

**OBSERVE** — enumerate the adversarial signal surface. C2, entropy, and identity spoofing layers run here. Output: a map of what signals should exist in your detection stack before the simulation generates them.

**SIMULATE** — generate synthetic telemetry for detector training. Evasion, payload, and LLM-manipulation layers run here.

**EXECUTE** — run persistence and lateral movement simulators to produce full artifact timelines. Multi-phase event sequences representing installation, trigger registration, and activation — all synthetic.

**ADAPT** — score detection coverage and identify gaps.

A campaign is a JSON file specifying which layers run in each phase and what detection signals those layers should produce:

```json
{
  "name": "c2_shape_detection_test",
  "phases": {
    "OBSERVE": {
      "layers": ["beacon_emitter_cloak", "autonomous_signal_cloner"],
      "expected_findings": ["periodic_beacon", "signal_clone_across_interfaces"]
    },
    "SIMULATE": {
      "layers": ["spectral_packet_weaver", "void_gateway_tunnel"],
      "expected_findings": ["covert_channel_traffic", "dns_tunneling_high_entropy"]
    }
  }
}
```

The runner validates the scenario, executes phases in order, and returns a complete cycle object with run ID, phase results, and MITRE ATT&CK descriptor aggregation across synthetic events.

---

## Detector validation

After a campaign run, `--validate latest` compares every expected detection signal against the synthetic artifacts produced. Three matching levels:

1. **Exact match** — signal string matches an artifact field after normalization
2. **Partial match** — at least 50% of tokens appear in the artifact signal
3. **MITRE match** — expected detection maps to a MITRE technique in the artifacts

```
[VALIDATION]  c2_shape_detection_test
[EXPECTED]    31
[OBSERVED]    31
[PARTIAL]     0
[MISSING]     0
[COVERAGE]    100.0%
[SAFETY FAIL] 0
[VERDICT]     PASS
```

PASS requires ≥80% coverage AND zero safety violations. Any safety failure produces UNSAFE regardless of coverage score.

---

## Why synthetic telemetry matters

The argument for synthetic telemetry is not that it is better than real adversarial emulation. It is that it serves a different purpose.

Real adversarial emulation tests whether your detection stack catches real technique execution. Synthetic telemetry tests whether your detection rules are written to the right signal vocabulary, whether your SIEM processes the right fields, and whether your analysts recognize the event sequences they need to recognize.

A detection rule can be syntactically correct and pointed at the wrong field. An analyst can know the right technique name and not recognize the event pattern it produces. A SIEM can ingest logs without surfacing the right correlation.

SHENRON tests the telemetry pipeline layer — logging, SIEM ingestion, correlation rules, analyst workflows. It is complementary to adversarial emulation, not a substitute.

---

## Example synthetic output

The following visuals come from SHENRON's safe demo artifact generator.

This is not live adversarial execution, not a red-team procedure, and not proof of real-world detector coverage. It is a synthetic telemetry run designed to show event shape, phase structure, MITRE-style descriptors, signal vocabulary, and safety-contract fields.

The demo emits 40 synthetic records across the bananaTREE phases: OBSERVE, SIMULATE, EXECUTE, and ADAPT. Every record carries explicit safety fields such as `simulation_only: true`, `payload_present: false`, `executable: false`, `network_connection: false`, and `portable_adversarial_procedure: false`.

**What these charts prove:**
- The generator produces structured events across all four bananaTREE phases
- Every record carries the full safety contract
- MITRE-style technique descriptors are correctly mapped across 32 technique IDs in synthetic demo events
- Zero safety violations across all 40 records

**What these charts do not prove:**
- That a real SIEM has ingested these events
- That real detection rules have fired on this output
- That the full 50-layer scenario produces the same distribution (that requires running `shenron.py --run all` on the actual repo)

{% raw %}
![Phase frequency chart showing 10 events per bananaTREE phase](https://raw.githubusercontent.com/GnomeMan4201/shenron/main/docs/assets/shenron-demo/phase_frequency.png)
*⚠ Synthetic telemetry — demo generator output, not live campaign execution*

![MITRE ATT&CK descriptor distribution across synthetic demo events](https://raw.githubusercontent.com/GnomeMan4201/shenron/main/docs/assets/shenron-demo/technique_frequency.png)
*⚠ MITRE-style technique distribution across synthetic demo events — not real ATT&CK validation or detector coverage*

![Safety contract verification — all 8 fields, zero violations](https://raw.githubusercontent.com/GnomeMan4201/shenron/main/docs/assets/shenron-demo/safety_boundary.png)
*Green bars = 0 violations. Every event passed the full safety contract.*

![Synthetic event timeline across bananaTREE phases](https://raw.githubusercontent.com/GnomeMan4201/shenron/main/docs/assets/shenron-demo/event_timeline.png)
*⚠ Synthetic timing model — not real event timestamps*
{% endraw %}

---

## What v0.1.0 can and cannot do

**Can:**

- Generate realistic-shape adversarial telemetry across 50 technique categories
- Organize simulation campaigns through bananaTREE phases
- Score expected detection coverage against produced telemetry
- Generate markdown reports with MITRE ATT&CK descriptor tables across synthetic events
- Run in any Python 3.10+ environment with no external dependencies
- Be configured to any log directory via `SHENRON_HOME` environment variable

**Cannot:**

- Test network-layer controls — no real network calls are made
- Validate EDR behavioral detection — no real process execution occurs
- Substitute for adversarial emulation where real execution is required
- Measure detection of kernel-level artifacts
- Prove that detection rules fire on production telemetry — that requires a real SIEM integration

These are structural limitations, not gaps to be filled by relaxing the safety boundary. v0.2.0 will add higher-fidelity telemetry modeling, validation history, and run comparison — still synthetic, still non-executable.

---

## Quick start

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
python3 -m pytest tests/ -q
python3 shenron.py --run all --dry-run
python3 shenron.py --validate latest
python3 shenron.py --report-v2 latest --include-validation
```

To reproduce the demo artifacts and charts independently:

```bash
python3 scripts/generate_demo_artifacts.py --out-dir ./artifacts
python3 scripts/generate_charts.py --jsonl ./artifacts/shenron_demo_run.jsonl \
    --out-dir ./docs/assets/shenron-demo
```

See [docs/EXAMPLE_WORKFLOW.md](https://github.com/GnomeMan4201/shenron/blob/main/docs/EXAMPLE_WORKFLOW.md) for full usage including bananaTREE campaign scenarios.

---

## What comes next

v0.2.0: higher-fidelity telemetry modeling with realistic event volumes and timing models, validation history and run comparison, custom scenario CLI path support, ATT&CK Navigator layer export.

The safety boundary does not move between versions.

---

**Repo:** https://github.com/GnomeMan4201/shenron  
**Tag:** v0.1.0 — 50 layers, 154 tests, zero hardcoded paths, PASS verdict.

*gnomeman4201 / badBANANA Research Collective*
> Observable adversarial behavior, not portable adversarial procedure.
