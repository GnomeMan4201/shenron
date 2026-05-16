---
title: "Observable Adversarial Behavior, Not Portable Adversarial Procedure"
published: true
tags: security, blueteam, python, opensource
description: "How I built SHENRON as a defensive telemetry simulation lab for blue-team validation without shipping the attack."
cover_image: https://raw.githubusercontent.com/GnomeMan4201/shenron/main/assets/shenron_banner.png
---

*How I built SHENRON as a defensive telemetry simulation lab for blue-team validation without shipping the attack.*

**Repo:** https://github.com/GnomeMan4201/shenron

---

There is a specific problem that comes up when you are building detection systems without a red team budget, a dedicated lab environment, or a controlled range: you cannot safely generate realistic adversarial telemetry on demand.

You can read ATT&CK. You can study threat intelligence reports. You can look at PCAP samples from controlled captures. But actually producing a continuous, structured stream of adversarial-shaped events — the kind your SIEM rules are supposed to fire on — without introducing real malware into your environment is harder than it sounds.

That is the problem I built SHENRON to solve.

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

The safety verifier scans every artifact and flags violations. A single violation produces `VERDICT: UNSAFE` regardless of coverage score. The test suite has 117 tests, 35 of which are specifically about the validation and safety systems.

This matters because the goal is to generate training data for defenders — and training data that contains real payloads is not training data, it is a liability.

---

## What it is

SHENRON is a Python-based defensive adversarial telemetry simulation platform. It has 50 simulation layers, each representing a different adversarial technique or behavior class, organized through a four-phase campaign model called bananaTREE: OBSERVE, SIMULATE, EXECUTE, ADAPT.

Every layer emits structured JSONL artifacts. Every artifact carries an explicit safety contract: `simulation_only: true`, `executable: false`, `no_payload_present: true`.

A typical synthetic event looks like this:

````json
{
  "artifact_id": "a4f2c1d8-...",
  "layer": "beacon_emitter_cloak",
  "behavior_class": "http_beacon_sim",
  "technique": "T1071",
  "signal": "periodic_beacon_to_external_host",
  "interval_sim": 60,
  "jitter_sim": 0.12,
  "simulation_only": true,
  "executable": false,
  "no_payload_present": true
}
```

The core principle:

> **Observable adversarial behavior, not portable adversarial procedure.**

SHENRON documents what adversarial activity looks like from a defender's perspective. It does not implement that activity.

---

## Why I built it this way

I have been doing independent security research for a few years, self-taught, working primarily in Python and Bash on a mid-grade laptop and an Android smartphone. I am interested in the defensive side — specifically in the gap between "we have detection rules" and "we have validated that our detection rules fire on realistic telemetry."

That gap is large. Most SIEM rules have never been tested against realistic adversarial event sequences. You find out they do not work when something real happens.

The usual answer is: run an adversarial emulation platform. These are good tools. They also require real process execution, real network activity, and in many cases a dedicated lab environment that many practitioners do not have.

I wanted something that worked at the telemetry layer. That could generate the structural shape of adversarial event sequences without requiring any of those prerequisites.

---

## bananaTREE: the campaign model

bananaTREE organizes SHENRON campaigns into four phases:

**OBSERVE** — enumerate the adversarial signal surface. C2, entropy, and identity spoofing layers run here. Output: a map of what signals should exist in your detection stack before the simulation generates them.

**SIMULATE** — generate synthetic telemetry for detector training. Evasion, payload, and LLM-manipulation layers run here.

**EXECUTE** — run persistence and lateral movement simulators to produce full artifact timelines. Multi-phase event sequences representing installation, trigger registration, and activation — all synthetic. In SHENRON, EXECUTE means executing the simulation workflow, not executing adversarial procedures on the host.

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

The runner validates the scenario, executes phases in order, and returns a complete cycle object with run ID, phase results, and MITRE coverage aggregation.

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

Note: MITRE coverage here means simulated telemetry coverage against mapped technique labels, not proof that a production environment can detect live technique execution.

---

## Why synthetic telemetry matters

The argument for synthetic telemetry is not that it is better than real adversarial emulation. It is that it serves a different purpose.

Real adversarial emulation tests whether your detection stack catches real technique execution. Synthetic telemetry tests whether your detection rules are written to the right signal vocabulary, whether your SIEM processes the right fields, and whether your analysts recognize the event sequences they need to recognize.

A detection rule can be syntactically correct and pointed at the wrong field. An analyst can know the right technique name and not recognize the event pattern it produces. A SIEM can ingest logs without surfacing the right correlation.

SHENRON tests the telemetry pipeline layer — logging, SIEM ingestion, correlation rules, analyst workflows. It is complementary to adversarial emulation, not a substitute.

---

## What the output actually looks like

A useful way to judge SHENRON is not by asking whether it behaves like malware.

It does not.

The better question is:

> Can it produce adversarial-shaped telemetry that is structured enough to test defensive logic without creating portable adversarial procedure?

A generated event can still be useful to a defender because a detector, parser, report generator, or SIEM pipeline can ask practical questions:

- Did the expected field exist?
- Did the rule map the signal correctly?
- Did the campaign phase survive parsing?
- Did the report preserve the technique context?
- Did the validation layer observe the signal it expected?

But the event is not useful for offensive reuse because there is no payload, no execution primitive, no live network behavior, and no procedure to port.

## Visualizing the synthetic signal shape

The most useful SHENRON output is not a single event. It is the shape of the event set.

A campaign can produce:

- a synthetic event timeline
- signal frequency counts
- technique or layer frequency counts
- expected-vs-observed validation
- a human-readable report

That makes the project more like a defensive telemetry wind tunnel than an exploit simulator.

The point is not:

> Can this attack a system?

The point is:

> Can this generate enough observable structure to test whether defensive tooling recognizes what it claims to recognize?

## Important limitation

Synthetic telemetry validates the shape and routing of detection logic, not real adversary execution.

If a rule fails here, it likely has a vocabulary, field-mapping, parser, or correlation problem.

If a rule passes here, that only means the rule recognized the simulated signal. Real adversarial emulation is still required to test process behavior, network controls, endpoint response, and environmental side effects.

## The shortest version

SHENRON is not a red-team tool.

It is a defensive simulation harness for generating adversarial-shaped telemetry without adversarial execution.

That boundary matters because detection engineering needs realistic signal structure, but publishing portable adversarial procedure creates a different risk category entirely.

The goal is not to make attacks easier to run.

The goal is to make defensive assumptions easier to inspect.



## What v0.1.0 can and cannot do

**Can:**
- Generate realistic-shape adversarial telemetry across 50 technique categories

> By realistic-shape telemetry, I mean structurally similar event fields, timing patterns, technique labels, and correlation sequences — not real execution.

- Organize simulation campaigns through bananaTREE phases
- Score expected detection coverage against produced telemetry
- Generate 10-section markdown reports with MITRE coverage tables
- Run in any Python 3.10+ environment with no external dependencies
- Be configured to any log directory via `SHENRON_HOME` environment variable

**Cannot:**
- Test network-layer controls — no real network calls are made
- Validate EDR behavioral detection — no real process execution occurs
- Substitute for adversarial emulation where real execution is required
- Measure detection of kernel-level artifacts

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

See [docs/EXAMPLE_WORKFLOW.md](https://github.com/GnomeMan4201/shenron/blob/main/docs/EXAMPLE_WORKFLOW.md) for full usage including bananaTREE campaign scenarios.

## What comes next

v0.2.0: higher-fidelity telemetry modeling with realistic event volumes and timing models, validation history and run comparison, custom scenario CLI path support, ATT&CK Navigator layer export.

The safety boundary does not move between versions.

---

**Repo:** https://github.com/GnomeMan4201/shenron  
**Tag:** v0.1.0 — 50 layers, 117 tests, zero hardcoded paths, PASS verdict.

*gnomeman4201 / badBANANA Research Collective*

> Observable adversarial behavior, not portable adversarial procedure.


## Example visual output

Synthetic technique / layer frequency:

![SHENRON synthetic technique frequency](https://raw.githubusercontent.com/gnomeman4201/shenron/main/docs/assets/shenron-demo/technique_frequency.png)

Synthetic signal frequency:

![SHENRON synthetic signal frequency](https://raw.githubusercontent.com/gnomeman4201/shenron/main/docs/assets/shenron-demo/signal_frequency.png)

Synthetic phase frequency:

![SHENRON synthetic phase frequency](https://raw.githubusercontent.com/gnomeman4201/shenron/main/docs/assets/shenron-demo/phase_frequency.png)

Safety boundary:

![SHENRON safety boundary](https://raw.githubusercontent.com/gnomeman4201/shenron/main/docs/assets/shenron-demo/safety_boundary.png)

