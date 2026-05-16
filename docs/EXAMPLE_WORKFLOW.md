# Example Workflow

Copy-pasteable commands for common SHENRON operations. All commands run from the repo root.

---

## Setup

```bash
cat > docs/EXAMPLE_WORKFLOW.md << 'ENDOFFILE'
# Example Workflow

Copy-pasteable commands for common SHENRON operations. All commands run from the repo root.

---

## Setup

```bash
cat > docs/devto_launch_article.md << 'ENDOFFILE'
---
title: "I Built a Defensive Simulation Lab for Adversarial Telemetry — Without Shipping the Attack"
published: false
tags: security, blueteam, python, opensource
description: "SHENRON is a 50-layer telemetry simulation platform that generates synthetic adversarial-shaped events for detector validation. No payloads. No network calls. Just the shape of the attack, not the attack itself."
---

# I Built a Defensive Simulation Lab for Adversarial Telemetry — Without Shipping the Attack

There is a specific problem that comes up when you are building detection systems
without a red team budget, a dedicated lab environment, or a controlled range: you
cannot safely generate realistic adversarial telemetry on demand.

You can read ATT&CK. You can study threat intelligence reports. You can look at PCAP
samples from controlled captures. But actually producing a continuous, structured
stream of adversarial-shaped events — the kind your SIEM rules are supposed to fire
on — without introducing real malware into your environment is harder than it sounds.

That is the problem I built SHENRON to solve.

---

## What it is

SHENRON is a Python-based defensive adversarial telemetry simulation platform. It has
50 simulation layers, each representing a different adversarial technique or behavior
class, organized through a four-phase campaign model called bananaTREE: OBSERVE,
SIMULATE, EXECUTE, ADAPT.

Every layer emits structured JSONL artifacts. Every artifact carries an explicit safety
contract: `simulation_only: true`, `executable: false`, `no_payload_present: true`.

The core principle:

> **Observable adversarial behavior, not portable adversarial procedure.**

SHENRON documents what adversarial activity looks like from a defender's perspective.
It does not implement that activity.

---

## Why I built it this way

I have been doing independent security research for a few years, self-taught, working
primarily in Python and bash. I am interested in the defensive side — specifically in
the gap between "we have detection rules" and "we have validated that our detection
rules fire on realistic telemetry."

That gap is large. Most SIEM rules have never been tested against realistic adversarial
event sequences. They find out the rules do not work when something real happens.

The usual answer is: run an adversarial emulation platform. These are good tools. They
also require real process execution, real network activity, and in many cases a dedicated
lab environment that many practitioners simply do not have.

I wanted something that worked at the telemetry layer. That could generate the structural
shape of adversarial event sequences without requiring any of those prerequisites.

---

## The safety boundary

SHENRON does not contain:

- Executable payloads or shellcode
- Real network connections or socket bindings
- Subprocess spawning or shell command execution
- Real file writes outside its own log directory
- Exploit code of any kind

This is not a disclaimer. It is an architectural constraint.

Every layer is structured so that the real behavior it represents is described in the
artifact metadata, not performed by the code. A C2 beaconing layer contains data
structures describing timing intervals, entropy patterns, and protocol shapes — not
socket calls. A persistence layer describes what cron modification looks like as a log
event sequence. It does not write to cron.

The safety verifier in `core/reports/model.py` scans every artifact and flags
violations. A single violation produces `VERDICT: UNSAFE` regardless of coverage score.

---

## bananaTREE: the campaign model

bananaTREE organizes SHENRON campaigns into four phases:

**OBSERVE** — enumerate the adversarial signal surface. C2, entropy, and identity
spoofing layers run here. Output: a map of what signals should exist in your detection
stack.

**SIMULATE** — generate synthetic telemetry for detector training. Evasion, payload,
and LLM-manipulation layers run here.

**EXECUTE** — run persistence and lateral movement simulators to produce full artifact
timelines.

**ADAPT** — score detection coverage and identify gaps.

A campaign is a JSON file specifying which layers run in each phase and what detection
signals those layers should produce. The runner validates the scenario, executes phases
in order, and returns a complete cycle object with run ID, phase results, and MITRE
coverage.

---

## Detector validation

After a campaign run, `--validate latest` compares every expected detection signal
against the synthetic artifacts produced. Three matching levels:

1. **Exact match** — signal string matches an artifact field after normalization
2. **Partial match** — at least 50% of tokens appear in the artifact signal
3. **MITRE match** — expected detection maps to a MITRE technique in the artifacts

Result: PASS, PARTIAL, or MISS per expected detection. Coverage: PASS x 1.0 +
PARTIAL x 0.5. Verdicts: PASS >=80%, PARTIAL >=50%, FAIL <50%, UNSAFE on any
safety violation.

---

## Why synthetic telemetry matters

The argument for synthetic telemetry is not that it is better than real adversarial
emulation. It is that it serves a different purpose.

Real adversarial emulation tests whether your detection stack catches real technique
execution. Synthetic telemetry tests whether your detection rules are written to the
right signal vocabulary, whether your SIEM processes the right fields, and whether
your analysts recognize the event sequences they need to recognize.

A detection rule can be syntactically correct and pointed at the wrong field. An analyst
can know the right technique name and not recognize the event pattern it produces. SHENRON
tests the telemetry pipeline layer — logging, SIEM ingestion, correlation rules, analyst
workflows. It is complementary to adversarial emulation, not a substitute.

---

## What v0.1.0 can and cannot do

**Can:**
- Generate realistic-shape adversarial telemetry across 50 technique categories
- Organize simulation campaigns through bananaTREE phases
- Score expected detection coverage against produced telemetry
- Generate 10-section markdown reports with MITRE coverage tables
- Run in any Python 3.10+ environment with no external dependencies
- Be configured to any log directory via environment variables

**Cannot:**
- Test network-layer controls (no real network calls)
- Validate EDR behavioral detection (no real process execution)
- Substitute for adversarial emulation where real execution is required
- Measure detection of kernel-level artifacts

---

## What comes next

v0.2.0: higher-fidelity telemetry modeling, validation history and run comparison,
custom scenario CLI support, expanded scenario library, ATT&CK Navigator layer export.

The safety boundary does not move between versions.

---

## Where to find it

github.com/GnomeMan4201/shenron

v0.1.0 is tagged. 117 tests pass. 50/50 layers dry-run clean. Zero hardcoded paths.

---

*gnomeman4201 / badBANANA Research Collective*
*Observable adversarial behavior, not portable adversarial procedure.*
