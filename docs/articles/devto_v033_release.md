---
title: "SHENRON v0.3.3: From Telemetry Generator to Blue-Team Reasoning Instrument"
published: true
tags: security, blueteam, python, opensource
---

*What changed between "here is synthetic telemetry" and "here is what your validation claims to prove."*

**Repo:** https://github.com/GnomeMan4201/shenron

---

The first article described what SHENRON is: a defensive telemetry simulation platform that generates adversarial-shaped synthetic events without producing payloads, shellcode, subprocess execution, or portable adversarial procedure.

This article describes what it became.

---

## The gap the first version couldn't close

Generating synthetic telemetry is useful. It lets you test whether your SIEM ingests the right fields, whether your detection rules are pointed at the right signal vocabulary, and whether your analysts recognize the event sequences they need to recognize.

But it doesn't answer the harder question: **what exactly did your validation claim to prove?**

A detection stack validated against persistence-shaped telemetry has not been tested against C2 beaconing, lateral movement, or anti-forensics. That is not a failure — it is a scope boundary. The problem is when the scope boundary is invisible.

v0.3.3 makes it visible.

---

## What ships in one command

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
python3 shenron.py --release-demo
```

That produces a 9-file artifact bundle:

```
shenron_demo_run.jsonl              40 synthetic events
shenron_demo_report.md              run report
safety_verification.md              safety contract verification
navigator_layer.json                ATT&CK Navigator layer (synthetic)
shenron_demo_run_ecs.json           ECS-formatted events
shenron_demo_run_ecs_bulk.ndjson    Elastic bulk API format
shenron_demo_run_splunk_hec.json    Splunk HEC format
narrative.md                        tactic profile narrative
charts/                             5 dark-mode PNGs
MANIFEST.md                         bundle index
```

Every record in the JSONL carries an explicit safety contract:

```json
{
  "phase": "OBSERVE",
  "layer": "beacon_emitter_cloak",
  "signal": "periodic_beacon",
  "mitre_technique": "T1071.001",
  "safety": {
    "simulation_only": true,
    "executable": false,
    "payload_present": false,
    "portable_adversarial_procedure": false,
    "network_connection": false,
    "subprocess_spawned": false,
    "real_file_written": false,
    "shell_invoked": false
  }
}
```

The ECS export goes directly into Elastic:

```bash
curl -X POST 'http://localhost:9200/_bulk' \
     -H 'Content-Type: application/x-ndjson' \
     --data-binary @shenron_demo_run_ecs_bulk.ndjson
```

Every ECS event carries `event.dataset: shenron.synthetic`, `labels.simulation_only: true`, and `[SHENRON SYNTHETIC]` in the message field. These are not real events. Your detection rules firing or not firing on them tells you something about your rules, not about real adversarial behavior.

---

## The coverage gap feature

The most important feature in v0.3.3 is `--narrate`.

After running two different scenarios, compare them:

```bash
python3 shenron.py --scenario apt_kill_chain --dry-run
python3 shenron.py --scenario persistence_runbook --dry-run
python3 shenron.py --compare <apt_id> <persistence_id> --narrate
```

The terminal output:

```
  [NARRATIVE]   apt_kill_chain → persistence_runbook

  Coverage gap families (4):
    ✗  Command-and-Control
    ✗  Defense Evasion
    ✗  Lateral Movement
    ✗  Discovery

  Primary concern:
    If C2-shaped telemetry is not in your validation set, your detectors
    have not been tested against the phase where most APT campaigns are
    first visible — initial callback after compromise.
```

The full narrative report names every missing signal by tactic family:

```
### Command-and-Control

MITRE descriptors not present in Run B: T1071, T1132
Signal shapes absent from Run B: DNS-based C2 signaling,
encoded URI C2 parameter, and periodic C2 beaconing.

> If C2-shaped telemetry is not in your validation set, your detectors
> have not been tested against the phase where most APT campaigns are
> first visible — initial callback after compromise.
```

And produces a concrete recommendation:

```
To close the Command-and-Control, Defense Evasion, Lateral Movement,
and Discovery gaps, run a scenario that includes those signal families
alongside persistence_runbook. Suggested: apt_kill_chain (covers C2,
lateral movement, persistence, and evasion) or evasion_stress_test
(covers masquerading, log deletion, and anti-forensics).
```

This is deterministic and template-based. No LLM. The narration engine classifies signals into tactic families using a static taxonomy of 80+ signal names and 35 MITRE technique IDs, then assembles analyst-language prose from that classification.

---

## Coverage assumption auditing

Define what you believe your detection stack covers:

```yaml
name: persistence_coverage_assumption
claims:
  - "We can observe persistence-shaped telemetry"
  - "We can detect suspicious scheduled task behavior"
expected_techniques:
  - T1053.005
  - T1547.001
expected_signals:
  - scheduled_task_creation
  - hidden_temp_directory
expected_phases:
  - EXECUTE
```

Audit it:

```bash
python3 shenron.py --assumption assumptions/my_assumption.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl
```

```
  [ASSUMPTION]  persistence_coverage_assumption
  [RECORDS]     40

  Claims        0 supported  0 partial  2 unsupported
  Techniques    2 observed   1 missing
  Signals       1 observed   1 missing

  [COVERAGE]    45.0%
  [VERDICT]     FAIL
```

SHENRON is not telling you your detection stack fails. It is telling you that your assumption, as written, is not supported by the evidence in this artifact. That is a different question, and a more useful one.

The assumption auditor asks: **what exactly did your validation claim to prove, and does the evidence support that claim?**

---

## Coverage drift tracking

```bash
python3 shenron.py --coverage-history --out-dir reports/history
```

With 256 runs across 8 campaigns in the timeline:

```
  [HISTORY]     256 runs · 8 campaigns

  apt_kill_chain              7 runs   16 techniques
  c2_shape_detection_test    79 runs   16 techniques
  full_stack_adversarial     26 runs   28 techniques
  persistence_pressure_test 108 runs   10 techniques

  [DRIFT]       No technique drift detected
```

No drift is good news — the campaigns are producing consistent technique sets across runs. The tracker becomes more useful over time as you modify scenarios, update layer configurations, and run across different environments. If a configuration change silently drops technique coverage, the history report shows it.

---

## Mutation variants

Test whether your analysis pipeline is brittle:

```bash
python3 shenron.py --mutate \
  --events artifacts/demo/shenron_demo_run.jsonl \
  --out-dir artifacts/mutations
```

Seven safe variants:

```
  [field_drop          ]   40 →  40 records    40 changes
  [timing_jitter       ]   40 →  40 records    40 changes
  [label_ambiguity     ]   40 →  40 records     3 changes
  [signal_density_high ]   40 → 120 records    80 changes
  [signal_density_low  ]   40 →  17 records    23 changes
  [phase_imbalance     ]   40 →  40 records    30 changes
  [technique_noise     ]   40 →  40 records    11 changes
```

Run `--verify-safety` on any variant to confirm the safety contract is intact:

```bash
python3 shenron.py --verify-safety artifacts/mutations/mutation_label_ambiguity.jsonl
```

The question each mutation is designed to answer:

- `field_drop`: Does your pipeline depend on optional fields being present?
- `timing_jitter`: Do your correlation rules break on ±5 minute timing variance?
- `label_ambiguity`: Do your rules fire on specific signal names or on signal patterns?
- `signal_density_high`: Can your SIEM handle 3× the expected event volume without dropping records?
- `signal_density_low`: Does your detection still work when 50% of events are missing?
- `phase_imbalance`: Does your phase-aware analysis handle imbalanced runs?
- `technique_noise`: Do your MITRE-based correlations produce false positives under noisy technique labels?

---

## What this does not prove

Every report SHENRON produces includes this section. It is not boilerplate — it is load-bearing.

- That real adversarial techniques were executed
- That real detection rules fired on these signals
- That a SIEM or EDR would catch the described behaviors
- That coverage in SHENRON equals coverage in production
- That closing a SHENRON gap closes the same gap in your environment

SHENRON tests the telemetry pipeline layer. It is complementary to adversarial emulation, not a substitute. The value is in making assumptions inspectable, not in replacing the work of actually testing your stack against real execution.

---

## The core identity

SHENRON does not ask "is your detector good?"

It asks: **what exactly did your validation claim to prove?**

That question is more honest, more tractable, and more useful than most of what passes for detection coverage measurement.

---

**Repo:** https://github.com/GnomeMan4201/shenron
**Tag:** v0.3.3 — 50 layers · 283 tests · zero hardcoded paths · PASS verdict

*gnomeman4201 / badBANANA Research Collective*
> Observable adversarial behavior, not portable adversarial procedure.
