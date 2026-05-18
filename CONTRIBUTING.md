# Contributing to SHENRON

Thank you for your interest in SHENRON. This document explains how to contribute effectively.

---

## What SHENRON is

A defensive evidence discipline tool. The core question it answers:

> Does this artifact support the validation claim being made about it?

Before contributing, read `docs/LIMITATIONS.md` and `docs/SAFETY_MODEL.md`.
Every contribution must respect the safety boundary.

---

## Safety boundary — non-negotiable

Every canonical layer must:

- Emit synthetic telemetry only — no real subprocess execution, no real filesystem writes, no real network calls
- Carry flat safety fields: `simulation_only: true`, `executable: false`, `no_payload_present: true`
- Return a list of event dicts from `main()`
- Be decorated with `@register_payload(name="layer_name")`

If your layer calls `subprocess`, `shutil`, `socket`, `os.system`, `eval`, or `exec` — it will not be merged.

---

## How to add a canonical layer

1. Create `core/layers/your_layer_name.py`
2. Follow this structure:

```python
from core.engine.payload_registry import register_payload
from datetime import datetime, timezone

MITRE_TECHNIQUES = ["T1XXX"]

@register_payload(name="your_layer_name")
def main():
    ts = datetime.now(timezone.utc).isoformat()
    events = []
    events.append({
        "timestamp":          ts,
        "layer":              "your_layer_name",
        "phase":              "EXECUTE",
        "mitre_techniques":   MITRE_TECHNIQUES,
        "behavior_class":     "your_behavior_sim",
        "detection_opportunities": ["your_signal_sim"],
        "simulation_only":    True,
        "executable":         False,
        "no_payload_present": True,
        "subprocess_spawned": False,
        "subprocess_called":  False,
    })
    print(f"  [SHENRON]     your_layer_name")
    print(f"  [SAFE]        simulation_only: true — telemetry only")
    return events
```

3. Verify it loads and runs:

```bash
python3 shenron.py run your_layer_name
python3 shenron.py run all --dry-run
```

4. Run the full test suite — all 347 tests must pass:

```bash
python3 -m pytest tests/ -q
```

5. Verify schema validation passes on any artifact it generates.

---

## How to add an assumption YAML

Assumption YAMLs live in `assumptions/examples/`. Follow this structure:

```yaml
id: your_coverage_claim
description: What this claim validates

claims:
  - id: evidence_of_x
    type: positive_evidence
    severity: high
    requires_techniques:
      - T1053
    requires_signals:
      - your_signal_sim

  - id: no_y_overclaim
    type: out_of_scope_claim
    severity: high
    description: Do not use this artifact to claim Y coverage
    requires_techniques:
      - T1566
```

Valid `type` values: `positive_evidence`, `negative_evidence`, `out_of_scope_claim`
Valid `severity` values: `high`, `medium`, `low`

---

## How to add a Sigma rule

Sigma rules live in `sigma/rules/<category>/`. Follow the existing rule structure.
SHENRON-native fields: `behavior_class`, `detection_opp`, `mitre_technique`, `layer`, `phase`.
Unsupported fields: `EventID`, `Hashes`, `Channel`, `Provider_Name`.

Test your rule:

```bash
python3 shenron.py sigma validate sigma/rules/your_category/your_rule.yml \
  --events artifacts/demo/shenron_demo_run.jsonl \
  --match-mode explain
```

---

## Development setup

```bash
git clone https://github.com/GnomeMan4201/shenron
cd shenron
pip install pyyaml pytest
python3 -m pytest tests/ -q
python3 shenron.py quickstart
```

No other dependencies required. SHENRON is stdlib-first by design.

---

## Pull request checklist

- [ ] All 347 existing tests pass
- [ ] New layer follows safety contract (no subprocess, no filesystem writes, no network)
- [ ] New layer carries all required safety fields
- [ ] `python3 shenron.py run all --dry-run` shows 0 failed
- [ ] `python3 shenron.py schema validate --events <artifact>` passes
- [ ] New assumption YAML validates correctly against demo artifact
- [ ] New Sigma rule tested with `--match-mode explain`

---

## What not to contribute

- Layers that perform real execution of any kind
- External Sigma rules pulled from third-party repositories without review
- LLM integrations or AI-generated content in layer logic
- Hardcoded personal paths or system-specific assumptions
- New dependencies beyond `pyyaml`

---

*gnomeman4201 / badBANANA Research Collective*

> Observable adversarial behavior, not portable adversarial procedure.
