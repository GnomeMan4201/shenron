# Blue Team Workflow

## The core workflow
Generate or obtain a SHENRON artifact
Define your claims (assumption YAMLs)
Validate claims against the artifact
Validate Sigma rules against the artifact
Export for SIEM ingestion or reporting
Review the evidence bundle
## Step 1 — One-command quickstart

```bash
python3 shenron.py quickstart
```

Produces in `reports/demo/`:
- `sigma_validation.txt`
- `assumption_validation.txt`
- `attack_navigator_layer.json`
- `shenron_report.html`

## Step 2 — Run a specific campaign

```bash
python3 shenron.py run persistence
python3 shenron.py run c2
python3 shenron.py run all --dry-run
```

## Step 3 — Validate your claims

```bash
# Validate a single assumption
python3 shenron.py assumption validate \
  assumptions/examples/persistence_coverage.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl

# Diff two assumptions against the same artifact
python3 shenron.py assumption diff \
  assumptions/examples/persistence_coverage.yaml \
  assumptions/examples/broad_detection_claim.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl

# Compare multiple assumptions
python3 shenron.py assumption compare \
  assumptions/examples/persistence_coverage.yaml \
  assumptions/examples/c2_coverage.yaml \
  --events artifacts/demo/shenron_demo_run.jsonl
```

## Step 4 — Validate Sigma rules

```bash
python3 shenron.py sigma validate-dir sigma/rules/ \
  --events artifacts/demo/shenron_demo_run.jsonl
```

Verdicts:
- `TRIGGERED` — rule logic matched the artifact
- `PARTIAL` — some detection conditions matched
- `NOT_TRIGGERED` — rule did not match
- `UNSUPPORTED` — rule depends on fields not present in SHENRON artifacts

## Step 5 — Export for your SIEM

```bash
# Elastic ECS
python3 shenron.py export ecs \
  --events artifacts/demo/shenron_demo_run.jsonl \
  --out reports/ecs_export.json

# Elastic bulk API format
python3 shenron.py export ecs \
  --events artifacts/demo/shenron_demo_run.jsonl \
  --out reports/bulk.ndjson --bulk

# Splunk HEC
python3 shenron.py export hec \
  --events artifacts/demo/shenron_demo_run.jsonl \
  --out reports/hec_export.ndjson
```

## Step 6 — Validate the artifact schema

```bash
python3 shenron.py schema validate \
  --events artifacts/demo/shenron_demo_run.jsonl
```

## Reading assumption results

| Status | Meaning |
|---|---|
| `SUPPORTED` | Artifact contains evidence supporting this claim |
| `PARTIALLY_SUPPORTED` | Some claims supported, some not |
| `UNSUPPORTED` | Artifact does not support this claim |
| `OUT_OF_SCOPE_VIOLATION` | Artifact is being used to support a claim it cannot honestly back |

`OUT_OF_SCOPE_VIOLATION` is the most important result. It means you are overclaiming.

## Writing your own assumption YAML

```yaml
id: my_coverage_claim
description: Validates artifact contains X telemetry

claims:
  - id: evidence_of_x
    type: positive_evidence
    severity: high
    requires_techniques:
      - T1053
    requires_signals:
      - scheduled_task_creation_sim

  - id: no_y_overclaim
    type: out_of_scope_claim
    severity: high
    description: Do not use this artifact to claim Y coverage
    requires_techniques:
      - T1566
```
