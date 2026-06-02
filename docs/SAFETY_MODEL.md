# SHENRON Safety Model

## What the safety boundary means

SHENRON generates synthetic telemetry that represents the *observable shape* of
adversarial behavior — the logs and events a defender would see — without containing
the procedure that would make that behavior executable or portable.

## Safety contract fields

Every SHENRON event carries these fields (canonical source: `core/safety/contract.py`):

| Field | Required value | Meaning |
|---|---|---|
| `simulation_only` | `true` | This event is synthetic. It does not represent real activity. |
| `executable` | `false` | No executable code is present or was run to produce this event. |
| `payload_present` | `false` | No payload, shellcode, or exploit is embedded in this artifact. |
| `portable_adversarial_procedure` | `false` | No portable adversarial procedure is encoded in this artifact. |
| `network_connection` | `false` | No real network connection was made to produce this event. |
| `subprocess_spawned` | `false` | No real subprocess was spawned to produce this event. |
| `real_file_written` | `false` | No real files outside the SHENRON log directory were written. |
| `shell_invoked` | `false` | No shell was invoked to produce this event. |

## What SHENRON does not contain

- Executable payloads or shellcode
- Real network connections or socket bindings
- Subprocess spawning or shell command execution
- Real file writes outside its own log directory
- Exploit code of any kind
- Portable adversarial procedures

## This is an architectural constraint, not a disclaimer

The layer loader (`discover_canonical()`) only loads canonical layers. All 51 canonical
layers were audited in v0.4.0 to verify compliance with the safety contract.
`obfuscated_skinwalker_dropper` was rewritten in v0.4.0 after audit found real
filesystem writes in the pre-v0.4.0 implementation.

## Verifying the safety contract

```bash
# Validate safety contract on any artifact
python3 shenron.py schema validate --events artifacts/demo/shenron_demo_run.jsonl

# Run dry-run across all 51 layers
python3 shenron.py run all --dry-run
```

## CLI utility subprocess use

`shenron.py` may invoke local SHENRON helper scripts (e.g. `scripts/generate_demo_artifacts.py`)
via `sys.executable`. This is a CLI utility call, not adversarial simulation.
The safety contract fields above apply to generated telemetry records, not to CLI scaffolding.
