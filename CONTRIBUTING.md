# Contributing to SHENRON

Thank you for improving SHENRON. Contributions should strengthen its defensive evidence discipline without expanding it into an operational adversary tool.

Before contributing, read [the limitations](docs/LIMITATIONS.md), [the safety model](docs/SAFETY_MODEL.md), and [the security policy](SECURITY.md).

## Development setup

SHENRON supports Python 3.10–3.12.

```bash
git clone https://github.com/GnomeMan4201/shenron.git
cd shenron

python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e '.[dev]'

python3 -m pytest tests/ -q
python3 shenron.py run all --dry-run
```

Use `requirements.txt` for runtime-only installation. The editable `.[dev]` installation is the contributor path because it follows the dependencies declared in `pyproject.toml`.

## Safety boundary

Every canonical simulation layer must:

- emit synthetic telemetry only;
- make no real network connections, subprocess calls, shell invocations, payload execution, or writes outside SHENRON-controlled artifact paths;
- identify itself with `simulation_only: true` and `executable: false`;
- state payload absence using the current safety contract;
- register under its canonical layer name;
- expose defender-observable signals through fields such as `mitre_techniques`, `behavior_class`, and `detection_opportunities`.

The static safety gate rejects forbidden imports and calls. Do not work around that gate. If a defensive utility needs a capability near the boundary, explain the requirement and add an invariant test before implementation.

## Adding or changing a layer

1. Place the canonical implementation in `core/layers/`.
2. Register it with `@register_payload(name="layer_name")`.
3. Add it to the correct category in `core/engine/layer_loader.py`.
4. Emit telemetry through the configured artifact path.
5. Add regression coverage for its schema, safety contract, category, and expected signals.
6. Verify:

```bash
python3 shenron.py run layer_name
python3 shenron.py run all --dry-run
python3 -m pytest tests/ -q
```

## Assumption YAMLs

Assumptions live in `assumptions/examples/`. Positive claims must reference signals that are deterministically emitted by the scoped category run. A mandatory CI claim must not depend on random vector selection.

Valid claim types are `positive_evidence`, `negative_evidence`, and `out_of_scope_claim`. Valid severities are `high`, `medium`, and `low`.

Run the complete contract gate after modifying assumptions or category mappings:

```bash
python3 shenron.py --validate-all-assumptions
```

## Sigma rules

Sigma rules live under `sigma/rules/<category>/`. SHENRON-native mappings include `behavior_class`, `detection_opp`, `mitre_technique`, `layer`, `phase`, and `signal`. The pySigma bridge also maps supported Windows Event Log fields including `EventID`, `Channel`, and `Provider_Name`.

Test rules against an artifact that actually emits the referenced telemetry:

```bash
python3 shenron.py sigma \
  --validate-dir sigma/rules/ \
  --events artifacts/demo/shenron_demo_run.jsonl
```

When a rule is expected to trigger against the full canonical corpus, update the deterministic integration gate in `tests/test_sigma_integration.py`.

## Pull request checklist

- [ ] The change is bounded and its user-facing contract is explained.
- [ ] New behavior has regression coverage.
- [ ] `python3 -m pytest tests/ -q` passes.
- [ ] `python3 shenron.py run all --dry-run` reports no failed canonical layers.
- [ ] `python3 shenron.py --validate-all-assumptions` passes when assumptions or category mappings change.
- [ ] Package and documentation versions agree when preparing a release.
- [ ] README and examples contain no frozen counts unless they are generated automatically.
- [ ] No real adversarial capability or unreviewed third-party rule content is introduced.

Dependency additions are allowed only when they are necessary, declared in `pyproject.toml`, compatible with supported Python versions, and justified in the pull request.

## Reporting vulnerabilities

Do not open a public issue for a suspected security or safety-boundary vulnerability. Follow [SECURITY.md](SECURITY.md).

*Observable adversarial behavior, not portable adversarial procedure.*
