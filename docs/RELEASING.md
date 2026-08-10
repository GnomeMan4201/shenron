# Releasing SHENRON

SHENRON releases are evidence-bearing maintenance events. A release is ready only when the package version, changelog, tag, tests, safety gate, and built artifacts agree.

## Release contract

A stable release must satisfy all of the following:

- `pyproject.toml` contains the intended semantic version;
- `CHANGELOG.md` has a dated section for that version;
- `python3 scripts/check_release_version.py` passes;
- the pull request CI is green;
- the merged `main` CI is green;
- the release tag is exactly `v<project-version>`;
- the release workflow builds and attaches a wheel and source distribution.

The GitHub release is the public release record. This repository does not claim a PyPI publication unless a separate verified publishing workflow is added.

## Preparing a release

1. Create a bounded release-readiness branch.
2. Move completed changelog entries from **Unreleased** into a dated version section.
3. Set the same version in `pyproject.toml`.
4. Run:

```bash
python3 scripts/check_release_version.py
python3 -m pytest tests/ -q
python3 shenron.py run all --dry-run
python3 shenron.py --validate-all-assumptions
python3 -m build
```

5. Open a pull request and require every CI job to pass.
6. Merge only the verified head.
7. Confirm the post-merge `main` workflow passes.

## Publishing

Create the GitHub release from the verified `main` commit using the exact tag `v<project-version>`. Publishing the tag starts `.github/workflows/release.yml`.

The release workflow:

- revalidates the tag against `pyproject.toml` and `CHANGELOG.md`;
- installs the project from a clean runner;
- runs the full test suite and static dry-run;
- builds the wheel and source distribution;
- creates the GitHub release when needed or uploads artifacts to an existing release.

A release is complete only after that workflow is green and both distribution artifacts are attached.

## After publishing

- Confirm the README release badge resolves to the new version.
- Confirm installation from the attached wheel and `shenron --version`.
- Leave **Unreleased** present for subsequent work.
- Record any release-only correction in the next changelog section; do not silently replace published artifacts.
