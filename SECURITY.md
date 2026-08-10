# Security Policy

SHENRON is a defensive simulation and detection-engineering project. Safety-boundary failures are treated as security vulnerabilities even when they do not fit a conventional application-security category.

## Supported versions

| Version | Supported |
|---|---|
| 0.4.x | Yes |
| Earlier versions | No |

Use the latest published release before reporting a defect that may already be fixed.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Preferred channel: use GitHub's private **Report a vulnerability** flow in the repository Security tab. If that flow is unavailable, email **badbanana@proton.me** with the subject `SHENRON security report`.

Include:

- the affected version or commit;
- the relevant file, command, or artifact;
- the expected safety or security invariant;
- the observed behavior;
- minimal reproduction steps;
- whether real network, process, shell, filesystem, credential, or payload behavior occurred.

Do not include live credentials, sensitive production telemetry, malware, exploit payloads, or data you are not authorized to share.

You should receive an acknowledgement within seven days. Validation, remediation, and coordinated disclosure timing depend on severity and reproducibility. No public disclosure date is promised until the report is confirmed.

## Security and safety scope

Examples that belong in a private report include:

- a simulation layer making a real network connection or binding a socket;
- subprocess, shell, or payload execution from a simulation path;
- writes outside SHENRON-controlled artifact or report locations;
- unsafe path traversal or archive extraction;
- secrets committed to source, examples, logs, or generated artifacts;
- CI or release workflows that grant unnecessary write privileges;
- an evidence validator silently accepting unsupported claims;
- import/export behavior that removes or changes safety fields.

Feature requests, documentation questions, and ordinary false-positive discussions may use public issues when they contain no sensitive details.

## Disclosure

Please allow a reasonable remediation window before public disclosure. Confirmed fixes will be documented in the changelog and, when appropriate, credited with the reporter's permission.
