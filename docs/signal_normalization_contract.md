# Signal matching contract — narrow normalization fix

This document describes syntactic comparison of **synthetic signal labels** in
`core/assumptions/validator.py`. It does not establish that any telemetry
was independently observed, that an ATT&CK technique is mapped correctly, or
that real-world detection coverage was demonstrated.

## What is normalized

A canonical label uses lowercase letters, digits and underscores, such as
`credential_access`. For compatibility, the evaluator accepts these spelling
equivalences **before exact equality comparison**:

- ASCII-style case differences: `CREDENTIAL_ACCESS` → `credential_access`
- Hyphens: `credential-access` → `credential_access`
- Spaces and runs of underscores: `credential access` and
  `credential__access` → `credential_access`
- Leading/trailing whitespace is ignored.

All **other punctuation is significant and is never silently deleted**.
`!credential_access`, `~credential_access`, `credential_access!`,
`credential.access`, and `credential/access` are **not** equivalent to
`credential_access`.

## What is not established

This is an exact normalized token comparison, **not** a negation parser.
For instance, `NOT credential_access` remains a distinct token, and
a requirement explicitly asking for a punctuation-bearing label could
match that identical label. Such labels are not automatically interpreted
as truth or absence. The source fields currently consulted include
`behavior_class`, `phase`, `detection_opportunities`,
`expected_events`, and `alert_signatures`; the use of expected or
planned fields as support remains a separate provenance question.

Claim-to-artifact `same_artifact` matching proves membership in one
parsed record only. It does not prove actor, session, causal or real-world
equivalence. T1078 use for synthetic device identities remains a separate
unresolved semantic-mapping issue.

## Regression and decision gate

See `tests/test_signal_punctuation_regression.py`. The regression is
considered passed only when punctuation-shaped negative examples fail to
satisfy positive canonical requirements in both category and same-record
scopes, the corresponding out-of-scope false violations disappear, and
supported spelling-equivalence controls stay green. Do not claim resolution
if the exact-head hosted CI fails.
