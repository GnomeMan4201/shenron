# DEPRECATED: core/assumption/ (singular)
# This engine is preserved for test_assumption.py backward compatibility only.
# All CLI entry points now use core/assumptions/ (plural).
# Do not add new features here. Consolidation target: remove after test migration.
import warnings as _warnings
_warnings.warn(
    "core/assumption (singular) is deprecated. Use core/assumptions (plural).",
    DeprecationWarning,
    stacklevel=2,
)
