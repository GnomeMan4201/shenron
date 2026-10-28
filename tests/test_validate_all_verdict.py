"""Regression for category verdict: UNSUPPORTED must never pass as SUPPORTED."""
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from core.cli.commands import validate_all as module


@pytest.mark.parametrize("status", ["UNSUPPORTED", "PARTIALLY SUPPORTED", "OUT OF SCOPE VIOLATION"])
def test_non_supported_category_fails_verdict(tmp_path, status):
    artifact = tmp_path / "shenron_identity.jsonl"
    artifact.write_text("{}\n")
    args = SimpleNamespace(no_rerun=True, scope_dir=str(tmp_path))
    result = SimpleNamespace(
        status=SimpleNamespace(value=status),
        supported_count=0, unsupported_count=1,
    )
    with patch.dict(module.CATEGORY_ASSUMPTIONS, {"identity": "assumptions/examples/identity_spoofing_coverage.yaml"}, clear=True):
        with patch.object(module, "_validate_assumption", return_value=result):
            assert module.cmd_validate_all(args) == 1


def test_supported_category_passes_verdict(tmp_path):
    artifact = tmp_path / "shenron_identity.jsonl"
    artifact.write_text("{}\n")
    args = SimpleNamespace(no_rerun=True, scope_dir=str(tmp_path))
    result = SimpleNamespace(
        status=SimpleNamespace(value="SUPPORTED"),
        supported_count=1, unsupported_count=0,
    )
    with patch.dict(module.CATEGORY_ASSUMPTIONS, {"identity": "assumptions/examples/identity_spoofing_coverage.yaml"}, clear=True):
        with patch.object(module, "_validate_assumption", return_value=result):
            assert module.cmd_validate_all(args) == 0
