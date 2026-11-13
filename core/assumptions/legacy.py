"""Explicitly identify frozen, noncanonical example documents.

Only the exact committed versions in this repository's built-in examples
directory are excluded from claims evaluation. Unknown or edited inputs
must reach the strict assumption loader and fail there.
"""
import hashlib
from pathlib import Path


_KNOWN_LEGACY_BLOBS = {
    "c2_lateral_coverage.yaml": "7c871a14916a50a2fa9eb2a87e982e35251a2105",
    "assumption_dependency_confusion.yaml": "fd3ce211a53b98f5e7c33eef6868fa63c375861a",
}


def documented_builtin_legacy_exclusion(path: Path, directory: Path):
    path = Path(path)
    directory = Path(directory)
    builtin = Path(__file__).resolve().parents[2] / "assumptions" / "examples"
    if directory.resolve() != builtin.resolve() or path.name not in _KNOWN_LEGACY_BLOBS:
        return None
    data = path.read_bytes()
    header = b"blob " + str(len(data)).encode("ascii") + bytes([0])
    actual = hashlib.sha1(header + data).hexdigest()
    if actual != _KNOWN_LEGACY_BLOBS[path.name]:
        raise ValueError(
            f"{path}: pinned legacy example changed; review and classify before auditing"
        )
    return {
        "filename": path.name,
        "reason": "legacy_format_not_validated",
        "git_blob_sha1": actual,
    }
