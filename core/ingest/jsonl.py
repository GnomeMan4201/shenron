"""Strict JSONL evidence ingestion shared by assumption and Sigma validators."""
import json
from pathlib import Path


class ArtifactInputError(ValueError):
    """Evidence could not be read as a complete stream of JSON objects."""


def load_jsonl_objects(path, *, record_validator=None) -> list:
    source = Path(path)
    records = []
    # Decode physical lines separately: text buffering can encounter invalid
    # bytes from later lines before yielding the current one. Preserve the
    # universal LF/CRLF/CR line boundaries accepted by the original text reader.
    with source.open("rb") as stream:
        line_number = 0
        for chunk in stream:
            for raw_line in chunk.splitlines(keepends=True):
                line_number += 1
                try:
                    line = raw_line.decode("utf-8")
                except UnicodeDecodeError as exc:
                    raise ArtifactInputError(
                        f"Invalid UTF-8 in {source} at line {line_number}: {exc}"
                    ) from exc
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ArtifactInputError(
                        f"Malformed JSONL in {source} at line {line_number}: {exc}"
                    ) from exc
                if not isinstance(record, dict):
                    raise ArtifactInputError(
                        f"Expected an object in {source} at line {line_number}"
                    )
                if record_validator is not None:
                    record_validator(record, line_number, source)
                records.append(record)
    return records
