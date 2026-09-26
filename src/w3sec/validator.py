from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .records import RecordLoadError, discover_case_records, load_yaml_mapping


def _load_schema(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    errors: list[str] = []
    if not path.exists():
        return None, [f"missing {path.as_posix()}"]
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        return schema, errors
    except (json.JSONDecodeError, SchemaError) as exc:
        return None, [f"{path.as_posix()}: invalid JSON Schema: {exc}"]


def _validate_record(path: Path, record: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema)
    return [
        f"{path.as_posix()}: {error.message}"
        for error in sorted(validator.iter_errors(record), key=lambda e: list(e.path))
    ]


def validate_repo(root: Path) -> list[str]:
    errors: list[str] = []
    root = root.resolve()
    case_schema, schema_errors = _load_schema(root / "schemas" / "case.schema.json")
    errors.extend(schema_errors)
    if case_schema is None:
        return errors

    records: list[tuple[Path, dict[str, Any]]] = []
    try:
        records = discover_case_records(root)
    except RecordLoadError as exc:
        errors.append(str(exc))
        return errors
    if not records:
        errors.append("no case.yaml records found")
        return errors

    seen: dict[str, Path] = {}
    for path, record in records:
        errors.extend(_validate_record(path.relative_to(root), record, case_schema))
        record_id = str(record.get("id", ""))
        if record_id:
            if record_id in seen:
                errors.append(
                    f"duplicate case id {record_id!r}: "
                    f"{seen[record_id].relative_to(root)} and {path.relative_to(root)}"
                )
            else:
                seen[record_id] = path

    corpus_path = root / "corpus" / "index.yaml"
    if corpus_path.exists():
        try:
            corpus = load_yaml_mapping(corpus_path)
            corpus_schema, corpus_errors = _load_schema(root / "schemas" / "corpus-index.schema.json")
            errors.extend(corpus_errors)
            if corpus_schema:
                errors.extend(_validate_record(corpus_path.relative_to(root), corpus, corpus_schema))
            corpus_ids = {
                str(item.get("id"))
                for item in corpus.get("records", [])
                if isinstance(item, dict) and item.get("id")
            }
            for case_id in sorted(seen.keys() - corpus_ids):
                errors.append(f"case id missing from corpus/index.yaml: {case_id}")
            for corpus_id in sorted(corpus_ids - set(seen)):
                errors.append(f"corpus id has no case.yaml record: {corpus_id}")
        except RecordLoadError as exc:
            errors.append(str(exc))
    return errors
