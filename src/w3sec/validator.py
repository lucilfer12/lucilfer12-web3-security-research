from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .records import RecordLoadError, discover_case_records, discover_knowledge_files, load_yaml_mapping


REGISTRY_SCHEMAS = {
    "invariants": "schemas/registry.schema.json",
    "patterns": "schemas/registry.schema.json",
    "counterexamples": "schemas/registry.schema.json",
    "protocols": "schemas/registry.schema.json",
    "experiments": "schemas/registry.schema.json",
    "lineage": "schemas/lineage.schema.json",
}


def _load_schema(path: Path) -> tuple[dict[str, Any] | None, list[str]]:
    if not path.exists():
        return None, [f"missing {path.as_posix()}"]
    try:
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        return schema, []
    except (json.JSONDecodeError, SchemaError) as exc:
        return None, [f"{path.as_posix()}: invalid JSON Schema: {exc}"]
def _validate(path: Path, value: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    validator = Draft202012Validator(schema)
    return [f"{path.as_posix()}: {e.message}" for e in sorted(validator.iter_errors(value), key=lambda e: list(e.path))]


def _list_ids(records: list[dict[str, Any]]) -> set[str]:
    return {str(item["id"]) for item in records if isinstance(item, dict) and item.get("id")}


def validate_repo(root: Path) -> list[str]:
    root = root.resolve()
    errors: list[str] = []
    case_schema, schema_errors = _load_schema(root / "schemas" / "case.schema.json")
    errors.extend(schema_errors)
    if case_schema is None:
        return errors
    try:
        cases = discover_case_records(root)
    except RecordLoadError as exc:
        return [str(exc)]
    if not cases:
        return ["no case.yaml records found"]

    case_ids: set[str] = set()
    for path, record in cases:
        errors.extend(_validate(path.relative_to(root), record, case_schema))
        if record.get("id"):
            record_id = str(record["id"])
            if record_id in case_ids:
                errors.append(f"duplicate case id: {record_id}")
            case_ids.add(record_id)

    registry_ids: dict[str, set[str]] = {}
    for path in discover_knowledge_files(root):
        data = load_yaml_mapping(path)
        schema_name = REGISTRY_SCHEMAS.get(path.stem, "schemas/registry.schema.json")
        schema, schema_errors = _load_schema(root / schema_name)
        errors.extend(schema_errors)
        if schema:
            errors.extend(_validate(path.relative_to(root), data, schema))
        for field in ("invariants", "patterns", "counterexamples", "protocols", "experiments"):
            items = data.get(field)
            if isinstance(items, list):
                registry_ids.setdefault(field, set()).update(_list_ids(items))

    corpus = root / "corpus" / "index.yaml"
    if corpus.exists():
        try:
            corpus_data = load_yaml_mapping(corpus)
            schema, schema_errors = _load_schema(root / "schemas" / "corpus-index.schema.json")
            errors.extend(schema_errors)
            if schema:
                errors.extend(_validate(corpus.relative_to(root), corpus_data, schema))
            corpus_ids = _list_ids(corpus_data.get("records", []))
            for value in sorted(case_ids - corpus_ids):
                errors.append(f"case id missing from corpus/index.yaml: {value}")
            for value in sorted(corpus_ids - case_ids):
                errors.append(f"corpus id has no case.yaml record: {value}")
        except RecordLoadError as exc:
            errors.append(str(exc))
    known_nodes = {f"case:{value}" for value in case_ids}
    for kind, field in {
        "invariant": "invariants",
        "pattern": "patterns",
        "counterexample": "counterexamples",
        "protocol": "protocols",
        "experiment": "experiments",
    }.items():
        known_nodes.update(f"{kind}:{value}" for value in registry_ids.get(field, set()))

    lineage = root / "corpus" / "knowledge" / "lineage.yaml"
    if lineage.exists():
        data = load_yaml_mapping(lineage)
        for index, edge in enumerate(data.get("edges", []) or [], 1):
            if not isinstance(edge, dict):
                continue
            for endpoint in ("source", "target"):
                value = str(edge.get(endpoint, ""))
                if value and value not in known_nodes:
                    errors.append(f"{lineage.relative_to(root)} edge #{index}: unknown {endpoint} node {value}")

    reference_fields = {
        "invariants": "invariant",
        "patterns": "pattern",
        "counterexamples": "counterexample",
        "protocols": "protocol",
    }
    for path, record in cases:
        for field, kind in reference_fields.items():
            for target in record.get(field, []) or []:
                if f"{kind}:{target}" not in known_nodes:
                    errors.append(f"{path.relative_to(root)}: unknown {field} reference {target}")
        for relation in record.get("relationships", []) or []:
            if isinstance(relation, dict) and relation.get("target"):
                target = str(relation["target"])
                if target not in known_nodes:
                    errors.append(f"{path.relative_to(root)}: unknown relationship target {target}")

    for path in sorted((root / "experiments").glob("*.yaml")) if (root / "experiments").exists() else []:
        schema, schema_errors = _load_schema(root / "schemas" / "experiment.schema.json")
        errors.extend(schema_errors)
        if schema:
            try:
                data = load_yaml_mapping(path)
                errors.extend(_validate(path.relative_to(root), data, schema))
            except RecordLoadError as exc:
                errors.append(str(exc))
    return sorted(set(errors))
