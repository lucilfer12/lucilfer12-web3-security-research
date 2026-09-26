from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from .records import (
    RecordLoadError,
    discover_case_records,
    discover_knowledge_files,
    load_yaml_mapping,
)


SCHEMAS = {
    "invariants": "schemas/registry.schema.json",
    "patterns": "schemas/registry.schema.json",
    "counterexamples": "schemas/registry.schema.json",
    "protocols": "schemas/registry.schema.json",
    "experiments": "schemas/registry.schema.json",
    "evidence": "schemas/registry.schema.json",
    "hypotheses": "schemas/hypotheses.schema.json",
    "sources": "schemas/registry.schema.json",
    "regressions": "schemas/registry.schema.json",
    "protocol_versions": "schemas/registry.schema.json",
    "negative_results": "schemas/registry.schema.json",
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
    return [
        f"{path.as_posix()}: {error.message}"
        for error in sorted(validator.iter_errors(value), key=lambda e: list(e.path))
    ]


def _list_ids(records: list[dict[str, Any]]) -> set[str]:
    return {str(item["id"]) for item in records if isinstance(item, dict) and item.get("id")}


def _items(data: dict[str, Any], key: str) -> list[dict[str, Any]]:
    values = data.get(key, [])
    return [value for value in values if isinstance(value, dict)] if isinstance(values, list) else []
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

    registry_ids: dict[str, set[str]] = {}
    registry_items: dict[str, list[dict[str, Any]]] = {}
    case_ids: set[str] = set()
    for path, record in cases:
        errors.extend(_validate(path.relative_to(root), record, case_schema))
        if record.get("id"):
            case_id = str(record["id"])
            if case_id in case_ids:
                errors.append(f"duplicate case id: {case_id}")
            case_ids.add(case_id)
    for path in discover_knowledge_files(root):
        data = load_yaml_mapping(path)
        stem = path.stem
        key = {
            "invariants": "invariants", "patterns": "patterns",
            "counterexamples": "counterexamples", "protocols": "protocols",
            "experiments": "experiments", "evidence": "evidence",
            "hypotheses": "hypotheses", "sources": "source_repos",
            "regressions": "regressions", "protocol_versions": "protocol_versions",
            "negative_results": "negative_results", "lineage": "edges",
        }.get(stem)
        if key is None:
            continue
        schema, schema_errors = _load_schema(root / SCHEMAS[stem])
        errors.extend(schema_errors)
        if schema:
            errors.extend(_validate(path.relative_to(root), data, schema))
        records = _items(data, key)
        registry_items[key] = records
        ids = _list_ids(records)
        registry_ids[key] = ids
        declared = [item.get("id") for item in records if item.get("id")]
        if len(declared) != len(ids):
            errors.append(f"{path.relative_to(root)} contains duplicate id(s)")
    corpus = root / "corpus" / "index.yaml"
    if corpus.exists():
        try:
            data = load_yaml_mapping(corpus)
            schema, schema_errors = _load_schema(root / "schemas" / "corpus-index.schema.json")
            errors.extend(schema_errors)
            if schema:
                errors.extend(_validate(corpus.relative_to(root), data, schema))
            corpus_ids = _list_ids(_items(data, "records"))
            for value in sorted(case_ids - corpus_ids):
                errors.append(f"case id missing from corpus/index.yaml: {value}")
            for value in sorted(corpus_ids - case_ids):
                errors.append(f"corpus id has no case.yaml record: {value}")
        except RecordLoadError as exc:
            errors.append(str(exc))
    known_nodes = {f"case:{value}" for value in case_ids}
    for kind, field in {
        "invariant": "invariants", "pattern": "patterns",
        "counterexample": "counterexamples", "protocol": "protocols",
        "experiment": "experiments", "evidence": "evidence",
        "hypothesis": "hypotheses", "source": "source_repos",
        "regression": "regressions", "protocol-version": "protocol_versions",
        "negative_result": "negative_results",
    }.items():
        known_nodes.update(f"{kind}:{value}" for value in registry_ids.get(field, set()))

    reference_fields = {
        "invariants": "invariant", "patterns": "pattern",
        "counterexamples": "counterexample", "protocols": "protocol",
        "evidence": "evidence", "hypotheses": "hypothesis",
        "sources": "source", "regressions": "regression",
    }
    for path, record in cases:
        for field, kind in reference_fields.items():
            for target in record.get(field, []) or []:
                ref = f"{kind}:{target}"
                if ref not in known_nodes:
                    errors.append(f"{path.relative_to(root)}: unknown {field} reference {target}")
        for relation in record.get("relationships", []) or []:
            if isinstance(relation, dict) and relation.get("target"):
                target = str(relation["target"])
                if target not in known_nodes:
                    errors.append(f"{path.relative_to(root)}: unknown relationship target {target}")

    cross_fields = {
        "hypotheses": [("cases", "case"), ("invariants", "invariant"), ("evidence", "evidence")],
        "evidence": [("case", "case")],
        "counterexamples": [("case", "case")],
        "patterns": [("cases", "case"), ("invariants", "invariant")],
        "invariants": [("cases", "case")],
        "protocols": [("cases", "case")],
        "regressions": [("case", "case")],
        "protocol_versions": [("protocol", "protocol"), ("cases", "case")],
        "negative_results": [("case", "case")],
    }
    for field, rules in cross_fields.items():
        for item in registry_items.get(field, []):
            for attr, kind in rules:
                values = item.get(attr, [])
                if isinstance(values, str):
                    values = [values]
                if not isinstance(values, list):
                    continue
                for value in values:
                    if f"{kind}:{value}" not in known_nodes:
                        errors.append(f"{field}:{item.get('id')}: unknown {attr} reference {value}")

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
            for evidence_id in edge.get("evidence", []) or []:
                if f"evidence:{evidence_id}" not in known_nodes:
                    errors.append(f"{lineage.relative_to(root)} edge #{index}: unknown evidence {evidence_id}")

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
