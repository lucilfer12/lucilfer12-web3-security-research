from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

import yaml


class RecordLoadError(ValueError):
    """Raised when a research YAML record cannot be loaded safely."""


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RecordLoadError(f"{path}: invalid YAML: {exc}") from exc


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    value = load_yaml(path)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RecordLoadError(f"{path}: expected a YAML mapping at the document root")
    return value
def load_yaml_list(path: Path, key: str) -> list[dict[str, Any]]:
    value = load_yaml_mapping(path)
    records = value.get(key, [])
    if not isinstance(records, list):
        raise RecordLoadError(f"{path}: {key} must be a YAML list")
    if not all(isinstance(item, dict) for item in records):
        raise RecordLoadError(f"{path}: {key} must contain mappings only")
    return records


def discover_case_files(root: Path) -> list[Path]:
    base = root / "case-studies"
    return sorted(base.rglob("case.yaml")) if base.exists() else []


def discover_case_records(root: Path) -> list[tuple[Path, dict[str, Any]]]:
    return [(path, load_yaml_mapping(path)) for path in discover_case_files(root)]


def discover_knowledge_files(root: Path) -> list[Path]:
    base = root / "corpus" / "knowledge"
    return sorted(base.glob("*.yaml")) if base.exists() else []


def discover_files(root: Path, patterns: Iterable[str]) -> list[Path]:
    found: set[Path] = set()
    for pattern in patterns:
        found.update(root.glob(pattern))
    return sorted(found)
