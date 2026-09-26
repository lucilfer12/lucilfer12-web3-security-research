from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


class RecordLoadError(ValueError):
    """Raised when a research YAML record cannot be loaded safely."""


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    try:
        value = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RecordLoadError(f"{path}: invalid YAML: {exc}") from exc
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise RecordLoadError(f"{path}: expected a YAML mapping at the document root")
    return value


def discover_case_files(root: Path) -> list[Path]:
    base = root / "case-studies"
    return sorted(base.rglob("case.yaml")) if base.exists() else []


def discover_case_records(root: Path) -> list[tuple[Path, dict[str, Any]]]:
    return [(path, load_yaml_mapping(path)) for path in discover_case_files(root)]
