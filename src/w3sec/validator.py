from __future__ import annotations
import json
from pathlib import Path
REQUIRED = ("id", "title", "type", "status", "category", "security_property")
def _simple_yaml(path: Path) -> dict:
    data = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#") or raw.startswith(" "):
            continue
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        value = value.strip()
        if value in ("true", "false"):
            value = value == "true"
        elif value.startswith(("'", '"')) and value.endswith(value[0]):
            value = value[1:-1]
        data[key.strip()] = value
    return data
def validate_repo(root: Path) -> list[str]:
    errors: list[str] = []
    schema = root / "schemas" / "case.schema.json"
    if not schema.exists():
        errors.append("missing schemas/case.schema.json")
    else:
        try:
            json.loads(schema.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            errors.append(f"invalid case schema: {exc}")
    base = root / "case-studies"
    case_files = sorted(base.rglob("case.yaml")) if base.exists() else []
    if not case_files:
        errors.append("no case.yaml records found")
    for path in case_files:
        data = _simple_yaml(path)
        for field in REQUIRED:
            if not data.get(field):
                errors.append(f"{path.relative_to(root)} missing {field}")
    return errors