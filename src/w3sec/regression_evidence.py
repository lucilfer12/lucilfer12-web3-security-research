from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .records import load_yaml_mapping


VALID_STATUSES = {"attempted", "passed", "failed", "inconclusive"}
REQUIRED_FIELDS = (
    "finding",
    "source_revision",
    "environment_hash",
    "execution_id",
    "status",
    "timestamp",
)


def _registry(root: Path) -> list[dict[str, Any]]:
    path = root / "corpus" / "knowledge" / "regressions.yaml"
    if not path.exists():
        return []
    value = load_yaml_mapping(path).get("regressions", [])
    return value if isinstance(value, list) else []


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


def validate_regression_evidence(item: dict[str, Any]) -> dict[str, Any]:
    missing = [key for key in REQUIRED_FIELDS if not item.get(key)]
    status = str(item.get("status", "")).lower()
    if status not in VALID_STATUSES:
        return {"valid": False, "passed": False, "missing": missing, "reason": "invalid-status"}
    if status == "passed" and not item.get("patched_revision"):
        missing.append("patched_revision")
    if item.get("artifact_hashes") is not None and not isinstance(item.get("artifact_hashes"), list):
        return {"valid": False, "passed": False, "missing": missing, "reason": "artifact_hashes-must-be-list"}
    if item.get("parent_evidence_ids") is not None and not isinstance(item.get("parent_evidence_ids"), list):
        return {"valid": False, "passed": False, "missing": missing, "reason": "parent_evidence_ids-must-be-list"}
    passed = not missing and status == "passed"
    return {"valid": not missing, "passed": passed, "missing": sorted(set(missing)), "reason": "ok" if passed else "not-passed"}


def load_regression_evidence(root: Path) -> list[dict[str, Any]]:
    records = []
    for item in _registry(root):
        if not isinstance(item, dict):
            continue
        result = validate_regression_evidence(item)
        record = dict(item)
        record["validation"] = result
        record["evidence_id"] = str(item.get("evidence_id") or ("regression:" + str(item.get("id") or _digest({k: str(v) for k, v in item.items()}))))
        records.append(record)
    return records


def regression_passed_for(case_ids: set[str], pattern_id: str | None, root: Path) -> list[dict[str, Any]]:
    matches = []
    for item in load_regression_evidence(root):
        linked_case = str(item.get("case", ""))
        linked_finding = str(item.get("finding", ""))
        linked_pattern = str(item.get("pattern", ""))
        linked = linked_case in case_ids or (pattern_id is not None and linked_pattern == pattern_id)
        if linked or linked_finding == pattern_id:
            matches.append(item)
    return matches


def build_regression_evidence(root: Path) -> dict[str, Any]:
    records = load_regression_evidence(root)
    return {
        "schema": "atlas.regression-evidence.v1",
        "records": records,
        "summary": {
            "total": len(records),
            "valid": sum(bool(x["validation"]["valid"]) for x in records),
            "passed": sum(bool(x["validation"]["passed"]) for x in records),
            "failed": sum(str(x.get("status", "")).lower() == "failed" for x in records),
            "inconclusive": sum(str(x.get("status", "")).lower() == "inconclusive" for x in records),
        },
    }
__all__ = ["VALID_STATUSES", "validate_regression_evidence", "load_regression_evidence", "regression_passed_for", "build_regression_evidence"]

