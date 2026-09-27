from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .records import load_yaml_mapping


@dataclass(frozen=True)
class VersionContext:
    id: str
    protocol: str
    version: str
    status: str
    cases: tuple[str, ...]
    security_model: dict[str, Any]


def _registry(root: Path) -> list[dict[str, Any]]:
    path = root / "corpus" / "knowledge" / "protocol_versions.yaml"
    if not path.exists():
        return []
    data = load_yaml_mapping(path)
    value = data.get("protocol_versions", [])
    return value if isinstance(value, list) else []


def load_version_contexts(root: Path) -> list[VersionContext]:
    result = []
    for item in _registry(root):
        raw_model = item.get("security_model", {})
        model = raw_model if isinstance(raw_model, dict) else {}
        result.append(VersionContext(
            id=str(item.get("id")),
            protocol=str(item.get("protocol")),
            version=str(item.get("version", "unknown")),
            status=str(item.get("status", "unresolved")),
            cases=tuple(str(x) for x in item.get("cases", []) or []),
            security_model=model,
        ))
    return result


def _fingerprint(model: dict[str, Any]) -> dict[str, Any]:
    fields = (
        "assumptions", "invariants", "authorization_rules", "replay_rules",
        "accounting_rules", "lifecycle_rules", "known_changes", "implementation",
    )
    return {field: model.get(field) for field in fields if field in model}


def diff_versions(before: VersionContext, after: VersionContext) -> dict[str, Any]:
    before_model, after_model = _fingerprint(before.security_model), _fingerprint(after.security_model)
    keys = sorted(set(before_model) | set(after_model))
    changes = []
    for key in keys:
        if before_model.get(key) != after_model.get(key):
            changes.append({
                "field": key,
                "before": before_model.get(key),
                "after": after_model.get(key),
            })
    return {
        "protocol": before.protocol,
        "before": {"id": before.id, "version": before.version},
        "after": {"id": after.id, "version": after.version},
        "security_model_changed": bool(changes),
        "changes": changes,
        "affected_cases": sorted(set(before.cases) | set(after.cases)),
    }


def build_version_diff_report(root: Path) -> dict[str, Any]:
    contexts = load_version_contexts(root)
    by_protocol: dict[str, list[VersionContext]] = {}
    for context in contexts:
        by_protocol.setdefault(context.protocol, []).append(context)
    diffs = []
    unresolved = []
    for protocol, items in sorted(by_protocol.items()):
        known = [item for item in items if item.version.lower() not in {"unknown", "", "none"}]
        if len(known) < 2:
            unresolved.append({
                "protocol": protocol,
                "contexts": [item.id for item in items],
                "reason": "At least two source-backed protocol versions are required for a differential security model.",
            })
            continue
        known.sort(key=lambda item: item.version)
        for before, after in zip(known, known[1:]):
            diffs.append(diff_versions(before, after))
    return {
        "schema_version": 1,
        "report_kind": "protocol-security-model-diff",
        "context_count": len(contexts),
        "protocol_count": len(by_protocol),
        "diff_count": len(diffs),
        "diffs": diffs,
        "unresolved": unresolved,
        "policy": "No version is inferred from a filename, git date, or case title; differences require explicit source-backed version contexts.",
    }


def write_version_diff_report(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "longitudinal" / "protocol-version-diffs.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_version_diff_report(root), indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


__all__ = ["VersionContext", "load_version_contexts", "diff_versions", "build_version_diff_report", "write_version_diff_report"]
