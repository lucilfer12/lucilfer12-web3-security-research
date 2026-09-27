from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


@dataclass(frozen=True)
class FederationRoot:
    id: str
    path: Path
    adapter: str
    required: bool
    dataset: str | None = None


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _source_roots(root: Path) -> list[FederationRoot]:
    config = root / "corpus" / "federation" / "sources.yaml"
    data = _load_yaml(config) if config.exists() else {"sources": []}
    result: list[FederationRoot] = []
    for item in data.get("sources", []):
        base = root if item["path"] == "." else (root / item["path"]).resolve()
        result.append(FederationRoot(
            id=str(item["id"]),
            path=base,
            adapter=str(item["adapter"]),
            required=bool(item.get("required", False)),
            dataset=item.get("dataset"),
        ))
    return result


def _distribution(values: list[Any]) -> dict[str, int]:
    return dict(sorted(Counter(str(v) for v in values if v not in (None, "")).items()))


def _scf(source: FederationRoot) -> dict[str, Any]:
    path = source.path / str(source.dataset)
    if not path.exists():
        return {"available": False, "record_count": 0, "path": path.as_posix()}
    rows = _load_json(path)
    projects = {str(row.get("project")) for row in rows if row.get("project")}
    return {
        "available": True,
        "record_count": len(rows),
        "unique_projects": len(projects),
        "status_counts": _distribution([row.get("status") for row in rows]),
        "evidence_levels": _distribution([row.get("evidence_level") for row in rows]),
        "record_types": _distribution([row.get("record_type") for row in rows]),
        "path": path.as_posix(),
    }
def _zdf(source: FederationRoot) -> dict[str, Any]:
    path = source.path / str(source.dataset)
    if not path.exists():
        return {"available": False, "case_count": 0, "path": path.as_posix()}
    rows = _load_yaml(path)
    if not isinstance(rows, list):
        rows = []
    return {
        "available": True,
        "case_count": len(rows),
        "bug_classes": len({str(row.get("bug_class")) for row in rows if row.get("bug_class")}),
        "classification_counts": _distribution([row.get("classification") for row in rows]),
        "evidence_grades": _distribution([row.get("evidence_grade") for row in rows]),
        "scope_counts": _distribution([row.get("scope") for row in rows]),
        "path": path.as_posix(),
    }


def _sil(source: FederationRoot) -> dict[str, Any]:
    path = source.path / str(source.dataset)
    if not path.exists():
        return {"available": False, "finding_count": 0, "property_count": 0, "path": path.as_posix()}
    data = _load_json(path)
    findings = data.get("findings", [])
    properties = data.get("properties", [])
    return {
        "available": True,
        "finding_count": len(findings),
        "property_count": len(properties),
        "finding_kinds": _distribution([row.get("kind") for row in findings]),
        "finding_severities": _distribution([row.get("severity") for row in findings]),
        "property_confidence": _distribution([row.get("confidence") for row in properties]),
        "path": path.as_posix(),
    }


def _scsl(source: FederationRoot) -> dict[str, Any]:
    base = source.path / str(source.dataset)
    if not base.exists():
        return {"available": False, "finding_families": 0, "regression_tests": 0, "path": base.as_posix()}
    findings = [p for p in base.glob("*") if p.is_dir()]
    tests = list((source.path / "test").glob("*.t.sol"))
    return {
        "available": True,
        "finding_families": len(findings),
        "regression_tests": len(tests),
        "finding_names": sorted(p.name for p in findings),
        "test_names": sorted(p.stem for p in tests),
        "path": base.as_posix(),
    }
def _central(source: FederationRoot) -> dict[str, Any]:
    knowledge = source.path / "corpus" / "knowledge"
    cases = list((source.path / "case-studies").rglob("case.yaml"))
    ledger = source.path / "ledger" / "events.jsonl"
    return {
        "available": source.path.exists(),
        "case_files": len(cases),
        "knowledge_files": len(list(knowledge.glob("*.yaml"))) if knowledge.exists() else 0,
        "ledger_events": sum(1 for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()) if ledger.exists() else 0,
        "path": source.path.as_posix(),
    }


ADAPTERS = {
    "central": _central,
    "scf": _scf,
    "zdf": _zdf,
    "sil": _sil,
    "scsl": _scsl,
}


def build_federation_snapshot(root: Path) -> dict[str, Any]:
    roots = _source_roots(root.resolve())
    sources = {}
    missing_required = []
    for source in roots:
        adapter = ADAPTERS.get(source.adapter)
        if adapter is None:
            sources[source.id] = {"available": False, "error": f"unknown adapter {source.adapter}"}
            if source.required:
                missing_required.append(source.id)
            continue
        summary = adapter(source)
        summary["adapter"] = source.adapter
        summary["required"] = source.required
        sources[source.id] = summary
        if source.required and not summary.get("available", False):
            missing_required.append(source.id)
    return {
        "schema_version": 1,
        "snapshot_kind": "federation",
        "root": root.resolve().as_posix(),
        "sources": sources,
        "missing_required_sources": sorted(missing_required),
        "federation_health": "ok" if not missing_required else "blocked",
    }


def write_federation_snapshot(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "federation" / "snapshot.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(build_federation_snapshot(root), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target
def normalized_external_candidates(root: Path) -> list[dict[str, Any]]:
    """Return lead-only objects; never promote external data automatically."""
    snapshot = build_federation_snapshot(root)
    leads: list[dict[str, Any]] = []
    scf = snapshot["sources"].get("source.repo.forensics", {})
    if scf.get("available"):
        leads.append({
            "source": "source.repo.forensics",
            "kind": "external-finding-lead",
            "count": scf.get("record_count", 0),
            "evidence_status": "unreviewed-secondary",
            "promotion": "blocked",
        })
    zdf = snapshot["sources"].get("source.repo.zeroday", {})
    if zdf.get("available"):
        leads.append({
            "source": "source.repo.zeroday",
            "kind": "forensic-case-lead",
            "count": zdf.get("case_count", 0),
            "evidence_status": "external-curated",
            "promotion": "requires-local-review",
        })
    sil = snapshot["sources"].get("source.repo.invariants", {})
    if sil.get("available"):
        leads.append({
            "source": "source.repo.invariants",
            "kind": "execution-evidence-lead",
            "count": sil.get("finding_count", 0) + sil.get("property_count", 0),
            "evidence_status": "execution-artifact",
            "promotion": "requires-linkage",
        })
    return leads


def parse_git_head(root: Path) -> str | None:
    head = root / ".git" / "HEAD"
    if not head.exists():
        return None
    value = head.read_text(encoding="utf-8").strip()
    match = re.fullmatch(r"ref: (.+)", value)
    return match.group(1) if match else value
