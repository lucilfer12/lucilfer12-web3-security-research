from __future__ import annotations
import json
import re
import shutil
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .records import load_yaml_mapping
from .runtime import hidden_run


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
            id=str(item["id"]), path=base, adapter=str(item["adapter"]),
            required=bool(item.get("required", False)), dataset=item.get("dataset"),
        ))
    return result


def _distribution(values: list[Any]) -> dict[str, int]:
    return dict(sorted(Counter(str(v) for v in values if v not in (None, "")).items()))


def _tokens(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{4,}", text.lower()))


def _patterns(root: Path) -> list[dict[str, Any]]:
    path = root / "corpus" / "knowledge" / "patterns.yaml"
    if not path.exists():
        return []
    data = load_yaml_mapping(path)
    value = data.get("patterns", [])
    return value if isinstance(value, list) else []


def _pattern_links(root: Path, text: str) -> list[str]:
    text_tokens = _tokens(text)
    links = []
    for pattern in _patterns(root):
        basis = f"{pattern.get('name', '')} {pattern.get('statement', '')}"
        overlap = text_tokens & _tokens(basis)
        if overlap:
            links.append(str(pattern.get("id")))
    return sorted(links)
def _git_head(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    try:
        result = hidden_run(
            ["git", "-C", str(path), "rev-parse", "HEAD"], check=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    value = result.stdout.strip()
    return value or None


def _scf(source: FederationRoot) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = source.path / str(source.dataset)
    if not path.exists():
        return {"available": False, "record_count": 0, "path": path.as_posix()}, []
    rows = _load_json(path)
    candidates = []
    for index, row in enumerate(rows, 1):
        title = str(row.get("title", ""))
        candidates.append({
            "id": f"scf:{row.get('case_id') or index}",
            "source": source.id,
            "record_type": "external-finding",
            "title": title,
            "status": "external-candidate",
            "severity": row.get("severity"),
            "theme": row.get("vulnerability_class") or title,
            "evidence_level": row.get("evidence_level"),
            "locator": row.get("sources") or [],
            "candidate_pattern_links": _pattern_links(source.path.parent / "lucilfer12-web3-security-research" if False else Path(__file__).resolve().parents[2], title),
            "promotion": "blocked-until-reviewed",
        })
    return {
        "available": True, "record_count": len(rows),
        "unique_projects": len({str(row.get("project")) for row in rows if row.get("project")}),
        "status_counts": _distribution([row.get("status") for row in rows]),
        "evidence_levels": _distribution([row.get("evidence_level") for row in rows]),
        "record_types": _distribution([row.get("record_type") for row in rows]),
        "path": path.as_posix(), "git_head": _git_head(source.path),
    }, candidates


def _zdf(source: FederationRoot) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = source.path / str(source.dataset)
    if not path.exists():
        return {"available": False, "case_count": 0, "path": path.as_posix()}, []
    rows = _load_yaml(path)
    if not isinstance(rows, list):
        rows = []
    candidates = []
    for row in rows:
        title = f"{row.get('protocol', '')} {row.get('bug_class', '')}"
        candidates.append({
            "id": f"zdf:{row.get('case_id')}",
            "source": source.id,
            "record_type": "forensic-case-lead",
            "title": title,
            "status": "external-curated",
            "theme": row.get("bug_class"),
            "evidence_level": row.get("evidence_grade"),
            "scope": row.get("scope"),
            "candidate_pattern_links": _pattern_links(Path(__file__).resolve().parents[2], title),
            "promotion": "requires-local-review",
        })
    return {
        "available": True, "case_count": len(rows),
        "bug_classes": len({str(row.get("bug_class")) for row in rows if row.get("bug_class")}),
        "classification_counts": _distribution([row.get("classification") for row in rows]),
        "evidence_grades": _distribution([row.get("evidence_grade") for row in rows]),
        "scope_counts": _distribution([row.get("scope") for row in rows]),
        "path": path.as_posix(), "git_head": _git_head(source.path),
    }, candidates
def _sil(source: FederationRoot) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    path = source.path / str(source.dataset)
    if not path.exists():
        return {"available": False, "finding_count": 0, "property_count": 0, "path": path.as_posix()}, []
    data = _load_json(path)
    findings, properties = data.get("findings", []), data.get("properties", [])
    candidates = []
    for row in findings:
        title = f"{row.get('kind', '')} {row.get('title', '')}"
        candidates.append({
            "id": f"sil:{row.get('id')}",
            "source": source.id,
            "record_type": "execution-finding",
            "title": title,
            "status": "external-observation",
            "theme": row.get("kind"),
            "evidence_level": row.get("confidence"),
            "locator": f"{row.get('file')}:{row.get('line')}",
            "candidate_pattern_links": _pattern_links(Path(__file__).resolve().parents[2], title),
            "promotion": "requires-linkage",
        })
    for row in properties:
        title = str(row.get("name", ""))
        candidates.append({
            "id": f"sil-property:{row.get('name')}",
            "source": source.id,
            "record_type": "execution-property",
            "title": title,
            "status": "external-property",
            "theme": "property",
            "evidence_level": row.get("confidence"),
            "candidate_pattern_links": _pattern_links(Path(__file__).resolve().parents[2], title),
            "promotion": "requires-linkage",
        })
    return {
        "available": True, "finding_count": len(findings), "property_count": len(properties),
        "finding_kinds": _distribution([row.get("kind") for row in findings]),
        "finding_severities": _distribution([row.get("severity") for row in findings]),
        "property_confidence": _distribution([row.get("confidence") for row in properties]),
        "path": path.as_posix(), "git_head": _git_head(source.path),
    }, candidates


def _scsl(source: FederationRoot) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    base = source.path / str(source.dataset)
    tests = list((source.path / "test").glob("*.t.sol"))
    if not base.exists():
        return {"available": False, "finding_families": 0, "regression_tests": len(tests), "path": base.as_posix()}, []
    finding_dirs = [p for p in base.glob("*") if p.is_dir()]
    candidates = []
    for p in finding_dirs:
        title = p.name
        candidates.append({
            "id": f"scsl:{p.name}",
            "source": source.id,
            "record_type": "finding-family",
            "title": title,
            "status": "external-pattern-lead",
            "theme": title,
            "evidence_level": "repository-documented",
            "candidate_pattern_links": _pattern_links(Path(__file__).resolve().parents[2], title),
            "promotion": "requires-local-reproduction",
        })
    for p in tests:
        title = p.stem
        candidates.append({
            "id": f"scsl-test:{p.stem}",
            "source": source.id,
            "record_type": "regression-test-lead",
            "title": title,
            "status": "external-regression-lead",
            "theme": title,
            "evidence_level": "executable-source",
            "candidate_pattern_links": _pattern_links(Path(__file__).resolve().parents[2], title),
            "promotion": "requires-local-import",
        })
    return {
        "available": True, "finding_families": len(finding_dirs), "regression_tests": len(tests),
        "finding_names": sorted(p.name for p in finding_dirs),
        "test_names": sorted(p.stem for p in tests),
        "forge_available": bool(shutil.which("forge")),
        "forge_command": "forge test --root <smart-contract-security-lab> -vv",
        "path": base.as_posix(), "git_head": _git_head(source.path),
    }, candidates
def _central(source: FederationRoot) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    knowledge = source.path / "corpus" / "knowledge"
    cases = list((source.path / "case-studies").rglob("case.yaml"))
    ledger = source.path / "ledger" / "events.jsonl"
    return {
        "available": source.path.exists(), "case_files": len(cases),
        "knowledge_files": len(list(knowledge.glob("*.yaml"))) if knowledge.exists() else 0,
        "ledger_events": sum(1 for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()) if ledger.exists() else 0,
        "path": source.path.as_posix(), "git_head": _git_head(source.path),
    }, []


ADAPTERS = {"central": _central, "scf": _scf, "zdf": _zdf, "sil": _sil, "scsl": _scsl}


def build_federation_snapshot(root: Path) -> dict[str, Any]:
    roots = _source_roots(root.resolve())
    sources, candidates, missing_required = {}, [], []
    for source in roots:
        adapter = ADAPTERS.get(source.adapter)
        if adapter is None:
            sources[source.id] = {"available": False, "error": f"unknown adapter {source.adapter}"}
            if source.required:
                missing_required.append(source.id)
            continue
        summary, rows = adapter(source)
        summary["adapter"], summary["required"] = source.adapter, source.required
        sources[source.id], candidates = summary, candidates + rows
        if source.required and not summary.get("available", False):
            missing_required.append(source.id)
    return {
        "schema_version": 2, "snapshot_kind": "federation",
        "root": root.resolve().as_posix(), "sources": sources,
        "candidate_record_count": len(candidates),
        "source_counts": dict(sorted(Counter(x["source"] for x in candidates).items())),
        "missing_required_sources": sorted(missing_required),
        "federation_health": "ok" if not missing_required else "blocked",
        "candidate_policy": "External records are leads only; canonical promotion requires local review, provenance and explicit research events.",
    }


def normalized_candidate_records(root: Path) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    roots = _source_roots(root.resolve())
    for source in roots:
        adapter = ADAPTERS.get(source.adapter)
        if adapter is None:
            continue
        _, rows = adapter(source)
        candidates.extend(rows)
    return candidates
def build_candidate_network(root: Path) -> dict[str, Any]:
    candidates = normalized_candidate_records(root)
    recurrence = Counter()
    links = Counter()
    for item in candidates:
        theme = str(item.get("theme") or "").strip().lower()
        if theme:
            recurrence[theme] += 1
        for pattern in item.get("candidate_pattern_links", []):
            links[pattern] += 1
    return {
        "schema_version": 1,
        "candidate_count": len(candidates),
        "theme_recurrence": [
            {"theme": theme, "count": count}
            for theme, count in recurrence.most_common()
            if count > 1
        ],
        "pattern_link_leads": [
            {"pattern": pattern, "candidate_count": count}
            for pattern, count in links.most_common()
        ],
        "policy": "Candidate network is a research queue, not canonical evidence.",
    }


def write_federation_snapshot(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "federation" / "snapshot.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_federation_snapshot(root), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return target


def write_candidate_snapshot(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "federation" / "candidate-records.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": 1,
        "snapshot_kind": "normalized-external-candidates",
        "generated_from": build_federation_snapshot(root),
        "records": normalized_candidate_records(root),
    }
    target.write_text(json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


__all__ = [
    "build_federation_snapshot",
    "write_federation_snapshot",
    "normalized_candidate_records",
    "build_candidate_network",
    "write_candidate_snapshot",
]
