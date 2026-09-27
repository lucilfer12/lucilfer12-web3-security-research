from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from .graph import ResearchGraph
from .records import discover_case_records, load_yaml_mapping


def _registry(root: Path, stem: str, key: str) -> list[dict[str, Any]]:
    path = root / "corpus" / "knowledge" / f"{stem}.yaml"
    if not path.exists():
        return []
    value = load_yaml_mapping(path).get(key, [])
    return value if isinstance(value, list) else []


def _case_map(root: Path) -> dict[str, dict[str, Any]]:
    return {
        str(record.get("id")): record
        for _, record in discover_case_records(root)
        if record.get("id")
    }


def _tokens(text: str) -> set[str]:
    return {
        token for token in re.findall(r"[a-z0-9]{4,}", text.lower())
        if token not in {"case", "protocol", "security", "research"}
    }


def build_cross_case_matrix(root: Path) -> dict[str, Any]:
    cases = _case_map(root)
    rows = []
    for case_id, case in sorted(cases.items()):
        rows.append({
            "case": case_id,
            "category": case.get("category"),
            "protocols": sorted(case.get("protocols", []) or []),
            "invariants": sorted(case.get("invariants", []) or []),
            "patterns": sorted(case.get("patterns", []) or []),
            "hypotheses": sorted(case.get("hypotheses", []) or []),
            "evidence": sorted(case.get("evidence", []) or []),
            "regressions": sorted(case.get("regressions", []) or []),
            "stages": sorted(case.get("stages", []) or []),
        })

    dimensions = {
        "invariant": Counter(),
        "pattern": Counter(),
        "hypothesis": Counter(),
        "protocol": Counter(),
        "category": Counter(),
        "regression": Counter(),
    }
    row_fields = {
        "invariant": "invariants",
        "pattern": "patterns",
        "hypothesis": "hypotheses",
        "protocol": "protocols",
        "category": "category",
        "regression": "regressions",
    }
    for row in rows:
        for key, field in row_fields.items():
            values = row.get(field, [])
            if isinstance(values, str):
                values = [values]
            dimensions[key].update(values or [])
    recurrence = {
        key: [
            {"id": item, "case_count": count}
            for item, count in sorted(counter.items())
            if count > 1
        ]
        for key, counter in dimensions.items()
    }
    return {"schema_version": 1, "cases": rows, "recurrence": recurrence}


def build_pattern_leads(root: Path) -> list[dict[str, Any]]:
    cases = _case_map(root)
    patterns = _registry(root, "patterns", "patterns")
    leads = []
    for pattern in patterns:
        pattern_id = str(pattern.get("id"))
        linked_cases = set(pattern.get("cases", []) or [])
        text = str(pattern.get("statement", ""))
        token_hits = []
        for case_id, case in cases.items():
            case_text = " ".join([
                str(case.get("title", "")), str(case.get("category", "")),
                " ".join(str(x) for x in case.get("tags", []) or []),
            ])
            overlap = len(_tokens(text) & _tokens(case_text))
            if overlap:
                token_hits.append({"case": case_id, "token_overlap": overlap})
        leads.append({
            "pattern": pattern_id,
            "status": pattern.get("status"),
            "linked_case_count": len(linked_cases),
            "linked_cases": sorted(linked_cases),
            "semantic_lead_cases": sorted(token_hits, key=lambda x: (-x["token_overlap"], x["case"])),
            "cross_case_evidence": len(linked_cases) >= 2,
        })
    return leads
def build_promotion_readiness(root: Path) -> list[dict[str, Any]]:
    graph = ResearchGraph.from_repo(root)
    patterns = _registry(root, "patterns", "patterns")
    regressions = {
        str(item.get("case")): item
        for item in _registry(root, "regressions", "regressions")
        if item.get("case")
    }
    result = []
    for pattern in patterns:
        pid = str(pattern.get("id"))
        node = graph.nodes.get(f"pattern:{pid}")
        incoming = graph.reverse_neighbors(node) if node else []
        corroborating_cases = sorted({
            ref.id for ref in incoming
            if ref.kind == "case"
        } | set(pattern.get("cases", []) or []))
        criteria = {
            "cross_case": len(corroborating_cases) >= 2,
            "regression_coverage": any(case in regressions for case in corroborating_cases),
            "explicit_scope": bool(pattern.get("scope") or pattern.get("statement")),
            "counterexample_analysis": any(ref.kind == "counterexample" for ref in incoming),
            "independent_reproduction": bool(pattern.get("independent_reproduction")),
            "cross_protocol": len({
                str(_case_map(root).get(case, {}).get("protocols", ["unknown"])[0])
                for case in corroborating_cases
            }) >= 2 if corroborating_cases else False,
        }
        passed = sum(criteria.values())
        result.append({
            "pattern": pid,
            "current_status": pattern.get("status"),
            "criteria": criteria,
            "criteria_passed": passed,
            "criteria_total": len(criteria),
            "ready_for_validation": passed == len(criteria),
        })
    return result


def build_research_debt(root: Path) -> dict[str, Any]:
    versions = _registry(root, "protocol_versions", "protocol_versions")
    hypotheses = _registry(root, "hypotheses", "hypotheses")
    patterns = _registry(root, "patterns", "patterns")
    ledger = root / "ledger" / "events.jsonl"
    ledger_events = sum(1 for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()) if ledger.exists() else 0
    unresolved_versions = [
        str(item.get("id")) for item in versions
        if str(item.get("status", "")).lower() == "unresolved" or item.get("version") in (None, "", "unknown")
    ]
    candidate_hypotheses = [str(item.get("id")) for item in hypotheses if item.get("status") == "candidate"]
    candidate_patterns = [str(item.get("id")) for item in patterns if item.get("status") == "candidate"]
    return {
        "unresolved_protocol_versions": sorted(unresolved_versions),
        "candidate_hypotheses": sorted(candidate_hypotheses),
        "candidate_patterns": sorted(candidate_patterns),
        "ledger_event_count": ledger_events,
        "history_reconstruction_required": ledger_events <= 1,
    }


def build_longitudinal_report(root: Path) -> dict[str, Any]:
    root = root.resolve()
    matrix = build_cross_case_matrix(root)
    return {
        "schema_version": 1,
        "report_kind": "longitudinal-research",
        "cross_case": matrix,
        "pattern_leads": build_pattern_leads(root),
        "promotion_readiness": build_promotion_readiness(root),
        "research_debt": build_research_debt(root),
    }


def write_longitudinal_report(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "longitudinal" / "research-intelligence.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(build_longitudinal_report(root), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target
def build_inventory_integrity(root: Path) -> dict[str, Any]:
    graph = ResearchGraph.from_repo(root)
    lineage_path = root / "corpus" / "knowledge" / "lineage.yaml"
    declared_edges = 0
    if lineage_path.exists():
        declared = load_yaml_mapping(lineage_path).get("edges", [])
        declared_edges = len(declared) if isinstance(declared, list) else 0
    readme = root / "README.md"
    text = readme.read_text(encoding="utf-8") if readme.exists() else ""
    match = re.search(r"(\d+) explicit lineage edges", text)
    documented_edges = int(match.group(1)) if match else None
    return {
        "graph_node_count": len(graph.nodes),
        "graph_edge_count": len(graph.edges),
        "lineage_declared_edges": declared_edges,
        "readme_documented_edges": documented_edges,
        "lineage_consistent": documented_edges in (None, declared_edges, len(graph.edges)),
    }


def build_research_metrics(root: Path) -> dict[str, Any]:
    report = build_longitudinal_report(root)
    debt = report["research_debt"]
    readiness = report["promotion_readiness"]
    ready = sum(1 for item in readiness if item["ready_for_validation"])
    total = len(readiness)
    return {
        "schema_version": 1,
        "knowledge_objects": {
            "cases": len(_case_map(root)),
            "hypotheses": len(_registry(root, "hypotheses", "hypotheses")),
            "patterns": len(_registry(root, "patterns", "patterns")),
            "invariants": len(_registry(root, "invariants", "invariants")),
            "counterexamples": len(_registry(root, "counterexamples", "counterexamples")),
            "evidence": len(_registry(root, "evidence", "evidence")),
            "experiments": len(_registry(root, "experiments", "experiments")),
            "regressions": len(_registry(root, "regressions", "regressions")),
        },
        "debt": debt,
        "promotion": {
            "patterns_ready": ready,
            "patterns_total": total,
        },
        "integrity": build_inventory_integrity(root),
    }


__all__ = [
    "build_cross_case_matrix",
    "build_pattern_leads",
    "build_promotion_readiness",
    "build_research_debt",
    "build_longitudinal_report",
    "write_longitudinal_report",
    "build_inventory_integrity",
    "build_research_metrics",
]
