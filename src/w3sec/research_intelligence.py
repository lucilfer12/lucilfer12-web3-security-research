from __future__ import annotations
import json
import re
from collections import Counter
from itertools import combinations
from pathlib import Path
from typing import Any

from .federation import build_candidate_network, normalized_candidate_records
from .graph import ResearchGraph
from .history import build_temporal_timeline
from .promotion import build_promotion_engine
from .records import discover_case_records, load_yaml_mapping
from .versions import build_version_diff_report


def _registry(root: Path, stem: str, key: str) -> list[dict[str, Any]]:
    path = root / "corpus" / "knowledge" / f"{stem}.yaml"
    if not path.exists():
        return []
    value = load_yaml_mapping(path).get(key, [])
    return value if isinstance(value, list) else []


def _case_map(root: Path) -> dict[str, dict[str, Any]]:
    return {str(r.get("id")): r for _, r in discover_case_records(root) if r.get("id")}


def _tokens(text: str) -> set[str]:
    stop = {"case", "protocol", "security", "research", "external", "finding"}
    return {x for x in re.findall(r"[a-z0-9]{4,}", text.lower()) if x not in stop}


def build_cross_case_matrix(root: Path) -> dict[str, Any]:
    cases = _case_map(root)
    rows = []
    for case_id, case in sorted(cases.items()):
        rows.append({
            "case": case_id, "category": case.get("category"),
            "protocols": sorted(case.get("protocols", []) or []),
            "invariants": sorted(case.get("invariants", []) or []),
            "patterns": sorted(case.get("patterns", []) or []),
            "hypotheses": sorted(case.get("hypotheses", []) or []),
            "evidence": sorted(case.get("evidence", []) or []),
            "regressions": sorted(case.get("regressions", []) or []),
            "stages": sorted(case.get("stages", []) or []),
        })
    pairs = []
    for left, right in combinations(rows, 2):
        common = {
            "invariants": sorted(set(left["invariants"]) & set(right["invariants"])),
            "patterns": sorted(set(left["patterns"]) & set(right["patterns"])),
            "protocols": sorted(set(left["protocols"]) & set(right["protocols"])),
        }
        shared = sum(bool(values) for values in common.values())
        if shared:
            pairs.append({"left": left["case"], "right": right["case"], "shared": common, "shared_dimensions": shared})
    recurrence = {}
    for field in ("invariants", "patterns", "hypotheses", "protocols", "category", "regressions"):
        counter = Counter()
        for row in rows:
            values = row.get(field, [])
            if isinstance(values, str):
                values = [values]
            counter.update(values or [])
        recurrence[field] = [{"id": x, "case_count": n} for x, n in sorted(counter.items()) if n > 1]
    return {"schema_version": 2, "cases": rows, "recurrence": recurrence, "pairwise_intersections": pairs}
def build_pattern_leads(root: Path) -> list[dict[str, Any]]:
    cases = _case_map(root)
    patterns = _registry(root, "patterns", "patterns")
    external = normalized_candidate_records(root)
    leads = []
    for pattern in patterns:
        pid = str(pattern.get("id"))
        linked = {str(x) for x in pattern.get("cases", []) or []}
        statement = str(pattern.get("statement", ""))
        semantic = []
        for case_id, case in cases.items():
            text = " ".join([
                str(case.get("title", "")), str(case.get("category", "")),
                " ".join(str(x) for x in case.get("tags", []) or []),
            ])
            overlap = len(_tokens(statement) & _tokens(text))
            if overlap:
                semantic.append({"case": case_id, "token_overlap": overlap})
        ext = [x for x in external if pid in {str(y) for y in x.get("candidate_pattern_links", [])}]
        leads.append({
            "pattern": pid, "status": pattern.get("status"),
            "linked_cases": sorted(linked),
            "semantic_lead_cases": sorted(semantic, key=lambda x: (-x["token_overlap"], x["case"])),
            "external_candidate_count": len(ext),
            "external_sources": sorted({str(x.get("source")) for x in ext}),
            "cross_case_evidence": len(linked) >= 2,
        })
    return leads


def build_cross_protocol_leads(root: Path) -> dict[str, Any]:
    cases = _case_map(root)
    external = normalized_candidate_records(root)
    patterns = _registry(root, "patterns", "patterns")
    results = []
    for pattern in patterns:
        pid = str(pattern.get("id"))
        case_ids = {str(x) for x in pattern.get("cases", []) or [] if str(x) in cases}
        protocols = {str(p) for cid in case_ids for p in cases[cid].get("protocols", []) or []}
        external_matches = [x for x in external if pid in {str(y) for y in x.get("candidate_pattern_links", [])}]
        results.append({
            "pattern": pid,
            "canonical_case_count": len(case_ids),
            "canonical_protocols": sorted(protocols),
            "external_candidate_count": len(external_matches),
            "external_sources": sorted({str(x.get("source")) for x in external_matches}),
            "status": "lead" if external_matches else "unresolved",
        })
    return {
        "schema_version": 1,
        "patterns": results,
        "candidate_network": build_candidate_network(root),
        "policy": "Cross-protocol links are leads until independently reviewed and attached to source-backed evidence.",
    }


def build_research_debt(root: Path) -> dict[str, Any]:
    versions = _registry(root, "protocol_versions", "protocol_versions")
    hypotheses = _registry(root, "hypotheses", "hypotheses")
    patterns = _registry(root, "patterns", "patterns")
    ledger = root / "ledger" / "events.jsonl"
    event_count = sum(1 for line in ledger.read_text(encoding="utf-8").splitlines() if line.strip()) if ledger.exists() else 0
    unresolved_versions = [
        str(x.get("id")) for x in versions
        if str(x.get("status", "")).lower() == "unresolved" or str(x.get("version", "")).lower() in {"", "unknown", "none"}
    ]
    return {
        "unresolved_protocol_versions": sorted(unresolved_versions),
        "candidate_hypotheses": sorted(str(x.get("id")) for x in hypotheses if x.get("status") == "candidate"),
        "candidate_patterns": sorted(str(x.get("id")) for x in patterns if x.get("status") == "candidate"),
        "ledger_event_count": event_count,
        "history_reconstruction_required": event_count <= 1,
        "negative_evidence_records": len(_registry(root, "negative_results", "negative_results")),
        "passed_regressions": sum(str(x.get("status")).lower() in {"passed", "verified", "green"} for x in _registry(root, "regressions", "regressions")),
    }
def build_longitudinal_report(root: Path) -> dict[str, Any]:
    root = root.resolve()
    return {
        "schema_version": 2,
        "report_kind": "longitudinal-research",
        "cross_case": build_cross_case_matrix(root),
        "cross_protocol": build_cross_protocol_leads(root),
        "pattern_leads": build_pattern_leads(root),
        "promotion": build_promotion_engine(root),
        "versions": build_version_diff_report(root),
        "temporal": build_temporal_timeline(root, limit=200),
        "research_debt": build_research_debt(root),
    }


def write_longitudinal_report(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "longitudinal" / "research-intelligence.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_longitudinal_report(root), indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return target
def build_inventory_integrity(root: Path) -> dict[str, Any]:
    graph = ResearchGraph.from_repo(root)
    lineage_path = root / "corpus" / "knowledge" / "lineage.yaml"
    declared_edges = 0
    if lineage_path.exists():
        value = load_yaml_mapping(lineage_path).get("edges", [])
        declared_edges = len(value) if isinstance(value, list) else 0
    return {
        "graph_node_count": len(graph.nodes),
        "graph_edge_count": len(graph.edges),
        "lineage_declared_edges": declared_edges,
        "lineage_consistent": declared_edges <= len(graph.edges),
    }


def build_research_metrics(root: Path) -> dict[str, Any]:
    report = build_longitudinal_report(root)
    promotion = report["promotion"]
    decisions = promotion["decisions"]
    return {
        "schema_version": 2,
        "knowledge_objects": {
            "cases": len(_case_map(root)),
            "hypotheses": len(_registry(root, "hypotheses", "hypotheses")),
            "patterns": len(_registry(root, "patterns", "patterns")),
            "invariants": len(_registry(root, "invariants", "invariants")),
            "counterexamples": len(_registry(root, "counterexamples", "counterexamples")),
            "evidence": len(_registry(root, "evidence", "evidence")),
            "experiments": len(_registry(root, "experiments", "experiments")),
            "regressions": len(_registry(root, "regressions", "regressions")),
            "questions": len(_registry(root, "questions", "questions")),
            "claims": len(_registry(root, "claims", "claims")),
            "observations": len(_registry(root, "observations", "observations")),
        },
        "federation": {"external_candidate_records": len(normalized_candidate_records(root))},
        "debt": report["research_debt"],
        "temporal": report["temporal"]["sources"],
        "versions": {
            "contexts": report["versions"]["context_count"],
            "diffs": report["versions"]["diff_count"],
            "unresolved": len(report["versions"]["unresolved"]),
        },
        "promotion": {
            "patterns_total": len(decisions),
            "patterns_promotable": sum(x["decision"] == "promote" for x in decisions),
        },
        "integrity": build_inventory_integrity(root),
    }


__all__ = [
    "build_cross_case_matrix", "build_cross_protocol_leads", "build_pattern_leads",
    "build_research_debt", "build_longitudinal_report", "write_longitudinal_report",
    "build_inventory_integrity", "build_research_metrics",
]
