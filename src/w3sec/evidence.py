from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .finding_gate import evaluate_finding


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _node(kind: str, node_id: str, **data: Any) -> dict[str, Any]:
    return {"id": f"{kind}:{node_id}", "kind": kind, **data}


def _audit_reports(root: Path) -> list[dict[str, Any]]:
    base = root / "reports" / "contract-audits"
    reports = []
    if not base.exists():
        return reports
    for path in sorted(base.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict):
            value["_path"] = str(path)
            reports.append(value)
    return reports


def _promotion_snapshot(root: Path) -> dict[str, Any]:
    from .promotion import build_promotion_engine
    report = build_promotion_engine(root)
    return {
        "promotable_count": report["promotable_count"],
        "blocked_count": report["blocked_count"],
        "decisions": report["decisions"],
    }


def _chronicle_snapshot(root: Path) -> dict[str, Any]:
    from .chronicle import build_chronicle
    report = build_chronicle(root)
    return {
        "event_count": report["ledger"]["event_count"],
        "first_timestamp": report["ledger"]["first_timestamp"],
        "last_timestamp": report["ledger"]["last_timestamp"],
    }


def build_evidence_graph(root: Path) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, str]] = []
    debt: list[dict[str, Any]] = []
    findings = 0
    validated = 0

    for report in _audit_reports(root):
        report_id = str(report.get("id") or Path(report["_path"]).stem)
        report_node = _node("audit", report_id, source=report["_path"])
        nodes[report_node["id"]] = report_node
        for index, finding in enumerate(report.get("findings", [])):
            if not isinstance(finding, dict):
                continue
            findings += 1
            finding_id = str(finding.get("id") or f"{report_id}-{index + 1}")
            result = evaluate_finding(finding)
            fn = _node("finding", finding_id, status=result.status, evidence_grade=result.evidence_grade, gates=result.gates, missing=list(result.missing))
            nodes[fn["id"]] = fn
            edges.append({"source": report_node["id"], "relation": "produced", "target": fn["id"]})
            if result.validated:
                validated += 1
            for gate, passed in result.gates.items():
                gate_id = f"{finding_id}:{gate}"
                gate_node = _node("proof", gate_id, gate=gate, satisfied=passed)
                nodes[gate_node["id"]] = gate_node
                edges.append({"source": fn["id"], "relation": "requires", "target": gate_node["id"]})
            for missing in result.missing:
                debt.append({"finding": finding_id, "dimension": missing, "status": "open"})

    document = {
        "schema": "atlas.evidence-graph.v1",
        "nodes": list(nodes.values()),
        "edges": edges,
        "summary": {"finding_count": findings, "validated_count": validated, "proof_node_count": sum(1 for n in nodes.values() if n["kind"] == "proof"), "research_debt_count": len(debt)},
        "research_debt": debt,
        "promotion": _promotion_snapshot(root),
        "chronicle": _chronicle_snapshot(root),
    }
    document["graph_sha256"] = _digest({k: v for k, v in document.items() if k != "graph_sha256"})
    return document


def write_evidence_graph(root: Path, path: Path | None = None) -> Path:
    target = path or root / "reports" / "longitudinal" / "evidence-graph.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_evidence_graph(root), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


__all__ = ["build_evidence_graph", "write_evidence_graph"]
