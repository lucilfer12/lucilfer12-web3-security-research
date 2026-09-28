from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .coverage import build_coverage
from .finding_gate import gate_summary
from .contract_audit import list_contract_audits
from .inventory import build_inventory
from .ledger import verify_chain
from .records import discover_case_records
from .promotion import build_promotion_engine
from .graph import ResearchGraph


QUALITY_CONSTITUTION = (
    "tool-signal-is-not-vulnerability",
    "candidate-is-not-validated",
    "ai-is-not-authority",
    "no-evidence-no-proof",
    "no-reproduction-no-validation",
    "no-impact-measurement-no-validation",
    "independent-verification-is-explicit",
    "regression-proof-is-tracked-separately",
    "unknown-results-remain-visible",
)


def _case_quality_issues(record: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    status = str(record.get("status", "")).strip().lower()
    stages = {str(x).strip().lower() for x in record.get("stages", []) or []}
    evidence = record.get("evidence", []) or []
    provenance = record.get("provenance", []) or []
    if not isinstance(evidence, list):
        evidence = []
    if not isinstance(provenance, list):
        provenance = []

    if status in {"validated", "validated-pattern"}:
        if not evidence:
            issues.append("validated status without evidence references")
        if "reproduced" not in stages:
            issues.append("validated status without reproduced stage")
        if "measured" not in stages:
            issues.append("validated status without measured stage")

    if record.get("reproducible") is True:
        if not evidence:
            issues.append("reproducible=true without evidence references")
        if "reproduced" not in stages:
            issues.append("reproducible=true without reproduced stage")
        if not provenance:
            issues.append("reproducible=true without provenance")
    return issues


def build_quality_report(root: Path) -> dict[str, Any]:
    root = root.expanduser().resolve()
    validation_errors: list[str] = []
    try:
        from .validator import validate_repo
        validation_errors = validate_repo(root)
    except Exception as exc:
        validation_errors = [f"validator engine failure: {exc!r}"]

    ledger_errors = verify_chain(root / "ledger" / "events.jsonl")
    case_issues: list[dict[str, Any]] = []
    try:
        for path, record in discover_case_records(root):
            issues = _case_quality_issues(record)
            if issues:
                case_issues.append({
                    "path": str(path.relative_to(root)).replace("\\", "/"),
                    "id": record.get("id"),
                    "issues": issues,
                })
    except Exception as exc:
        case_issues.append({"path": "case-studies", "id": None, "issues": [f"record scan failure: {exc!r}"]})

    audits = list_contract_audits(root)
    findings = [
        item
        for report in audits
        for item in (report.get("findings", []) if isinstance(report, dict) else [])
        if isinstance(item, dict)
    ]
    gate = gate_summary(findings)
    inventory = build_inventory(root)
    coverage = build_coverage(root)
    promotion = build_promotion_engine(root)
    graph = ResearchGraph.from_repo(root)

    blocking = list(validation_errors) + list(ledger_errors)
    return {
        "schema_version": 1,
        "quality_engine": "ATLAS-quality-constitution",
        "ok": not blocking and not case_issues,
        "blocking_issues": blocking,
        "case_integrity_issues": case_issues,
        "proof_debt": {
            "contract_audit_count": len(audits),
            "finding_count": gate["finding_count"],
            "validated_count": gate["validated_count"],
            "candidate_count": gate["status_counts"].get("candidate", 0),
            "observed_count": gate["status_counts"].get("observed", 0),
            "reproduced_count": gate["status_counts"].get("reproduced", 0),
            "policy": "Unproven findings remain visible as research debt and are never promoted by the scanner.",
        },
        "ledger": {
            "ok": not ledger_errors,
            "error_count": len(ledger_errors),
        },
        "repository": {
            "case_count": inventory.get("case_count", 0),
            "graph_nodes": len(graph.nodes),
            "graph_edges": len(graph.edges),
            "coverage": coverage,
        },
        "promotion": {
            "promotable_count": promotion.get("promotable_count", 0),
            "blocked_count": promotion.get("blocked_count", 0),
        },
        "constitution": list(QUALITY_CONSTITUTION),
    }


def write_quality_report(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "longitudinal" / "quality-report.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(build_quality_report(root), indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return target


__all__ = ["QUALITY_CONSTITUTION", "build_quality_report", "write_quality_report"]
