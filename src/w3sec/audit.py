from __future__ import annotations

from pathlib import Path
from typing import Any

from .coverage import build_coverage
from .intake import OperationCancelled
from .export import graph_document
from .federation import build_federation_snapshot
from .ledger import verify_chain
from .promotion import build_promotion_engine
from .research_intelligence import build_research_metrics
from .validator import validate_repo
from .versions import build_version_diff_report


def audit_repo(root: Path, progress=None, cancel=None) -> dict[str, Any]:
    root = root.resolve()

    def mark(percent: int, label: str) -> None:
        if cancel and cancel():
            raise OperationCancelled("ATLAS operation cancelled")
        if progress:
            progress(percent, label)

    mark(2, "Validating repository")
    validation_errors = validate_repo(root)
    mark(12, "Verifying temporal ledger")
    ledger_path = root / "ledger" / "events.jsonl"
    ledger_errors = verify_chain(ledger_path)
    mark(25, "Building evidence graph")
    graph = graph_document(root)
    mark(38, "Measuring coverage")
    coverage = build_coverage(root)
    mark(51, "Checking federation state")
    federation = build_federation_snapshot(root)
    mark(63, "Comparing protocol versions")
    versions = build_version_diff_report(root)
    mark(75, "Evaluating promotion gates")
    promotion = build_promotion_engine(root)
    mark(88, "Building research intelligence")
    intelligence = build_research_metrics(root)
    mark(97, "Assembling audit result")
    return {
        "schema_version": 2,
        "ok": not validation_errors and not ledger_errors and federation["federation_health"] == "ok",
        "validation_errors": validation_errors,
        "ledger_errors": ledger_errors,
        "graph": {
            "node_count": len(graph["nodes"]),
            "edge_count": len(graph["edges"]),
        },
        "coverage": coverage,
        "federation": {
            "health": federation["federation_health"],
            "candidate_record_count": federation["candidate_record_count"],
        },
        "longitudinal": {
            "promotion_promotable": intelligence["promotion"]["patterns_promotable"],
            "protocol_diff_count": versions["diff_count"],
            "protocol_unresolved": len(versions["unresolved"]),
        },
        "research_debt": intelligence["debt"],
    }
