from __future__ import annotations

from pathlib import Path
from typing import Any

from .coverage import build_coverage
from .export import graph_document
from .federation import build_federation_snapshot
from .ledger import verify_chain
from .promotion import build_promotion_engine
from .research_intelligence import build_research_metrics
from .validator import validate_repo
from .versions import build_version_diff_report


def audit_repo(root: Path) -> dict[str, Any]:
    root = root.resolve()
    validation_errors = validate_repo(root)
    ledger_path = root / "ledger" / "events.jsonl"
    ledger_errors = verify_chain(ledger_path)
    graph = graph_document(root)
    coverage = build_coverage(root)
    federation = build_federation_snapshot(root)
    versions = build_version_diff_report(root)
    promotion = build_promotion_engine(root)
    intelligence = build_research_metrics(root)
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
