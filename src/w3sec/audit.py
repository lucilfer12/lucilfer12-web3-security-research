from __future__ import annotations

from pathlib import Path
from typing import Any

from .coverage import build_coverage
from .export import graph_document
from .ledger import verify_chain
from .validator import validate_repo


def audit_repo(root: Path) -> dict[str, Any]:
    root = root.resolve()
    validation_errors = validate_repo(root)
    ledger_path = root / "ledger" / "events.jsonl"
    ledger_errors = verify_chain(ledger_path)
    graph = graph_document(root)
    coverage = build_coverage(root)
    return {
        "schema_version": 1,
        "ok": not validation_errors and not ledger_errors,
        "validation_errors": validation_errors,
        "ledger_errors": ledger_errors,
        "graph": {
            "node_count": len(graph["nodes"]),
            "edge_count": len(graph["edges"]),
        },
        "coverage": coverage,
    }
