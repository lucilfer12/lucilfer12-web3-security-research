from __future__ import annotations

from pathlib import Path
from typing import Any

from ..coverage import build_coverage
from ..export import graph_document
from ..evidence_fabric import build_evidence_fabric
from ..federation import build_federation_snapshot
from ..graph import ResearchGraph
from ..ledger import verify_chain
from ..promotion_verified import build_promotion_engine
from ..research_intelligence import build_research_metrics
from ..research_run import RUN_STAGES, ResearchRun
from ..validator import validate_repo
from ..versions import build_version_diff_report
from ..intake import OperationCancelled, list_intakes
from ..contract_audit import list_contract_audits


def audit_repo(root: Path, progress=None, cancel=None, run: ResearchRun | None = None) -> dict[str, Any]:
    root = root.resolve()
    run = run or ResearchRun.start(root, kind="repository-audit")

    def mark(percent: int, label: str) -> None:
        run.check_cancelled(cancel)
        if progress:
            progress(percent, label)

    def stage(name: str, percent: int, label: str, builder):
        run.check_cancelled(cancel)
        if run.is_completed(name):
            mark(percent, f"{label} · resumed from checkpoint")
            return run.result(name)
        run.begin_stage(name)
        mark(percent, label)
        value = builder()
        run.check_cancelled(cancel)
        run.checkpoint(name, value)
        return value

    try:
        validation_errors = stage(
            RUN_STAGES[0], 5, "Validating repository",
            lambda: validate_repo(root),
        )
        ledger_path = root / "ledger" / "events.jsonl"
        ledger_errors = stage(
            RUN_STAGES[1], 15, "Verifying temporal ledger",
            lambda: verify_chain(ledger_path),
        )
        graph = stage(
            RUN_STAGES[2], 25, "Building knowledge graph",
            lambda: graph_document(root),
        )
        coverage = stage(
            RUN_STAGES[3], 40, "Calculating coverage",
            lambda: build_coverage(root),
        )
        federation = stage(
            RUN_STAGES[4], 55, "Refreshing federation snapshot",
            lambda: build_federation_snapshot(root),
        )
        versions = stage(
            RUN_STAGES[5], 68, "Comparing protocol versions",
            lambda: build_version_diff_report(root),
        )
        promotion = stage(
            RUN_STAGES[6], 80, "Running promotion checks",
            lambda: build_promotion_engine(root),
        )
        intelligence = stage(
            RUN_STAGES[7], 92, "Updating research intelligence",
            lambda: build_research_metrics(root),
        )

        findings: list[dict[str, Any]] = []
        for report in list_contract_audits(root):
            findings.extend(
                item for item in report.get("findings", [])
                if isinstance(item, dict)
            )
        fabric = build_evidence_fabric(findings)
        result = {
            "schema_version": 3,
            "run_id": run.run_id,
            "run_status": "completed",
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
            "evidence_fabric": fabric,
        }
        if not run.is_completed(RUN_STAGES[8]):
            run.begin_stage(RUN_STAGES[8])
            mark(96, "Assembling audit result")
            run.checkpoint(RUN_STAGES[8], result)
        else:
            result = run.result(RUN_STAGES[8]) or result
        run.complete(result)
        mark(100, f"Audit complete · run {run.run_id}")
        return result
    except OperationCancelled:
        run.cancel()
        raise
    except Exception as exc:
        run.fail(exc)
        raise
