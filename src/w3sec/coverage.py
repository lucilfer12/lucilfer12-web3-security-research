from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import ResearchStage, stage_gaps
from .query import CaseQuery, query_cases
from .records import discover_knowledge_files, load_yaml_mapping


def _registry_ids(root: Path, key: str) -> set[str]:
    ids: set[str] = set()
    for path in discover_knowledge_files(root):
        data = load_yaml_mapping(path)
        values = data.get(key, [])
        if isinstance(values, list):
            ids.update(
                str(item["id"])
                for item in values
                if isinstance(item, dict) and item.get("id")
            )
    return ids


def build_coverage(root: Path) -> dict[str, Any]:
    cases = query_cases(root, CaseQuery())
    stages = {stage.value: 0 for stage in ResearchStage}
    debt = {stage.value: 0 for stage in ResearchStage}
    per_case: list[dict[str, Any]] = []

    for _, record in cases:
        try:
            present = {ResearchStage(value) for value in record.get("stages", [])}
        except (TypeError, ValueError):
            present = set()
        for stage in present:
            stages[stage.value] += 1
        gaps = stage_gaps(present)
        for stage in gaps:
            debt[stage.value] += 1
        per_case.append({
            "id": record.get("id"),
            "highest_stage": (
                max(present, key=lambda item: list(ResearchStage).index(item)).value
                if present else None
            ),
            "stages": sorted(stage.value for stage in present),
            "stage_debt": [stage.value for stage in gaps],
            "has_evidence": bool(record.get("evidence")),
            "has_hypotheses": bool(record.get("hypotheses")),
            "has_regression_plan": bool(record.get("regressions")),
        })

    evidence = _registry_ids(root, "evidence")
    hypotheses = _registry_ids(root, "hypotheses")
    regressions = _registry_ids(root, "regressions")
    return {
        "schema_version": 1,
        "case_count": len(cases),
        "stage_counts": stages,
        "stage_debt": debt,
        "evidence_count": len(evidence),
        "hypothesis_count": len(hypotheses),
        "regression_plan_count": len(regressions),
        "cases_without_evidence": [x["id"] for x in per_case if not x["has_evidence"]],
        "cases_without_hypotheses": [x["id"] for x in per_case if not x["has_hypotheses"]],
        "cases_without_regression_plan": [x["id"] for x in per_case if not x["has_regression_plan"]],
        "cases": sorted(per_case, key=lambda x: str(x["id"])),
    }
