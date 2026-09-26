from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .model import ResearchStage, stage_gaps
from .query import CaseQuery, query_cases
from .records import discover_knowledge_files, load_yaml_mapping


def _counter(values: list[str]) -> dict[str, int]:
    counts = Counter(values)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def build_inventory(root: Path) -> dict[str, Any]:
    cases = query_cases(root, CaseQuery())
    registry_counts: Counter[str] = Counter()
    knowledge_files: dict[str, int] = {}
    for path in discover_knowledge_files(root):
        data = load_yaml_mapping(path)
        for key in (
            "invariants", "patterns", "counterexamples", "experiments",
            "protocols", "evidence", "hypotheses", "source_repos",
            "regressions", "protocol_versions", "negative_results", "edges",
        ):
            items = data.get(key)
            if isinstance(items, list):
                registry_counts[key] += len(items)
                knowledge_files[f"{path.stem}.{key}"] = len(items)

    status_values = [str(record.get("status", "")) for _, record in cases]
    category_values = [str(record.get("category", "")) for _, record in cases]
    type_values = [str(record.get("type", "")) for _, record in cases]
    disclosure_values = [str(record.get("disclosure", "")) for _, record in cases]
    stage_counts: Counter[str] = Counter()
    debt_counts: Counter[str] = Counter()
    reproducible = 0
    for _, record in cases:
        reproducible += record.get("reproducible") is True
        try:
            normalized = {ResearchStage(value) for value in record.get("stages", [])}
        except (TypeError, ValueError):
            normalized = set()
        for stage in normalized:
            stage_counts[stage.value] += 1
        for gap in stage_gaps(normalized):
            debt_counts[gap.value] += 1

    return {
        "schema_version": 1,
        "case_count": len(cases),
        "reproducible_cases": reproducible,
        "status_counts": _counter(status_values),
        "category_counts": _counter(category_values),
        "type_counts": _counter(type_values),
        "disclosure_counts": _counter(disclosure_values),
        "research_stage_counts": dict(sorted(stage_counts.items())),
        "research_debt_counts": dict(sorted(debt_counts.items())),
        "knowledge_registry_counts": dict(sorted(registry_counts.items())),
        "knowledge_files": knowledge_files,
        "case_ids": sorted(str(record.get("id", "")) for _, record in cases),
    }
