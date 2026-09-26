from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .records import discover_case_records


@dataclass(frozen=True, slots=True)
class CaseQuery:
    category: str | None = None
    status: str | None = None
    record_type: str | None = None
    tag: str | None = None
    text: str | None = None
    stage: str | None = None
    invariant: str | None = None
    pattern: str | None = None
    protocol: str | None = None
    evidence: str | None = None
    hypothesis: str | None = None
    source: str | None = None
    regression: str | None = None


def _has(values: Any, needle: str | None) -> bool:
    return needle is None or needle in (values or [])


def _matches(record: dict[str, Any], query: CaseQuery) -> bool:
    if query.category and record.get("category") != query.category:
        return False
    if query.status and record.get("status") != query.status:
        return False
    if query.record_type and record.get("type") != query.record_type:
        return False
    if query.tag and not _has(record.get("tags"), query.tag):
        return False
    if query.stage and not _has(record.get("stages"), query.stage):
        return False
    if query.invariant and not _has(record.get("invariants"), query.invariant):
        return False
    if query.pattern and not _has(record.get("patterns"), query.pattern):
        return False
    if query.protocol and not _has(record.get("protocols"), query.protocol):
        return False
    if query.evidence and not _has(record.get("evidence"), query.evidence):
        return False
    if query.hypothesis and not _has(record.get("hypotheses"), query.hypothesis):
        return False
    if query.source and not _has(record.get("sources"), query.source):
        return False
    if query.regression and not _has(record.get("regressions"), query.regression):
        return False
    if query.text:
        haystack = " ".join(str(record.get(key, "")) for key in (
            "id", "title", "category", "security_property", "root_cause", "failure", "impact"
        )).lower()
        if query.text.lower() not in haystack:
            return False
    return True


def query_cases(root: Path, query: CaseQuery) -> list[tuple[Path, dict[str, Any]]]:
    return [(path, record) for path, record in discover_case_records(root) if _matches(record, query)]
def summarize_cases(matches: list[tuple[Path, dict[str, Any]]]) -> list[dict[str, Any]]:
    return [{
        "id": record.get("id"),
        "title": record.get("title"),
        "type": record.get("type"),
        "status": record.get("status"),
        "category": record.get("category"),
        "stages": record.get("stages", []),
        "reproducible": record.get("reproducible", False),
        "path": path.as_posix(),
    } for path, record in matches]
