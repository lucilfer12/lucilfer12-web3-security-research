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
def _matches(record: dict[str, Any], query: CaseQuery) -> bool:
    if query.category and record.get("category") != query.category:
        return False
    if query.status and record.get("status") != query.status:
        return False
    if query.record_type and record.get("type") != query.record_type:
        return False
    if query.tag and query.tag not in (record.get("tags", []) or []):
        return False
    if query.text:
        haystack = " ".join(
            str(record.get(key, "")) for key in
            ("id", "title", "category", "security_property", "root_cause", "failure", "impact")
        ).lower()
        if query.text.lower() not in haystack:
            return False
    return True
def query_cases(root: Path, query: CaseQuery) -> list[tuple[Path, dict[str, Any]]]:
    return [(path, record) for path, record in discover_case_records(root) if _matches(record, query)]


def summarize_cases(matches: list[tuple[Path, dict[str, Any]]]) -> list[dict[str, Any]]:
    return [
        {
            "id": record.get("id"),
            "title": record.get("title"),
            "type": record.get("type"),
            "status": record.get("status"),
            "category": record.get("category"),
            "reproducible": record.get("reproducible", False),
            "path": path.as_posix(),
        }
        for path, record in matches
    ]
