from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from .records import discover_case_records


def build_inventory(root: Path) -> dict[str, Any]:
    records = discover_case_records(root)
    statuses = Counter()
    categories = Counter()
    types = Counter()
    disclosures = Counter()
    reproducible = 0

    for _, record in records:
        statuses[str(record.get("status", ""))] += 1
        categories[str(record.get("category", ""))] += 1
        types[str(record.get("type", ""))] += 1
        disclosures[str(record.get("disclosure", ""))] += 1
        if record.get("reproducible") is True:
            reproducible += 1

    def ordered(counter: Counter[str]) -> dict[str, int]:
        return dict(sorted(counter.items(), key=lambda item: (-item[1], item[0])))

    return {
        "case_count": len(records),
        "reproducible_cases": reproducible,
        "status_counts": ordered(statuses),
        "category_counts": ordered(categories),
        "type_counts": ordered(types),
        "disclosure_counts": ordered(disclosures),
        "case_ids": sorted(str(record.get("id", "")) for _, record in records),
    }
