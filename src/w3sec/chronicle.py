from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from .ledger import iter_events
from .records import discover_case_records, discover_knowledge_files, load_yaml_mapping


def read_ledger(path: Path) -> list[dict[str, Any]]:
    return list(iter_events(path)) if path.exists() else []


def build_chronicle(root: Path) -> dict[str, Any]:
    root = root.resolve()
    ledger_path = root / "ledger" / "events.jsonl"
    events = read_ledger(ledger_path)
    type_counts = Counter(str(event.get("event_type")) for event in events)
    subject_counts = Counter(
        f"{event.get('subject', {}).get('kind')}:{event.get('subject', {}).get('id')}"
        for event in events
    )
    first = events[0].get("timestamp") if events else None
    last = events[-1].get("timestamp") if events else None
    records = []
    for path, record in discover_case_records(root):
        records.append({
            "kind": "case",
            "id": record.get("id"),
            "path": path.relative_to(root).as_posix(),
            "historical_time_known": False,
            "note": "Current-state backfill only; no historical timestamp inferred.",
        })
    for path in discover_knowledge_files(root):
        data = load_yaml_mapping(path)
        for key, values in data.items():
            if not isinstance(values, list):
                continue
            for item in values:
                if isinstance(item, dict) and item.get("id"):
                    records.append({
                        "kind": key.rstrip("s"),
                        "id": item["id"],
                        "path": path.relative_to(root).as_posix(),
                        "historical_time_known": False,
                        "note": "Current-state backfill only; no historical timestamp inferred.",
                    })
    return {
        "schema_version": 1,
        "report_kind": "security-research-chronicle",
        "ledger": {
            "event_count": len(events),
            "first_timestamp": first,
            "last_timestamp": last,
            "event_type_counts": dict(sorted(type_counts.items())),
            "subject_counts": dict(sorted(subject_counts.items())),
            "genesis_only": len(events) <= 1,
        },
        "historical_backfill": {
            "objects": records,
            "policy": "Do not invent historical timestamps; mark time unknown until source evidence supplies them.",
        },
    }
def write_chronicle(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "longitudinal" / "chronicle.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(build_chronicle(root), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target


def build_event_backfill_plan(root: Path) -> dict[str, Any]:
    report = build_chronicle(root)
    objects = report["historical_backfill"]["objects"]
    plan = []
    for item in objects:
        plan.append({
            "subject": f"{item['kind']}:{item['id']}",
            "recommended_events": [
                "record_discovered",
                "source_attached",
                "evidence_reviewed",
                "current_state_snapshot",
            ],
            "timestamp_policy": "unknown-until-sourced",
        })
    return {
        "schema_version": 1,
        "kind": "event-backfill-plan",
        "safe_to_apply_without_fabrication": True,
        "plan": plan,
    }


def write_event_backfill_plan(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "longitudinal" / "backfill-plan.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(build_event_backfill_plan(root), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return target


__all__ = [
    "build_chronicle",
    "write_chronicle",
    "build_event_backfill_plan",
    "write_event_backfill_plan",
]
