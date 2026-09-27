from __future__ import annotations
import json
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from .chronicle import read_ledger
from .runtime import hidden_run


def _git_output(root: Path, *args: str) -> str:
    result = hidden_run(
        ["git", "-C", str(root), *args], check=True,
    )
    return result.stdout


def _domain_for_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    if normalized.startswith("case-studies/"):
        return "cases"
    if normalized.startswith("corpus/knowledge/"):
        return "knowledge"
    if normalized.startswith("corpus/federation/"):
        return "federation"
    if normalized.startswith("ledger/"):
        return "ledger"
    if normalized.startswith("experiments/"):
        return "experiments"
    if normalized.startswith("src/"):
        return "tooling"
    if normalized.startswith("tests/"):
        return "tests"
    if normalized.startswith("docs/"):
        return "docs"
    return "other"


def collect_git_history(root: Path, limit: int = 200) -> list[dict[str, Any]]:
    raw = _git_output(
        root,
        "log", f"-{limit}", "--date=iso-strict",
        "--format=__COMMIT__%n%H%n%cI%n%an%n%s",
        "--name-only",
    )
    lines = raw.splitlines()
    commits, current = [], None
    for line in lines:
        if line == "__COMMIT__":
            if current:
                commits.append(current)
            current = {"paths": []}
            continue
        if current is None:
            continue
        if "sha" not in current:
            current["sha"] = line
        elif "timestamp" not in current:
            current["timestamp"] = line
        elif "author" not in current:
            current["author"] = line
        elif "subject" not in current:
            current["subject"] = line
        elif line.strip():
            current["paths"].append(line.strip())
    if current:
        commits.append(current)
    for commit in commits:
        commit["domains"] = sorted({_domain_for_path(path) for path in commit["paths"]})
        commit["event_type"] = "repository_commit"
    return commits
def build_temporal_timeline(root: Path, limit: int = 200) -> dict[str, Any]:
    ledger_events = []
    for event in read_ledger(root / "ledger" / "events.jsonl"):
        ledger_events.append({
            "timestamp": event.get("timestamp"),
            "event_type": f"ledger:{event.get('event_type')}",
            "actor": event.get("actor"),
            "subject": event.get("subject"),
            "source": "hash-chained-ledger",
            "event_id": event.get("event_id"),
            "event_hash": event.get("event_hash"),
        })
    git_events = [
        {
            "timestamp": item.get("timestamp"),
            "event_type": "repository_commit",
            "actor": item.get("author"),
            "subject": {"kind": "commit", "id": item.get("sha")},
            "source": "git-history",
            "event_id": item.get("sha"),
            "subject_line": item.get("subject"),
            "domains": item.get("domains", []),
            "paths": item.get("paths", []),
        }
        for item in collect_git_history(root, limit)
    ]
    timeline = sorted(ledger_events + git_events, key=lambda item: str(item.get("timestamp") or ""))
    return {
        "schema_version": 1,
        "event_count": len(timeline),
        "timeline": timeline,
        "sources": {
            "ledger_event_count": len(ledger_events),
            "git_commit_count": len(git_events),
        },
        "interpretation": {
            "ledger": "Explicit research events with hash-chain integrity.",
            "git": "Repository change history used only as temporal provenance; it is not treated as proof of a research conclusion.",
        },
    }


def build_domain_evolution(root: Path, limit: int = 200) -> dict[str, Any]:
    commits = collect_git_history(root, limit)
    by_domain = Counter(domain for commit in commits for domain in commit.get("domains", []))
    return {
        "schema_version": 1,
        "commit_count": len(commits),
        "domain_change_counts": dict(sorted(by_domain.items())),
        "commits": commits,
    }


def write_temporal_history(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "longitudinal" / "temporal-history.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_temporal_timeline(root), indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


def write_domain_evolution(root: Path, output: Path | None = None) -> Path:
    target = output or root / "reports" / "longitudinal" / "domain-evolution.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(build_domain_evolution(root), indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return target


__all__ = ["collect_git_history", "build_temporal_timeline", "build_domain_evolution", "write_temporal_history", "write_domain_evolution"]
