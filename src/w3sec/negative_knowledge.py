from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

NEGATIVE_SCHEMA_VERSION = 1

def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str) + "\n").encode("utf-8")

def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()

def negative_path(root: Path) -> Path:
    return root / "research" / "negative-knowledge.jsonl"

def record_negative_result(root: Path, *, hypothesis: str, attempt: str, environment: dict[str, Any] | None,
                          tool: str, input_space: dict[str, Any] | None, explored_states: int,
                          observed_behavior: dict[str, Any] | None, proof_failure_reason: str,
                          confidence: str) -> dict[str, Any]:
    for key, value in {"hypothesis": hypothesis, "attempt": attempt, "tool": tool,
                       "proof_failure_reason": proof_failure_reason, "confidence": confidence}.items():
        if not str(value).strip():
            raise ValueError(f"{key} must be non-empty")
    if explored_states < 0:
        raise ValueError("explored_states must be >= 0")
    record = {
        "schema_version": NEGATIVE_SCHEMA_VERSION, "id": "",
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "hypothesis": hypothesis.strip(), "attempt": attempt.strip(),
        "environment": environment or {}, "tool": tool.strip(), "input_space": input_space or {},
        "explored_states": int(explored_states), "observed_behavior": observed_behavior or {},
        "proof_failure_reason": proof_failure_reason.strip(), "confidence": confidence.strip(),
    }
    record["fingerprint"] = _digest({
        "hypothesis": record["hypothesis"].lower(), "tool": record["tool"].lower(),
        "input_space": record["input_space"],
    })
    record["id"] = f"neg-{record['fingerprint'][:20]}"
    path = negative_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, ensure_ascii=False) + "\n")
    return record

def load_negative_results(root: Path) -> list[dict[str, Any]]:
    path = negative_path(root)
    if not path.exists():
        return []
    result = []
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_no}: negative result must be an object")
            result.append(value)
    return result

def find_matching_negative_results(root: Path, *, hypothesis: str, tool: str,
                                   input_space: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    fingerprint = _digest({
        "hypothesis": hypothesis.strip().lower(), "tool": tool.strip().lower(),
        "input_space": input_space or {},
    })
    return [item for item in load_negative_results(root) if item.get("fingerprint") == fingerprint]
