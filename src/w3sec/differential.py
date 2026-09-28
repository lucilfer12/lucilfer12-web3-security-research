from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Generic, Hashable, TypeVar

State = TypeVar("State")

DIFFERENTIAL_SCHEMA_VERSION = 1


@dataclass(frozen=True, slots=True)
class Divergence(Generic[State]):
    step: int
    action: str
    left: State
    right: State


@dataclass(frozen=True, slots=True)
class DifferentialResult(Generic[State]):
    actions: tuple[str, ...]
    divergence: Divergence[State] | None


def run_differential(
    initial: State,
    actions: list[str],
    left_step: Callable[[State, str], State],
    right_step: Callable[[State, str], State],
    state_key: Callable[[State], Hashable] | None = None,
) -> DifferentialResult[State]:
    left = right = initial
    compare = state_key or (lambda value: value)
    for index, action in enumerate(actions, 1):
        left = left_step(left, action)
        right = right_step(right, action)
        if compare(left) != compare(right):
            return DifferentialResult(tuple(actions), Divergence(index, action, left, right))
    return DifferentialResult(tuple(actions), None)


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()

def _stable_finding_key(item: dict[str, Any]) -> str:
    fields = {key: item.get(key) for key in ("rule_id", "engine", "file", "signal", "check", "function", "selector")
              if item.get(key) not in (None, "")}
    if not fields:
        fields = {"description": str(item.get("description", ""))[:320], "elements": item.get("elements", [])}
    return _digest(fields)[:24]

def _index(items: list[dict[str, Any]], keyer) -> dict[str, dict[str, Any]]:
    return {keyer(item): item for item in items if isinstance(item, dict)}

def _compare(before: dict[str, Any], after: dict[str, Any]) -> dict[str, list[str]]:
    b, a = set(before), set(after)
    return {"introduced": sorted(a-b), "removed": sorted(b-a), "unchanged": sorted(a&b)}

def _contracts(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [x for x in report.get("contracts", []) if isinstance(x, dict)]

def _functions(report: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for c in _contracts(report):
        for f in c.get("functions", []) or []:
            if isinstance(f, dict):
                out.append({**f, "file": c.get("file", ""), "contract": c.get("name", "")})
    return out

def _findings(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [x for x in (list(report.get("findings", [])) + list(report.get("engine_findings", []))) if isinstance(x, dict)]

def compare_revisions(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    sb = {str(x["path"]): x for x in before.get("files", []) if isinstance(x, dict) and x.get("path")}
    sa = {str(x["path"]): x for x in after.get("files", []) if isinstance(x, dict) and x.get("path")}
    cb = _index(_contracts(before), lambda x: f'{x.get("file","")}::{x.get("name","")}')
    ca = _index(_contracts(after), lambda x: f'{x.get("file","")}::{x.get("name","")}')
    fb = _index(_functions(before), lambda x: f'{x.get("file","")}::{x.get("contract","")}::{x.get("name","")}::{x.get("signature","")}')
    fa = _index(_functions(after), lambda x: f'{x.get("file","")}::{x.get("contract","")}::{x.get("name","")}::{x.get("signature","")}')
    xb = _index(_findings(before), _stable_finding_key)
    xa = _index(_findings(after), _stable_finding_key)
    result = {
        "schema_version": DIFFERENTIAL_SCHEMA_VERSION,
        "before_revision": before.get("target", {}).get("source_hash") or before.get("id"),
        "after_revision": after.get("target", {}).get("source_hash") or after.get("id"),
        "source": {**_compare(sb, sa), "changed": sorted(path for path in set(sb)&set(sa) if sb[path].get("sha256") != sa[path].get("sha256"))},
        "structure": {"contracts": _compare(cb, ca), "functions": _compare(fb, fa)},
        "findings": _compare(xb, xa),
        "execution": {},
    }
    regressed, fixed = [], []
    for key in sorted(set(xb)&set(xa)):
        new = xa[key]
        if str(new.get("status", "")).lower() == "regressed" or new.get("regression_evidence"):
            regressed.append(key)
        if new.get("fixed_but_unproven"):
            fixed.append(key)
    for key in set(xb)-set(xa):
        if xb[key].get("fixed_but_unproven"):
            fixed.append(key)
    result["findings"]["regressed"] = sorted(set(regressed))
    result["findings"]["fixed_but_unproven"] = sorted(set(fixed))
    for domain in ("traces", "state_deltas", "economic_impacts"):
        old, new = before.get(domain, {}) or {}, after.get(domain, {}) or {}
        if isinstance(old, dict) and isinstance(new, dict):
            result["execution"][domain] = {"before_digest": _digest(old), "after_digest": _digest(new), "unchanged": old == new}
    result["digest"] = _digest(result)
    return result

def compare_intake_files(before_path: Path, after_path: Path) -> dict[str, Any]:
    return compare_revisions(json.loads(before_path.read_text(encoding="utf-8")),
                             json.loads(after_path.read_text(encoding="utf-8")))

def write_differential_report(root: Path, result: dict[str, Any]) -> Path:
    path = root / "reports" / "differential" / f'{str(result.get("before_revision") or "before")[:16]}--{str(result.get("after_revision") or "after")[:16]}.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path
