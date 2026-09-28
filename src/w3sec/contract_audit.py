from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .finding_gate import attach_gate, gate_summary
from .intake import _prepared_target, build_intake, write_intake_report


PRIORITY = {
    "delegatecall": "critical",
    "selfdestruct": "critical",
    "tx_origin": "critical",
    "upgrade": "high",
    "low_level_call": "high",
    "assembly": "high",
    "unchecked": "medium",
    "ecrecover": "medium",
    "create2": "medium",
    "timestamp": "medium",
    "block_number": "medium",
    "fallback": "medium",
    "receive": "low",
    "unsafe": "high",
    "invoke_signed": "high",
    "raw_call": "high",
    "sysvar": "medium",
    "account_info": "medium",
    "entry_point": "medium",
    "contract_call": "medium",
    "as_contract": "high",
    "tx_sender": "medium",
    "gtxn": "medium",
    "itxn": "medium",
    "ensure_signed": "high",
    "get_caller_address": "high",
    "storage_write": "high",
}

TITLES = {
    "delegatecall": "Dynamic code execution path requires review",
    "selfdestruct": "Contract destruction primitive requires lifecycle review",
    "tx_origin": "Transaction-origin authorization signal requires review",
    "upgrade": "Upgradeability / initialization path requires review",
    "low_level_call": "Low-level external call requires call-target and return-data review",
    "assembly": "Inline assembly requires memory / storage / control-flow review",
    "unchecked": "Unchecked arithmetic block requires invariant review",
    "ecrecover": "Signature recovery path requires domain / replay review",
    "create2": "Deterministic deployment path requires address / initialization review",
    "timestamp": "Block timestamp dependency requires temporal-assumption review",
    "block_number": "Block number dependency requires temporal-assumption review",
    "fallback": "Fallback dispatch path requires reachability / value-flow review",
    "receive": "Receive path requires unsolicited-value-flow review",
    "unsafe": "Unsafe primitive requires manual memory / authority review",
    "invoke_signed": "Program-derived authority invocation requires signer-seed review",
    "raw_call": "Raw external-call primitive requires value / target / callback review",
    "sysvar": "System-variable dependency requires freshness and authority review",
    "account_info": "Account metadata flow requires owner / signer / writable review",
    "entry_point": "Externally reachable entry point requires authorization review",
    "contract_call": "Cross-contract call requires callee / return-state review",
    "as_contract": "Contract-as-principal context requires authorization review",
    "tx_sender": "Transaction sender dependency requires authorization review",
    "gtxn": "Grouped transaction dependency requires group-index / replay review",
    "itxn": "Inner transaction creation requires authority / value-flow review",
    "ensure_signed": "Signed-origin enforcement requires origin boundary review",
    "get_caller_address": "Caller identity primitive requires authorization review",
    "storage_write": "Direct storage mutation requires invariant review",
}

RESEARCH_HINTS = {
    "delegatecall": ["upgrade", "lifecycle", "authorization"],
    "selfdestruct": ["lifecycle"],
    "tx_origin": ["authorization", "privileged"],
    "upgrade": ["lifecycle", "authorization"],
    "low_level_call": ["accounting", "state", "call"],
    "assembly": ["state", "accounting"],
    "unchecked": ["accounting", "arithmetic"],
    "ecrecover": ["replay", "authorization"],
    "create2": ["lifecycle", "replay"],
    "timestamp": ["temporal"],
    "block_number": ["temporal"],
    "fallback": ["reachability", "lifecycle"],
    "receive": ["reachability"],
    "unsafe": ["state", "memory"],
    "invoke_signed": ["authorization"],
    "raw_call": ["call", "authorization"],
    "sysvar": ["temporal", "authorization"],
    "account_info": ["authorization", "state"],
    "entry_point": ["authorization", "reachability"],
    "contract_call": ["call", "state"],
    "as_contract": ["authorization"],
    "tx_sender": ["authorization"],
    "gtxn": ["replay"],
    "itxn": ["call", "value"],
    "ensure_signed": ["authorization"],
    "get_caller_address": ["authorization"],
    "storage_write": ["state", "accounting"],
}

def _load_patterns(root: Path) -> list[dict[str, Any]]:
    path = root / "corpus" / "knowledge" / "patterns.yaml"
    if not path.exists():
        return []
    try:
        from .records import load_yaml_mapping
        data = load_yaml_mapping(path)
        return [x for x in (data.get("patterns", []) or []) if isinstance(x, dict)]
    except Exception:
        return []

def _find_related_patterns(root: Path, signal: str) -> list[str]:
    hints = RESEARCH_HINTS.get(signal, [])
    result = []
    for item in _load_patterns(root):
        hay = json.dumps(item, ensure_ascii=False).lower()
        if any(term in hay for term in hints):
            if item.get("id"):
                result.append(str(item["id"]))
    return sorted(set(result))[:8]

def _unit_for_line(units: list[dict[str, Any]], line: int, file_rel: str) -> str | None:
    candidates = [u for u in units if u.get("file") == file_rel and int(u.get("line", 0)) <= line]
    if not candidates:
        return None
    return max(candidates, key=lambda x: int(x.get("line", 0))).get("name")

def _snippet(root_target: Path, rel: str, line: int) -> str | None:
    try:
        path = root_target / rel if root_target.is_dir() else root_target.parent / rel
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].strip()[:320]
    except Exception:
        return None
    return None
def build_contract_audit(target: Path, research_root: Path, progress=None) -> dict[str, Any]:
    def mark(percent: int, label: str) -> None:
        if progress:
            progress(percent, label)
    mark(5, "Preparing audit target")
    target = target.expanduser().resolve()
    research_root = research_root.expanduser().resolve()
    mark(15, "Building contract intake")
    intake = build_intake(target)
    intake_path = write_intake_report(research_root, intake)
    mark(25, "Starting structural scan")

    findings: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    with _prepared_target(target) as (scan_root, _archive_format):
        root_for_snippet = scan_root
        files = intake.get("files", []) or []
        total_files = max(1, len(files))
        for file_index, file_info in enumerate(files, 1):
            rel_preview = str(file_info.get("path", ""))
            mark(25 + int(65 * file_index / total_files), f"Scanning {rel_preview}")
            rel = str(file_info.get("path", ""))
            for signal in file_info.get("signals", []) or []:
                sid = str(signal.get("id", ""))
                lines = [int(x) for x in signal.get("lines", []) if isinstance(x, int) or str(x).isdigit()]
                if sid in ("access_control", "reentrancy_control"):
                    controls.append({
                        "control": sid,
                        "file": rel,
                        "lines": lines[:50],
                        "count": int(signal.get("count", 0)),
                    })
                    continue
                if sid not in PRIORITY:
                    continue
                unit = _unit_for_line(intake.get("contracts", []) or [], lines[0], rel) if lines else None
                for line in lines[:50]:
                    findings.append({
                        "id": f"atlas-review-{len(findings)+1:04d}",
                        "priority": PRIORITY[sid],
                        "status": "review-required",
                        "evidence_type": "static-structural-signal",
                        "signal": sid,
                        "title": TITLES[sid],
                        "file": rel,
                        "line": line,
                        "contract_or_unit": unit,
                        "snippet": _snippet(root_for_snippet, rel, line),
                        "related_research_patterns": _find_related_patterns(research_root, sid),
                        "limitation": "This is a deterministic source signal, not proof that an exploitable vulnerability exists.",
                    })

    priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: (priority_order[x["priority"]], x["file"], x["line"], x["signal"]))
    for i, item in enumerate(findings, 1):
        item["id"] = f"atlas-review-{i:04d}"
        item["source_hash"] = intake["target"]["source_hash"]
        findings[i - 1] = attach_gate(item)

    report = {
        "schema_version": 1,
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "id": f"atlas-audit-{intake['target']['source_hash'][:16]}",
        "target": intake["target"],
        "intake_report": str(intake_path.relative_to(research_root)).replace("\\", "/"),
        "analysis_pipeline": [
            "source/archive intake",
            "content hashing",
            "structural extraction",
            "security-signal collection",
            "research-pattern cross-reference",
            "auditable finding generation",
        ],
        "summary": {
            "finding_count": len(findings),
            "critical": sum(x["priority"] == "critical" for x in findings),
            "high": sum(x["priority"] == "high" for x in findings),
            "medium": sum(x["priority"] == "medium" for x in findings),
            "low": sum(x["priority"] == "low" for x in findings),
            "control_observation_count": len(controls),
            "file_count": intake["summary"].get("file_count", intake["summary"]["source_file_count"]),
            "source_file_count": intake["summary"]["source_file_count"],
            "contract_count": intake["summary"]["contract_count"],
            "function_count": intake["summary"]["function_count"],
        },
        "controls_observed": controls,
        "findings": findings,
        "verification": gate_summary(findings),
        "intake": intake,
    }
    mark(95, "Writing audit findings")
    write_contract_audit(research_root, report)
    mark(100, "Audit complete")
    return report


def write_contract_audit(root: Path, report: dict[str, Any]) -> Path:
    out = root / "reports" / "contract-audits"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f'{report["id"]}.json'
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def list_contract_audits(root: Path) -> list[dict[str, Any]]:
    out = root / "reports" / "contract-audits"
    if not out.exists():
        return []
    result = []
    for path in sorted(out.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("id"):
            result.append(value)
    return result
