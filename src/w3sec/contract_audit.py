from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .finding_gate import attach_gate, gate_summary
from .intake import OperationCancelled, _prepared_target, build_intake, write_intake_report
from .scanner import _production_path, _rust_in_scope, _rust_scope, run_security_scan


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
    "rust_unsafe_block": "medium",
    "rust_unsafe_impl": "medium",
    "rust_unwrap_expect": "medium",
    "rust_input_sized_allocation": "medium",
    "rust_gas_ordering": "medium",
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
    "unsafe": "Legacy generic unsafe signal requires language-specific review",
    "rust_unsafe_block": "Rust unsafe block requires memory-safety and authority review",
    "rust_unsafe_impl": "Rust unsafe trait implementation requires invariant review",
    "rust_unwrap_expect": "Rust panic path requires attacker-input reachability review",
    "rust_input_sized_allocation": "Rust input-sized allocation requires resource-limit review",
    "rust_gas_ordering": "Rust host work before gas charge requires ordering review",
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

RESEARCH_PATTERN_MAP = {
    "delegatecall": ["pattern.lifecycle-reachability-destruction", "pattern.unbounded-privileged-input"],
    "selfdestruct": ["pattern.lifecycle-reachability-destruction"],
    "tx_origin": ["pattern.unbounded-privileged-input"],
    "upgrade": ["pattern.lifecycle-reachability-destruction", "pattern.replay-state-reset"],
    "low_level_call": ["pattern.silent-accounting-shortfall"],
    "assembly": ["pattern.silent-accounting-shortfall"],
    "unchecked": ["pattern.silent-accounting-shortfall"],
    "ecrecover": ["pattern.replay-state-reset"],
    "create2": ["pattern.lifecycle-reachability-destruction", "pattern.replay-state-reset"],
    "timestamp": ["pattern.replay-state-reset"],
    "block_number": ["pattern.replay-state-reset"],
    "fallback": ["pattern.lifecycle-reachability-destruction"],
    "receive": ["pattern.lifecycle-reachability-destruction"],
    "unsafe": ["pattern.unbounded-privileged-input"],
    "rust_unsafe_block": ["pattern.unbounded-privileged-input"],
    "rust_unsafe_impl": ["pattern.unbounded-privileged-input"],
    "rust_unwrap_expect": ["pattern.unbounded-privileged-input"],
    "rust_input_sized_allocation": ["pattern.unbounded-privileged-input"],
    "rust_gas_ordering": ["pattern.silent-accounting-shortfall"],
    "invoke_signed": ["pattern.unbounded-privileged-input"],
    "raw_call": ["pattern.unbounded-privileged-input"],
    "sysvar": ["pattern.replay-state-reset"],
    "account_info": ["pattern.unbounded-privileged-input"],
    "entry_point": ["pattern.unbounded-privileged-input"],
    "contract_call": ["pattern.silent-accounting-shortfall"],
    "as_contract": ["pattern.unbounded-privileged-input"],
    "tx_sender": ["pattern.unbounded-privileged-input"],
    "gtxn": ["pattern.replay-state-reset"],
    "itxn": ["pattern.silent-accounting-shortfall"],
    "ensure_signed": ["pattern.unbounded-privileged-input"],
    "get_caller_address": ["pattern.unbounded-privileged-input"],
    "storage_write": ["pattern.silent-accounting-shortfall"],
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
    available = {str(item.get("id")) for item in _load_patterns(root) if item.get("id")}
    mapped = RESEARCH_PATTERN_MAP.get(signal, [])
    return [pattern_id for pattern_id in mapped if pattern_id in available]

def _unit_for_line(units: list[dict[str, Any]], line: int, file_rel: str) -> str | None:
    candidates = [u for u in units if u.get("file") == file_rel and int(u.get("line", 0)) <= line]
    if not candidates:
        return None
    return max(candidates, key=lambda x: int(x.get("line", 0))).get("name")

def _static_priority(signal: str) -> str:
    """Static/heuristic rules are review leads until evidence gates are satisfied."""
    priority = PRIORITY.get(signal, "low")
    return "medium" if priority in {"critical", "high"} else priority


SEMANTIC_PRIORITY = {
    "consensus_invariant_gap": "high",
    "panic_on_input": "medium",
    "input_sized_resource": "medium",
    "unchecked_input_arithmetic": "medium",
    "uncapped_deserialization": "medium",
    "gas_ordering": "medium",
}


def _semantic_priority(signal: str, scope: str) -> str:
    hint = SEMANTIC_PRIORITY.get(signal, "low")
    if scope != "production" and hint in {"high", "medium"}:
        return "low"
    return "medium" if hint == "high" else hint


def _triage_score(item: dict[str, Any]) -> int:
    score = int(item.get("triage_score") or 0)
    if score:
        return max(0, min(100, score))
    confidence = str(item.get("confidence") or "").lower()
    reachability = str(item.get("reachability") or "").lower()
    scope = str(item.get("scope") or "").lower()
    signal = str(item.get("signal") or "")
    evidence_type = str(item.get("evidence_type") or "")
    score += {"high": 24, "medium": 14, "low": 6}.get(confidence, 0)
    score += {
        "entry-point-direct": 38,
        "consensus-validation": 38,
        "boundary-only": 14,
        "internal-taint": 4,
    }.get(reachability, 0)
    score += 15 if scope == "production" else 4
    score += {
        "consensus_invariant_gap": 8,
        "gas_ordering": 7,
        "uncapped_deserialization": 6,
        "input_sized_resource": 5,
        "unchecked_input_arithmetic": 5,
        "panic_on_input": 3,
    }.get(signal, 0)
    score += 2 if evidence_type.startswith("taint-and-control-flow") else 0
    score += 2 if item.get("taint") else 0
    score += 2 if item.get("entry_point_reason") == "boundary-function-or-boundary-path" else 0
    score -= min(8, 4 * len(item.get("guards") or []))
    return max(0, min(100, score))


def _snippet(root_target: Path, rel: str, line: int) -> str | None:
    try:
        path = root_target / rel if root_target.is_dir() else root_target.parent / rel
        lines = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()
        if 1 <= line <= len(lines):
            return lines[line - 1].lstrip("﻿").strip()[:320]
    except Exception:
        return None
    return None
def _assert_production_only(findings: list[dict[str, Any]]) -> None:
    """Post-condition: nothing outside production scope may reach `findings`."""
    leaked = [
        f"{x.get('file')}:{x.get('line')}" for x in findings
        if x.get("scope") != "production" or not _production_path(str(x.get("file") or ""))
    ]
    if leaked:
        raise AssertionError(f"{len(leaked)} non-production finding(s) escaped the scope filter: {leaked[:5]}")


def build_contract_audit(target: Path, research_root: Path, progress=None, cancel=None) -> dict[str, Any]:
    def mark(percent: int, label: str) -> None:
        if cancel and cancel():
            raise OperationCancelled("ATLAS operation cancelled")
        if progress:
            progress(percent, label)
    mark(5, "Preparing audit target")
    target = target.expanduser().resolve()
    research_root = research_root.expanduser().resolve()
    mark(15, "Building contract intake")
    intake = build_intake(
        target,
        progress=lambda percent, label: mark(15 + int(percent * 0.10), label),
        cancel=cancel,
    )
    intake_path = write_intake_report(research_root, intake)
    mark(25, "Starting structural scan")

    findings: list[dict[str, Any]] = []
    controls: list[dict[str, Any]] = []
    with _prepared_target(target, cancel=cancel) as (scan_root, _archive_format):
        root_for_snippet = scan_root
        files = intake.get("files", []) or []
        rust_roots, rust_meta = _rust_scope(scan_root)
        rust_workspace_roots = [Path(p) for p in rust_meta.get("workspace_package_roots", []) if p]
        total_files = max(1, len(files))
        for file_index, file_info in enumerate(files, 1):
            if cancel and cancel():
                raise OperationCancelled("ATLAS operation cancelled")
            rel_preview = str(file_info.get("path", ""))
            mark(25 + int(65 * file_index / total_files), f"Scanning {rel_preview}")
            rel = str(file_info.get("path", ""))
            is_rust = Path(rel).suffix.lower() == ".rs"
            if is_rust:
                production = _production_path(rel)
                if production and not _rust_in_scope(scan_root / rel, rust_roots):
                    continue
                if not production and rust_workspace_roots and not _rust_in_scope(scan_root / rel, rust_workspace_roots):
                    continue
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
                # The semantic Rust pass supersedes broad unwrap/allocation matches in
                # production code. Keep the raw signals in engine evidence, but avoid
                # double-counting them as primary audit findings.
                if is_rust and production and sid in {"rust_unwrap_expect", "rust_input_sized_allocation"}:
                    continue
                unit = _unit_for_line(
                    intake.get("source_units") or intake.get("contracts") or [],
                    lines[0],
                    rel,
                ) if lines else None
                for line in lines[:50]:
                    scope = "production" if _production_path(rel) else "supporting"
                    findings.append({
                        "id": f"atlas-review-{len(findings)+1:04d}",
                        "priority": _static_priority(sid) if scope == "production" else "low",
                        "severity_hint": PRIORITY[sid],
                        "status": "review-required" if scope == "production" else "supporting-evidence",
                        "evidence_type": "static-structural-signal",
                        "signal": sid,
                        "title": TITLES[sid],
                        "file": rel,
                        "line": line,
                        "scope": scope,
                        "contract_or_unit": unit,
                        "snippet": _snippet(root_for_snippet, rel, line),
                        "related_research_patterns": _find_related_patterns(research_root, sid),
                        "triage_score": 20 if scope == "production" else 5,
                        "limitation": (
                            "Static/heuristic review lead only. A high/critical severity hint "
                            "is not asserted until security-property, reproduction, impact, and "
                            "independent-verification gates are evidenced. Supporting-scope code "
                            "is retained as evidence but is not treated as production attack surface."
                        ),
                    })

    # The semantic engine runs after the intake pass so its richer taint/control-flow
    # evidence can be merged into the user-visible audit findings instead of being hidden
    # only inside engine_scan.
    engine_scan = run_security_scan(target, progress=mark, cancel=cancel)
    semantic_findings = []
    for item in engine_scan.get("engine_findings", []) or []:
        if item.get("engine") != "atlas-semantic-rust":
            continue
        signal = str(item.get("signal") or "")
        scope = str(item.get("scope") or "supporting")
        triage = _triage_score(item)
        semantic_findings.append({
            "id": f"atlas-review-semantic-{len(semantic_findings)+1:04d}",
            "priority": _semantic_priority(signal, scope),
            "severity_hint": SEMANTIC_PRIORITY.get(signal, "medium"),
            "status": "review-required" if scope == "production" else "supporting-evidence",
            "evidence_type": item.get("evidence_type", "taint-and-control-flow-analysis"),
            "signal": signal,
            "title": item.get("analysis") or f"Semantic Rust finding: {signal}",
            "file": item.get("file"),
            "line": item.get("line"),
            "scope": scope,
            "contract_or_unit": _unit_for_line(
                intake.get("source_units") or intake.get("contracts") or [],
                int(item.get("line", 0) or 0),
                str(item.get("file") or ""),
            ),
            "snippet": _snippet(
                scan_root if "scan_root" in locals() else target,
                str(item.get("file") or ""),
                int(item.get("line", 0) or 0),
            ) or item.get("matched_text"),
            "confidence": item.get("confidence"),
            "reachability": item.get("reachability"),
            "taint": item.get("taint", []),
            "guards": item.get("guards", []),
            "entry_point": item.get("entry_point", False),
            "entry_point_reason": item.get("entry_point_reason"),
            "triage_score": triage,
            "source_hash": intake["target"]["source_hash"],
            "analysis": item.get("analysis"),
            "limitation": (
                "Semantic analysis narrows reachability and evidence but does not prove exploitability. "
                "Promotion still requires a stated security property, local reproduction, measured impact, "
                "and independent verification."
            ),
        })
    findings.extend(semantic_findings)

    # Deduplicate the same file/line/signal emitted by overlapping static passes.
    deduped = {}
    for item in findings:
        key = (item.get("file"), item.get("line"), item.get("signal"), item.get("scope"))
        existing = deduped.get(key)
        if existing is None or _triage_score(item) > _triage_score(existing):
            deduped[key] = item
    findings = list(deduped.values())

    # Scope contract: only production-scope findings may appear in `findings` or be counted
    # in finding_count. Tests, benchmarks and tooling stay available as separate evidence.
    def _is_production(item: dict[str, Any]) -> bool:
        return item.get("scope") == "production" and _production_path(str(item.get("file") or ""))

    supporting_evidence = [
        {
            "id": f"atlas-support-{i:04d}",
            "file": x.get("file"),
            "line": x.get("line"),
            "signal": x.get("signal"),
            "scope": "supporting",
            "priority": x.get("priority", "low"),
            "severity_hint": x.get("severity_hint"),
            "status": "supporting-evidence",
            "evidence_type": x.get("evidence_type"),
            "title": x.get("title"),
            "matched_text": x.get("matched_text"),
            "snippet": x.get("snippet"),
            "confidence": x.get("confidence"),
            "reachability": x.get("reachability"),
            "taint": x.get("taint", []),
            "guards": x.get("guards", []),
            "entry_point": x.get("entry_point", False),
            "entry_point_reason": x.get("entry_point_reason"),
            "triage_score": x.get("triage_score"),
            "analysis": x.get("analysis"),
            "related_research_patterns": x.get("related_research_patterns", []),
            "limitation": x.get("limitation"),
        }
        for i, x in enumerate([y for y in findings if not _is_production(y)], 1)
    ]
    findings = [y for y in findings if _is_production(y)]
    _assert_production_only(findings)

    # Triage order is intentionally evidence-driven rather than "all medium": direct taint,
    # consensus-boundary reachability, missing guards, and production scope move candidates up.
    for item in findings:
        item["triage_score"] = _triage_score(item)
    findings.sort(key=lambda x: (-int(x.get("triage_score", 0)), x.get("file") or "", int(x.get("line", 0) or 0), x.get("signal") or ""))
    for i, item in enumerate(findings, 1):
        item["id"] = f"atlas-review-{i:04d}"
        item["source_hash"] = intake["target"]["source_hash"]
        item["target_input_sha256"] = intake["target"].get("input_sha256")
        findings[i - 1] = attach_gate(item)

    status_counts: dict[str, int] = {}
    evidence_grade_counts: dict[str, int] = {}
    for item in findings:
        status = str(item.get("status") or "candidate")
        grade = str((item.get("verification") or {}).get("evidence_grade") or "E")
        status_counts[status] = status_counts.get(status, 0) + 1
        evidence_grade_counts[grade] = evidence_grade_counts.get(grade, 0) + 1

    report = {
        "schema_version": 1,
        "finding_policy": {
            "static_priority_cap": "medium",
            "promotion_requires": [
                "security_property",
                "reproduction",
                "impact",
                "independent_verification",
            ],
        },
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
            "status_counts": status_counts,
            "evidence_grade_counts": evidence_grade_counts,
            "verification_ready_count": sum(
                bool(
                    (x.get("verification") or {}).get("gates", {}).get("source_pinned")
                    and (
                        (x.get("verification") or {}).get("gates", {}).get("security_property")
                        or x.get("security_property")
                    )
                )
                for x in findings
            ),
            "critical": sum(x["priority"] == "critical" for x in findings),
            "high": sum(x["priority"] == "high" for x in findings),
            "medium": sum(x["priority"] == "medium" for x in findings),
            "low": sum(x["priority"] == "low" for x in findings),
            "control_observation_count": len(controls),
            "file_count": intake["summary"].get("file_count", intake["summary"]["source_file_count"]),
            "source_file_count": intake["summary"]["source_file_count"],
            "contract_count": intake["summary"]["contract_count"],
            "function_count": intake["summary"]["function_count"],
            "production_finding_count": sum(x.get("scope") == "production" for x in findings),
            "supporting_finding_count": len(supporting_evidence),
            "supporting_semantic_finding_count": sum(
                str(x.get("evidence_type", "")).startswith("taint-and-control-flow")
                for x in supporting_evidence
            ),
            "supporting_high_confidence_count": sum(
                x.get("confidence") == "high" for x in supporting_evidence
            ),
            "semantic_finding_count": sum(str(x.get("evidence_type", "")).startswith("taint-and-control-flow") for x in findings),
            "high_confidence_count": sum(x.get("confidence") == "high" for x in findings),
            "direct_taint_count": sum(x.get("reachability") == "entry-point-direct" for x in findings),
            "entry_point_count": sum(bool(x.get("entry_point")) for x in findings),
        },
        "controls_observed": controls,
        "findings": findings,
        "supporting_evidence": supporting_evidence,
        "verification": gate_summary(findings),
        "intake": intake,
        "engine_scan": engine_scan,
    }
    report["summary"]["engine_finding_count"] = int(engine_scan.get("engine_finding_count", 0))

    mark(99, "Audit findings ready")
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
