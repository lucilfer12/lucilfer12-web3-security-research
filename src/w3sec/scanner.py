from __future__ import annotations

import json
import shutil
import time
from pathlib import Path
from typing import Any

from .intake import SOURCE_EXTENSIONS, SIGNAL_PATTERNS, _files, _prepared_target
from .runtime import run_bounded

SCANNER_VERSION = "1.0"

_EXTERNAL = {
    "slither": {
        "command": lambda root: ["slither", ".", "--json", "-"],
        "timeout": 180,
        "scope": "solidity-project",
    },
    "forge": {
        "command": lambda root: ["forge", "build", "--offline"],
        "timeout": 180,
        "scope": "foundry-project",
    },
}


def _mark(progress, percent: int, label: str) -> None:
    if progress:
        progress(percent, label)


def _run_tool(name: str, spec: dict[str, Any], root: Path) -> dict[str, Any]:
    executable = name
    path = shutil.which(executable)
    if not path:
        return {
            "engine": name,
            "available": False,
            "executed": False,
            "status": "unavailable",
            "executable": None,
        }

    started = time.perf_counter()
    result = run_bounded(
        spec["command"](root),
        cwd=root,
        timeout=float(spec["timeout"]),
        max_output_bytes=2_000_000,
    )
    elapsed = round(time.perf_counter() - started, 3)
    return {
        "engine": name,
        "available": True,
        "executed": True,
        "status": (
            "timeout" if result.timed_out
            else "output_limited" if result.output_limited
            else "passed" if result.returncode == 0
            else "failed"
        ),
        "returncode": result.returncode,
        "duration_seconds": elapsed,
        "command": list(result.command),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def _normalize_slither(result: dict[str, Any]) -> list[dict[str, Any]]:
    raw = result.get("stdout") or ""
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return []

    detectors = (((payload or {}).get("results") or {}).get("detectors") or [])
    findings: list[dict[str, Any]] = []
    for index, item in enumerate(detectors, 1):
        if not isinstance(item, dict):
            continue
        findings.append({
            "id": f"slither-{index:04d}",
            "engine": "slither",
            "check": item.get("check"),
            "impact": item.get("impact"),
            "confidence": item.get("confidence"),
            "description": item.get("description"),
            "elements": item.get("elements", []),
        })
    return findings


def _atlas_rule_findings(root: Path, progress=None, focus: Path | None = None) -> list[dict[str, Any]]:
    pool = [focus] if focus is not None else _files(root)
    files = [path for path in pool if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS]
    findings: list[dict[str, Any]] = []
    total = max(1, len(files))
    for index, path in enumerate(files, 1):
        _mark(progress, 92 + int(index / total), f"ATLAS rules · {path.name}")
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            findings.append({
                "id": f"atlas-rule-read-error-{index:04d}",
                "engine": "atlas-rules",
                "rule_id": "atlas.file.read-error",
                "file": str(path.relative_to(root)).replace("\\", "/"),
                "status": "error",
                "error": repr(exc),
            })
            continue
        relative = str(path.relative_to(root)).replace("\\", "/")
        for signal_id, pattern in SIGNAL_PATTERNS.items():
            for match_index, match in enumerate(
                __import__("re").finditer(pattern, source, flags=__import__("re").MULTILINE),
                1,
            ):
                findings.append({
                    "id": f"atlas-rule-{len(findings)+1:06d}",
                    "engine": "atlas-rules",
                    "rule_id": f"atlas.signal.{signal_id}",
                    "signal": signal_id,
                    "file": relative,
                    "line": source.count("\n", 0, match.start()) + 1,
                    "matched_text": match.group(0)[:160],
                    "evidence_type": "deterministic-source-rule",
                    "status": "review-required",
                })
    return findings



def _structural_snapshot(root: Path, focus: Path | None = None) -> dict[str, Any]:
    files = [focus] if focus is not None else _files(root)
    source = []
    total_lines = 0
    total_bytes = 0
    for path in files:
        total_bytes += path.stat().st_size
        if path.suffix.lower() in {".sol", ".vy", ".move", ".rs", ".cairo", ".sway", ".fe", ".huff", ".clar", ".scilla", ".func", ".fc", ".tact", ".teal", ".tz", ".michelson", ".wat", ".asm", ".js", ".ts", ".go"}:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            source.append({
                "path": str(path.relative_to(root)).replace("\\", "/"),
                "bytes": path.stat().st_size,
                "lines": len(text.splitlines()),
            })
            total_lines += len(text.splitlines())
    return {
        "file_count": len(files),
        "source_file_count": len(source),
        "source_lines": total_lines,
        "total_bytes": total_bytes,
        "files": source,
    }


def run_security_scan(target: Path, progress=None) -> dict[str, Any]:
    target = target.expanduser().resolve()
    _mark(progress, 91, "Opening scan workspace")
    with _prepared_target(
        target,
        progress=lambda p, label: _mark(progress, 91 + min(1, int(p / 10)), label),
    ) as (prepared_root, archive_format):
        focus = prepared_root if prepared_root.is_file() else None
        root = prepared_root.parent if prepared_root.is_file() else prepared_root
        snapshot = _structural_snapshot(root, focus=focus)
        _mark(progress, 92, f"Structural pass · {snapshot['source_file_count']} source files")
        normalized = _atlas_rule_findings(root, progress, focus=focus)

        has_solidity = any(x["path"].lower().endswith(".sol") for x in snapshot["files"])
        has_foundry = (root / "foundry.toml").is_file()
        engines: list[dict[str, Any]] = [{
            "engine": "atlas-structural",
            "available": True,
            "executed": True,
            "status": "passed",
            "version": SCANNER_VERSION,
            "metrics": {
                "files": snapshot["file_count"],
                "source_files": snapshot["source_file_count"],
                "source_lines": snapshot["source_lines"],
                "bytes": snapshot["total_bytes"],
            },
        }]
        external_findings: list[dict[str, Any]] = []

        candidates = []
        if has_solidity:
            candidates.append("slither")
        if has_foundry:
            candidates.append("forge")

        for index, name in enumerate(candidates):
            _mark(progress, 93 + min(5, index + 0), f"Security engine · {name}")
            result = _run_tool(name, _EXTERNAL[name], root)
            if name == "slither":
                external_findings.extend(_normalize_slither(result))
            engines.append(result)

        _mark(progress, 98, "Finalizing engine evidence")
        return {
            "schema_version": 1,
            "scanner_version": SCANNER_VERSION,
            "target": str(target),
            "archive_format": archive_format,
            "structural": snapshot,
            "engines": engines,
            "engine_findings": normalized + external_findings,
            "engine_finding_count": len(normalized) + len(external_findings),
            "evidence_policy": (
                "External engine output is recorded as engine evidence; "
                "static signals are not promoted to validated vulnerabilities."
            ),
        }
