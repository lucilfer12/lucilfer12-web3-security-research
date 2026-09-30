from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .engine_orchestrator import EngineOrchestrator
from .intake import OperationCancelled, SOURCE_EXTENSIONS, _files, _mask_non_code, _prepared_target, _signals
from .rust_analysis import (
    RustIndex,
    analyse_gas,
    cast_report,
    function_regions,
    length_upper_bound_proofs,
    line_depths,
    local_types,
    size_bound_proofs,
    upper_bound_proofs,
)

SCANNER_VERSION = "1.0.7"

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


def _run_tool(name: str, spec: dict[str, Any], root: Path, cancel=None) -> dict[str, Any]:
    if cancel and cancel():
        raise OperationCancelled("ATLAS operation cancelled")
    return EngineOrchestrator().run_legacy(name, spec, root, cancel=cancel)


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


RUST_EXCLUDED_PARTS = {
    "test", "tests", "fuzz", "fuzzers", "bench", "benches", "estimator",
    "examples", "example", "integration-tests", "tools",
}


def _production_path(relative: str) -> bool:
    parts = [part.lower() for part in Path(relative).parts]
    if any(
        part in RUST_EXCLUDED_PARTS
        or part.startswith("bench")
        or part in {"test-loop-tests", "near-test-contracts"}
        for part in parts[:-1]
    ):
        return False
    name = parts[-1] if parts else ""
    return not (
        name.startswith("test_")
        or name.endswith(("_test.rs", "_tests.rs"))
        or name in {"test.rs", "tests.rs", "testonly.rs", "build.rs"}
    )


def _rust_scope(root: Path) -> tuple[list[Path], dict[str, Any]]:
    cargo_toml = root / "Cargo.toml"
    cargo = shutil.which("cargo")
    if not cargo_toml.is_file() or not cargo:
        return [], {"method": "fallback-path-filter", "reason": "cargo-metadata-unavailable"}
    try:
        proc = subprocess.run(
            [cargo, "metadata", "--no-deps", "--format-version", "1"],
            cwd=root, capture_output=True, text=True, timeout=25, check=False,
        )
        if proc.returncode != 0:
            return [], {"method": "fallback-path-filter", "reason": "cargo-metadata-failed"}
        payload = json.loads(proc.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return [], {"method": "fallback-path-filter", "reason": "cargo-metadata-error"}

    packages = payload.get("packages") or []
    by_name = {str(p.get("name")): p for p in packages if p.get("name")}
    workspace_names = {
        str(p.get("name")) for p in packages if p.get("source") is None and p.get("name")
    }
    neard_packages = {
        str(p.get("name"))
        for p in packages
        if any(
            str(t.get("name")) == "neard" and "bin" in (t.get("kind") or [])
            for t in p.get("targets") or []
        )
    }
    reachable = set(neard_packages)
    changed = True
    while changed:
        changed = False
        for name in list(reachable):
            for dep in by_name.get(name, {}).get("dependencies") or []:
                dep_name = str(dep.get("name"))
                if dep_name in workspace_names and dep_name not in reachable:
                    reachable.add(dep_name)
                    changed = True

    reachable_manifests = []
    workspace_manifests = []
    for name in sorted(workspace_names):
        package = by_name.get(name)
        if not package or package.get("source") is not None or not package.get("manifest_path"):
            continue
        manifest_root = Path(str(package["manifest_path"])).parent.resolve()
        workspace_manifests.append(manifest_root)
        if name in reachable:
            reachable_manifests.append(manifest_root)
    return reachable_manifests, {
        "method": "cargo-metadata",
        "root_packages": sorted(neard_packages),
        "reachable_workspace_packages": sorted(reachable),
        "workspace_package_roots": [str(p) for p in workspace_manifests],
    }


def _rust_in_scope(path: Path, roots: list[Path]) -> bool:
    if not roots:
        return True
    resolved = path.resolve()
    return any(resolved.is_relative_to(root) for root in roots)


RUST_BOUNDARY_PATH_PARTS = {
    "runtime", "rpc", "network", "host", "transaction", "transactions", "receipt",
    "state_sync", "chunk", "chunks", "protocol", "vm", "chain", "client",
    "validator", "epoch_manager", "storage", "adversarial", "peer_manager",
}
RUST_BOUNDARY_NAME_RE = re.compile(
    r"(?:handle|process|dispatch|execute|validate|apply|submit|query|decode|deserialize|"
    r"parse|receive|accept|route|serve|commit|import|export|sync|load|store|call|run)",
    re.IGNORECASE,
)
RUST_INPUT_TOKEN_RE = re.compile(
    r"\b(?:request|message|payload|input|bytes|raw|transaction|receipt|action|block|chunk|"
    r"shard|account|gas|balance|signer|signature|query|params|args|data)\b",
    re.IGNORECASE,
)




RUST_TAINT_PARAM_TYPES = re.compile(
    r"(?:&\s*(?:mut\s*)?)?\[u8\]|String|Vec\s*<|Request|Message|Payload|Transaction|Receipt|"
    r"Block|Chunk|AccountId|Balance|Gas|Signature|CryptoHash|u(?:8|16|32|64|128)|usize",
    re.IGNORECASE,
)
RUST_RAW_PARAM_TYPES = re.compile(
    r"(?:&\s*(?:mut\s*)?)?\[u8\]|String|Vec\s*<|Request|Message|Payload",
    re.IGNORECASE,
)
RUST_STRUCTURED_INPUT_TYPES = re.compile(
    r"Transaction|Receipt|Block|Chunk|AccountId|Balance|Gas|Signature|CryptoHash",
    re.IGNORECASE,
)
RUST_INPUT_NAME_HINTS = re.compile(
    r"\b(?:input|request|message|payload|raw|bytes|data|tx|transaction|receipt|action|block|chunk|"
    r"account|gas|balance|signature|params|args|peer|header|query|proof|part|parts|len|length|"
    r"count|index|idx|offset|limit|ptr|size)\b",
    re.IGNORECASE,
)
RUST_DIRECT_INPUT_NAMES = re.compile(
    r"\b(?:input|request|message|payload|raw|bytes|data|tx|transaction|receipt|action|peer|query|params|args|proof)\b",
    re.IGNORECASE,
)
RUST_BOUNDARY_SCALAR_NAMES = re.compile(
    r"\b(?:len|length|count|index|idx|offset|limit|ptr|size|value|amount|gas|balance)\b",
    re.IGNORECASE,
)
RUST_TAINT_TOKENS = re.compile(
    r"\b(?:input|request|message|payload|raw|bytes|data|tx|transaction|receipt|action|block|chunk|"
    r"account|gas|balance|signature|params|args|peer|header|query|proof|part|parts)\b",
    re.IGNORECASE,
)
RUST_BOUNDARY_FN = re.compile(
    r"\b(?:handle|process|dispatch|execute|validate|apply|submit|query|decode|deserialize|"
    r"parse|receive|accept|route|serve|commit|import|export|sync|load|store|call|run|verify)\b",
    re.IGNORECASE,
)
RUST_VALIDATION_FN = re.compile(
    r"\b(?:validate_header|validate_block(?:_impl)?|validate_transaction|validate_receipt|"
    r"process_block|process_transactions|apply_block|verify_block)\b"
)


def _rust_scope_label(relative: str) -> str:
    return "production" if _production_path(relative) else "supporting"


def _rust_function_regions(source: str) -> list[dict[str, Any]]:
    masked = _mask_non_code(source)
    starts = list(re.finditer(
        r"\b(?:pub(?:\s*\([^)]*\))?\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"\((?P<params>[^)]*)\)",
        masked,
        flags=re.MULTILINE,
    ))
    regions: list[dict[str, Any]] = []
    for index, match in enumerate(starts):
        body_start = masked.find("{", match.end())
        if body_start < 0:
            continue
        depth = 0
        end = len(masked)
        for pos in range(body_start, len(masked)):
            char = masked[pos]
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    end = pos + 1
                    break
        params = match.group("params")
        line = masked.count("\n", 0, match.start()) + 1
        regions.append({
            "name": match.group("name"),
            "params": params,
            "line": line,
            "start": match.start(),
            "body_start": body_start,
            "end": end,
            "body": masked[body_start:end],
        })
    return regions


def _rust_taint_context(region: dict[str, Any], boundary: bool = False) -> dict[str, Any]:
    params = str(region.get("params") or "")
    tainted: set[str] = set()
    for param in re.finditer(
        r"\b([A-Za-z_][A-Za-z0-9_]*)\s*:\s*([^,]+)",
        params,
        flags=re.MULTILINE,
    ):
        name, annotation = param.group(1), param.group(2)
        raw = bool(RUST_RAW_PARAM_TYPES.search(annotation))
        structured = bool(RUST_STRUCTURED_INPUT_TYPES.search(annotation))
        direct_named = bool(RUST_DIRECT_INPUT_NAMES.search(name))
        boundary_scalar = bool(RUST_BOUNDARY_SCALAR_NAMES.search(name))
        scalar = bool(re.search(r"\b(?:u8|u16|u32|u64|u128|usize|isize)\b", annotation))
        if raw or direct_named or (boundary and structured) or (boundary and scalar and boundary_scalar):
            tainted.add(name)

    body = str(region.get("body") or "")
    lines = body.splitlines()
    for _ in range(4):
        changed = False
        for line in lines:
            assignment = re.search(
                r"(?:let\s+(?:mut\s+)?)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^;]+)",
                line,
            )
            if not assignment:
                continue
            lhs, rhs = assignment.group(1), assignment.group(2)
            if lhs in tainted:
                continue
            if any(re.search(rf"\b{re.escape(name)}\b", rhs) for name in tainted):
                tainted.add(lhs)
                changed = True
        if not changed:
            break

    return {
        "tainted_variables": sorted(tainted),
        "direct_input_parameter": bool(tainted),
        "boundary_function": bool(boundary),
        "validation_function": bool(RUST_VALIDATION_FN.search(str(region.get("name") or ""))),
    }


def _rust_line_has_taint(line: str, taint: set[str]) -> bool:
    if not taint:
        return False
    return any(re.search(rf"\b{re.escape(name)}\b", line) for name in taint)


def _rust_semantic_findings(relative: str, source: str, scope: str) -> list[dict[str, Any]]:
    if not relative.lower().endswith(".rs"):
        return []
    regions = _rust_function_regions(source)
    gas_index = RustIndex()
    gas_index.add_file(relative, function_regions(_mask_non_code(source)))
    gas_index.finalize()
    findings: list[dict[str, Any]] = []
    for region in regions:
        body = str(region["body"])
        body_lines = body.splitlines()
        base_line = int(region["line"])
        path_parts = set(relative.lower().replace("\\", "/").split("/"))
        boundary = bool(RUST_BOUNDARY_FN.search(str(region.get("name") or ""))) or bool(
            path_parts.intersection({
                "near-vm-runner", "logic", "network", "jsonrpc", "rpc", "state_sync",
                "chunk", "chunks", "receipt", "transaction", "transactions", "peer_manager",
            })
        )
        context = _rust_taint_context(region, boundary=boundary)
        taint = set(context["tainted_variables"])
        depths = line_depths(body_lines)
        local_int_types = local_types(str(region.get("params") or ""), body)

        def add(signal: str, line_offset: int, evidence: dict[str, Any], title: str) -> None:
            findings.append({
                "id": f"atlas-semantic-{len(findings)+1:06d}",
                "engine": "atlas-semantic-rust",
                "rule_id": f"atlas.rust.{signal}",
                "signal": signal,
                "file": relative,
                "line": base_line + max(0, line_offset),
                "matched_text": evidence.get("matched_text", "")[:320],
                "evidence_type": "taint-and-control-flow-analysis",
                "scope": scope,
                "language": "rust",
                "status": "review-required",
                "confidence": evidence.get("confidence", "medium"),
                "reachability": evidence.get("reachability", "unknown"),
                "taint": evidence.get("taint", sorted(taint)),
                "guards": evidence.get("guards", []),
                "entry_point": bool(boundary),
                "entry_point_reason": (
                    "boundary-function-or-boundary-path" if boundary else "internal-function"
                ),
                "analysis": title,
            })

        # Panic-on-input: unwrap/expect/unreachable plus indexing/slicing tied to tainted
        # values or a boundary function. Constant unwraps and lock unwraps are not tainted.
        for idx, line in enumerate(body_lines):
            panic = re.search(
                r"\b(?:unwrap|expect)\s*\(|\bunreachable!\s*\(|"
                r"\[[^\]\n]*\b(?:len|count|index|ord|idx)\b[^\]\n]*\]",
                line,
                flags=re.IGNORECASE,
            )
            if not panic:
                continue
            panic_prefix = line[:panic.start()]
            direct = _rust_line_has_taint(panic_prefix, taint)
            # Boundary function names alone are not enough: constant/lock unwraps are
            # common and should not be treated as attacker-controlled panic paths.
            if direct:
                guards = []
                window = "\n".join(body_lines[max(0, idx - 8):idx + 1])
                for guard in ("checked_", "ok_or", "get(", "len()", "is_empty", "contains", "limit", "MAX_"):
                    if guard in window:
                        guards.append(guard)
                add(
                    "panic_on_input",
                    idx,
                    {
                        "matched_text": line.strip(),
                        "confidence": "high" if direct and boundary and not guards else "medium",
                        "reachability": ("entry-point-direct" if boundary else "internal-taint") if direct else "boundary-only",
                        "guards": guards,
                    },
                    "Potential panic or unchecked indexing reachable from an input boundary.",
                )

        # Input-sized memory work: retain the signal unless a machine-checkable size
        # proof shows a constant or an explicit dominating input bound.
        for idx, line in enumerate(body_lines):
            if not re.search(r"\b(?:Vec::with_capacity|reserve|reserve_exact|resize|extend)\b", line):
                continue
            if not (_rust_line_has_taint(line, taint) or re.search(r"\.(?:len|capacity)\s*\(\)", line)):
                continue
            proofs = size_bound_proofs(body_lines, depths, idx, line, taint)
            if proofs:
                continue
            add(
                "input_sized_resource",
                idx,
                {
                    "matched_text": line.strip(),
                    "confidence": "high" if _rust_line_has_taint(line, taint) and boundary else "medium",
                    "reachability": ("entry-point-direct" if boundary else "internal-taint") if _rust_line_has_taint(line, taint) else ("boundary-only" if boundary else "unknown"),
                    "guards": [],
                },
                "Input-derived collection growth requires an explicit protocol/resource cap.",
            )

        # Unchecked arithmetic/casts on tainted values. Only the actual arithmetic
        # expression or narrowing cast must contain the tainted variable; unrelated arithmetic
        # elsewhere on the same line is not enough.
        for idx, line in enumerate(body_lines):
            if not taint:
                continue
            binary_matches = list(re.finditer(
                r"\b[A-Za-z_][A-Za-z0-9_]*\b\s*(?:\+|-|\*)\s*"
                r"(?:\b[A-Za-z_][A-Za-z0-9_]*\b|\d[\d_]*)",
                line,
            ))
            tainted_binary = any(
                any(re.search(rf"\b{re.escape(name)}\b", line[m.start():m.end()]) for name in taint)
                for m in binary_matches
            )
            _, unproven_casts = cast_report(line, local_int_types)
            tainted_cast = any(
                any(re.search(rf"\b{re.escape(name)}\b", item) for name in taint)
                for item in unproven_casts
            )
            if tainted_binary or tainted_cast:
                safe_ops = ("checked_add", "checked_sub", "checked_mul", "saturating_", "try_into")
                confidence = "high" if boundary and not any(op in line for op in safe_ops) else "medium"
                add(
                    "unchecked_input_arithmetic",
                    idx,
                    {
                        "matched_text": line.strip(),
                        "confidence": confidence,
                        "reachability": "entry-point-direct" if boundary else "internal-taint",
                        "guards": [op for op in safe_ops if op in line],
                    },
                    "Arithmetic or cast uses an input-tainted value without an obvious checked/saturating operation.",
                )

        # Deserialization without a nearby visible size bound. This deliberately does not
        # claim a vulnerability; upstream caps can exist in callers, so the result is a trace lead.
        for idx, line in enumerate(body_lines):
            if not re.search(r"\b(?:try_from_slice|deserialize|from_slice|decode)\b", line):
                continue
            joined = "\n".join(body_lines[max(0, idx - 10):idx + 1])
            direct = _rust_line_has_taint(line, taint) or bool(
                re.search(r"(?:input|payload|bytes|data)\b", joined, re.IGNORECASE)
            )
            if not direct:
                continue
            bounded = False
            for name in taint:
                if re.search(rf"\b{re.escape(name)}\b", joined):
                    if upper_bound_proofs(body_lines, depths, idx, name):
                        bounded = True
                        break
                    if length_upper_bound_proofs(body_lines, depths, idx, f"{name}.len()"):
                        bounded = True
                        break
            if bounded:
                continue
            guards = [g for g in ("MAX_", "limit", "truncate", "take(", "object_length", "size_limit") if g.lower() in joined.lower()]
            add(
                "uncapped_deserialization",
                idx,
                {
                    "matched_text": line.strip(),
                    "confidence": "medium" if boundary and not guards else "low",
                    "reachability": "entry-point-direct" if boundary else "internal-taint",
                    "guards": guards,
                },
                "Input reaches deserialization; verify the size/canonical-encoding guard before decoding.",
            )

        # Host gas ordering: use a same-file interprocedural charge summary so a helper
        # that always charges is treated as an effective charge at its call site.
        if "near-vm-runner" in relative.lower() and ("/logic/" in relative.lower() or "\\logic\\" in relative.lower()):
            gas = analyse_gas(body, gas_index)
            work = gas.get("work")
            if gas.get("status") == "ordering" and work is not None and taint:
                line_offset = body[:work.start()].count("\n")
                first = gas.get("first")
                charge_chain = first[3] if isinstance(first, tuple) and len(first) == 4 else []
                add(
                    "gas_ordering",
                    line_offset,
                    {
                        "matched_text": work.group(0),
                        "confidence": "high" if boundary else "medium",
                        "reachability": "entry-point-direct" if boundary else "internal-taint",
                        "gas_status": gas.get("status"),
                        "charge_chain": charge_chain,
                    },
                    "Input-dependent host work occurs before the first effective gas charge.",
                )

        # Nearcore-specific consensus invariant completeness. This is not a generic "missing
        # check" guess: it is only emitted for the block-validation seam where the historical
        # total-supply bug lived, and the rule names the expected property explicitly.
        if (
            "chain/chain/src/chain.rs" in relative.replace("\\", "/").lower()
            and context["validation_function"]
            and any(token in body for token in ("verify_gas_price", "validate_chunk_headers", "verify_challenges"))
            and not re.search(r"\b(?:total_supply|verify_total_supply|balance_burnt)\b", body)
        ):
            add(
                "consensus_invariant_gap",
                0,
                {
                    "matched_text": str(region["name"]),
                    "confidence": "high",
                    "reachability": "consensus-validation",
                    "guards": [],
                },
                "Consensus block validation seam lacks the total-supply/burned-balance invariant check used by the fixed nearcore rule.",
            )

    return findings


def _atlas_rule_findings(root: Path, progress=None, focus: Path | None = None, cancel=None) -> list[dict[str, Any]]:
    pool = [focus] if focus is not None else _files(root)
    source_candidates = [path for path in pool if path.is_file() and path.suffix.lower() in SOURCE_EXTENSIONS]
    rust_roots, rust_meta = _rust_scope(root) if any(
        path.suffix.lower() == ".rs" for path in source_candidates
    ) else ([], {"method": "not-rust"})
    files = []
    workspace_roots = [Path(p) for p in rust_meta.get("workspace_package_roots", []) if p]
    for path in source_candidates:
        relative = str(path.relative_to(root)).replace("\\", "/")
        if path.suffix.lower() == ".rs":
            is_production = _production_path(relative)
            # Production Rust is restricted to crates reachable from a neard binary.
            # Test/fuzz/bench/supporting Rust is still scanned, but remains explicitly
            # marked as supporting evidence so it can improve recall without pretending
            # that test-only code is production attack surface.
            if is_production and not _rust_in_scope(path, rust_roots):
                continue
            if not is_production and workspace_roots and not _rust_in_scope(path, workspace_roots):
                continue
        files.append(path)
    findings: list[dict[str, Any]] = []
    total = max(1, len(files))
    for index, path in enumerate(files, 1):
        if cancel and cancel():
            raise OperationCancelled("ATLAS operation cancelled")
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
        source_lines = source.splitlines()
        for signal in _signals(source, path.suffix.lower()):
            signal_id = str(signal.get("id"))
            for line in signal.get("lines", []) or []:
                line_number = int(line)
                matched = source_lines[line_number - 1].strip()[:160] if 0 < line_number <= len(source_lines) else ""
                findings.append({
                    "id": f"atlas-rule-{len(findings)+1:06d}",
                    "engine": "atlas-rules",
                    "rule_id": f"atlas.signal.{signal_id}",
                    "signal": signal_id,
                    "file": relative,
                    "line": line_number,
                    "matched_text": matched,
                    "evidence_type": "deterministic-source-rule",
                    "scope": _rust_scope_label(relative) if path.suffix.lower() == ".rs" else "source",
                    "language": path.suffix.lower().lstrip("."),
                    "status": "review-required",
                })
        if path.suffix.lower() == ".rs":
            findings.extend(_rust_semantic_findings(relative, source, _rust_scope_label(relative)))
    if rust_meta.get("method") == "cargo-metadata":
        for item in findings:
            if item.get("language") == "rust":
                item["rust_scope"] = rust_meta
    return findings



def _structural_snapshot(root: Path, focus: Path | None = None, cancel=None) -> dict[str, Any]:
    files = [focus] if focus is not None else _files(root)
    source = []
    total_lines = 0
    total_bytes = 0
    for path in files:
        if cancel and cancel():
            raise OperationCancelled("ATLAS operation cancelled")
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


def run_security_scan(target: Path, progress=None, cancel=None) -> dict[str, Any]:
    target = target.expanduser().resolve()
    if cancel and cancel():
        raise OperationCancelled("ATLAS operation cancelled")
    _mark(progress, 91, "Opening scan workspace")
    with _prepared_target(
        target,
        progress=lambda p, label: _mark(progress, 91 + min(1, int(p / 10)), label),
        cancel=cancel,
    ) as (prepared_root, archive_format):
        focus = prepared_root if prepared_root.is_file() else None
        root = prepared_root.parent if prepared_root.is_file() else prepared_root
        snapshot = _structural_snapshot(root, focus=focus, cancel=cancel)
        _mark(progress, 92, f"Structural pass · {snapshot['source_file_count']} source files")
        normalized = _atlas_rule_findings(root, progress, focus=focus, cancel=cancel)

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
            if cancel and cancel():
                raise OperationCancelled("ATLAS operation cancelled")
            _mark(progress, 93 + min(5, index + 0), f"Security engine · {name}")
            result = _run_tool(name, _EXTERNAL[name], root, cancel=cancel)
            if name == "slither":
                external_findings.extend(_normalize_slither(result))
            engines.append(result)

        if cancel and cancel():
            raise OperationCancelled("ATLAS operation cancelled")
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
