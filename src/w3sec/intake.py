from __future__ import annotations
import hashlib
import json
import os
import re
import subprocess
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

INTAKE_VERSION = "1.1.0"
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "cache", "out", "artifacts", "broadcast", "dist", "build",
}
SOURCE_EXTENSIONS = {".sol", ".yul", ".vy"}
CONFIG_NAMES = {
    "foundry.toml", "hardhat.config.js", "hardhat.config.ts",
    "hardhat.config.cjs", "hardhat.config.mjs", "brownie-config.yaml",
    "brownie-config.yml", "ape-config.yaml", "ape-config.yml",
    "package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json",
}
SIGNAL_PATTERNS = {
    "delegatecall": r"\bdelegatecall\b",
    "low_level_call": r"\.\s*call\s*(?:\{|\()",
    "staticcall": r"\bstaticcall\b",
    "tx_origin": r"\btx\.origin\b",
    "selfdestruct": r"\bselfdestruct\b",
    "assembly": r"\bassembly\b",
    "unchecked": r"\bunchecked\b",
    "ecrecover": r"\becrecover\s*\(",
    "create2": r"\bCREATE2\b|\bcreate2\b",
    "timestamp": r"\bblock\.timestamp\b",
    "block_number": r"\bblock\.number\b",
    "fallback": r"\bfallback\s*\(",
    "receive": r"\breceive\s*\(",
    "upgrade": r"\b(?:UUPS|TransparentUpgradeableProxy|BeaconProxy|upgradeTo|upgradeToAndCall|initializer)\b",
    "access_control": r"\b(?:onlyOwner|AccessControl|hasRole|grantRole|revokeRole)\b",
    "reentrancy_control": r"\b(?:ReentrancyGuard|nonReentrant)\b",
}
def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _safe_id(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", text).strip("-").lower() or "target"


def _git(target: Path, *args: str) -> str | None:
    root = target if target.is_dir() else target.parent
    try:
        return subprocess.run(
            ["git", "-C", str(root), *args],
            capture_output=True, text=True, timeout=5, check=True,
        ).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None


def _files(target: Path) -> list[Path]:
    if target.is_file():
        return [target] if target.suffix.lower() in SOURCE_EXTENSIONS else []
    found: list[Path] = []
    for base, dirs, names in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".cache"))
        for name in sorted(names):
            p = Path(base) / name
            if p.suffix.lower() in SOURCE_EXTENSIONS:
                found.append(p)
    return found


def _configs(target: Path) -> list[dict[str, str]]:
    root = target if target.is_dir() else target.parent
    result = []
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            if name in CONFIG_NAMES:
                p = Path(base) / name
                result.append({"path": str(p.relative_to(root)).replace("\\", "/"), "name": name})
    return result


def _tool_versions() -> dict[str, Any]:
    commands = {
        "forge": ["forge", "--version"], "solc": ["solc", "--version"],
        "slither": ["slither", "--version"], "mythril": ["myth", "version"],
        "echidna": ["echidna", "--version"],
    }
    result = {}
    for name, command in commands.items():
        path = shutil.which(command[0])
        if not path:
            result[name] = {"available": False}
            continue
        try:
            proc = subprocess.run(command, capture_output=True, text=True, timeout=4)
            output = (proc.stdout or proc.stderr).strip().splitlines()
            result[name] = {"available": proc.returncode == 0, "path": path, "version": output[0] if output else None}
        except (OSError, subprocess.SubprocessError):
            result[name] = {"available": False, "path": path}
    return result


def _matches(text: str, pattern: str) -> list[int]:
    return [m.start() for m in re.finditer(pattern, text, flags=re.MULTILINE)]


def _contract_records(path: Path, text: str) -> list[dict[str, Any]]:
    records = []
    pattern = re.compile(
        r"\b(?P<kind>abstract\s+contract|contract|interface|library)\s+"
        r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
        r"(?:\s+is\s+(?P<bases>[^\{]+))?\s*\{",
        re.MULTILINE,
    )
    for match in pattern.finditer(text):
        name = match.group("name")
        start_line = text.count("\n", 0, match.start()) + 1
        bases = [x.strip() for x in (match.group("bases") or "").split(",") if x.strip()]
        records.append({
            "id": _safe_id(f"{path.as_posix()}::{name}"),
            "name": name,
            "kind": re.sub(r"\s+", " ", match.group("kind")),
            "line": start_line,
            "bases": bases,
            "offset": match.start(),
        })
    return records


def _functions(text: str) -> list[dict[str, Any]]:
    pattern = re.compile(
        r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*"
        r"\([^)]*\)(?P<tail>[^\{;]*)",
        re.MULTILINE,
    )
    result = []
    for match in pattern.finditer(text):
        tail = re.sub(r"\s+", " ", match.group("tail") or "").strip()
        result.append({
            "name": match.group("name"),
            "line": text.count("\n", 0, match.start()) + 1,
            "offset": match.start(),
            "visibility": next((x for x in ("external", "public", "internal", "private") if re.search(rf"\b{x}\b", tail)), None),
            "modifiers": re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", re.sub(r"\b(?:returns|external|public|internal|private|view|pure|payable|virtual|override|mutating)\b[^\n]*", "", tail)),
        })
    return result


def _imports(text: str) -> list[str]:
    return sorted(set(re.findall(r'\bimport\s+(?:[^;]*?\s+from\s+)?["\']([^"\']+)["\']\s*;', text)))


def _pragmas(text: str) -> list[str]:
    return sorted(set(re.findall(r"\bpragma\s+solidity\s+([^;]+);", text)))


def _signals(text: str) -> list[dict[str, Any]]:
    result = []
    for name, pattern in SIGNAL_PATTERNS.items():
        matches = _matches(text, pattern)
        if matches:
            result.append({
                "id": name,
                "count": len(matches),
                "lines": [text.count("\n", 0, pos) + 1 for pos in matches[:50]],
            })
    return result
def build_intake(target: Path) -> dict[str, Any]:
    target = target.expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(target)
    source_files = _files(target)
    captured = datetime.now(timezone.utc).isoformat()
    relative_root = target.parent if target.is_file() else target
    files = []
    contracts = []
    aggregate = hashlib.sha256()
    for path in source_files:
        text = _text(path)
        digest = _sha256(path)
        rel = str(path.relative_to(relative_root)).replace("\\", "/")
        aggregate.update(rel.encode("utf-8"))
        aggregate.update(digest.encode("ascii"))
        funcs = _functions(text)
        local_contracts = _contract_records(path, text)
        for index, c in enumerate(local_contracts):
            start = int(c.pop("offset"))
            end = int(local_contracts[index + 1]["offset"]) if index + 1 < len(local_contracts) else len(text)
            local_funcs = [
                {k: v for k, v in f.items() if k != "offset"}
                for f in funcs if start <= int(f["offset"]) < end
            ]
            c["file"] = rel
            c["function_count"] = len(local_funcs)
            c["functions"] = local_funcs
            c["signals"] = _signals(text[start:end])
            contracts.append(c)
        files.append({
            "path": rel,
            "absolute_path": str(path),
            "sha256": digest,
            "bytes": path.stat().st_size,
            "lines": text.count("\n") + (1 if text else 0),
            "language": path.suffix.lower().lstrip("."),
            "pragma_solidity": _pragmas(text),
            "imports": _imports(text),
            "signals": _signals(text),
            "contract_count": len(local_contracts),
            "function_count": len(funcs),
        })
    target_id = _safe_id(f"{target.name}-{aggregate.hexdigest()[:12]}")
    return {
        "intake_version": INTAKE_VERSION,
        "id": target_id,
        "captured_at": captured,
        "target": {
            "kind": "file" if target.is_file() else "repository",
            "path": str(target),
            "name": target.name,
            "source_hash": aggregate.hexdigest(),
        },
        "git": {
            "commit": _git(target, "rev-parse", "HEAD"),
            "branch": _git(target, "branch", "--show-current"),
            "remote": _git(target, "config", "--get", "remote.origin.url"),
            "dirty": _git(target, "status", "--porcelain") not in (None, ""),
        },
        "toolchain": {"project_files": _configs(target), "local_tools": _tool_versions()},
        "summary": {
            "source_file_count": len(files),
            "contract_count": len(contracts),
            "function_count": sum(int(f.get("function_count", 0)) for f in files),
            "total_bytes": sum(int(f["bytes"]) for f in files),
            "security_signal_kinds": sorted({s["id"] for f in files for s in f["signals"]}),
        },
        "files": files,
        "contracts": contracts,
    }


def write_intake_report(root: Path, report: dict[str, Any]) -> Path:
    out = root / "reports" / "intake"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f'{report["id"]}.json'
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    from .ledger import append_event, iter_events
    from .model import NodeRef
    ledger_path = root / "ledger" / "events.jsonl"
    registered = False
    if ledger_path.exists():
        registered = any(
            event.get("event_type") == "intake-registered"
            and event.get("subject", {}).get("id") == report["id"]
            for event in iter_events(ledger_path)
        )
    if not registered:
        append_event(
            root / "ledger" / "events.jsonl",
            event_type="intake-registered", subject=NodeRef("intake", str(report["id"])),
            timestamp=str(report["captured_at"]), actor="w3sec-intake",
            payload={"target_kind": report["target"]["kind"], "source_hash": report["target"]["source_hash"],
                     "source_file_count": report["summary"]["source_file_count"], "contract_count": report["summary"]["contract_count"]},
        )
    return path


def list_intakes(root: Path) -> list[dict[str, Any]]:
    out = root / "reports" / "intake"
    reports = []
    if not out.exists():
        return reports
    for path in sorted(out.glob("*.json")):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(value, dict) and value.get("id"):
            reports.append(value)
    return reports
