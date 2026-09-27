from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ledger import append_event, iter_events
from .model import NodeRef
from .runtime import hidden_run

INTAKE_VERSION = "2.0-dev"

SOURCE_EXTENSIONS = {
    ".sol", ".yul", ".vy", ".cairo", ".move", ".rs", ".sway", ".fe", ".huff",
    ".clar", ".clarity", ".scilla", ".func", ".fc", ".tolk", ".tact", ".tsol",
    ".teal", ".pyteal", ".tz", ".michelson", ".hs", ".rholang", ".wat", ".asm",
    ".js", ".ts", ".go",
}
ARTIFACT_EXTENSIONS = {".abi", ".bin", ".hex", ".wasm", ".json"}
SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "cache", "out", "artifacts", "broadcast", "dist", "build", ".next",
}
CONFIG_NAMES = {
    "foundry.toml", "hardhat.config.js", "hardhat.config.ts",
    "hardhat.config.cjs", "hardhat.config.mjs", "brownie-config.yaml",
    "brownie-config.yml", "ape-config.yaml", "ape-config.yml",
    "move.toml", "Scarb.toml", "Cargo.toml", "Anchor.toml", "Forc.toml",
    "package.json", "pnpm-lock.yaml", "yarn.lock", "package-lock.json",
}
LANGUAGES = {
    ".sol": "Solidity", ".yul": "Yul", ".vy": "Vyper", ".cairo": "Cairo",
    ".move": "Move", ".rs": "Rust (Solana/CosmWasm/ink!/generic)", ".sway": "Sway",
    ".fe": "Fe", ".huff": "Huff", ".clar": "Clarity", ".clarity": "Clarity",
    ".scilla": "Scilla", ".func": "FunC", ".fc": "FunC", ".tolk": "Tolk",
    ".tact": "Tact", ".tsol": "Tact/Solidity-family", ".teal": "TEAL",
    ".pyteal": "PyTeal", ".tz": "Michelson", ".michelson": "Michelson",
    ".hs": "Haskell/Plutus-family", ".rholang": "Rholang", ".wat": "WebAssembly Text",
    ".asm": "Assembly", ".js": "JavaScript/TypeScript", ".ts": "TypeScript",
    ".go": "Go / chain tooling",
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
    "create2": r"\bcreate2\b",
    "timestamp": r"\bblock\.timestamp\b",
    "block_number": r"\bblock\.number\b",
    "fallback": r"\bfallback\s*\(",
    "receive": r"\breceive\s*\(",
    "upgrade": r"\b(?:upgradeTo|upgradeToAndCall|UUPS|TransparentUpgradeableProxy|BeaconProxy|initializer)\b",
    "unsafe": r"\bunsafe\b",
    "invoke_signed": r"\binvoke_signed\b",
    "raw_call": r"\braw_call\b",
    "sysvar": r"\bsysvar\b",
}

def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _safe_id(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", text).strip("-").lower() or "target"

def _git(target: Path, *args: str) -> str | None:
    root = target if target.is_dir() else target.parent
    try:
        return hidden_run(["git", "-C", str(root), *args], cwd=None, timeout=5, check=True).stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None

def _language(path: Path) -> str:
    return LANGUAGES.get(path.suffix.lower(), path.suffix.lower().lstrip(".").upper() or "Unknown")

def _is_archive(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".7z", ".rar", ".gz"))

def _is_contract_related(path: Path) -> bool:
    # ATLAS accepts every file type. Known code/artifacts receive structural parsing;
    # unknown or binary files are retained as hashed inventory evidence.
    return path.is_file()
def _safe_extract_archive(archive: Path, destination: Path) -> str:
    destination = destination.resolve()
    lower = archive.name.lower()
    if lower.endswith(".zip"):
        with zipfile.ZipFile(archive) as zf:
            for member in zf.infolist():
                target = (destination / member.filename).resolve()
                if target != destination and destination not in target.parents:
                    raise ValueError(f"Unsafe archive member: {member.filename}")
            zf.extractall(destination)
        return "zip"
    if lower.endswith(".gz") and not lower.endswith((".tar.gz", ".tgz")):
        output = destination / archive.stem
        with gzip.open(archive, "rb") as source, output.open("wb") as target:
            shutil.copyfileobj(source, target)
        return "gzip"
    if lower.endswith((".7z", ".rar")):
        tool = shutil.which("7z") or shutil.which("7zz") or (shutil.which("unrar") if lower.endswith(".rar") else None)
        if not tool:
            return "7z-opaque" if lower.endswith(".7z") else "rar-opaque"
        result = hidden_run([tool, "x", "-y", f"-o{destination}", str(archive)], timeout=180, check=False)
        if result.returncode != 0:
            return "7z-opaque" if lower.endswith(".7z") else "rar-opaque"
        return "7z" if lower.endswith(".7z") else "rar"
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            if member.issym() or member.islnk():
                raise ValueError(f"Archive links are not accepted: {member.name}")
            target = (destination / member.name).resolve()
            if target != destination and destination not in target.parents:
                raise ValueError(f"Unsafe archive member: {member.name}")
        tf.extractall(destination)
    return "tar"

@contextmanager
def _prepared_target(target: Path):
    if target.is_file() and _is_archive(target):
        with tempfile.TemporaryDirectory(prefix="atlas-intake-") as td:
            root = Path(td)
            fmt = _safe_extract_archive(target, root)
            yield root, fmt
    else:
        yield target, None

def _files(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    found: list[Path] = []
    for base, dirs, names in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith(".cache"))
        for name in sorted(names):
            path = Path(base) / name
            if path.is_file():
                found.append(path)
    return found

def _configs(target: Path) -> list[dict[str, str]]:
    root = target if target.is_dir() else target.parent
    result = []
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for name in sorted(names):
            if name in CONFIG_NAMES:
                path = Path(base) / name
                result.append({"path": str(path.relative_to(root)).replace("\\", "/"), "name": name})
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
            proc = hidden_run(command, timeout=4, check=False)
            output = (proc.stdout or proc.stderr).strip().splitlines()
            result[name] = {"available": proc.returncode == 0, "path": path, "version": output[0] if output else None}
        except (OSError, subprocess.SubprocessError):
            result[name] = {"available": False, "path": path}
    return result

def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")

def _pragmas(text: str) -> list[str]:
    return sorted(set(re.findall(r"\bpragma\s+solidity\s+([^;]+);", text)))

def _imports(text: str) -> list[str]:
    return sorted(set(re.findall(r'\bimport\s+(?:[^;]*?\s+from\s+)?["\']([^"\']+)["\']\s*;', text)))

def _signals(text: str) -> list[dict[str, Any]]:
    result = []
    for name, pattern in SIGNAL_PATTERNS.items():
        matches = list(re.finditer(pattern, text, flags=re.MULTILINE))
        if matches:
            result.append({
                "id": name,
                "count": len(matches),
                "lines": [text.count("\n", 0, m.start()) + 1 for m in matches[:50]],
            })
    return result
def _functions(text: str, ext: str) -> list[dict[str, Any]]:
    patterns = {
        ".sol": r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)(?P<tail>[^\{;]*)",
        ".vy": r"(?m)^\s*def\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<tail>[^)]*)\)",
        ".move": r"\b(?:public\s+(?:\([^)]*\)\s+)?)?(?:entry\s+)?fun\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<tail>[^)]*)\)",
        ".rs": r"\b(?:pub\s+)?(?:async\s+)?fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<tail>[^)]*)\)",
        ".cairo": r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<tail>[^)]*)\)",
        ".sway": r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<tail>[^)]*)\)",
        ".fe": r"\bfn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<tail>[^)]*)\)",
        ".ts": r"\b(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<tail>[^)]*)\)",
        ".js": r"\b(?:export\s+)?(?:async\s+)?function\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<tail>[^)]*)\)",
    }
    pattern = re.compile(patterns.get(ext, r"(?!)"), re.MULTILINE)
    result = []
    for match in pattern.finditer(text):
        tail = re.sub(r"\s+", " ", match.groupdict().get("tail") or "").strip()
        result.append({
            "name": match.group("name"),
            "line": text.count("\n", 0, match.start()) + 1,
            "offset": match.start(),
            "visibility": next((x for x in ("external", "public", "internal", "private") if re.search(rf"\b{x}\b", tail)), None),
            "modifiers": re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", tail),
        })
    return result

def _units(path: Path, text: str) -> list[dict[str, Any]]:
    ext = path.suffix.lower()
    result: list[dict[str, Any]] = []
    if ext in {".sol", ".yul"}:
        pattern = re.compile(
            r"\b(?P<kind>abstract\s+contract|contract|interface|library)\s+"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)"
            r"(?:\s+is\s+(?P<bases>[^\{]+))?\s*\{", re.MULTILINE
        )
        for m in pattern.finditer(text):
            result.append({
                "id": _safe_id(f"{path.as_posix()}::{m.group('name')}"),
                "name": m.group("name"),
                "kind": re.sub(r"\s+", " ", m.group("kind")),
                "line": text.count("\n", 0, m.start()) + 1,
                "bases": [x.strip() for x in (m.group("bases") or "").split(",") if x.strip()],
                "offset": m.start(),
            })
    elif text.strip():
        first_line = next((i for i, line in enumerate(text.splitlines(), 1) if line.strip()), 1)
        result.append({
            "id": _safe_id(f"{path.as_posix()}::module"),
            "name": path.stem,
            "kind": f"{_language(path)} source unit",
            "line": first_line,
            "bases": [],
            "offset": 0,
        })
    return result
def _artifact_meta(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {}
    if path.suffix.lower() == ".json":
        try:
            value = json.loads(_text(path))
            if isinstance(value, dict) and isinstance(value.get("abi"), list):
                result["abi_entries"] = len(value["abi"])
                result["abi_functions"] = sum(isinstance(x, dict) and x.get("type") == "function" for x in value["abi"])
                result["abi_events"] = sum(isinstance(x, dict) and x.get("type") == "event" for x in value["abi"])
        except (OSError, json.JSONDecodeError):
            pass
    return result

def _record_file(path: Path, root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    rel = str(path.relative_to(root)).replace("\\", "/")
    digest = _sha256(path)
    ext = path.suffix.lower()
    source = ext in SOURCE_EXTENSIONS
    text = _text(path) if source or ext == ".json" else ""
    units = _units(path, text) if source else []
    funcs = _functions(text, ext) if source else []
    unit_by_index = []
    for index, unit in enumerate(units):
        start = int(unit["offset"])
        end = int(units[index + 1]["offset"]) if index + 1 < len(units) else len(text)
        local = [{k: v for k, v in f.items() if k != "offset"} for f in funcs if start <= int(f["offset"]) < end]
        unit = dict(unit)
        unit.pop("offset", None)
        unit["file"] = rel
        unit["function_count"] = len(local)
        unit["functions"] = local
        unit["signals"] = _signals(text[start:end]) if source else []
        unit_by_index.append(unit)
    file_record = {
        "path": rel,
        "sha256": digest,
        "bytes": path.stat().st_size,
        "lines": text.count("\n") + (1 if text else 0) if source else None,
        "language": _language(path),
        "pragma_solidity": _pragmas(text) if ext == ".sol" else [],
        "imports": _imports(text) if ext == ".sol" else [],
        "signals": _signals(text) if source else [],
        "contract_count": len(unit_by_index),
        "function_count": len(funcs),
        "source": source,
        "artifact": ext in ARTIFACT_EXTENSIONS,
        "artifact_meta": _artifact_meta(path),
    }
    if not source:
        file_record["lines"] = 0
    return file_record, unit_by_index
def build_intake(target: Path) -> dict[str, Any]:
    target = target.expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(target)
    input_sha256 = _sha256(target) if target.is_file() else None
    with _prepared_target(target) as (scan_root, archive_format):
        source_files = _files(scan_root)
        aggregate = hashlib.sha256()
        files: list[dict[str, Any]] = []
        contracts: list[dict[str, Any]] = []
        for path in source_files:
            record, units = _record_file(path, scan_root)
            files.append(record)
            contracts.extend(units)
            aggregate.update(record["path"].encode("utf-8"))
            aggregate.update(record["sha256"].encode("ascii"))
        target_id = _safe_id(f"{target.name}-{aggregate.hexdigest()[:16]}")
        return {
            "intake_version": INTAKE_VERSION,
            "id": target_id,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "target": {
                "kind": "archive" if archive_format else ("file" if target.is_file() else "repository"),
                "path": str(target),
                "name": target.name,
                "source_hash": aggregate.hexdigest(),
                "input_sha256": input_sha256,
                "archive_format": archive_format,
            },
            "git": {
                "commit": None if archive_format or target.is_file() else _git(target, "rev-parse", "HEAD"),
                "branch": None if archive_format or target.is_file() else _git(target, "branch", "--show-current"),
                "remote": None if archive_format or target.is_file() else _git(target, "config", "--get", "remote.origin.url"),
                "dirty": None if archive_format or target.is_file() else _git(target, "status", "--porcelain") not in (None, ""),
            },
            "toolchain": {"project_files": _configs(scan_root), "local_tools": _tool_versions()},
            "summary": {
                "file_count": len(files),
                "source_file_count": sum(bool(x.get("source")) for x in files),
                "contract_count": len(contracts),
                "function_count": sum(int(x.get("function_count", 0)) for x in files),
                "total_bytes": sum(int(x["bytes"]) for x in files),
                "languages": sorted(set(x["language"] for x in files)),
                "security_signal_kinds": sorted({s["id"] for f in files for s in f.get("signals", [])}),
                "artifact_file_count": sum(bool(x.get("artifact")) for x in files),
            },
            "files": files,
            "contracts": contracts,
        }

def write_intake_report(root: Path, report: dict[str, Any]) -> Path:
    out = root / "reports" / "intake"
    out.mkdir(parents=True, exist_ok=True)
    path = out / f'{report["id"]}.json'
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
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
            ledger_path,
            event_type="intake-registered",
            subject=NodeRef("intake", str(report["id"])),
            timestamp=str(report["captured_at"]),
            actor="atlas-intake",
            payload={
                "target_kind": report["target"]["kind"],
                "source_hash": report["target"]["source_hash"],
                "source_file_count": report["summary"]["source_file_count"],
                "contract_count": report["summary"]["contract_count"],
            },
        )
    return path
def list_intakes(root: Path) -> list[dict[str, Any]]:
    out = root / "reports" / "intake"
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
