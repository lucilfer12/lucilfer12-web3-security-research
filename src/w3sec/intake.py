from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
import shutil
import stat
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


def _git_context(target: Path, archive_format: str | None) -> dict[str, Any]:
    if archive_format:
        return {"commit": None, "branch": None, "remote": None, "dirty": None, "repo_relative_path": None}
    probe = target if target.is_dir() else target.parent
    top = _git(probe, "rev-parse", "--show-toplevel")
    if not top:
        return {"commit": None, "branch": None, "remote": None, "dirty": None, "repo_relative_path": None}
    repo_root = Path(top).resolve()
    rel = None
    if target.is_file():
        try:
            rel = str(target.resolve().relative_to(repo_root)).replace("\\", "/")
        except ValueError:
            rel = None
    return {
        "commit": _git(probe, "rev-parse", "HEAD"),
        "branch": _git(probe, "branch", "--show-current"),
        "remote": _git(probe, "config", "--get", "remote.origin.url"),
        "dirty": _git(probe, "status", "--porcelain") not in (None, ""),
        "repo_relative_path": rel,
    }

def _language(path: Path) -> str:
    return LANGUAGES.get(path.suffix.lower(), path.suffix.lower().lstrip(".").upper() or "Unknown")

def _is_archive(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith((".zip", ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".7z", ".rar", ".gz"))

ARCHIVE_MAX_FILES = 10_000
ARCHIVE_MAX_MEMBER_BYTES = 64 * 1024 * 1024
ARCHIVE_MAX_TOTAL_BYTES = 256 * 1024 * 1024
ARCHIVE_MAX_COMPRESSION_RATIO = 1_000


def _is_contract_related(path: Path) -> bool:
    # ATLAS accepts every file type. Known code/artifacts receive structural parsing;
    # unknown or binary files are retained as hashed inventory evidence.
    return path.is_file()


def _safe_member_name(name: str) -> str:
    normalized = name.replace("\\", "/")
    from pathlib import PurePosixPath
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or normalized.startswith("/") or ".." in pure.parts:
        raise ValueError(f"Unsafe archive member: {name}")
    cleaned = "/".join(part for part in pure.parts if part not in {"", "."})
    if not cleaned:
        raise ValueError(f"Empty archive member: {name}")
    return cleaned


def _archive_limits(count: int, total: int, size: int, compressed: int, name: str) -> tuple[int, int]:
    if count > ARCHIVE_MAX_FILES:
        raise ValueError("Archive file-count limit exceeded")
    if size > ARCHIVE_MAX_MEMBER_BYTES:
        raise ValueError(f"Archive member too large: {name}")
    if total + size > ARCHIVE_MAX_TOTAL_BYTES:
        raise ValueError("Archive total uncompressed-size limit exceeded")
    if size and compressed == 0:
        raise ValueError(f"Invalid compressed-size metadata: {name}")
    if compressed and size / compressed > ARCHIVE_MAX_COMPRESSION_RATIO:
        raise ValueError(f"Archive compression-ratio limit exceeded: {name}")
    return count, total + size


def _commit_extraction(staging: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for child in staging.iterdir():
        target = destination / child.name
        if target.exists():
            raise ValueError(f"Archive extraction collision: {target.name}")
        shutil.move(str(child), str(target))
    shutil.rmtree(staging, ignore_errors=True)


def _safe_extract_archive(archive: Path, destination: Path) -> str:
    destination = destination.resolve()
    lower = archive.name.lower()
    staging = Path(tempfile.mkdtemp(prefix="atlas-extract-", dir=destination.parent))
    try:
        if lower.endswith(".7z") or lower.endswith(".rar"):
            shutil.rmtree(staging, ignore_errors=True)
            # External extractors are treated as opaque until they have a dedicated
            # sandboxed adapter with the same member/path limits.
            return "7z-opaque" if lower.endswith(".7z") else "rar-opaque"

        if lower.endswith(".gz") and not lower.endswith((".tar.gz", ".tgz")):
            output = staging / archive.stem
            total = 0
            with gzip.open(archive, "rb") as source, output.open("wb") as target:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > ARCHIVE_MAX_MEMBER_BYTES:
                        raise ValueError("Gzip decompressed-size limit exceeded")
                    target.write(chunk)
            _commit_extraction(staging, destination)
            return "gzip"

        seen: set[str] = set()
        count = 0
        total = 0
        if lower.endswith(".zip"):
            with zipfile.ZipFile(archive) as zf:
                for member in zf.infolist():
                    name = _safe_member_name(member.filename)
                    folded = name.casefold()
                    if folded in seen:
                        raise ValueError(f"Duplicate/case-colliding archive member: {member.filename}")
                    seen.add(folded)
                    if member.flag_bits & 0x1:
                        raise ValueError(f"Encrypted ZIP member is not accepted: {member.filename}")
                    if member.is_dir():
                        (staging / name).mkdir(parents=True, exist_ok=True)
                        continue
                    mode = (member.external_attr >> 16) & 0o177777
                    if stat.S_ISLNK(mode) or stat.S_ISFIFO(mode) or stat.S_ISCHR(mode) or stat.S_ISBLK(mode):
                        raise ValueError(f"Special ZIP member is not accepted: {member.filename}")
                    count += 1
                    _, total = _archive_limits(count, total, member.file_size, member.compress_size, member.filename)
                    target = staging / name
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member, "r") as source, target.open("wb") as sink:
                        copied = 0
                        while True:
                            chunk = source.read(1024 * 1024)
                            if not chunk:
                                break
                            copied += len(chunk)
                            sink.write(chunk)
                    if copied != member.file_size:
                        raise ValueError(f"ZIP member size mismatch: {member.filename}")
            archive_bytes = max(1, archive.stat().st_size)
            if total / archive_bytes > ARCHIVE_MAX_COMPRESSION_RATIO:
                raise ValueError("Archive total compression-ratio limit exceeded")
            _commit_extraction(staging, destination)
            return "zip"

        with tarfile.open(archive, "r:*") as tf:
            for member in tf.getmembers():
                name = _safe_member_name(member.name)
                folded = name.casefold()
                if folded in seen:
                    raise ValueError(f"Duplicate/case-colliding archive member: {member.name}")
                seen.add(folded)
                if member.issym() or member.islnk() or not (member.isdir() or member.isfile()):
                    raise ValueError(f"Archive link/special file is not accepted: {member.name}")
                if member.isdir():
                    (staging / name).mkdir(parents=True, exist_ok=True)
                    continue
                count += 1
                _, total = _archive_limits(count, total, member.size, max(1, member.size), member.name)
                target = staging / name
                target.parent.mkdir(parents=True, exist_ok=True)
                source = tf.extractfile(member)
                if source is None:
                    raise ValueError(f"Cannot read archive member: {member.name}")
                with source, target.open("wb") as sink:
                    shutil.copyfileobj(source, sink, length=1024 * 1024)
            archive_bytes = max(1, archive.stat().st_size)
            if total / archive_bytes > ARCHIVE_MAX_COMPRESSION_RATIO:
                raise ValueError("Archive total compression-ratio limit exceeded")
        _commit_extraction(staging, destination)
        return "tar"
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

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
        "forge": ["forge", "--version"],
        "anvil": ["anvil", "--version"],
        "cast": ["cast", "--version"],
        "solc": ["solc", "--version"],
        "slither": ["slither", "--version"],
        "semgrep": ["semgrep", "--version"],
        "mythril": ["myth", "version"],
        "echidna": ["echidna", "--version"],
        "halmos": ["halmos", "--version"],
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


def _manifest_sha256(files: list[dict[str, Any]]) -> str:
    payload = [
        {
            "path": item["path"],
            "sha256": item["sha256"],
            "bytes": int(item["bytes"]),
            "language": item["language"],
        }
        for item in sorted(files, key=lambda value: str(value["path"]))
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


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
        source_hash = aggregate.hexdigest()
        manifest_sha256 = _manifest_sha256(files)
        target_id = _safe_id(f"{target.name}-{source_hash[:16]}")
        return {
            "intake_version": INTAKE_VERSION,
            "id": target_id,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "target": {
                "kind": "archive" if archive_format else ("file" if target.is_file() else "repository"),
                "path": str(target),
                "name": target.name,
                "source_hash": source_hash,
                "manifest_sha256": manifest_sha256,
                "input_sha256": input_sha256,
                "archive_format": archive_format,
                "content_address": f"sha256:{source_hash}",
                "archive_policy": {
                    "max_files": ARCHIVE_MAX_FILES,
                    "max_member_bytes": ARCHIVE_MAX_MEMBER_BYTES,
                    "max_total_bytes": ARCHIVE_MAX_TOTAL_BYTES,
                    "max_compression_ratio": ARCHIVE_MAX_COMPRESSION_RATIO,
                    "links_allowed": False,
                    "special_files_allowed": False,
                    "atomic_extraction": True,
                },
            },
            "git": _git_context(target, archive_format),
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
                "manifest_sha256": manifest_sha256,
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
