from __future__ import annotations

import hashlib
import json
import platform
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROOF_BUNDLE_SCHEMA_VERSION = 2

def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str) + "\n").encode("utf-8")

def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()

def _file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def _git_context(root: Path) -> dict[str, Any]:
    result = {"available": False}
    try:
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True, text=True, timeout=10, check=False)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=str(root), capture_output=True, text=True, timeout=10, check=False)
        if head.returncode == 0:
            result.update({"available": True, "commit": head.stdout.strip()})
        result["dirty"] = bool(dirty.returncode == 0 and dirty.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return result

def _safe_rel(path: str) -> str:
    normalized = path.replace("\\", "/").lstrip("/")
    parts = [part for part in normalized.split("/") if part not in ("", ".")]
    if ".." in parts:
        raise ValueError(f"unsafe proof bundle path: {path}")
    return "/".join(parts)

def build_proof_bundle(root: Path, finding: dict[str, Any], output: Path) -> Path:
    root = root.expanduser().resolve()
    if not finding.get("id"):
        raise ValueError("finding id is required")
    artifacts = []
    for raw in finding.get("artifacts", []) or []:
        rel = _safe_rel(str(raw))
        path = root / rel
        if not path.is_file():
            raise FileNotFoundError(path)
        artifacts.append((rel, path))
    identity = {
        "schema_version": PROOF_BUNDLE_SCHEMA_VERSION,
        "finding_id": str(finding["id"]),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "claim_digest": _digest(finding.get("claim", finding)),
    }
    environment = {
        "python": sys.version, "platform": platform.platform(),
        "implementation": platform.python_implementation(), "git": _git_context(root),
        "toolchain": finding.get("toolchain", {}),
    }
    payloads = {
        "identity.json": identity, "finding.json": finding,
        "claim.json": finding.get("claim", {}), "verification.json": finding.get("verification", {}),
        "regression.json": finding.get("regression", {}), "environment.json": environment,
    }
    hashes = {name: _digest(value) for name, value in payloads.items()}
    for rel, path in artifacts:
        hashes[f"artifacts/{rel}"] = _file_digest(path)
    payloads["hashes.json"] = hashes
    output = output.expanduser().resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for name in sorted(payloads):
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, _canonical(payloads[name]))
        for rel, path in sorted(artifacts):
            info = zipfile.ZipInfo(f"artifacts/{rel}", date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            bundle.writestr(info, path.read_bytes())
    return output

def verify_proof_bundle(path: Path) -> dict[str, Any]:
    path = path.expanduser().resolve()
    with zipfile.ZipFile(path) as bundle:
        names = bundle.namelist()
        if any(_safe_rel(name) != name for name in names):
            raise ValueError("proof bundle contains unsafe path")
        required = {"identity.json","finding.json","claim.json","verification.json","regression.json","environment.json","hashes.json"}
        missing = sorted(required-set(names))
        if missing:
            raise ValueError(f"proof bundle missing required files: {', '.join(missing)}")
        hashes = json.loads(bundle.read("hashes.json"))
        mismatches = []
        for name, expected in hashes.items():
            value = hashlib.sha256(bundle.read(name)).hexdigest() if name.startswith("artifacts/") else _digest(json.loads(bundle.read(name)))
            if value != expected:
                mismatches.append(name)
    return {"schema_version": PROOF_BUNDLE_SCHEMA_VERSION, "valid": not mismatches, "mismatches": mismatches, "file_count": len(names), "sha256": _file_digest(path)}
