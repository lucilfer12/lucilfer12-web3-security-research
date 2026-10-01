from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .finding_gate import attach_gate
from .runtime import run_bounded


ALLOWED_TEST_BINS = {
    "cargo": {"test", "check", "build"},
    "forge": {"test", "build"},
    "python": {"-m"},
    "python3": {"-m"},
    "py": {"-m"},
    "pytest": set(),
}

FORBIDDEN_TOKENS = {
    "broadcast", "deploy", "publish", "verify", "cast", "send",
    "anvil", "curl", "wget", "ssh", "scp", "ffi", "vm.ffi",
}


@dataclass(frozen=True, slots=True)
class VerificationResult:
    finding_id: str
    outcome: str
    mode: str
    command: tuple[str, ...]
    expected_exit: int
    returncode: int
    duration_seconds: float
    workspace: str
    target_hash: str
    workspace_hash_after: str
    target_input_hash: str
    target_input_hash_after: str
    source_hash_claim: str | None
    security_property: str
    stdout: str
    stderr: str
    timed_out: bool
    output_limited: bool
    toolchain: str | None
    reproducer: str | None

    @property
    def reproduced(self) -> bool:
        return self.outcome == "reproduced"

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "outcome": self.outcome,
            "mode": self.mode,
            "command": list(self.command),
            "expected_exit": self.expected_exit,
            "returncode": self.returncode,
            "duration_seconds": round(self.duration_seconds, 6),
            "workspace": self.workspace,
            "target_hash": self.target_hash,
            "workspace_hash_after": self.workspace_hash_after,
            "target_input_hash": self.target_input_hash,
            "target_input_hash_after": self.target_input_hash_after,
            "source_hash_claim": self.source_hash_claim,
            "binding": {
                "workspace_hash_before_execution": self.target_hash,
                "workspace_hash_after_execution": self.workspace_hash_after,
                "workspace_unchanged": self.target_hash == self.workspace_hash_after,
                "target_input_hash_present": bool(self.target_input_hash),
                "target_input_unchanged": self.target_input_hash == self.target_input_hash_after,
                "finding_source_hash_claimed": bool(self.source_hash_claim),
            },
            "security_property": self.security_property,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "output_limited": self.output_limited,
            "toolchain": self.toolchain,
            "reproducer": self.reproducer,
            "policy": (
                "isolated-copy; stdin=devnull; bounded-output; bounded-time; "
                "cargo/forge require --offline; OS-level network access is not sandboxed"
            ),
            "promotion_effect": (
                "reproduction evidence may satisfy the reproduction gate only when "
                "the security property and expected outcome are explicitly stated"
                if self.reproduced else
                "execution result alone does not prove exploitability"
            ),
        }


def split_command(text: str) -> tuple[str, ...]:
    tokens = tuple(shlex.split(text, posix=False))
    if not tokens:
        raise ValueError("Verification command is empty.")
    return tokens


def _basename(token: str) -> str:
    return Path(token.strip('"')).name.lower()


def validate_command(command: Sequence[str]) -> tuple[str, ...]:
    tokens = tuple(command)
    if not tokens:
        raise ValueError("Verification command is empty.")
    binary = _basename(tokens[0])
    if binary not in ALLOWED_TEST_BINS:
        raise ValueError(
            f"Unsupported verification executable '{binary}'. "
            "Allowed local test runners: cargo, forge, python, pytest."
        )
    normalized = [str(token).strip('"').lower() for token in tokens[1:]]
    normalized_ops = {token.lstrip("-") for token in normalized}
    for bad in FORBIDDEN_TOKENS:
        if (
            bad in normalized
            or bad in normalized_ops
            or f"--{bad}" in normalized
            or any(token.startswith(f"--{bad}=") for token in normalized)
        ):
            raise ValueError(f"Command contains forbidden operation '{bad}'.")
    for token in tokens:
        raw = str(token).strip('"')
        if (
            Path(raw).is_absolute()
            or ".." in Path(raw).parts
            or ":\\"
            in raw
            or raw.startswith("\\\\")
        ):
            raise ValueError("Verification command may not reference paths outside the isolated workspace.")
    if binary in {"cargo", "forge"}:
        if len(tokens) < 2 or tokens[1].lower() not in ALLOWED_TEST_BINS[binary]:
            raise ValueError(f"{binary} verification is limited to test/check/build.")
        if "--offline" not in normalized:
            raise ValueError(f"{binary} verification must include --offline.")
    elif binary in {"python", "python3", "py"}:
        if len(tokens) < 3 or tuple(tokens[1:3]) not in (("-m", "pytest"), ("-m", "unittest")):
            raise ValueError("Python verification must run pytest or unittest.")
    elif binary == "pytest" and any(x.startswith("-c") for x in tokens[1:]):
        raise ValueError("Custom pytest config paths are not allowed.")
    return tokens


def detect_toolchain(root: Path) -> list[str]:
    found: list[str] = []
    if (root / "foundry.toml").is_file():
        found.append("foundry")
    if (root / "Cargo.toml").is_file() or list(root.glob("**/Cargo.toml")):
        found.append("cargo")
    if any((root / name).is_file() for name in ("pyproject.toml", "pytest.ini", "setup.py", "requirements.txt")):
        found.append("python")
    return found
def _safe_members_zip(archive: Path) -> list[str]:
    from zipfile import ZipFile
    with ZipFile(archive) as zf:
        names = zf.namelist()
    for name in names:
        p = Path(name)
        if p.is_absolute() or ".." in p.parts:
            raise ValueError(f"Unsafe archive member: {name}")
    return names


def _extract_archive(archive: Path, destination: Path) -> None:
    suffixes = "".join(archive.suffixes[-2:]).lower()
    if archive.suffix.lower() == ".zip":
        from zipfile import ZipFile
        _safe_members_zip(archive)
        with ZipFile(archive) as zf:
            zf.extractall(destination)
        return
    if archive.suffix.lower() in {".tar", ".tgz", ".gz", ".bz2", ".xz"} or suffixes in {".tar.gz", ".tar.bz2", ".tar.xz"}:
        import tarfile
        with tarfile.open(archive) as tf:
            for member in tf.getmembers():
                p = Path(member.name)
                if p.is_absolute() or ".." in p.parts or member.issym() or member.islnk():
                    raise ValueError(f"Unsafe archive member: {member.name}")
            tf.extractall(destination)
        return
    raise ValueError(f"Unsupported verification archive: {archive.suffix}")


def _copy_tree(source: Path, destination: Path) -> None:
    ignored = shutil.ignore_patterns(
        ".git", "target", "out", "cache", ".venv", "venv", "node_modules", "__pycache__"
    )
    shutil.copytree(source, destination, ignore=ignored, dirs_exist_ok=True)


def _path_within(base: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _prepare_standalone_foundry(workspace: Path, target: Path, reproducer: Path) -> Path:
    """Create a minimal offline Foundry harness for one standalone Solidity target."""
    if target.suffix.lower() != ".sol" or not reproducer.is_file():
        raise ValueError("Standalone Foundry verification requires a Solidity target and one reproducer file.")
    if reproducer.suffix.lower() not in {".sol", ".t.sol"}:
        raise ValueError("Foundry reproducer must be a .sol or .t.sol file.")
    src_dir = workspace / "src"
    test_dir = workspace / "test"
    src_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)
    copied_target = workspace / target.name
    target_in_src = src_dir / target.name
    if copied_target.exists():
        shutil.move(str(copied_target), str(target_in_src))
    elif not target_in_src.exists():
        raise FileNotFoundError(f"standalone Solidity target missing from verification workspace: {target.name}")
    shutil.copy2(reproducer, test_dir / reproducer.name)
    (workspace / "foundry.toml").write_text(
        "[profile.default]\n"
        'src = "src"\n'
        'test = "test"\n'
        'out = "out"\n'
        'libs = []\n',
        encoding="utf-8",
    )
    return workspace


def _attach_reproducer(project: Path, reproducer: Path, target: Path, standalone: bool) -> Path:
    reproducer = reproducer.expanduser().resolve()
    if not reproducer.exists():
        raise FileNotFoundError(reproducer)
    if reproducer.is_dir():
        destination = project / "test" / reproducer.name
        _copy_tree(reproducer, destination)
        return destination
    destination_dir = project / "test"
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / reproducer.name
    shutil.copy2(reproducer, destination)
    if standalone and target.suffix.lower() == ".sol":
        (project / "foundry.toml").write_text(
            "[profile.default]\n"
            'src = "src"\n'
            'test = "test"\n'
            'out = "out"\n'
            'libs = []\n',
            encoding="utf-8",
        )
        src_target = project / "src" / target.name
        copied_target = project / target.name
        (project / "src").mkdir(parents=True, exist_ok=True)
        if copied_target.exists() and not src_target.exists():
            shutil.move(str(copied_target), str(src_target))
    return destination


def prepare_workspace(
    target: Path, reproducer: Path | None = None
) -> tuple[Path, Path]:
    target = target.expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(target)
    reproducer = reproducer.expanduser().resolve() if reproducer is not None else None
    if reproducer is not None and not reproducer.exists():
        raise FileNotFoundError(reproducer)
    base = Path(tempfile.mkdtemp(prefix="atlas-verification-"))
    workspace = base / "target"
    if target.is_dir():
        _copy_tree(target, workspace)
    elif target.suffix.lower() in {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz"}:
        workspace.mkdir()
        _extract_archive(target, workspace)
    else:
        workspace.mkdir()
        shutil.copy2(target, workspace / target.name)
    project = _find_project_root(workspace)
    if reproducer is not None:
        standalone = target.is_file() and target.suffix.lower() == ".sol" and not (
            (project / "foundry.toml").is_file()
        )
        if standalone:
            project = _prepare_standalone_foundry(workspace, target, reproducer)
        elif reproducer.is_dir():
            _attach_reproducer(project, reproducer, target, False)
        else:
            _attach_reproducer(project, reproducer, target, False)
    return base, project


def _find_project_root(workspace: Path) -> Path:
    markers = ("foundry.toml", "Cargo.toml", "pyproject.toml", "package.json")
    if any((workspace / marker).is_file() for marker in markers):
        return workspace
    candidates: list[Path] = []
    for marker in markers:
        candidates.extend(p.parent for p in workspace.glob(f"*/{marker}"))
    if candidates:
        return sorted(candidates, key=lambda p: len(p.parts))[0]
    return workspace


def workspace_hash(root: Path) -> str:
    digest = hashlib.sha256()
    if root.is_file():
        digest.update(root.name.encode())
        digest.update(root.read_bytes())
        return digest.hexdigest()
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()
def target_toolchains(target: Path) -> list[str]:
    target = target.expanduser().resolve()
    if target.is_dir():
        return detect_toolchain(target)
    if target.suffix.lower() == ".zip":
        from zipfile import ZipFile
        try:
            with ZipFile(target) as zf:
                names = zf.namelist()
        except OSError:
            return []
        found: list[str] = []
        if any(Path(name).name.lower() == "foundry.toml" for name in names):
            found.append("foundry")
        if any(Path(name).name.lower() == "cargo.toml" for name in names):
            found.append("cargo")
        if any(Path(name).name.lower() in {"pyproject.toml", "pytest.ini"} for name in names):
            found.append("python")
        return found
    if target.is_file():
        for parent in (target.parent, *target.parents):
            if (parent / "foundry.toml").is_file() and target.suffix.lower() == ".sol":
                return ["foundry"]
            if (parent / "Cargo.toml").is_file() and target.suffix.lower() == ".rs":
                return ["cargo"]
            if (
                any((parent / marker).is_file() for marker in ("pyproject.toml", "pytest.ini"))
                and target.suffix.lower() == ".py"
            ):
                return ["python"]
    return []


def default_command(project: Path) -> tuple[str, ...] | None:
    tools = detect_toolchain(project)
    if "foundry" in tools and shutil.which("forge"):
        return ("forge", "test", "--offline", "-vv")
    if "cargo" in tools and shutil.which("cargo"):
        return ("cargo", "test", "--workspace", "--offline")
    if "python" in tools and shutil.which("pytest"):
        return ("pytest", "-q")
    return None


def suggested_command(target: Path, reproducer: Path | None = None) -> tuple[str, ...] | None:
    toolchains = target_toolchains(target)
    if reproducer is not None and target.is_file() and target.suffix.lower() == ".sol" and "foundry" not in toolchains:
        toolchains = ["foundry", *toolchains]
    for toolchain in toolchains:
        if toolchain == "foundry" and shutil.which("forge"):
            return ("forge", "test", "--offline", "-vv")
        if toolchain == "cargo" and shutil.which("cargo"):
            return ("cargo", "test", "--workspace", "--offline")
        if toolchain == "python" and shutil.which("pytest"):
            return ("pytest", "-q")
    return None


def tool_versions(project: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    for binary, args in (("forge", ("--version",)), ("cargo", ("--version",)), ("pytest", ("--version",))):
        exe = shutil.which(binary)
        if not exe:
            continue
        result = run_bounded((exe, *args), cwd=project, timeout=15, max_output_bytes=16384)
        text = (result.stdout or result.stderr).strip().splitlines()
        if result.returncode == 0 and text:
            versions[binary] = text[0][:240]
    return versions


def target_input_hash(target: Path) -> str:
    target = target.expanduser().resolve()
    if target.is_file():
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    return workspace_hash(target)


def run_verification(
    target: Path,
    finding: dict[str, Any],
    command: Sequence[str],
    *,
    expected_exit: int = 0,
    mode: str = "baseline",
    security_property: str = "",
    timeout_seconds: int = 300,
    max_output_bytes: int = 4 * 1024 * 1024,
    reproducer: Path | None = None,
) -> VerificationResult:
    if mode not in {"baseline", "reproduction"}:
        raise ValueError("mode must be baseline or reproduction")
    command = validate_command(command)
    if not security_property.strip():
        raise ValueError("A security property is required for verification.")
    base, project = prepare_workspace(target, reproducer=reproducer)
    workspace_before = workspace_hash(project)
    input_hash = target_input_hash(target)
    source_hash_claim = str(finding.get("source_hash")) if finding.get("source_hash") else None
    toolchain = detect_toolchain(project)
    started = time.perf_counter()
    try:
        result = run_bounded(
            command,
            cwd=project,
            timeout=timeout_seconds,
            max_output_bytes=max_output_bytes,
            env={
                "PATH": os.environ.get("PATH", ""),
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
                "WINDIR": os.environ.get("WINDIR", ""),
                "TEMP": tempfile.gettempdir(),
                "TMP": tempfile.gettempdir(),
            },
        )
        duration = time.perf_counter() - started
        workspace_after = workspace_hash(project)
        original_after = target_input_hash(target)
        if result.timed_out or result.output_limited:
            outcome = "inconclusive"
        elif result.returncode == expected_exit:
            outcome = "reproduced" if mode == "reproduction" else "execution-pass"
        else:
            outcome = "not-reproduced" if mode == "reproduction" else "execution-fail"
        return VerificationResult(
            finding_id=str(finding.get("id") or "unknown"),
            outcome=outcome,
            mode=mode,
            command=tuple(command),
            expected_exit=expected_exit,
            returncode=result.returncode,
            duration_seconds=duration,
            workspace=str(project),
            target_hash=workspace_before,
            workspace_hash_after=workspace_after,
            target_input_hash=input_hash,
            target_input_hash_after=original_after,
            source_hash_claim=source_hash_claim,
            security_property=security_property.strip(),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
            output_limited=result.output_limited,
            toolchain=toolchain[0] if toolchain else None,
            reproducer=str(reproducer.expanduser().resolve()) if reproducer is not None else None,
        )
    finally:
        shutil.rmtree(base, ignore_errors=True)
def write_verification_result(
    repo: Path,
    result: VerificationResult,
    report_path: Path | None = None,
) -> Path:
    out = repo / "reports" / "contract-audits" / "verifications"
    out.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    path = out / f"{stamp}-{result.finding_id}.json"
    payload = result.as_dict()
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if report_path and report_path.is_file():
        _attach_to_report(report_path, payload)
    return path


def _attach_to_report(report_path: Path, verification: dict[str, Any]) -> None:
    try:
        report = json.loads(report_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return
    findings = report.get("findings", [])
    for finding in findings:
        if str(finding.get("id")) == str(verification.get("finding_id")):
            finding.setdefault("verifications", []).append(verification)
            updated = attach_gate(finding)
            finding.clear()
            finding.update(updated)
            break
    report["verification_history"] = report.get("verification_history", [])
    report["verification_history"].append(verification)
    tmp = report_path.with_suffix(report_path.suffix + ".tmp")
    tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, report_path)


def human_outcome(result: VerificationResult) -> str:
    labels = {
        "reproduced": "REPRODUCED",
        "not-reproduced": "NOT REPRODUCED",
        "execution-pass": "EXECUTION PASS",
        "execution-fail": "EXECUTION FAIL",
        "inconclusive": "INCONCLUSIVE",
    }
    return labels.get(result.outcome, result.outcome.upper())
