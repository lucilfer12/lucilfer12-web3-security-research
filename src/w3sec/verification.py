from __future__ import annotations

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from .finding_gate import attach_gate
from .isolation import VerificationRefused, require_isolation  # noqa: F401
from .run_classifier import classify_run, tool_and_subcommand
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
    target_input_hash_claim: str | None
    source_hash_match: bool | None
    security_property: str
    stdout: str
    stderr: str
    timed_out: bool
    output_limited: bool
    toolchain: str | None
    toolchain_manifest: dict[str, Any]
    reproducer: str | None
    baseline: dict[str, Any] | None
    isolation: str = "unspecified"
    failure_class: str = "n/a"
    failing_tests: tuple[str, ...] = ()
    tests_passed: int = 0
    tests_failed: int = 0
    tests_executed: bool = False

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
            "target_input_hash_claim": self.target_input_hash_claim,
            "source_hash_match": self.source_hash_match,
            "binding": {
                "workspace_hash_before_execution": self.target_hash,
                "workspace_hash_after_execution": self.workspace_hash_after,
                "workspace_unchanged": self.target_hash == self.workspace_hash_after,
                "target_input_hash_present": bool(self.target_input_hash),
                "target_input_unchanged": self.target_input_hash == self.target_input_hash_after,
                "finding_source_hash_claimed": bool(self.source_hash_claim),
                "finding_source_hash_match": self.source_hash_match,
            },
            "security_property": self.security_property,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "timed_out": self.timed_out,
            "output_limited": self.output_limited,
            "toolchain": self.toolchain,
            "toolchain_manifest": self.toolchain_manifest,
            "reproducer": self.reproducer,
            "baseline": self.baseline,
            "isolation": self.isolation,
            "failure_class": self.failure_class,
            "failing_tests": list(self.failing_tests),
            "test_execution": {
                "tests_executed": self.tests_executed,
                "tests_passed": self.tests_passed,
                "tests_failed": self.tests_failed,
                "executed_test_count": self.tests_passed + self.tests_failed,
            },
            "policy": (
                "fail-closed: runs only in an attested isolated environment or when the operator "
                "declared the target code trusted; isolated-copy; stdin=devnull; bounded-output; "
                "bounded-time; cargo/forge require --offline; a reproduction needs executed tests, "
                "not just an exit code"
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


def _foundry_profile(root: Path) -> dict[str, str]:
    """Read a Foundry project's [profile.default] test/out/cache_path, falling back to Foundry's
    own defaults (test, out, cache). Never raises: a missing or malformed foundry.toml, or a
    non-string value for one of these keys, just yields the default for that key.

    This exists because several places in this module used to hardcode Foundry's defaults
    (assuming every project keeps test="test" and cache_path="cache"), which silently broke on
    any project that customizes either -- a real reproducer could land in a directory forge never
    scans, and a customized cache directory's internal bookkeeping file (which forge touches on
    every invocation, even a no-op one) would not be excluded from the workspace-unchanged hash,
    permanently preventing a "confirmed" outcome regardless of how real the finding is.
    """
    defaults = {"test": "test", "out": "out", "cache_path": "cache"}
    toml_path = root / "foundry.toml"
    if not toml_path.is_file():
        return defaults
    try:
        import tomllib

        with toml_path.open("rb") as handle:
            doc = tomllib.load(handle)
        profile = doc.get("profile", {}).get("default", {})
        for key in defaults:
            value = profile.get(key)
            if isinstance(value, str) and value.strip():
                defaults[key] = value.strip()
    except Exception:
        pass
    return defaults


def _copy_tree(source: Path, destination: Path) -> None:
    extra_ignored: set[str] = set()
    if (source / "foundry.toml").is_file():
        profile = _foundry_profile(source)
        extra_ignored = {profile["cache_path"].lower(), profile["out"].lower()}
    ignored = shutil.ignore_patterns(
        *({".git", "target", "out", "cache", ".venv", "venv", "__pycache__"} | extra_ignored)
    )
    shutil.copytree(source, destination, ignore=ignored, dirs_exist_ok=True)


def _path_within(base: Path, path: Path) -> bool:
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def _remove_reproducer_from_baseline(
    target: Path,
    baseline_project: Path,
    reproducer: Path | None,
) -> bool:
    """Remove an in-tree reproducer from the clean baseline copy."""
    if reproducer is None or not target.is_dir() or not _path_within(target, reproducer):
        return False
    relative = reproducer.resolve().relative_to(target.resolve())
    candidate = baseline_project / relative
    if candidate.is_dir():
        shutil.rmtree(candidate)
        return True
    if candidate.is_file():
        candidate.unlink()
        return True
    return False


def _prepare_standalone_rust(
    workspace: Path, target: Path, reproducer: Path | None = None
) -> Path:
    """Create a minimal Cargo harness for one standalone Rust source file."""
    if target.suffix.lower() != ".rs":
        raise ValueError("Standalone Cargo verification requires a Rust target.")
    if reproducer is not None and reproducer.suffix.lower() != ".rs":
        raise ValueError("Cargo reproducer must be a .rs file.")
    src_dir = workspace / "src"
    test_dir = workspace / "tests"
    src_dir.mkdir(parents=True, exist_ok=True)
    test_dir.mkdir(parents=True, exist_ok=True)
    target_copy = src_dir / "lib.rs"
    shutil.copy2(target, target_copy)
    if reproducer is None:
        (test_dir / "atlas_baseline.rs").write_text(
            "#[test]\n"
            "fn atlas_baseline_compiles_target() {\n"
            "    assert!(true);\n"
            "}\n",
            encoding="utf-8",
        )
    else:
        shutil.copy2(reproducer, test_dir / reproducer.name)
    (workspace / "Cargo.toml").write_text(
        "[package]\n"
        'name = "atlas_standalone_target"\n'
        'version = "0.0.0"\n'
        'edition = "2021"\n',
        encoding="utf-8",
    )
    return workspace


def _prepare_standalone_foundry(
    workspace: Path, target: Path, reproducer: Path | None = None
) -> Path:
    """Create a minimal offline Foundry harness for one standalone Solidity target."""
    if target.suffix.lower() != ".sol":
        raise ValueError("Standalone Foundry verification requires a Solidity target.")
    if reproducer is not None and reproducer.suffix.lower() not in {".sol", ".t.sol"}:
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
    if reproducer is None:
        (test_dir / "AtlasBaseline.t.sol").write_text(
            "pragma solidity ^0.8.20;\n"
            f'import "../src/{target.name}";\n'
            "contract AtlasBaseline {\n"
            "    function test_atlas_baseline() external {}\n"
            "}\n",
            encoding="utf-8",
        )
    else:
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


def _reproducer_destination(project: Path, reproducer: Path) -> Path:
    """Choose the native test location for the detected project toolchain."""
    if (project / "foundry.toml").is_file():
        test_dir = _foundry_profile(project)["test"]
        return project / test_dir / reproducer.name
    if (project / "Cargo.toml").is_file():
        return project / "tests" / reproducer.name
    if any((project / marker).is_file() for marker in ("pyproject.toml", "pytest.ini", "setup.py")):
        return project / "tests" / reproducer.name
    return project / "test" / reproducer.name


def _attach_reproducer(project: Path, reproducer: Path, target: Path, standalone: bool) -> Path:
    reproducer = reproducer.expanduser().resolve()
    if not reproducer.exists():
        raise FileNotFoundError(reproducer)
    destination = _reproducer_destination(project, reproducer)
    if reproducer.is_dir():
        _copy_tree(reproducer, destination)
        return destination
    destination.parent.mkdir(parents=True, exist_ok=True)
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
        standalone_sol = target.is_file() and target.suffix.lower() == ".sol" and not (
            (project / "foundry.toml").is_file()
        )
        standalone_rust = target.is_file() and target.suffix.lower() == ".rs" and not (
            (project / "Cargo.toml").is_file()
        )
        if standalone_sol:
            project = _prepare_standalone_foundry(workspace, target, reproducer)
        elif standalone_rust:
            project = _prepare_standalone_rust(workspace, target, reproducer)
        elif reproducer.is_dir():
            _attach_reproducer(project, reproducer, target, False)
        else:
            _attach_reproducer(project, reproducer, target, False)
    return base, project


def prepare_baseline_workspace(target: Path) -> tuple[Path, Path]:
    """Prepare a clean verification workspace with a runnable health test."""
    base, project = prepare_workspace(target)
    if target.is_file() and target.suffix.lower() == ".rs" and not (project / "Cargo.toml").is_file():
        project = _prepare_standalone_rust(project, target)
    elif target.is_file() and target.suffix.lower() == ".sol" and not (project / "foundry.toml").is_file():
        project = _prepare_standalone_foundry(project, target)
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


_HASH_IGNORED_DIRS = {
    ".git", "target", "out", "cache", ".cache", ".venv", "venv",
    "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache",
}


def _hashable_files(root: Path):
    ignored_dirs = _HASH_IGNORED_DIRS
    if (root / "foundry.toml").is_file():
        profile = _foundry_profile(root)
        ignored_dirs = _HASH_IGNORED_DIRS | {profile["cache_path"].lower(), profile["out"].lower()}
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        try:
            parts = path.relative_to(root).parts
        except ValueError:
            continue
        if any(part.lower() in ignored_dirs for part in parts[:-1]):
            continue
        yield path


def workspace_hash(root: Path) -> str:
    digest = hashlib.sha256()
    if root.is_file():
        digest.update(root.name.encode())
        digest.update(root.read_bytes())
        return digest.hexdigest()
    for path in sorted(_hashable_files(root)):
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


def native_test_command(project: Path) -> tuple[str, ...] | None:
    tools = detect_toolchain(project)
    if "foundry" in tools:
        return ("forge", "test", "--offline", "-vv")
    if "cargo" in tools:
        command = ["cargo", "test", "--workspace", "--offline"]
        if (project / "Cargo.lock").is_file():
            command.append("--locked")
        return tuple(command)
    if "python" in tools:
        return ("pytest", "-q")
    return None


def default_command(project: Path) -> tuple[str, ...] | None:
    command = native_test_command(project)
    if command is None:
        return None
    return command if shutil.which(command[0]) else None


def suggested_command(target: Path, reproducer: Path | None = None) -> tuple[str, ...] | None:
    toolchains = target_toolchains(target)
    if reproducer is not None and target.is_file() and target.suffix.lower() == ".sol" and "foundry" not in toolchains:
        toolchains = ["foundry", *toolchains]
    if reproducer is not None and target.is_file() and target.suffix.lower() == ".rs" and "cargo" not in toolchains:
        toolchains = ["cargo", *toolchains]
    for toolchain in toolchains:
        if toolchain == "foundry" and shutil.which("forge"):
            project = target if target.is_dir() else target.parent
            test_dir = _foundry_profile(project)["test"]
            if reproducer is not None:
                return (
                    "forge", "test", "--offline", "-vv",
                    "--match-path", f"{test_dir}/{reproducer.name}",
                )
            return ("forge", "test", "--offline", "-vv")
        if toolchain == "cargo" and shutil.which("cargo"):
            project = target if target.is_dir() else target.parent
            if reproducer is not None and reproducer.suffix.lower() == ".rs":
                command = ["cargo", "test", "--test", reproducer.stem, "--offline"]
            else:
                command = ["cargo", "test", "--workspace", "--offline"]
            if (project / "Cargo.lock").is_file():
                command.append("--locked")
            return tuple(command)
        if toolchain == "python" and shutil.which("pytest"):
            if reproducer is not None:
                return ("pytest", "-q", f"tests/{reproducer.name}")
            return ("pytest", "-q")
    return None


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tool_versions(project: Path) -> dict[str, str]:
    versions: dict[str, str] = {}
    candidates = (
        ("forge", ("--version",)),
        ("cargo", ("--version",)),
        ("rustc", ("--version",)),
        ("pytest", ("--version",)),
        ("python", ("--version",)),
        ("solc", ("--version",)),
    )
    for binary, args in candidates:
        exe = shutil.which(binary)
        if not exe:
            continue
        try:
            result = subprocess.run(
                (exe, *args),
                cwd=project,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        text = (result.stdout or result.stderr).strip().splitlines()
        if result.returncode == 0 and text:
            versions[binary] = text[0][:240]
    return versions


def toolchain_manifest(project: Path) -> dict[str, Any]:
    """Capture reproducibility metadata without installing or mutating dependencies."""
    project = project.expanduser().resolve()
    manifests = {}
    for name in (
        "Cargo.lock",
        "foundry.lock",
        "pyproject.toml",
        "pytest.ini",
        "requirements.txt",
        "requirements-dev.txt",
    ):
        path = project / name
        if path.is_file():
            manifests[name] = {
                "sha256": _sha256_file(path),
                "bytes": path.stat().st_size,
            }
    return {
        "platform": os.name,
        "toolchains": detect_toolchain(project),
        "versions": tool_versions(project),
        "dependency_manifests": manifests,
    }


def target_input_hash(target: Path) -> str:
    target = target.expanduser().resolve()
    if target.is_file():
        digest = hashlib.sha256()
        with target.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    return workspace_hash(target)


def _aggregate_source_hash(root: Path) -> str:
    """Match the intake source_hash algorithm for directory/archive targets."""
    from .intake import _files

    files = _files(root)
    aggregate = hashlib.sha256()
    for path in files:
        rel = path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        aggregate.update(rel.encode("utf-8"))
        aggregate.update(digest.encode("ascii"))
    return aggregate.hexdigest()


def target_source_hash(target: Path) -> str | None:
    target = target.expanduser().resolve()
    if target.is_dir():
        return _aggregate_source_hash(target)
    if target.suffix.lower() not in {".zip", ".tar", ".tgz", ".gz", ".bz2", ".xz"}:
        return None
    with tempfile.TemporaryDirectory(prefix="atlas-source-bind-") as td:
        root = Path(td) / "target"
        root.mkdir()
        _extract_archive(target, root)
        return _aggregate_source_hash(root)


def _verification_env(extra_env: Mapping[str, str] | None = None) -> dict[str, str]:
    value = {
        "PATH": os.environ.get("PATH", ""),
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
        "WINDIR": os.environ.get("WINDIR", ""),
        "TEMP": tempfile.gettempdir(),
        "TMP": tempfile.gettempdir(),
        "CARGO_NET_OFFLINE": "true",
        "FOUNDRY_OFFLINE": "true",
        "GIT_TERMINAL_PROMPT": "0",
    }
    if extra_env:
        allowed = {"ATLAS_PROOF_MARKER", "ATLAS_PROOF_REPRODUCER_SHA256"}
        for key, item in extra_env.items():
            if key in allowed:
                value[key] = str(item)
    return value


def run_verification(
    target: Path,
    finding: dict[str, Any],
    command: Sequence[str],
    *,
    expected_exit: int = 0,
    mode: str = "baseline",
    baseline_expected_exit: int = 0,
    security_property: str = "",
    timeout_seconds: int = 300,
    max_output_bytes: int = 4 * 1024 * 1024,
    reproducer: Path | None = None,
    baseline_command: Sequence[str] | None = None,
    extra_env: Mapping[str, str] | None = None,
    trusted_target_code: bool = False,
) -> VerificationResult:
    if mode not in {"baseline", "reproduction"}:
        raise ValueError("mode must be baseline or reproduction")
    command = validate_command(command)
    decision = require_isolation(trusted_target_code)
    tool, subcommand = tool_and_subcommand(command)
    judged = tool is not None and subcommand == "test"
    if not security_property.strip():
        raise ValueError("A security property is required for verification.")
    source_hash_claim = str(finding.get("source_hash")) if finding.get("source_hash") else None
    claimed_source_match = None
    bound_source = target_source_hash(target)
    if source_hash_claim and bound_source is not None:
        claimed_source_match = bound_source == source_hash_claim
        if not claimed_source_match:
            raise ValueError(
                "Verification target binding mismatch: directory/archive source differs from the finding."
            )
    input_hash = target_input_hash(target)
    input_hash_claim = (
        str(finding.get("target_input_sha256"))
        if finding.get("target_input_sha256")
        else None
    )
    baseline: dict[str, Any] | None = None
    baseline_class = None
    baseline_manifest: dict[str, Any] = {}
    if mode == "reproduction":
        baseline_base, baseline_project = prepare_baseline_workspace(target)
        reproducer_removed = _remove_reproducer_from_baseline(
            target, baseline_project, reproducer
        )
        baseline_before = workspace_hash(baseline_project)
        baseline_manifest = toolchain_manifest(baseline_project)
        baseline_command_value = (
            validate_command(baseline_command)
            if baseline_command is not None
            else (native_test_command(baseline_project) or command)
        )
        baseline_started = time.perf_counter()
        if baseline_command_value is None:
            shutil.rmtree(baseline_base, ignore_errors=True)
            baseline = {
                "command": None,
                "expected_exit": baseline_expected_exit,
                "returncode": -1,
                "duration_seconds": 0.0,
                "timed_out": False,
                "output_limited": False,
                "workspace_hash_before": baseline_before,
                "workspace_hash_after": baseline_before,
                "workspace_unchanged": True,
                "failure_class": "no-baseline-command",
                "reproducer_removed_from_baseline": reproducer_removed,
                "healthy": False,
                "stdout": "",
                "stderr": (
                    "ATLAS could not derive a clean baseline test command for this target. "
                    "Provide --baseline-command or use a native project with a test runner."
                ),
            }
        else:
            try:
                baseline_tool, baseline_subcommand = tool_and_subcommand(baseline_command_value)
                baseline_judged = baseline_tool is not None and baseline_subcommand == "test"
                baseline_result = run_bounded(
                    baseline_command_value,
                    cwd=baseline_project,
                    timeout=timeout_seconds,
                    max_output_bytes=max_output_bytes,
                    env=_verification_env(),
                )
                baseline_after = workspace_hash(baseline_project)
                baseline_class = (
                    classify_run(baseline_tool, baseline_result.stdout, baseline_result.stderr)
                    if baseline_judged and baseline_tool
                    else None
                )
                baseline_healthy = (
                    not baseline_result.timed_out
                    and not baseline_result.output_limited
                    and baseline_result.returncode == baseline_expected_exit
                    and (
                        (
                            baseline_class is not None
                            and baseline_class.kind == "tests-passed"
                            and baseline_class.passed > 0
                        )
                        if baseline_judged
                        else True
                    )
                )
                baseline = {
                    "command": list(baseline_command_value),
                    "expected_exit": baseline_expected_exit,
                    "returncode": baseline_result.returncode,
                    "duration_seconds": round(time.perf_counter() - baseline_started, 6),
                    "timed_out": baseline_result.timed_out,
                    "output_limited": baseline_result.output_limited,
                    "workspace_hash_before": baseline_before,
                    "workspace_hash_after": baseline_after,
                    "workspace_unchanged": baseline_before == baseline_after,
                    "failure_class": baseline_class.kind if baseline_class else "n/a",
                    "reproducer_removed_from_baseline": reproducer_removed,
                    "tests_passed": baseline_class.passed if baseline_class else 0,
                    "tests_failed": baseline_class.failed if baseline_class else 0,
                    "tests_executed": bool(
                        baseline_class and (baseline_class.passed + baseline_class.failed) > 0
                    ),
                    "healthy": baseline_healthy,
                    "stdout": baseline_result.stdout,
                    "stderr": baseline_result.stderr,
                }
            finally:
                shutil.rmtree(baseline_base, ignore_errors=True)
        if not baseline["healthy"]:
            return VerificationResult(
                finding_id=str(finding.get("id") or "unknown"),
                outcome="inconclusive",
                mode=mode,
                command=tuple(command),
                expected_exit=expected_exit,
                returncode=int(baseline["returncode"]),
                duration_seconds=float(baseline["duration_seconds"]),
                workspace=str(baseline_project),
                target_hash=str(baseline["workspace_hash_before"]),
                workspace_hash_after=str(baseline["workspace_hash_after"]),
                target_input_hash=input_hash,
                target_input_hash_after=target_input_hash(target),
                source_hash_claim=source_hash_claim,
                target_input_hash_claim=input_hash_claim if "input_hash_claim" in locals() else None,
                source_hash_match=claimed_source_match,
                security_property=security_property.strip(),
                stdout=str(baseline.get("stdout") or ""),
                stderr=str(baseline.get("stderr") or ""),
                timed_out=bool(baseline["timed_out"]),
                output_limited=bool(baseline["output_limited"]),
                toolchain=(baseline_manifest.get("toolchains") or [None])[0],
                toolchain_manifest=baseline_manifest,
                reproducer=str(reproducer.expanduser().resolve()) if reproducer is not None else None,
                baseline=baseline,
                isolation=decision.mode,
                failure_class=str(baseline.get("failure_class", "n/a")),
                failing_tests=tuple(baseline_class.failing_tests) if baseline_class else (),
                tests_passed=baseline_class.passed if baseline_class else 0,
                tests_failed=baseline_class.failed if baseline_class else 0,
                tests_executed=bool(baseline_class and (baseline_class.passed + baseline_class.failed) > 0),
            )
    base, project = prepare_workspace(target, reproducer=reproducer)
    workspace_before = workspace_hash(project)
    source_hash_match = (
        claimed_source_match
        if claimed_source_match is not None
        else ((input_hash == input_hash_claim) if input_hash_claim else None)
    )
    if input_hash_claim and not source_hash_match:
        shutil.rmtree(base, ignore_errors=True)
        raise ValueError(
            "Verification target binding mismatch: the finding was generated from different input bytes."
        )
    toolchain = detect_toolchain(project)
    manifest = toolchain_manifest(project)
    started = time.perf_counter()
    try:
        result = run_bounded(
            command,
            cwd=project,
            timeout=timeout_seconds,
            max_output_bytes=max_output_bytes,
            env=_verification_env(extra_env),
        )
        duration = time.perf_counter() - started
        workspace_after = workspace_hash(project)
        original_after = target_input_hash(target)
        run_class = classify_run(tool, result.stdout, result.stderr) if judged else None
        if result.timed_out or result.output_limited:
            outcome = "inconclusive"
        elif mode == "reproduction" and (
            run_class is None
            or run_class.kind in {"build-error", "no-tests-ran", "unknown"}
            or (run_class.passed + run_class.failed) == 0
        ):
            # An exit code is not evidence: cargo/forge can fail before any test executes.
            # Reproduction requires an actual test result, not merely process termination.
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
            target_input_hash_claim=input_hash_claim,
            source_hash_match=source_hash_match,
            security_property=security_property.strip(),
            stdout=result.stdout,
            stderr=result.stderr,
            timed_out=result.timed_out,
            output_limited=result.output_limited,
            toolchain=toolchain[0] if toolchain else None,
            toolchain_manifest=manifest,
            reproducer=str(reproducer.expanduser().resolve()) if reproducer is not None else None,
            baseline=baseline,
            isolation=decision.mode,
            failure_class=run_class.kind if run_class else "n/a",
            failing_tests=run_class.failing_tests if run_class else (),
            tests_passed=run_class.passed if run_class else 0,
            tests_failed=run_class.failed if run_class else 0,
            tests_executed=bool(run_class and (run_class.passed + run_class.failed) > 0),
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
