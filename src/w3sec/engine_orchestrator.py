from __future__ import annotations

import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Sequence

from .intake import OperationCancelled
from .runtime import run_bounded

@dataclass(frozen=True, slots=True)
class EngineSpec:
    name: str
    capability: str
    scope: str
    timeout_seconds: float
    command: tuple[str, ...]
    version_command: tuple[str, ...]
    sandbox_policy: str = "bounded-process; stdin=devnull; output-capped; workspace-cwd"

@dataclass(frozen=True, slots=True)
class EngineResult:
    engine: str
    capability: str
    scope: str
    available: bool
    executed: bool
    status: str
    version: str | None
    executable: str | None
    timeout_seconds: float
    sandbox_policy: str
    command: tuple[str, ...] = ()
    returncode: int | None = None
    duration_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    failure_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine, "capability": self.capability, "scope": self.scope,
            "available": self.available, "executed": self.executed, "status": self.status,
            "version": self.version, "executable": self.executable,
            "timeout_seconds": self.timeout_seconds, "sandbox_policy": self.sandbox_policy,
            "command": list(self.command), "returncode": self.returncode,
            "duration_seconds": self.duration_seconds, "stdout": self.stdout,
            "stderr": self.stderr, "failure_reason": self.failure_reason,
        }

ENGINE_SPECS = {
    "slither": EngineSpec("slither", "solidity-static-analysis", "solidity-project", 180.0,
                          ("slither", ".", "--json", "-"), ("slither", "--version")),
    "forge": EngineSpec("forge", "foundry-build", "foundry-project", 180.0,
                        ("forge", "build", "--offline"), ("forge", "--version")),
}

class EngineOrchestrator:
    def __init__(self, specs: dict[str, EngineSpec] | None = None) -> None:
        self.specs = dict(specs or ENGINE_SPECS)

    def _version(self, spec: EngineSpec, root: Path, cancel=None) -> str | None:
        result = run_bounded(spec.version_command, cwd=root, timeout=min(15.0, spec.timeout_seconds),
                             max_output_bytes=16_384, cancel=cancel)
        if result.cancelled:
            raise OperationCancelled("ATLAS operation cancelled")
        if result.returncode != 0:
            return None
        lines = (result.stdout or result.stderr).strip().splitlines()
        return lines[0][:240] if lines else None

    def run(self, name: str, root: Path, *, cancel=None) -> EngineResult:
        spec = self.specs[name]
        executable = shutil.which(spec.command[0])
        if not executable:
            return EngineResult(name, spec.capability, spec.scope, False, False, "unavailable",
                                None, None, spec.timeout_seconds, spec.sandbox_policy,
                                failure_reason="executable-not-found")
        try:
            version = self._version(spec, root, cancel)
            started = time.perf_counter()
            result = run_bounded(spec.command, cwd=root, timeout=spec.timeout_seconds,
                                 max_output_bytes=2_000_000, cancel=cancel)
        except OSError as exc:
            return EngineResult(name, spec.capability, spec.scope, True, False, "failed",
                                None, executable, spec.timeout_seconds, spec.sandbox_policy,
                                failure_reason=f"{type(exc).__name__}: {exc}")
        if result.cancelled:
            raise OperationCancelled("ATLAS operation cancelled")
        elapsed = round(time.perf_counter() - started, 3)
        status = "timeout" if result.timed_out else "output_limited" if result.output_limited else "passed" if result.returncode == 0 else "failed"
        return EngineResult(name, spec.capability, spec.scope, True, True, status, version, executable,
                            spec.timeout_seconds, spec.sandbox_policy, tuple(result.command),
                            result.returncode, elapsed, result.stdout, result.stderr,
                            None if status == "passed" else status)

    def run_legacy(self, name: str, legacy_spec: dict[str, Any], root: Path, *, cancel=None) -> dict[str, Any]:
        if name in self.specs:
            return self.run(name, root, cancel=cancel).as_dict()
        factory: Callable[[Path], Sequence[str]] | None = legacy_spec.get("command")
        if factory is None:
            raise ValueError(f"legacy engine {name} has no command")
        spec = EngineSpec(name, str(legacy_spec.get("capability", "external-engine")),
                          str(legacy_spec.get("scope", "workspace")),
                          float(legacy_spec.get("timeout", 180)), tuple(factory(root)),
                          (name, "--version"))
        return EngineOrchestrator({name: spec}).run(name, root, cancel=cancel).as_dict()
