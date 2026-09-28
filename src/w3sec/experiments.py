from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from pathlib import Path

from .records import load_yaml_mapping
from .runtime import run_bounded


@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    id: str
    hypothesis: str
    command: tuple[str, ...]
    timeout_seconds: int = 60
    expected_exit: int = 0
    max_output_bytes: int = 1_048_576


@dataclass(frozen=True, slots=True)
class ExperimentResult:
    id: str
    returncode: int
    duration_seconds: float
    stdout: str
    stderr: str
    expected_exit: int
    timed_out: bool = False
    output_limited: bool = False

    @property
    def passed(self) -> bool:
        return (
            self.returncode == self.expected_exit
            and not self.timed_out
            and not self.output_limited
        )
def load_experiment(path: Path) -> ExperimentSpec:
    data = load_yaml_mapping(path)
    command = data.get("command", [])
    if not isinstance(command, list) or not all(isinstance(x, str) for x in command):
        raise ValueError(f"{path}: command must be a list of strings")
    timeout = int(data.get("timeout_seconds", 60))
    if timeout < 1 or timeout > 3600:
        raise ValueError(f"{path}: timeout_seconds must be in 1..3600")
    max_output = int(data.get("max_output_bytes", 1_048_576))
    if max_output < 1024 or max_output > 64 * 1024 * 1024:
        raise ValueError(f"{path}: max_output_bytes must be in 1024..67108864")
    if not data.get("id") or not data.get("hypothesis"):
        raise ValueError(f"{path}: id and hypothesis are required")
    return ExperimentSpec(
        id=str(data["id"]),
        hypothesis=str(data["hypothesis"]),
        command=tuple(command),
        timeout_seconds=timeout,
        expected_exit=int(data.get("expected_exit", 0)),
        max_output_bytes=max_output,
    )


def _experiment_env() -> dict[str, str]:
    allowed = {
        "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "TEMP", "TMP",
        "USERPROFILE", "HOME", "TMPDIR", "LANG", "LC_ALL", "CI", "GITHUB_ACTIONS",
    }
    return {key: value for key, value in os.environ.items() if key.upper() in allowed}


def run_experiment(spec: ExperimentSpec, cwd: Path) -> ExperimentResult:
    started = time.perf_counter()
    result = run_bounded(
        list(spec.command),
        cwd=cwd,
        timeout=spec.timeout_seconds,
        max_output_bytes=spec.max_output_bytes,
        env=_experiment_env(),
    )
    return ExperimentResult(
        id=spec.id,
        returncode=result.returncode,
        duration_seconds=time.perf_counter() - started,
        stdout=result.stdout,
        stderr=result.stderr,
        expected_exit=spec.expected_exit,
        timed_out=result.timed_out,
        output_limited=result.output_limited,
    )
def result_to_json(result: ExperimentResult) -> str:
    return json.dumps({
        "id": result.id,
        "passed": result.passed,
        "returncode": result.returncode,
        "expected_exit": result.expected_exit,
        "duration_seconds": round(result.duration_seconds, 6),
        "timed_out": result.timed_out,
        "output_limited": result.output_limited,
        "environment_policy": "minimal-system-only",
        "stdout": result.stdout,
        "stderr": result.stderr,
    }, indent=2, ensure_ascii=False)
