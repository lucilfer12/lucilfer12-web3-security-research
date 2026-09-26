from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass(frozen=True, slots=True)
class ExperimentSpec:
    id: str
    hypothesis: str
    command: tuple[str, ...]
    timeout_seconds: int = 60
    expected_exit: int = 0


@dataclass(frozen=True, slots=True)
class ExperimentResult:
    id: str
    returncode: int
    duration_seconds: float
    stdout: str
    stderr: str
    expected_exit: int

    @property
    def passed(self) -> bool:
        return self.returncode == self.expected_exit
def load_experiment(path: Path) -> ExperimentSpec:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path}: experiment root must be a mapping")
    command = data.get("command", [])
    if not isinstance(command, list) or not all(isinstance(x, str) for x in command):
        raise ValueError(f"{path}: command must be a list of strings")
    timeout = int(data.get("timeout_seconds", 60))
    if timeout < 1 or timeout > 3600:
        raise ValueError(f"{path}: timeout_seconds must be in 1..3600")
    return ExperimentSpec(
        id=str(data["id"]),
        hypothesis=str(data["hypothesis"]),
        command=tuple(command),
        timeout_seconds=timeout,
        expected_exit=int(data.get("expected_exit", 0)),
    )


def run_experiment(spec: ExperimentSpec, cwd: Path) -> ExperimentResult:
    started = time.perf_counter()
    env = os.environ.copy()
    completed = subprocess.run(
        list(spec.command), cwd=cwd, capture_output=True, text=True,
        timeout=spec.timeout_seconds, env=env, check=False,
    )
    return ExperimentResult(
        id=spec.id,
        returncode=completed.returncode,
        duration_seconds=time.perf_counter() - started,
        stdout=completed.stdout,
        stderr=completed.stderr,
        expected_exit=spec.expected_exit,
    )
def result_to_json(result: ExperimentResult) -> str:
    return json.dumps({
        "id": result.id,
        "passed": result.passed,
        "returncode": result.returncode,
        "expected_exit": result.expected_exit,
        "duration_seconds": round(result.duration_seconds, 6),
        "stdout": result.stdout,
        "stderr": result.stderr,
    }, indent=2, ensure_ascii=False)
