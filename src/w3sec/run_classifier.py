"""Sound outcome classification for cargo/forge runs.

Exit codes alone are not evidence: `cargo test` exits 101 both when a test fails and when the
code does not compile; `forge test` exits 1 for both. A reproduction may only count when tests
actually executed. This module parses the tool output to tell those cases apart.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from collections.abc import Sequence

_CARGO_SUMMARY = re.compile(r"test result: (ok|FAILED)\. (\d+) passed; (\d+) failed")
_FORGE_SUMMARY = re.compile(r"Suite result: (ok|FAILED)\. (\d+) passed; (\d+) failed")
_CARGO_BUILD_ERR = re.compile(
    r"error: could not compile|error\[E\d{4}\]|error: failed to run custom build command|"
    r"error: failed to (?:parse|load) manifest|error: no matching package|error: failed to get `|"
    r"error: unable to get packages"
)
_FORGE_BUILD_ERR = re.compile(
    r"Compiler run failed|Error: Compiler|Unable to resolve imports|failed to resolve file|"
    r"error\[\d{4}\]"
)
_CARGO_FAILED_TEST = re.compile(r"^---- (\S+) stdout ----$", re.MULTILINE)
_FORGE_FAILED_TEST = re.compile(r"\[FAIL[^\]]*\]\s+([A-Za-z0-9_]+)\(")

KINDS = ("tests-failed", "tests-passed", "build-error", "no-tests-ran", "unknown")


@dataclass(frozen=True, slots=True)
class RunClass:
    kind: str
    passed: int
    failed: int
    failing_tests: tuple[str, ...]


def tool_and_subcommand(command: Sequence[str]) -> tuple[str | None, str | None]:
    if not command:
        return None, None
    name = str(command[0]).replace("\\", "/").rsplit("/", 1)[-1].lower()
    if name.endswith(".exe"):
        name = name[:-4]
    if name in {"cargo", "forge"} and len(command) > 1:
        return name, str(command[1]).lower()
    return None, None


def classify_run(tool: str, stdout: str, stderr: str) -> RunClass:
    text = f"{stdout}\n{stderr}"
    if tool == "cargo":
        summaries = _CARGO_SUMMARY.findall(text)
        build_error = bool(_CARGO_BUILD_ERR.search(text))
        names = _CARGO_FAILED_TEST.findall(text)
    elif tool == "forge":
        summaries = _FORGE_SUMMARY.findall(text)
        build_error = bool(_FORGE_BUILD_ERR.search(text))
        names = _FORGE_FAILED_TEST.findall(text)
    else:
        return RunClass("unknown", 0, 0, ())
    passed = sum(int(p) for _, p, _ in summaries)
    failed = sum(int(f) for _, _, f in summaries)
    unique = tuple(dict.fromkeys(names))
    if build_error:
        return RunClass("build-error", passed, failed, unique)
    if failed > 0:
        return RunClass("tests-failed", passed, failed, unique)
    if summaries and passed > 0:
        return RunClass("tests-passed", passed, failed, unique)
    if summaries:
        return RunClass("no-tests-ran", passed, failed, unique)
    return RunClass("unknown", passed, failed, unique)
