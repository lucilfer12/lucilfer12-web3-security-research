from __future__ import annotations

import os
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


DEFAULT_MAX_OUTPUT_BYTES = 1_048_576


@dataclass(frozen=True, slots=True)
class BoundedRunResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limited: bool = False


def _windows_kwargs() -> dict[str, object]:
    if os.name != "nt":
        return {}
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return {
        "creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000),
        "startupinfo": startupinfo,
    }


def _safe_env(env: Mapping[str, str] | None, allowlist: Sequence[str] | None) -> dict[str, str]:
    source = dict(os.environ if env is None else env)
    if allowlist is None:
        return source
    allowed = set(allowlist)
    return {key: value for key, value in source.items() if key in allowed}


def run_bounded(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    env: Mapping[str, str] | None = None,
    env_allowlist: Sequence[str] | None = None,
) -> BoundedRunResult:
    if not command or not all(isinstance(part, str) and part for part in command):
        raise ValueError("command must be a non-empty sequence of strings")
    if max_output_bytes < 1024:
        raise ValueError("max_output_bytes must be >= 1024")

    process = subprocess.Popen(
        list(command),
        cwd=str(cwd) if cwd else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=False,
        env=_safe_env(env, env_allowlist),
        **_windows_kwargs(),
    )
    stdout = bytearray()
    stderr = bytearray()
    limited = threading.Event()
    output_lock = threading.Lock()

    def pump(stream, bucket: bytearray) -> None:
        while True:
            chunk = stream.read(8192)
            if not chunk:
                return
            with output_lock:
                remaining = max_output_bytes - len(stdout) - len(stderr)
                if remaining <= 0:
                    limited.set()
                    chunk_to_store = b""
                else:
                    chunk_to_store = chunk[:remaining]
                    bucket.extend(chunk_to_store)
                    if len(chunk) > remaining:
                        limited.set()
            if limited.is_set():
                try:
                    process.terminate()
                except OSError:
                    pass
                return

    threads = [
        threading.Thread(target=pump, args=(process.stdout, stdout), daemon=True),
        threading.Thread(target=pump, args=(process.stderr, stderr), daemon=True),
    ]
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            process.terminate()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            try:
                process.kill()
            except OSError:
                pass
            process.wait()
    for thread in threads:
        thread.join(timeout=2)
    for stream in (process.stdout, process.stderr):
        try:
            stream.close()
        except Exception:
            pass

    return BoundedRunResult(
        command=tuple(command),
        returncode=process.returncode,
        stdout=bytes(stdout).decode("utf-8", errors="replace"),
        stderr=bytes(stderr).decode("utf-8", errors="replace"),
        timed_out=timed_out,
        output_limited=limited.is_set(),
    )


def hidden_run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    check: bool = False,
    capture_output: bool = True,
    env: dict[str, str] | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
) -> subprocess.CompletedProcess[str]:
    if not capture_output:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd) if cwd else None,
            stdin=subprocess.DEVNULL,
            text=True,
            timeout=timeout,
            check=check,
            env=env,
            **_windows_kwargs(),
        )
        return completed

    result = run_bounded(
        command,
        cwd=cwd,
        timeout=timeout,
        max_output_bytes=max_output_bytes,
        env=env,
    )
    completed = subprocess.CompletedProcess(
        list(command), result.returncode, result.stdout, result.stderr
    )
    if check and result.returncode != 0:
        raise subprocess.CalledProcessError(
            result.returncode, list(command), output=result.stdout, stderr=result.stderr
        )
    return completed
