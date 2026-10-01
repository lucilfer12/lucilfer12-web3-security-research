from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


DEFAULT_MAX_OUTPUT_BYTES = 1_048_576
_HOST_IS_WINDOWS = os.name == "nt"


@dataclass(frozen=True, slots=True)
class BoundedRunResult:
    command: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limited: bool = False
    cancelled: bool = False


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


def _sandbox_command(
    command: Sequence[str],
    *,
    cwd: Path | None,
    env: Mapping[str, str],
) -> tuple[str, ...]:
    """Wrap untrusted test execution in a Linux namespace sandbox when requested.

    Bubblewrap provides a private PID/user/network namespace, a read-only system view,
    hidden home directories, a writable disposable work tree, and a minimal environment.
    It is opt-in so normal local development keeps the existing execution path.
    """
    if _HOST_IS_WINDOWS or str(env.get("ATLAS_EXECUTION_SANDBOX", os.environ.get("ATLAS_EXECUTION_SANDBOX", ""))).lower() != "bwrap":
        return tuple(command)
    if cwd is None or not cwd.exists():
        raise ValueError("bubblewrap sandbox requires an existing working directory")
    bwrap = shutil.which("bwrap")
    if not bwrap:
        raise RuntimeError("ATLAS_EXECUTION_SANDBOX=bwrap requested, but bubblewrap is not installed")

    path = str(cwd.resolve())
    args: list[str] = [
        bwrap,
        "--die-with-parent",
        "--unshare-all",
        "--new-session",
        "--ro-bind", "/", "/",
        "--tmpfs", "/home",
        "--tmpfs", "/root",
        "--tmpfs", "/run",
        "--tmpfs", "/tmp",
        "--bind", path, "/atlas-work",
        "--chdir", "/atlas-work",
        "--proc", "/proc",
        "--dev", "/dev",
        "--clearenv",
        "--setenv", "PATH", env.get("PATH", os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")),
        "--setenv", "HOME", "/root",
        "--setenv", "TMPDIR", "/tmp",
    ]

    # Keep compiler/test tools reachable when distributions place them in $HOME,
    # without exposing the rest of the host user's home directory.
    tool_paths = []
    for binary in (str(command[0]), "cargo", "forge", "rustc"):
        resolved = shutil.which(binary, path=env.get("PATH")) or (binary if Path(binary).is_file() else None)
        if resolved:
            tool_paths.append(Path(resolved).resolve())
    mounted_dirs: set[str] = set()
    for tool in tool_paths:
        parent = str(tool.parent)
        if parent.startswith("/home/"):
            parts = Path(parent).parts
            current = Path("/home")
            for part in parts[2:]:
                current /= part
                args.extend(["--dir", str(current)])
            if str(parent) not in mounted_dirs:
                args.extend(["--ro-bind", parent, parent])
                mounted_dirs.add(str(parent))

    # Cargo's offline registry/git cache is bind-mounted read-only when present.
    for cache in (
        Path.home() / ".cargo" / "registry",
        Path.home() / ".cargo" / "git",
        Path.home() / ".rustup",
        Path.home() / ".foundry",
    ):
        resolved_cache = cache.resolve()
        if resolved_cache.is_dir() and str(resolved_cache).startswith("/home/"):
            parts = resolved_cache.parts
            current = Path("/home")
            for part in parts[2:]:
                current /= part
                args.extend(["--dir", str(current)])
            args.extend(["--ro-bind", str(resolved_cache), str(resolved_cache)])

    args.extend(["--", *map(str, command)])
    return tuple(args)


def run_bounded(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
    env: Mapping[str, str] | None = None,
    env_allowlist: Sequence[str] | None = None,
    cancel=None,
) -> BoundedRunResult:
    if not command or not all(isinstance(part, str) and part for part in command):
        raise ValueError("command must be a non-empty sequence of strings")
    if max_output_bytes < 1024:
        raise ValueError("max_output_bytes must be >= 1024")

    effective_env = _safe_env(env, env_allowlist)
    effective_command = _sandbox_command(command, cwd=cwd, env=effective_env)
    process = subprocess.Popen(
        list(effective_command),
        cwd=None if len(effective_command) != len(tuple(command)) else (str(cwd) if cwd else None),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL,
        text=False,
        env=effective_env,
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
    cancelled = False
    started = time.monotonic()
    while process.poll() is None:
        if cancel and cancel():
            cancelled = True
            try:
                process.terminate()
                process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
            break
        if timeout is not None and time.monotonic() - started >= timeout:
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
            break
        time.sleep(0.05)
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
        cancelled=cancelled,
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
