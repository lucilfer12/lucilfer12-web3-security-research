from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Sequence


def hidden_run(
    command: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: float | None = None,
    check: bool = False,
    capture_output: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    kwargs = {
        "cwd": str(cwd) if cwd else None,
        "capture_output": capture_output,
        "text": True,
        "timeout": timeout,
        "check": check,
        "env": env,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        kwargs["startupinfo"] = startupinfo
    return subprocess.run(list(command), **kwargs)
