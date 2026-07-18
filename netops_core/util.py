from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Iterable


MAX_CAPTURE_CHARS = 64_000


def platform_id() -> str:
    name = platform.system().lower()
    if name == "darwin":
        return "macos"
    if name == "windows":
        return "windows"
    if name == "linux":
        return "linux"
    return name or "unknown"


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def first_command(candidates: Iterable[str]) -> str | None:
    for candidate in candidates:
        if command_exists(candidate):
            return candidate
    return None


def run_command(
    args: list[str],
    *,
    timeout: float = 8,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    started = time.monotonic()
    executable = shutil.which(args[0]) if args else None
    if not args or executable is None:
        return {
            "available": False,
            "command": args[:1],
            "returncode": None,
            "stdout": "",
            "stderr": f"command not found: {args[0] if args else '<empty>'}",
            "duration_ms": 0,
            "timed_out": False,
        }
    safe_env = os.environ.copy()
    if env:
        safe_env.update(env)
    try:
        completed = subprocess.run(
            args,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=safe_env,
            cwd=str(cwd) if cwd else None,
        )
        duration = int((time.monotonic() - started) * 1000)
        return {
            "available": True,
            "command": [args[0]],
            "returncode": completed.returncode,
            "stdout": completed.stdout[-MAX_CAPTURE_CHARS:],
            "stderr": completed.stderr[-MAX_CAPTURE_CHARS:],
            "duration_ms": duration,
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        duration = int((time.monotonic() - started) * 1000)
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")
        return {
            "available": True,
            "command": [args[0]],
            "returncode": None,
            "stdout": stdout[-MAX_CAPTURE_CHARS:],
            "stderr": stderr[-MAX_CAPTURE_CHARS:],
            "duration_ms": duration,
            "timed_out": True,
        }


def read_text_limited(path: str | Path, limit: int = MAX_CAPTURE_CHARS) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
    except (OSError, PermissionError):
        return ""


def executable_path(path: str | Path) -> str | None:
    candidate = Path(path)
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None
