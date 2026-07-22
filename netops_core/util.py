from __future__ import annotations

import os
import platform
import math
import json
import shutil
import subprocess
import time
import re
import signal
import stat
import threading
import unicodedata
from contextlib import contextmanager
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator


MAX_CAPTURE_CHARS = 64_000
MAX_CAPTURE_LIMIT = 1_048_576
MAX_INPUT_CHARS = 4 * 1_048_576
MAX_JSON_BYTES = 32 * 1_048_576
MAX_JSON_NESTING_DEPTH = 128
MAX_JSON_NODES = 500_000
MAX_JSON_COLLECTION_ITEMS = 100_000
TRUSTED_POSIX_SEARCH_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_ANSI_ESCAPE_RE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\|$)|"
    r"[PX^_][^\x1b]*(?:\x1b\\|$)|[@-_])"
)


def _sanitize_process_output(value: Any) -> str:
    """Keep command evidence readable without returning terminal controls."""

    if isinstance(value, bytes):
        value = value.decode(errors="replace")
    text = str(value or "").replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_ESCAPE_RE.sub("", text)
    return "".join(
        character
        if character in {"\n", "\t"}
        or (
            unicodedata.category(character) not in {"Cc", "Cf"}
            and character not in {"\u2028", "\u2029"}
        )
        else " "
        for character in text
    )


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number is not allowed: {value}")


def _parse_json_integer(value: str) -> int:
    if len(value.lstrip("-")) > 128:
        raise ValueError("JSON integer exceeds the 128-digit limit")
    return int(value)


def _parse_json_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number is not allowed")
    return parsed


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key is not allowed: {key!r}")
        result[key] = value
    return result


def _validate_json_structure(value: Any) -> None:
    stack: list[tuple[Any, int]] = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("JSON document exceeds the node limit")
        if depth > MAX_JSON_NESTING_DEPTH:
            raise ValueError("JSON nesting exceeds the structural depth limit")
        if isinstance(item, list):
            if len(item) > MAX_JSON_COLLECTION_ITEMS:
                raise ValueError("JSON array exceeds the item limit")
            stack.extend((child, depth + 1) for child in reversed(item))
        elif isinstance(item, dict):
            if len(item) > MAX_JSON_COLLECTION_ITEMS:
                raise ValueError("JSON object exceeds the property limit")
            stack.extend(
                (child, depth + 1) for child in reversed(list(item.values()))
            )


def parse_json_strict(value: str | bytes | bytearray) -> Any:
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("utf-8", errors="strict")
    if not isinstance(value, str):
        raise TypeError("strict JSON input must be text or bytes")
    try:
        parsed = json.loads(
            value,
            parse_constant=_reject_json_constant,
            parse_int=_parse_json_integer,
            parse_float=_parse_json_float,
            object_pairs_hook=_unique_json_object,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the parser depth limit") from exc
    _validate_json_structure(parsed)
    return parsed


def load_json_limited(
    path: str | Path,
    *,
    max_bytes: int = MAX_JSON_BYTES,
) -> Any:
    """Load one strict UTF-8 JSON document without unbounded file reads."""

    if type(max_bytes) is not int or not 1 <= max_bytes <= MAX_JSON_BYTES:
        raise ValueError(f"max_bytes must be an integer from 1 to {MAX_JSON_BYTES}")
    payload = read_regular_bytes_limited(
        path,
        limit=max_bytes + 1,
        reject_size_over=max_bytes,
    )
    if len(payload) > max_bytes:
        raise ValueError(f"JSON document exceeds the {max_bytes}-byte limit: {path}")
    return parse_json_strict(payload)


@contextmanager
def open_regular_binary(
    path: str | Path,
    *,
    follow_final_symlink: bool = False,
) -> Iterator[BinaryIO]:
    """Open one stable regular-file inode without following the final link."""

    source = Path(os.path.abspath(Path(path).expanduser()))
    try:
        before = source.lstat()
    except OSError as exc:
        raise ValueError(f"input file cannot be inspected: {source}") from exc
    if stat.S_ISLNK(before.st_mode) and follow_final_symlink:
        try:
            resolved = source.resolve(strict=True)
        except OSError as exc:
            raise ValueError(f"input link target cannot be resolved: {source}") from exc
        with open_regular_binary(resolved) as handle:
            yield handle
        return
    if stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"input path must be a regular file: {source}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(source, flags)
    except OSError as exc:
        raise ValueError(f"input file cannot be opened safely: {source}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError(f"input file changed while being opened: {source}")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = -1
            yield handle
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_regular_bytes_limited(
    path: str | Path,
    *,
    limit: int,
    reject_size_over: int | None = None,
    follow_final_symlink: bool = False,
) -> bytes:
    if type(limit) is not int or not 0 <= limit <= MAX_JSON_BYTES + 1:
        raise ValueError("regular-file read limit is invalid")
    if reject_size_over is not None and (
        type(reject_size_over) is not int
        or not 0 <= reject_size_over <= MAX_JSON_BYTES
    ):
        raise ValueError("regular-file size limit is invalid")
    with open_regular_binary(
        path,
        follow_final_symlink=follow_final_symlink,
    ) as handle:
        before = os.fstat(handle.fileno())
        if reject_size_over is not None and before.st_size > reject_size_over:
            raise ValueError("input file exceeds the size limit")
        payload = handle.read(limit)
        after = os.fstat(handle.fileno())
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        ):
            raise ValueError("input file changed while being read")
        return payload


def platform_id() -> str:
    name = platform.system().lower()
    if name == "darwin":
        return "macos"
    if name == "windows":
        return "windows"
    if name == "linux":
        return "linux"
    return name or "unknown"


def trusted_system_environment(
    *,
    include_home: bool = False,
    include_ssh_auth: bool = False,
    platform_name: str | None = None,
) -> dict[str, str]:
    """Build a minimal environment for bundled operating-system commands.

    The caller's PATH, proxy variables, application tokens and arbitrary
    process environment are intentionally excluded. Explicit third-party tool
    overrides are handled separately by their reviewed adapters.
    """

    current = platform_name or platform_id()
    if current == "windows":
        system_root = (
            os.environ.get("SYSTEMROOT")
            or os.environ.get("SystemRoot")
            or os.environ.get("WINDIR")
            or r"C:\Windows"
        )
        root = system_root.rstrip("\\/")
        paths = [
            root + r"\System32\OpenSSH",
            root + r"\System32",
            root + r"\System32\WindowsPowerShell\v1.0",
            root,
        ]
        result = {
            "PATH": ";".join(paths),
            "SYSTEMROOT": system_root,
            "SystemRoot": system_root,
            "WINDIR": system_root,
            "COMSPEC": os.environ.get(
                "COMSPEC", root + r"\System32\cmd.exe"
            ),
            "PATHEXT": os.environ.get(
                "PATHEXT", ".COM;.EXE;.BAT;.CMD"
            ),
        }
        for key in ("TEMP", "TMP"):
            value = os.environ.get(key)
            if value:
                result[key] = value
    else:
        result = {"PATH": TRUSTED_POSIX_SEARCH_PATH}
        for key in ("LANG", "LC_ALL", "LC_CTYPE", "TMPDIR"):
            value = os.environ.get(key)
            if value:
                result[key] = value
    if include_home:
        for key in ("HOME", "USER", "LOGNAME", "USERPROFILE"):
            value = os.environ.get(key)
            if value:
                result[key] = value
    if include_ssh_auth:
        value = os.environ.get("SSH_AUTH_SOCK")
        if value:
            result["SSH_AUTH_SOCK"] = value
    return result


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def first_command(candidates: Iterable[str]) -> str | None:
    for candidate in candidates:
        if command_exists(candidate):
            return candidate
    return None


def _create_windows_kill_job() -> int:
    """Create a Job Object that kills every assigned process when closed."""

    import ctypes
    from ctypes import wintypes

    class IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BASIC_LIMIT_INFORMATION),
            ("IoInfo", IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateJobObjectW(None, None)
    if not handle:
        raise ctypes.WinError(ctypes.get_last_error())
    information = EXTENDED_LIMIT_INFORMATION()
    information.BasicLimitInformation.LimitFlags = 0x00002000
    if not kernel32.SetInformationJobObject(
        handle,
        9,
        ctypes.byref(information),
        ctypes.sizeof(information),
    ):
        error = ctypes.WinError(ctypes.get_last_error())
        kernel32.CloseHandle(handle)
        raise error
    return int(handle)


def _assign_and_resume_windows_job(job_handle: int, process_handle: int) -> None:
    """Atomically contain a newly created suspended process before it runs."""

    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    if not kernel32.AssignProcessToJobObject(job_handle, process_handle):
        raise ctypes.WinError(ctypes.get_last_error())
    ntdll = ctypes.WinDLL("ntdll")
    ntdll.NtResumeProcess.argtypes = [wintypes.HANDLE]
    ntdll.NtResumeProcess.restype = wintypes.LONG
    status = ntdll.NtResumeProcess(process_handle)
    if status != 0:
        raise OSError(f"NtResumeProcess failed with NTSTATUS 0x{status & 0xFFFFFFFF:08x}")


def _terminate_windows_job(job_handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.TerminateJobObject.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel32.TerminateJobObject.restype = wintypes.BOOL
    kernel32.TerminateJobObject(job_handle, 1)


def _close_windows_job(job_handle: int) -> None:
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.CloseHandle(job_handle)


def run_command(
    args: list[str],
    *,
    timeout: float = 8,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    inherit_env: bool = True,
    cwd: str | Path | None = None,
    capture_limit: int = MAX_CAPTURE_CHARS,
) -> dict[str, Any]:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or not 0.01 <= timeout <= 3_600
    ):
        raise ValueError("timeout must be a finite number from 0.01 to 3600 seconds")
    if type(capture_limit) is not int or not 1 <= capture_limit <= MAX_CAPTURE_LIMIT:
        raise ValueError(
            f"capture_limit must be an integer from 1 to {MAX_CAPTURE_LIMIT}"
        )
    if input_text is not None and (
        not isinstance(input_text, str) or len(input_text) > MAX_INPUT_CHARS
    ):
        raise ValueError(
            f"input_text must be a string of at most {MAX_INPUT_CHARS} characters"
        )
    started = time.monotonic()
    safe_env = os.environ.copy() if inherit_env else {}
    if env:
        safe_env.update(env)
    executable = (
        shutil.which(args[0], path=safe_env.get("PATH", "")) if args else None
    )
    if not args or executable is None:
        return {
            "available": False,
            "command": args[:1],
            "returncode": None,
            "stdout": "",
            "stderr": f"command not found: {args[0] if args else '<empty>'}",
            "duration_ms": 0,
            "timed_out": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
        }
    stdout_tail = bytearray()
    stderr_tail = bytearray()
    stdout_truncated = [False]
    stderr_truncated = [False]
    # ``capture_limit`` is a limit on the sanitized text returned to callers.
    # Retain at most four UTF-8 bytes per requested character while streaming,
    # then enforce the character limit after decoding and CRLF normalization.
    raw_capture_limit = capture_limit * 4

    def drain(stream: Any, tail: bytearray, truncated: list[bool]) -> None:
        try:
            while True:
                block = stream.read(65_536)
                if not block:
                    break
                tail.extend(block)
                overflow = len(tail) - raw_capture_limit
                if overflow > 0:
                    truncated[0] = True
                    del tail[:overflow]
        except (OSError, ValueError):
            pass
        finally:
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    encoding = "utf-8"
    command = [executable, *args[1:]]
    creationflags = 0
    windows_job: int | None = None
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
        creationflags |= getattr(subprocess, "CREATE_SUSPENDED", 0x00000004)
        try:
            windows_job = _create_windows_kill_job()
        except Exception as exc:
            return {
                "available": False,
                "command": args[:1],
                "returncode": None,
                "stdout": "",
                "stderr": _sanitize_process_output(exc),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "timed_out": False,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }
    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE if input_text is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=safe_env,
            cwd=str(cwd) if cwd else None,
            start_new_session=os.name == "posix",
            creationflags=creationflags,
            bufsize=0,
        )
    except (OSError, ValueError) as exc:
        if windows_job is not None:
            _close_windows_job(windows_job)
        return {
            "available": False,
            "command": args[:1],
            "returncode": None,
            "stdout": "",
            "stderr": _sanitize_process_output(exc),
            "duration_ms": int((time.monotonic() - started) * 1000),
            "timed_out": False,
            "stdout_truncated": False,
            "stderr_truncated": False,
        }

    if windows_job is not None:
        try:
            _assign_and_resume_windows_job(windows_job, int(process._handle))
        except Exception as exc:
            _terminate_windows_job(windows_job)
            try:
                process.kill()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
            _close_windows_job(windows_job)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass
            return {
                "available": False,
                "command": args[:1],
                "returncode": None,
                "stdout": "",
                "stderr": _sanitize_process_output(exc),
                "duration_ms": int((time.monotonic() - started) * 1000),
                "timed_out": False,
                "stdout_truncated": False,
                "stderr_truncated": False,
            }

    assert process.stdout is not None and process.stderr is not None
    readers = [
        threading.Thread(
            target=drain,
            args=(process.stdout, stdout_tail, stdout_truncated),
            daemon=True,
        ),
        threading.Thread(
            target=drain,
            args=(process.stderr, stderr_tail, stderr_truncated),
            daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    writer: threading.Thread | None = None
    if input_text is not None:
        assert process.stdin is not None

        def write_input() -> None:
            try:
                process.stdin.write(input_text.encode(encoding, errors="replace"))
                process.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                pass
            finally:
                try:
                    process.stdin.close()
                except (OSError, ValueError):
                    pass

        writer = threading.Thread(target=write_input, daemon=True)
        writer.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGKILL)
            elif windows_job is not None:
                _terminate_windows_job(windows_job)
            else:
                process.kill()
        except (OSError, ProcessLookupError):
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
    finally:
        # A command can fork background work and let its direct parent exit.
        # Terminate processes that remain in this call's private POSIX process
        # group. A deliberately detached new session is outside this boundary.
        if os.name == "posix":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        elif windows_job is not None:
            # Closing a KILL_ON_JOB_CLOSE Job Object also terminates descendants
            # left behind after a successful direct parent has already exited.
            _close_windows_job(windows_job)
            windows_job = None
        if writer is not None:
            writer.join(timeout=2)
        for reader in readers:
            reader.join(timeout=2)
        for stream in (process.stdout, process.stderr):
            try:
                stream.close()
            except (OSError, ValueError):
                pass
        for reader in readers:
            reader.join(timeout=1)

    def bounded_output(tail: bytearray, truncated: list[bool]) -> str:
        output = _sanitize_process_output(
            bytes(tail).decode(encoding, errors="replace")
        )
        if len(output) > capture_limit:
            truncated[0] = True
            output = output[-capture_limit:]
        return output

    stdout = bounded_output(stdout_tail, stdout_truncated)
    stderr = bounded_output(stderr_tail, stderr_truncated)
    duration = int((time.monotonic() - started) * 1000)
    if not timed_out:
        return {
            "available": True,
            "command": [args[0]],
            "returncode": process.returncode,
            "stdout": stdout,
            "stderr": stderr,
            "duration_ms": duration,
            "timed_out": False,
            "stdout_truncated": stdout_truncated[0],
            "stderr_truncated": stderr_truncated[0],
        }
    return {
        "available": True,
        "command": [args[0]],
        "returncode": None,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": duration,
        "timed_out": True,
        "stdout_truncated": stdout_truncated[0],
        "stderr_truncated": stderr_truncated[0],
    }


def read_text_limited(path: str | Path, limit: int = MAX_CAPTURE_CHARS) -> str:
    if type(limit) is not int or not 0 <= limit <= MAX_CAPTURE_LIMIT:
        raise ValueError(
            f"text read limit must be an integer from 0 to {MAX_CAPTURE_LIMIT}"
        )
    try:
        return read_regular_bytes_limited(
            path,
            limit=limit,
            follow_final_symlink=True,
        ).decode(
            "utf-8", errors="replace"
        )
    except (OSError, ValueError):
        return ""


def executable_path(path: str | Path) -> str | None:
    candidate = Path(path)
    if candidate.is_file() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None
