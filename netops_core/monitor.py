from __future__ import annotations

import hashlib
import json
import math
import os
import plistlib
import shlex
import shutil
import stat
import sys
import tempfile
import time
import unicodedata
from pathlib import Path
from typing import Any

from .models import (
    DiagnosticBundle,
    Observation,
    utc_now,
    validate_bundle_data,
    write_bundle,
    write_json_atomic,
)
from .scanner import (
    _validate_declared_target,
    scan_client,
    scan_node,
    scan_server_local,
    trace_target,
)
from .util import (
    parse_json_strict,
    platform_id,
    run_command,
    trusted_system_environment,
)


DEFAULTS = {
    "interval_seconds": 60,
    "full_interval_seconds": 900,
    "failure_threshold": 3,
    "incident_interval_seconds": 5,
    "incident_duration_seconds": 600,
    "retention_days": 7,
    "max_bytes": 200 * 1024 * 1024,
}
SETTING_LIMITS = {
    "interval_seconds": (10, 86_400),
    "full_interval_seconds": (60, 604_800),
    "failure_threshold": (1, 100),
    "incident_interval_seconds": (1, 3_600),
    "incident_duration_seconds": (10, 86_400),
    "retention_days": (1, 365),
    "max_bytes": (1_048_576, 10 * 1024 * 1024 * 1024),
}
STATE_MARKER_NAME = ".netops-monitor-state"
STATE_MARKER_INSTALLING_CONTENT = "netops-monitor-state-v2:installing\n"
STATE_MARKER_CONTENT = "netops-monitor-state-v2:active\n"
STATE_MARKER_REMOVING_CONTENT = "netops-monitor-state-v2:removing\n"
STATE_MARKER_REMOVED_CONTENT = "netops-monitor-state-v2:removed\n"
STATE_MANIFEST_NAME = ".netops-monitor-files.json"
MAX_MONITOR_CONTROL_FILE_BYTES = 1024 * 1024
MAX_MONITOR_STATE_FILE_BYTES = 256 * 1024
MAX_SNAPSHOT_FILES = 10_000
MAX_SNAPSHOT_DIRECTORY_ENTRIES = 20_000
MAX_REPORTED_REMOVALS = 1_000
MAX_MONITOR_FAILURE_COUNT = 10_000
MAX_MONITOR_CLOCK_SKEW_SECONDS = 300
SCHEDULED_MONITOR_MUTATION_AVAILABLE = False
SCHEDULED_MONITOR_MUTATION_UNAVAILABLE = (
    "scheduled monitor mutation is unavailable in this release"
)


def _run_scheduler_command(
    command: list[str], *, timeout: float
) -> dict[str, Any]:
    # Lowest scheduler-execution sink. Keep the release gate here as well as in
    # public/private lifecycle wrappers so direct imports cannot bypass it.
    _ = (command, timeout)
    raise RuntimeError(SCHEDULED_MONITOR_MUTATION_UNAVAILABLE)


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(os.path, "isjunction", None)
    if is_junction and is_junction(path):
        return True
    if os.name != "nt":
        return False
    # os.path.isjunction is unavailable on Python 3.10/3.11. Reject every
    # Windows reparse point conservatively so a junction cannot redirect a
    # privileged config, state, or scheduler path on supported runtimes.
    try:
        import ctypes

        get_attributes = ctypes.windll.kernel32.GetFileAttributesW
        get_attributes.argtypes = [ctypes.c_wchar_p]
        get_attributes.restype = ctypes.c_uint32
        attributes = get_attributes(os.fspath(path))
    except (AttributeError, OSError, TypeError):
        return True
    if attributes == 0xFFFFFFFF:
        return True
    return bool(attributes & 0x0400)


def _assert_real_directory(
    path: Path, *, identity: tuple[int, int] | None = None
) -> tuple[int, int]:
    try:
        info = path.lstat()
    except OSError as exc:
        raise ValueError(f"monitor directory is unavailable: {path}") from exc
    trusted_macos_alias = (
        sys.platform == "darwin"
        and str(path) in {"/etc", "/tmp", "/var"}
        and path.is_symlink()
    )
    if trusted_macos_alias:
        info = path.stat()
    if (_is_link_like(path) and not trusted_macos_alias) or not stat.S_ISDIR(
        info.st_mode
    ):
        raise ValueError(f"monitor path must be a real directory: {path}")
    current = (info.st_dev, info.st_ino)
    if identity is not None and current != identity:
        raise ValueError(f"monitor directory changed during operation: {path}")
    return current


def _directory_chain(path: Path) -> list[Path]:
    absolute = Path(os.path.abspath(path.expanduser()))
    chain: list[Path] = []
    current = absolute
    while current != current.parent:
        chain.append(current)
        current = current.parent
    chain.append(current)
    chain.reverse()
    return chain


def _secure_directory(
    path: Path,
    *,
    create: bool,
    mode: int = 0o700,
    enforce_mode: bool = True,
) -> tuple[int, int]:
    absolute = Path(os.path.abspath(path.expanduser()))
    for candidate in _directory_chain(absolute):
        if os.path.lexists(candidate):
            _assert_real_directory(candidate)
            continue
        if not create:
            raise ValueError(f"monitor directory does not exist: {candidate}")
        try:
            candidate.mkdir(mode=mode)
        except FileExistsError:
            pass
        _assert_real_directory(candidate)
    identity = _assert_real_directory(absolute)
    if os.name != "nt" and enforce_mode:
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(absolute, flags)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != identity:
                raise ValueError(f"monitor directory changed during operation: {absolute}")
            os.fchmod(descriptor, mode)
        finally:
            os.close(descriptor)
    return identity


def _read_regular_bytes(
    path: Path,
    *,
    label: str,
    max_bytes: int = MAX_MONITOR_CONTROL_FILE_BYTES,
) -> bytes:
    if (
        type(max_bytes) is not int
        or not 1 <= max_bytes <= MAX_MONITOR_CONTROL_FILE_BYTES
    ):
        raise ValueError("monitor file byte limit is invalid")
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError(f"{label} cannot be read") from exc
    if _is_link_like(path) or not stat.S_ISREG(before.st_mode):
        raise ValueError(f"{label} must be a regular file")
    if before.st_size > max_bytes:
        raise ValueError(f"{label} is unexpectedly large")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_BINARY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError(f"{label} cannot be read") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            or opened.st_size > max_bytes
        ):
            raise ValueError(f"{label} changed while being opened")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > max_bytes:
            raise ValueError(f"{label} is unexpectedly large")
        return payload
    finally:
        os.close(descriptor)


def _read_control_text(path: Path, *, label: str) -> str | None:
    if not os.path.lexists(path):
        return None
    try:
        return _read_regular_bytes(path, label=label).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"{label} is not valid UTF-8") from exc


def _chmod_regular_file(path: Path, mode: int) -> None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(f"monitor file must be regular: {path}")
        os.fchmod(descriptor, mode)
    finally:
        os.close(descriptor)


def _owned_file_paths(paths: dict[str, Path]) -> list[Path]:
    owned = [paths["config"]]
    owned.extend(paths[key] for key in ("service", "timer", "plist") if key in paths)
    return owned


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _manifest_payload(files: dict[str, str | bytes]) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "files": {
            path: _sha256_bytes(
                content if isinstance(content, bytes) else content.encode("utf-8")
            )
            for path, content in sorted(files.items())
        },
    }


def _read_manifest(state: Path) -> dict[str, Any] | None:
    path = state / STATE_MANIFEST_NAME
    text = _read_control_text(path, label="monitor ownership manifest")
    if text is None:
        return None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("monitor ownership manifest is invalid") from exc
    if (
        not isinstance(data, dict)
        or data.get("schema_version") != "1.0"
        or not isinstance(data.get("files"), dict)
        or not all(
            isinstance(path, str)
            and isinstance(digest, str)
            and len(digest) == 64
            for path, digest in data["files"].items()
        )
    ):
        raise ValueError("monitor ownership manifest is invalid")
    return data


def _verify_owner_manifest(paths: dict[str, Path], *, allow_missing: bool) -> None:
    manifest = _read_manifest(paths["state"])
    expected_paths = {str(path) for path in _owned_file_paths(paths)}
    if manifest is None or set(manifest["files"]) != expected_paths:
        raise ValueError("monitor ownership manifest is missing or incomplete")
    for path in _owned_file_paths(paths):
        if not os.path.lexists(path):
            if allow_missing:
                continue
            raise ValueError("an owned monitor file is missing")
        payload = _read_regular_bytes(path, label="owned monitor file")
        if _sha256_bytes(payload) != manifest["files"][str(path)]:
            raise ValueError("an owned monitor file was modified outside NetOps")


def _owner_state(paths: dict[str, Path]) -> str:
    content = _read_control_text(
        paths["state"] / STATE_MARKER_NAME,
        label="monitor state ownership marker",
    )
    if content is None:
        return "missing"
    if content == STATE_MARKER_INSTALLING_CONTENT:
        return "installing"
    if content == STATE_MARKER_CONTENT:
        return "active"
    if content == STATE_MARKER_REMOVING_CONTENT:
        return "removing"
    if content == STATE_MARKER_REMOVED_CONTENT:
        return "removed"
    raise ValueError("monitor state directory has an incompatible ownership marker")


def _validate_monitor_setting(key: str, value: Any) -> int:
    minimum, maximum = SETTING_LIMITS[key]
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(
            f"monitor setting {key} must be an integer in {minimum}..{maximum}"
        )
    return value


def _current_uid() -> int:
    getter = getattr(os, "getuid", None)
    return int(getter()) if getter is not None else 0


def _monitor_paths(scope: str) -> dict[str, Path]:
    current = platform_id()
    home = Path.home()
    if current == "linux" and scope == "system":
        return {
            "config": Path("/etc/netops/monitor.json"),
            "state": Path("/var/lib/netops"),
            "service": Path("/etc/systemd/system/netops-monitor.service"),
            "timer": Path("/etc/systemd/system/netops-monitor.timer"),
        }
    if current == "linux":
        return {
            "config": home / ".config/netops/monitor.json",
            "state": home / ".local/state/netops",
            "service": home / ".config/systemd/user/netops-monitor.service",
            "timer": home / ".config/systemd/user/netops-monitor.timer",
        }
    if current == "macos":
        base = home / "Library/Application Support/NetOps"
        return {
            "config": base / "monitor.json",
            "state": base / "state",
            "plist": home
            / "Library/LaunchAgents/io.github.con-benksl.netops-monitor.plist",
        }
    if current == "windows":
        base = Path(os.environ.get("LOCALAPPDATA", home / "AppData/Local")) / "NetOps"
        return {"config": base / "monitor.json", "state": base / "state"}
    raise RuntimeError(f"monitoring is unsupported on platform {current!r}")


def _systemd_quote(value: str) -> str:
    # systemd expands percent specifiers even inside quotes.  A literal path
    # component containing ``%`` therefore needs the documented ``%%`` form.
    _validate_scheduler_argument(value, systemd=True)
    return (
        '"'
        + value.replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
        + '"'
    )


def _validate_scheduler_argument(value: str, *, systemd: bool) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError("scheduler arguments must be non-empty strings")
    if any(
        character in {"\u2028", "\u2029"}
        or unicodedata.category(character) in {"Cc", "Cf"}
        for character in value
    ):
        raise ValueError("scheduler paths must not contain control or format characters")
    if systemd and "$" in value:
        raise ValueError("systemd paths must not contain '$' expansion syntax")


def build_install_plan(
    *,
    entry_script: str | Path,
    target: str,
    port: int,
    protocol: str,
    profile: str,
    scope: str,
    overrides: dict[str, int] | None = None,
) -> dict[str, Any]:
    if protocol not in {"tcp", "udp"}:
        raise ValueError("protocol must be tcp or udp")
    if protocol == "udp":
        raise ValueError(
            "scheduled UDP health checks require a protocol-aware client; "
            "a generic UDP probe would produce false confidence"
        )
    if profile not in {"client", "server"}:
        raise ValueError("profile must be client or server")
    if scope not in {"system", "user"}:
        raise ValueError("scope must be system or user")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    _validate_declared_target(target)
    settings = dict(DEFAULTS)
    if overrides:
        for key, value in overrides.items():
            if key not in settings:
                raise ValueError(f"unknown monitor setting: {key}")
            settings[key] = _validate_monitor_setting(key, value)
    for key, value in settings.items():
        _validate_monitor_setting(key, value)
    if settings["incident_interval_seconds"] > settings["incident_duration_seconds"]:
        raise ValueError(
            "incident_interval_seconds must not exceed incident_duration_seconds"
        )
    paths = _monitor_paths(scope)
    if platform_id() in {"macos", "windows"} and scope != "user":
        raise ValueError("macOS and Windows monitoring currently supports user scope only")
    entry = str(Path(entry_script).expanduser().resolve())
    config = {
        "schema_version": "1.0",
        "profile": profile,
        "scope": scope,
        "target": {"host": target, "port": port, "protocol": protocol},
        "state_dir": str(paths["state"]),
        **settings,
    }
    # pip installs console entry points as native ``.exe`` launchers on
    # Windows.  Passing that launcher to python.exe makes Python try to parse
    # the executable as source.  Source scripts still need the interpreter;
    # installed Windows launchers must be invoked directly.
    command_prefix = (
        [entry]
        if platform_id() == "windows" and Path(entry).suffix.casefold() == ".exe"
        else [str(Path(sys.executable).resolve()), entry]
    )
    command = [
        *command_prefix,
        "monitor",
        "sample",
        "--config",
        str(paths["config"]),
    ]
    current = platform_id()
    for item in command:
        _validate_scheduler_argument(item, systemd=current == "linux")
    files: dict[str, str | bytes] = {
        str(paths["config"]): json.dumps(
            config, ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    }
    commands: list[list[str]] = []
    if current == "linux":
        service = "\n".join(
            [
                "[Unit]",
                "Description=NetOps bounded network sample",
                "After=network-online.target",
                "",
                "[Service]",
                "Type=oneshot",
                "UMask=0077",
                f"ExecStart={' '.join(_systemd_quote(item) for item in command)}",
                "",
            ]
        )
        timer = "\n".join(
            [
                "[Unit]",
                "Description=Run NetOps network sample every minute",
                "",
                "[Timer]",
                "OnBootSec=1min",
                f"OnUnitActiveSec={settings['interval_seconds']}s",
                "Persistent=true",
                "AccuracySec=5s",
                "",
                "[Install]",
                "WantedBy=timers.target",
                "",
            ]
        )
        files[str(paths["service"])] = service
        files[str(paths["timer"])] = timer
        prefix = ["systemctl"] if scope == "system" else ["systemctl", "--user"]
        commands.extend(
            [
                [*prefix, "daemon-reload"],
                [*prefix, "enable", "--now", "netops-monitor.timer"],
            ]
        )
    elif current == "macos":
        label = "io.github.con-benksl.netops-monitor"
        plist = {
            "Label": label,
            "ProgramArguments": command,
            "StartInterval": settings["interval_seconds"],
            "RunAtLoad": True,
            "ProcessType": "Background",
            "Umask": 0o077,
            # Snapshots and monitor-state.json are the bounded durable record.
            # launchd path logs would grow outside the 200 MB retention budget.
            "StandardOutPath": "/dev/null",
            "StandardErrorPath": "/dev/null",
        }
        files[str(paths["plist"])] = plistlib.dumps(plist)
        domain = f"gui/{_current_uid()}"
        commands.extend(
            [
                ["launchctl", "bootout", domain, str(paths["plist"])],
                ["launchctl", "bootstrap", domain, str(paths["plist"])],
            ]
        )
    elif current == "windows":
        if (
            settings["interval_seconds"] < 60
            or settings["interval_seconds"] > 86_340
            or settings["interval_seconds"] % 60
        ):
            raise ValueError(
                "Windows monitor interval must be 60..86340 seconds in whole minutes"
            )
        task_command = subprocess_command_line(command)
        commands.append(
            [
                "schtasks",
                "/Create",
                "/TN",
                "NetOps Monitor",
                "/TR",
                task_command,
                "/SC",
                "MINUTE",
                "/MO",
                str(settings["interval_seconds"] // 60),
                "/F",
            ]
        )
    return {
        "platform": current,
        "scope": scope,
        "paths": {key: str(value) for key, value in paths.items()},
        "config": config,
        "sample_command": command,
        "files": files,
        "commands": commands,
    }


def subprocess_command_line(args: list[str]) -> str:
    if platform_id() == "windows":
        import subprocess

        return subprocess.list2cmdline(args)
    return " ".join(shlex.quote(item) for item in args)


def _validate_install_plan_paths(plan: dict[str, Any]) -> dict[str, Path]:
    """Reject a mutated plan before any local scheduler file is written."""

    current = platform_id()
    scope = plan.get("scope")
    if plan.get("platform") != current or scope not in {"system", "user"}:
        raise ValueError("monitor install plan does not match the current platform")
    expected = _monitor_paths(scope)
    raw_paths = plan.get("paths")
    if not isinstance(raw_paths, dict) or raw_paths != {
        key: str(value) for key, value in expected.items()
    }:
        raise ValueError("monitor install plan paths do not match NetOps defaults")
    files = plan.get("files")
    if not isinstance(files, dict):
        raise ValueError("monitor install plan files must be an object")
    allowed_files = {str(expected["config"])}
    allowed_files.update(
        str(expected[key]) for key in ("service", "timer", "plist") if key in expected
    )
    if str(expected["config"]) not in files or not set(files).issubset(allowed_files):
        raise ValueError("monitor install plan contains an unexpected file target")
    commands = plan.get("commands")
    if not isinstance(commands, list) or not all(
        isinstance(command, list)
        and command
        and all(isinstance(item, str) for item in command)
        for command in commands
    ):
        raise ValueError("monitor install plan contains an invalid scheduler command")
    allowed_executable = {
        "linux": "systemctl",
        "macos": "launchctl",
        "windows": "schtasks",
    }.get(current)
    if allowed_executable is None or any(
        command[0] != allowed_executable for command in commands
    ):
        raise ValueError("monitor install plan contains an unexpected scheduler command")
    if not commands:
        raise ValueError("monitor install plan must contain canonical scheduler commands")
    if commands:
        sample_command = plan.get("sample_command")
        if not isinstance(sample_command, list) or not all(
            isinstance(item, str) for item in sample_command
        ):
            raise ValueError("monitor install plan is missing its sample command")
        suffix = [
            "monitor",
            "sample",
            "--config",
            str(expected["config"]),
        ]
        if sample_command[-4:] != suffix:
            raise ValueError("monitor install plan sample command is invalid")
        if (
            current == "windows"
            and len(sample_command) == 5
            and Path(sample_command[0]).suffix.casefold() == ".exe"
        ):
            entry_script = sample_command[0]
            if Path(entry_script).name.casefold() != "netopsctl.exe":
                raise ValueError("monitor install plan launcher is not netopsctl.exe")
        elif len(sample_command) == 6:
            try:
                interpreter_matches = (
                    Path(sample_command[0]).resolve() == Path(sys.executable).resolve()
                )
            except OSError:
                interpreter_matches = False
            if not interpreter_matches:
                raise ValueError("monitor install plan uses an unexpected Python interpreter")
            entry_script = sample_command[1]
            if Path(entry_script).name.casefold() not in {"netopsctl", "netopsctl.py"}:
                raise ValueError("monitor install plan launcher is not netopsctl")
        else:
            raise ValueError("monitor install plan sample command has an invalid shape")

        config = plan.get("config")
        if not isinstance(config, dict):
            raise ValueError("monitor install plan config must be an object")
        target = config.get("target")
        if not isinstance(target, dict):
            raise ValueError("monitor install plan target must be an object")
        expected_plan = build_install_plan(
            entry_script=entry_script,
            target=target.get("host"),
            port=target.get("port"),
            protocol=target.get("protocol"),
            profile=config.get("profile"),
            scope=scope,
            overrides={key: config.get(key) for key in DEFAULTS},
        )
        if config != expected_plan["config"]:
            raise ValueError("monitor install plan config was mutated")
        if sample_command != expected_plan["sample_command"]:
            raise ValueError("monitor install plan sample command was mutated")
        if commands != expected_plan["commands"]:
            raise ValueError("monitor install plan scheduler commands were mutated")
        if files != expected_plan["files"]:
            raise ValueError("monitor install plan scheduler files were mutated")
    return expected


def _validate_monitor_path_types(paths: dict[str, Path]) -> None:
    for path in _owned_file_paths(paths):
        parent = path.parent
        for candidate in _directory_chain(parent):
            if os.path.lexists(candidate):
                _assert_real_directory(candidate)
        if os.path.lexists(path):
            info = path.lstat()
            if _is_link_like(path) or not stat.S_ISREG(info.st_mode):
                raise ValueError(f"monitor file path must be a regular file: {path}")
    state = paths["state"]
    for candidate in _directory_chain(state):
        if os.path.lexists(candidate):
            _assert_real_directory(candidate)


def _validate_root_controlled_path(path: str | Path, *, label: str) -> None:
    candidate = Path(os.path.abspath(Path(path).expanduser()))
    if not os.path.lexists(candidate):
        raise PermissionError(f"system monitor {label} does not exist")
    info = candidate.lstat()
    if _is_link_like(candidate) or not stat.S_ISREG(info.st_mode):
        raise PermissionError(f"system monitor {label} must be a regular file")
    for item in _directory_chain(candidate.parent):
        directory = item.lstat()
        if (
            _is_link_like(item)
            or not stat.S_ISDIR(directory.st_mode)
            or directory.st_uid != 0
            or directory.st_mode & 0o022
        ):
            raise PermissionError(
                f"system monitor {label} has an unsafe writable or unowned ancestor"
            )
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError(
            f"system monitor {label} must be root-owned and not group/world-writable"
        )


def _validate_root_controlled_directory_chain(
    path: str | Path,
    *,
    label: str,
) -> None:
    """Validate every existing directory before privileged creation or use."""

    candidate = Path(os.path.abspath(Path(path).expanduser()))
    for item in _directory_chain(candidate):
        if not os.path.lexists(item):
            continue
        try:
            info = item.lstat()
        except OSError as exc:
            raise PermissionError(
                f"system monitor {label} cannot be inspected"
            ) from exc
        if (
            _is_link_like(item)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise PermissionError(
                f"system monitor {label} has an unsafe writable or unowned directory"
            )


def _validate_user_controlled_directory_chain(
    path: str | Path,
    *,
    label: str,
) -> None:
    """Reject ancestors another local account could rename or replace."""

    if os.name == "nt":
        return
    current_uid = _current_uid()
    candidate = Path(os.path.abspath(Path(path).expanduser()))
    for item in _directory_chain(candidate):
        if not os.path.lexists(item):
            continue
        info = item.lstat()
        trusted_macos_alias = (
            sys.platform == "darwin"
            and str(item) in {"/etc", "/tmp", "/var"}
            and item.is_symlink()
        )
        if trusted_macos_alias:
            info = item.stat()
        sticky_shared = bool(info.st_mode & stat.S_ISVTX)
        if (
            (_is_link_like(item) and not trusted_macos_alias)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {0, current_uid}
            or (info.st_mode & 0o022 and not sticky_shared)
        ):
            raise PermissionError(
                f"user monitor {label} has an unsafe writable or unowned directory"
            )


def _validate_system_scope_data_paths(
    plan: dict[str, Any],
    paths: dict[str, Path],
) -> None:
    if plan["platform"] != "linux" or plan["scope"] != "system":
        return
    directories = {paths["config"].parent, paths["state"]}
    directories.update(path.parent for path in _owned_file_paths(paths))
    for directory in directories:
        _validate_root_controlled_directory_chain(
            directory,
            label="data directory",
        )


def _validate_root_controlled_directory_tree(
    path: str | Path,
    *,
    label: str,
    max_entries: int = 10_000,
) -> None:
    """Fail closed when privileged Python could import writable package data."""

    candidate = Path(os.path.abspath(Path(path).expanduser()))
    if not os.path.lexists(candidate):
        raise PermissionError(f"system monitor {label} does not exist")
    entry_count = 0
    pending = [candidate]
    while pending:
        current = pending.pop()
        try:
            info = current.lstat()
        except OSError as exc:
            raise PermissionError(f"system monitor {label} cannot be inspected") from exc
        if _is_link_like(current):
            raise PermissionError(f"system monitor {label} must not contain links")
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError(
                f"system monitor {label} must be root-owned and not group/world-writable"
            )
        if stat.S_ISDIR(info.st_mode):
            try:
                children = list(current.iterdir())
            except OSError as exc:
                raise PermissionError(
                    f"system monitor {label} cannot be inspected"
                ) from exc
            entry_count += len(children)
            if entry_count > max_entries:
                raise PermissionError(f"system monitor {label} is unexpectedly large")
            pending.extend(children)
        elif not stat.S_ISREG(info.st_mode):
            raise PermissionError(
                f"system monitor {label} must contain only regular files and directories"
            )
    for ancestor in _directory_chain(candidate.parent):
        info = ancestor.lstat()
        if (
            _is_link_like(ancestor)
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o022
        ):
            raise PermissionError(
                f"system monitor {label} has an unsafe writable or unowned ancestor"
            )


def _validate_system_scope_launcher(plan: dict[str, Any]) -> None:
    if plan["platform"] != "linux" or plan["scope"] != "system":
        return
    command = plan["sample_command"]
    if len(command) != 6:
        raise PermissionError("system monitor requires a Python launcher command")
    _validate_root_controlled_path(command[0], label="interpreter")
    _validate_root_controlled_path(command[1], label="entry point")
    _validate_root_controlled_directory_tree(
        Path(__file__).parent,
        label="Python package",
    )


def _scheduler_executable(platform_name: str, *, system_scope: bool) -> str:
    name = {
        "linux": "systemctl",
        "macos": "launchctl",
        "windows": "schtasks",
    }.get(platform_name)
    if name is None:
        raise RuntimeError("monitor scheduler is unsupported")
    discovered = shutil.which(name, path=trusted_system_environment()["PATH"])
    if discovered is None:
        raise RuntimeError("monitor scheduler executable is unavailable")
    try:
        resolved = Path(discovered).resolve(strict=True)
        info = resolved.lstat()
    except OSError as exc:
        raise RuntimeError("monitor scheduler executable cannot be verified") from exc
    if _is_link_like(resolved) or not stat.S_ISREG(info.st_mode):
        raise RuntimeError("monitor scheduler executable is not a regular file")
    if system_scope:
        _validate_root_controlled_path(resolved, label="scheduler executable")
    return str(resolved)


def _scheduler_command(
    command: list[str],
    *,
    platform_name: str,
    executable: str,
) -> list[str]:
    expected = {
        "linux": "systemctl",
        "macos": "launchctl",
        "windows": "schtasks",
    }[platform_name]
    if not command or command[0] != expected:
        raise ValueError("monitor scheduler command uses an unexpected executable")
    return [executable, *command[1:]]


def _safe_scheduler_result(result: dict[str, Any]) -> dict[str, Any]:
    return {
        key: result.get(key)
        for key in (
            "available",
            "returncode",
            "duration_ms",
            "timed_out",
            "stdout_truncated",
            "stderr_truncated",
        )
        if key in result
    }


_NOT_FOUND_MARKERS = (
    "not found",
    "no such",
    "could not find",
    "does not exist",
    "cannot find",
    "no files found",
    "not loaded",
    # schtasks.exe localizes its diagnostics. Unknown output remains a hard
    # failure; these phrases are only the well-known "task/file absent" case.
    "系统找不到指定的文件",
    "指定されたファイルが見つかりません",
    "das system kann die angegebene datei nicht finden",
    "le fichier spécifié est introuvable",
    "el sistema no puede encontrar el archivo especificado",
)
_NOT_RUNNING_MARKERS = (
    "not running",
    "not currently running",
    "is not running",
)


def _command_output(result: dict[str, Any]) -> str:
    return f"{result.get('stdout', '')}\n{result.get('stderr', '')}".strip().casefold()


def _command_reports_absent(result: dict[str, Any]) -> bool:
    if (
        not result.get("available", True)
        or result.get("returncode") == 0
        or result.get("stdout_truncated")
        or result.get("stderr_truncated")
    ):
        return False
    output = _command_output(result)
    return any(marker in output for marker in _NOT_FOUND_MARKERS)


def _command_reports_not_running(result: dict[str, Any]) -> bool:
    if (
        not result.get("available", True)
        or result.get("returncode") == 0
        or result.get("stdout_truncated")
        or result.get("stderr_truncated")
    ):
        return False
    output = _command_output(result)
    return _command_reports_absent(result) or any(
        marker in output for marker in _NOT_RUNNING_MARKERS
    )


def _preflight_monitor_ownership(
    plan: dict[str, Any],
    paths: dict[str, Path],
) -> tuple[bool, str]:
    """Avoid claiming non-NetOps state or replacing an unrelated scheduler."""

    state = paths["state"]
    owner_state = _owner_state(paths) if os.path.lexists(state) else "missing"
    already_owned = owner_state in {"active", "installing"}
    if owner_state == "active":
        _verify_owner_manifest(paths, allow_missing=False)
    elif owner_state == "installing":
        expected_manifest = _manifest_payload(plan["files"])
        manifest = _read_manifest(state)
        existing_owned = [
            path for path in _owned_file_paths(paths) if os.path.lexists(path)
        ]
        if manifest is None:
            if existing_owned:
                raise ValueError(
                    "incomplete monitor installation has files but no ownership manifest"
                )
        elif manifest != expected_manifest:
            raise ValueError(
                "incomplete monitor installation belongs to a different install plan"
            )
        if manifest is not None:
            _verify_owner_manifest(paths, allow_missing=True)
        allowed_state_entries = {STATE_MARKER_NAME, STATE_MANIFEST_NAME}
        try:
            unexpected = [
                item.name for item in state.iterdir() if item.name not in allowed_state_entries
            ]
        except OSError as exc:
            raise ValueError(
                "incomplete monitor state directory cannot be inspected"
            ) from exc
        if unexpected:
            raise ValueError(
                "incomplete monitor state directory contains unexpected data"
            )
    elif owner_state == "removing":
        raise RuntimeError("monitor removal is incomplete; finish removal before reinstalling")
    elif owner_state == "removed":
        if os.path.lexists(state / STATE_MANIFEST_NAME):
            raise ValueError("removed monitor state must not retain an ownership manifest")
        if any(os.path.lexists(path) for path in _owned_file_paths(paths)):
            raise FileExistsError(
                "refusing to replace files created after monitor removal"
            )
    if owner_state == "missing" and state.exists():
        try:
            has_existing_content = any(state.iterdir())
        except OSError as exc:
            raise ValueError("monitor state directory cannot be inspected") from exc
        if has_existing_content:
            raise ValueError("refusing to claim a non-empty unmarked monitor state directory")

    if owner_state == "missing" and any(
        os.path.lexists(path) for path in _owned_file_paths(paths)
    ):
        raise FileExistsError(
            "refusing to replace an existing unowned monitor config or scheduler file"
        )

    current = plan["platform"]
    scheduler_executable = _scheduler_executable(
        current,
        system_scope=current == "linux" and plan["scope"] == "system",
    )
    if already_owned:
        return True, scheduler_executable
    if current == "linux":
        prefix = ["systemctl"] if plan["scope"] == "system" else ["systemctl", "--user"]
        probe = [*prefix, "cat", "netops-monitor.service"]
    elif current == "macos":
        probe = [
            "launchctl",
            "print",
            f"gui/{_current_uid()}/io.github.con-benksl.netops-monitor",
        ]
    else:
        probe = ["schtasks", "/Query", "/TN", "NetOps Monitor"]
    probe = _scheduler_command(
        probe,
        platform_name=current,
        executable=scheduler_executable,
    )
    result = _run_scheduler_command(probe, timeout=10)
    if result.get("available") and result.get("returncode") == 0:
        raise FileExistsError(
            "refusing to replace an existing unowned monitor scheduler"
        )
    if not _command_reports_absent(result):
        raise RuntimeError("monitor scheduler ownership could not be verified")
    return False, scheduler_executable


def _write_content(
    path: Path,
    content: str | bytes,
    *,
    private_parent: bool = True,
) -> None:
    # Config and state live in dedicated private directories. Scheduler files
    # live in shared system directories such as /etc/systemd/system; validating
    # those directories must never chmod them to NetOps' private 0700 mode.
    parent_identity = _secure_directory(
        path.parent,
        create=True,
        enforce_mode=private_parent,
    )
    existing_identity: tuple[int, int] | None = None
    if os.path.lexists(path):
        info = path.lstat()
        if _is_link_like(path) or not stat.S_ISREG(info.st_mode):
            raise ValueError(f"refusing to replace a non-regular monitor file: {path}")
        existing_identity = (info.st_dev, info.st_ino)
    payload = content if isinstance(content, bytes) else content.encode("utf-8")
    descriptor, raw_temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(raw_temporary)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        _assert_real_directory(path.parent, identity=parent_identity)
        if existing_identity is None:
            if os.path.lexists(path):
                raise FileExistsError(f"monitor file appeared during write: {path}")
        else:
            info = path.lstat()
            if (
                _is_link_like(path)
                or not stat.S_ISREG(info.st_mode)
                or (info.st_dev, info.st_ino) != existing_identity
            ):
                raise ValueError(f"monitor file changed during write: {path}")
        temporary.replace(path)
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _unlink_regular(path: Path, *, label: str, missing_ok: bool) -> bool:
    if not os.path.lexists(path):
        if missing_ok:
            return False
        raise FileNotFoundError(path)
    info = path.lstat()
    if _is_link_like(path) or not stat.S_ISREG(info.st_mode):
        raise ValueError(f"{label} must be a regular file")
    identity = (info.st_dev, info.st_ino)
    parent_identity = _assert_real_directory(path.parent)
    current = path.lstat()
    if (current.st_dev, current.st_ino) != identity:
        raise ValueError(f"{label} changed during removal")
    _assert_real_directory(path.parent, identity=parent_identity)
    path.unlink()
    return True


def install_monitor(plan: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    """Validate/print an install plan; scheduler mutation is unreleased."""

    if not dry_run:
        raise RuntimeError(
            "scheduled monitor installation is unavailable in this release"
        )
    paths = _validate_install_plan_paths(plan)
    preflight: dict[str, str] = {
        "decision": "review-only",
        "reason": "scheduler-lifecycle-unreleased",
    }
    if plan["platform"] == "linux" and plan["scope"] == "system":
        try:
            _validate_system_scope_data_paths(plan, paths)
            _validate_system_scope_launcher(plan)
        except (OSError, PermissionError, ValueError):
            preflight = {
                "decision": "blocked",
                "reason": "system-launcher-or-path-trust-unverified",
            }
    return {
        "changed": False,
        "dry_run": True,
        "execution_available": SCHEDULED_MONITOR_MUTATION_AVAILABLE,
        "preflight": preflight,
        "report_zh": (
            "这里只生成不可执行的调度审查材料；本版本不会安装任务。"
            if preflight["decision"] != "blocked"
            else "系统级解释器、入口或目录信任检查未通过；不要复制计划中的调度命令。"
        ),
        "plan": serializable_plan(plan),
    }


def _install_monitor_unreleased(
    plan: dict[str, Any], *, authorized: bool, dry_run: bool
) -> dict[str, Any]:
    raise RuntimeError(
        "scheduled monitor installation is unavailable in this release"
    )
    # Retained only as review evidence for a future redesign. The unconditional
    # gate above is deliberately inside this private body as well as the public
    # wrapper, so importing an underscored symbol cannot bypass the release
    # boundary.
    if not authorized and not dry_run:
        raise PermissionError("monitor installation requires --authorized")
    if dry_run:
        return {"changed": False, "dry_run": True, "plan": serializable_plan(plan)}
    paths = _validate_install_plan_paths(plan)
    if plan["platform"] == "linux" and plan["scope"] == "system" and os.geteuid() != 0:
        raise PermissionError("system-scope Linux monitoring must run as root")
    _validate_monitor_path_types(paths)
    _validate_system_scope_data_paths(plan, paths)
    _validate_system_scope_launcher(plan)
    _, scheduler_executable = _preflight_monitor_ownership(
        plan,
        paths,
    )
    config_parent = Path(plan["paths"]["config"]).parent
    if config_parent.name.lower() != "netops":
        raise ValueError("monitor config must use a dedicated NetOps directory")
    _secure_directory(config_parent, create=True, mode=0o700)
    state = Path(plan["paths"]["state"])
    _secure_directory(state, create=True, mode=0o700)
    _validate_system_scope_data_paths(plan, paths)
    changed_files: list[str] = []
    marker = state / STATE_MARKER_NAME
    existing_marker = _read_control_text(
        marker,
        label="monitor state ownership marker",
    )
    if existing_marker != STATE_MARKER_INSTALLING_CONTENT:
        _write_content(marker, STATE_MARKER_INSTALLING_CONTENT)
        changed_files.append(str(marker))
    manifest_path = state / STATE_MANIFEST_NAME
    manifest_content = json.dumps(
        _manifest_payload(plan["files"]),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    ) + "\n"
    existing_manifest = _read_control_text(
        manifest_path,
        label="monitor ownership manifest",
    )
    if existing_manifest != manifest_content:
        _write_content(manifest_path, manifest_content)
        changed_files.append(str(manifest_path))
    for raw_path, content in plan["files"].items():
        path = Path(raw_path)
        existing = (
            _read_regular_bytes(path, label="owned monitor file")
            if os.path.lexists(path)
            else None
        )
        desired = content if isinstance(content, bytes) else content.encode("utf-8")
        if existing != desired:
            _write_content(
                path,
                content,
                private_parent=path == Path(plan["paths"]["config"]),
            )
            changed_files.append(str(path))
        elif os.name != "nt" and (path.stat().st_mode & 0o777) != 0o600:
            _chmod_regular_file(path, 0o600)
            changed_files.append(str(path))
    command_results: list[dict[str, Any]] = []
    for command in plan["commands"]:
        execution_command = _scheduler_command(
            command,
            platform_name=plan["platform"],
            executable=scheduler_executable,
        )
        result = _run_scheduler_command(execution_command, timeout=30)
        command_results.append(_safe_scheduler_result(result))
        # launchctl bootout is intentionally allowed to fail when no old job exists.
        expected_bootout_failure = (
            plan["platform"] == "macos"
            and len(command) > 1
            and command[1] == "bootout"
            and _command_reports_absent(result)
        )
        if result["returncode"] != 0 and not expected_bootout_failure:
            raise RuntimeError("monitor scheduler command failed")
    _verify_owner_manifest(paths, allow_missing=False)
    _write_content(marker, STATE_MARKER_CONTENT)
    if str(marker) not in changed_files:
        changed_files.append(str(marker))
    return {
        # Scheduler commands are state-changing even when unit/config bytes are
        # already identical. Do not under-report a successful enable/reload.
        "changed": bool(changed_files or command_results),
        "changed_files": changed_files,
        "scheduler_commands": command_results,
        "config": plan["paths"]["config"],
        "state": plan["paths"]["state"],
    }


def serializable_plan(plan: dict[str, Any]) -> dict[str, Any]:
    data = dict(plan)
    data["files"] = {
        path: content.decode("utf-8", errors="replace")
        if isinstance(content, bytes)
        else content
        for path, content in plan["files"].items()
    }
    return data


def _monitor_integrity(
    paths: dict[str, Path],
    *,
    current: str,
    scope: str,
) -> dict[str, str]:
    """Return a bounded integrity verdict without exposing local file content."""

    try:
        _validate_monitor_path_types(paths)
        state = paths["state"]
        owned_files = _owned_file_paths(paths)
        if not os.path.lexists(state):
            reason = (
                "owned-files-without-state"
                if any(os.path.lexists(path) for path in owned_files)
                else "not-installed"
            )
            return {
                "integrity": "unowned",
                "lifecycle": "missing",
                "integrity_reason": reason,
            }
        lifecycle = _owner_state(paths)
        if lifecycle == "active":
            _verify_owner_manifest(paths, allow_missing=False)
            verdict = "verified"
            reason = "manifest-and-files-match"
        elif lifecycle == "installing":
            manifest = _read_manifest(state)
            if manifest is not None:
                _verify_owner_manifest(paths, allow_missing=True)
            elif any(os.path.lexists(path) for path in owned_files):
                raise ValueError("incomplete install has unmanifested files")
            verdict = "unknown"
            reason = "installation-incomplete"
        elif lifecycle == "removing":
            _verify_owner_manifest(paths, allow_missing=True)
            verdict = "unknown"
            reason = "removal-incomplete"
        elif lifecycle == "removed":
            if os.path.lexists(state / STATE_MANIFEST_NAME) or any(
                os.path.lexists(path) for path in owned_files
            ):
                raise ValueError("removed state retains owned files")
            verdict = "verified"
            reason = "removal-complete"
        else:
            raise ValueError("unsupported monitor lifecycle")

        if os.name != "nt":
            expected_uid = 0 if current == "linux" and scope == "system" else _current_uid()
            private_paths = [state, state / STATE_MARKER_NAME]
            if os.path.lexists(state / STATE_MANIFEST_NAME):
                private_paths.append(state / STATE_MANIFEST_NAME)
            private_paths.extend(path for path in owned_files if os.path.lexists(path))
            for path in private_paths:
                info = path.lstat()
                if info.st_uid != expected_uid or info.st_mode & 0o077:
                    raise PermissionError("monitor control path permissions are unsafe")

        if current == "linux" and scope == "system":
            synthetic_plan = {"platform": "linux", "scope": "system"}
            _validate_system_scope_data_paths(synthetic_plan, paths)
            for path in [
                *[item for item in owned_files if os.path.lexists(item)],
                state / STATE_MARKER_NAME,
                *(
                    [state / STATE_MANIFEST_NAME]
                    if os.path.lexists(state / STATE_MANIFEST_NAME)
                    else []
                ),
            ]:
                _validate_root_controlled_path(path, label="owned control file")
        return {
            "integrity": verdict,
            "lifecycle": lifecycle,
            "integrity_reason": reason,
        }
    except (OSError, PermissionError, ValueError):
        return {
            "integrity": "tampered",
            "lifecycle": "unknown",
            "integrity_reason": "ownership-or-content-mismatch",
        }


def monitor_status(*, scope: str) -> dict[str, Any]:
    """Report owned-file integrity without executing a scheduler binary."""

    if scope not in {"system", "user"}:
        raise ValueError("monitor scope must be system or user")
    current = platform_id()
    if current in {"macos", "windows"} and scope != "user":
        raise ValueError("macOS and Windows monitoring supports user scope only")
    paths = _monitor_paths(scope)
    result: dict[str, Any] = {
        "platform": current,
        "scope": scope,
        "config_exists": os.path.lexists(paths["config"]),
        "state_exists": os.path.lexists(paths["state"]),
        "paths": {key: str(value) for key, value in paths.items()},
        "scheduler_management_available": SCHEDULED_MONITOR_MUTATION_AVAILABLE,
        "scheduler": {"available": False, "reason": "unreleased"},
    }
    result.update(_monitor_integrity(paths, current=current, scope=scope))
    integrity = result["integrity"]
    if integrity == "verified":
        summary = "现有 NetOps 监控文件完整性通过。"
    elif integrity == "unowned":
        summary = "未发现由 NetOps 证明所有权的监控文件。"
    elif integrity == "tampered":
        summary = "监控文件完整性未通过，不能信任或删除这些文件。"
    else:
        summary = "监控文件状态暂时无法确认。"
    result["report_zh"] = {
        "结论": summary,
        "限制": "本版本不查询调度器，因此不能据此判断定时任务是否正在运行。",
        "下一步": "仅核对文件和清单；不要手工执行状态输出中的任何路径或命令。",
    }
    return result


def _monitor_status_unreleased(*, scope: str) -> dict[str, Any]:
    raise RuntimeError(
        "scheduler status inspection is unavailable in this release"
    )
    # Kept as non-executable review evidence; see the release gate above.
    current = platform_id()
    if current in {"macos", "windows"} and scope != "user":
        raise ValueError("macOS and Windows monitoring supports user scope only")
    paths = _monitor_paths(scope)
    result: dict[str, Any] = {
        "platform": current,
        "scope": scope,
        "config_exists": paths["config"].exists(),
        "state_exists": paths["state"].exists(),
        "paths": {key: str(value) for key, value in paths.items()},
    }
    result.update(_monitor_integrity(paths, current=current, scope=scope))
    executable = _scheduler_executable(
        current,
        system_scope=current == "linux" and scope == "system",
    )
    if current == "linux":
        prefix = ["systemctl"] if scope == "system" else ["systemctl", "--user"]
        result["scheduler"] = _safe_scheduler_result(
            _run_scheduler_command(
                [executable, *prefix[1:], "is-enabled", "netops-monitor.timer"],
                timeout=10,
            )
        )
        result["active"] = _safe_scheduler_result(
            _run_scheduler_command(
                [executable, *prefix[1:], "is-active", "netops-monitor.timer"],
                timeout=10,
            )
        )
    elif current == "macos":
        result["scheduler"] = _safe_scheduler_result(
            _run_scheduler_command(
                [
                    executable,
                    "print",
                    f"gui/{_current_uid()}/io.github.con-benksl.netops-monitor",
                ],
                timeout=10,
            )
        )
    elif current == "windows":
        result["scheduler"] = _safe_scheduler_result(
            _run_scheduler_command(
                [executable, "/Query", "/TN", "NetOps Monitor"], timeout=10
            )
        )
    return result


def _scheduler_is_absent(
    platform_name: str,
    stop_result: dict[str, Any],
    verify_result: dict[str, Any],
) -> bool:
    if not verify_result.get("available", True):
        return False
    returncode = verify_result.get("returncode")
    if platform_name == "linux":
        state = str(verify_result.get("stdout", "")).strip().casefold()
        return returncode in {3, 4} and state in {"inactive", "failed", "unknown"}
    if returncode == 0:
        return False
    return _command_reports_absent(verify_result)


def remove_monitor(*, scope: str, dry_run: bool) -> dict[str, Any]:
    """Validate/print a removal plan; scheduler mutation is unreleased."""

    if scope not in {"system", "user"}:
        raise ValueError("monitor scope must be system or user")
    if not dry_run:
        raise RuntimeError(
            "scheduled monitor removal is unavailable in this release"
        )
    current = platform_id()
    if current in {"macos", "windows"} and scope != "user":
        raise ValueError("macOS and Windows monitoring supports user scope only")
    paths = _monitor_paths(scope)
    commands: list[list[str]]
    removable: list[Path] = [paths["config"]]
    if current == "linux":
        prefix = ["systemctl"] if scope == "system" else ["systemctl", "--user"]
        commands = [
            [*prefix, "disable", "--now", "netops-monitor.timer"],
            [*prefix, "stop", "netops-monitor.service"],
            [*prefix, "is-active", "netops-monitor.timer"],
            [*prefix, "is-active", "netops-monitor.service"],
            [*prefix, "daemon-reload"],
        ]
        removable.extend([paths["service"], paths["timer"]])
    elif current == "macos":
        domain = f"gui/{_current_uid()}"
        commands = [
            ["launchctl", "bootout", domain, str(paths["plist"])],
            ["launchctl", "print", f"{domain}/io.github.con-benksl.netops-monitor"],
        ]
        removable.append(paths["plist"])
    elif current == "windows":
        commands = [
            ["schtasks", "/End", "/TN", "NetOps Monitor"],
            ["schtasks", "/Delete", "/TN", "NetOps Monitor", "/F"],
            ["schtasks", "/Query", "/TN", "NetOps Monitor"],
        ]
    else:
        raise RuntimeError(f"monitoring is unsupported on platform {current!r}")
    integrity = _monitor_integrity(paths, current=current, scope=scope)
    plan_verified = (
        integrity.get("integrity") == "verified"
        and integrity.get("lifecycle") == "active"
    )
    return {
        "dry_run": True,
        "execution_available": SCHEDULED_MONITOR_MUTATION_AVAILABLE,
        "preflight": {
            "decision": "review-only" if plan_verified else "blocked",
            "reason": (
                "owned-files-verified"
                if plan_verified
                else "monitor-ownership-or-integrity-unverified"
            ),
        },
        "commands": commands if plan_verified else [],
        "commands_are_executable": False,
        "remove_files": [str(path) for path in removable],
        "preserve_state": str(paths["state"]),
        "report_zh": (
            "现有文件清单通过只读核对，但本版本仍不会停止或删除调度任务。"
            if plan_verified
            else "未能证明这些文件和同名任务属于 NetOps；不要复制或执行删除命令。"
        ),
    }


def _remove_monitor_unreleased(
    *, scope: str, authorized: bool, dry_run: bool
) -> dict[str, Any]:
    raise RuntimeError(
        "scheduled monitor removal is unavailable in this release"
    )
    # Kept as non-executable review evidence; see the release gate above.
    if not authorized and not dry_run:
        raise PermissionError("monitor removal requires --authorized")
    current = platform_id()
    if current in {"macos", "windows"} and scope != "user":
        raise ValueError("macOS and Windows monitoring supports user scope only")
    paths = _monitor_paths(scope)
    stop_commands: list[tuple[list[str], str]]
    verify_commands: list[list[str]]
    reload_command: list[str] | None = None
    removable: list[Path] = [paths["config"]]
    if current == "linux":
        prefix = ["systemctl"] if scope == "system" else ["systemctl", "--user"]
        stop_commands = [
            ([*prefix, "disable", "--now", "netops-monitor.timer"], "absent"),
            ([*prefix, "stop", "netops-monitor.service"], "absent"),
        ]
        verify_commands = [
            [*prefix, "is-active", "netops-monitor.timer"],
            [*prefix, "is-active", "netops-monitor.service"],
        ]
        reload_command = [*prefix, "daemon-reload"]
        removable.extend([paths["service"], paths["timer"]])
    elif current == "macos":
        domain = f"gui/{_current_uid()}"
        stop_commands = [
            (
                ["launchctl", "bootout", domain, str(paths["plist"])],
                "absent",
            )
        ]
        verify_commands = [
            [
                "launchctl",
                "print",
                f"{domain}/io.github.con-benksl.netops-monitor",
            ]
        ]
        removable.append(paths["plist"])
    elif current == "windows":
        stop_commands = [
            (["schtasks", "/End", "/TN", "NetOps Monitor"], "not-running"),
            (["schtasks", "/Delete", "/TN", "NetOps Monitor", "/F"], "absent"),
        ]
        verify_commands = [
            ["schtasks", "/Query", "/TN", "NetOps Monitor"]
        ]
    else:
        raise RuntimeError(f"monitoring is unsupported on platform {current!r}")
    if dry_run:
        return {
            "dry_run": True,
            "commands": [
                *(command for command, _ in stop_commands),
                *verify_commands,
                *([reload_command] if reload_command else []),
            ],
            "remove_files": [str(path) for path in removable],
            "preserve_state": str(paths["state"]),
        }
    try:
        _validate_monitor_path_types(paths)
        owner_state = _owner_state(paths) if os.path.lexists(paths["state"]) else "missing"
    except (OSError, ValueError):
        owner_state = "invalid"
    if owner_state == "removed":
        if any(os.path.lexists(path) for path in removable):
            return {
                "status": "blocked",
                "reason": "removed-monitor-paths-were-reused",
                "removed_files": [],
                "scheduler_commands": [],
                "preserved_state": str(paths["state"]),
            }
        manifest = paths["state"] / STATE_MANIFEST_NAME
        if os.path.lexists(manifest):
            try:
                _unlink_regular(
                    manifest,
                    label="monitor ownership manifest",
                    missing_ok=True,
                )
            except (OSError, ValueError):
                return {
                    "status": "partial",
                    "reason": "removed-monitor-manifest-cleanup-failed",
                    "removed_files": [],
                    "scheduler_commands": [],
                    "preserved_state": str(paths["state"]),
                }
        return {
            "status": "removed",
            "already_removed": True,
            "removed_files": [],
            "scheduler_commands": [],
            "preserved_state": str(paths["state"]),
        }
    if owner_state not in {"active", "removing"}:
        return {
            "status": "blocked",
            "reason": "monitor-ownership-unverified",
            "removed_files": [],
            "scheduler_commands": [],
            "preserved_state": str(paths["state"]),
        }
    try:
        _verify_owner_manifest(paths, allow_missing=True)
    except (OSError, ValueError):
        return {
            "status": "blocked",
            "reason": "monitor-owned-files-modified-or-unverified",
            "removed_files": [],
            "scheduler_commands": [],
            "preserved_state": str(paths["state"]),
        }
    if current == "linux" and scope == "system" and os.geteuid() != 0:
        raise PermissionError("system-scope Linux monitoring must run as root")
    scheduler_executable = _scheduler_executable(
        current,
        system_scope=current == "linux" and scope == "system",
    )
    command_results: list[dict[str, Any]] = []
    for command, allowed_failure in stop_commands:
        execution_command = _scheduler_command(
            command,
            platform_name=current,
            executable=scheduler_executable,
        )
        result = _run_scheduler_command(execution_command, timeout=30)
        command_results.append(_safe_scheduler_result(result))
        accepted = result.get("returncode") == 0
        if allowed_failure == "not-running":
            accepted = accepted or _command_reports_not_running(result)
        else:
            accepted = accepted or _command_reports_absent(result)
        if not accepted:
            return {
                "status": "blocked",
                "reason": "scheduler-stop-failed-or-unverified",
                "removed_files": [],
                "scheduler_commands": command_results,
                "preserved_state": str(paths["state"]),
            }
    for verify_command in verify_commands:
        execution_command = _scheduler_command(
            verify_command,
            platform_name=current,
            executable=scheduler_executable,
        )
        verify_result = _run_scheduler_command(execution_command, timeout=15)
        command_results.append(_safe_scheduler_result(verify_result))
        if not _scheduler_is_absent(current, {}, verify_result):
            return {
                "status": "blocked",
                "reason": "scheduler-still-active-or-unverified",
                "removed_files": [],
                "scheduler_commands": command_results,
                "preserved_state": str(paths["state"]),
            }
    try:
        _write_content(
            paths["state"] / STATE_MARKER_NAME,
            STATE_MARKER_REMOVING_CONTENT,
        )
    except (OSError, ValueError):
        return {
            "status": "partial",
            "reason": "scheduler-stopped-removal-marker-write-failed",
            "removed_files": [],
            "scheduler_commands": command_results,
            "preserved_state": str(paths["state"]),
        }
    removed: list[str] = []
    for path in removable:
        try:
            if _unlink_regular(path, label="owned monitor file", missing_ok=True):
                removed.append(str(path))
        except (OSError, ValueError):
            return {
                "status": "partial",
                "reason": "scheduler-stopped-but-file-removal-failed",
                "removed_files": removed,
                "failed_file": str(path),
                "scheduler_commands": command_results,
                "preserved_state": str(paths["state"]),
            }
    if reload_command is not None:
        execution_command = _scheduler_command(
            reload_command,
            platform_name=current,
            executable=scheduler_executable,
        )
        reload_result = _run_scheduler_command(execution_command, timeout=30)
        command_results.append(_safe_scheduler_result(reload_result))
        if reload_result.get("returncode") != 0:
            return {
                "status": "partial",
                "reason": "scheduler-stopped-files-removed-reload-failed",
                "removed_files": removed,
                "scheduler_commands": command_results,
                "preserved_state": str(paths["state"]),
            }
    try:
        _write_content(
            paths["state"] / STATE_MARKER_NAME,
            STATE_MARKER_REMOVED_CONTENT,
        )
        _unlink_regular(
            paths["state"] / STATE_MANIFEST_NAME,
            label="monitor ownership manifest",
            missing_ok=True,
        )
    except (OSError, ValueError):
        return {
            "status": "partial",
            "reason": "monitor-files-removed-ownership-finalize-failed",
            "removed_files": removed,
            "scheduler_commands": command_results,
            "preserved_state": str(paths["state"]),
        }
    return {
        "status": "removed",
        "removed_files": removed,
        "scheduler_commands": command_results,
        "preserved_state": str(paths["state"]),
    }


def _load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(os.path.abspath(Path(path).expanduser()))
    payload = _read_regular_bytes(config_path, label="monitor config")
    try:
        config = parse_json_strict(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("monitor config is invalid") from exc
    if not isinstance(config, dict):
        raise ValueError("monitor config must be an object")
    if config.get("schema_version") != "1.0":
        raise ValueError("unsupported monitor config schema")
    for key in DEFAULTS:
        config.setdefault(key, DEFAULTS[key])
        _validate_monitor_setting(key, config[key])
    if config["incident_interval_seconds"] > config["incident_duration_seconds"]:
        raise ValueError(
            "incident_interval_seconds must not exceed incident_duration_seconds"
        )
    if config.get("profile") not in {"client", "server"}:
        raise ValueError("monitor profile must be client or server")
    if config.get("scope") not in {"system", "user"}:
        raise ValueError("monitor scope must be system or user")
    if platform_id() in {"macos", "windows"} and config["scope"] != "user":
        raise ValueError("macOS and Windows monitoring supports user scope only")
    expected_paths = _monitor_paths(config["scope"])
    expected_config = Path(
        os.path.abspath(expected_paths["config"].expanduser())
    )
    if config_path != expected_config:
        raise ValueError("monitor config path does not match the canonical scope path")
    target = config.get("target")
    if not isinstance(target, dict):
        raise ValueError("monitor target must be an object")
    if not isinstance(target.get("host"), str) or not target["host"].strip():
        raise ValueError("monitor target host must be a non-empty string")
    _validate_declared_target(target["host"])
    if type(target.get("port")) is not int or not 1 <= target["port"] <= 65535:
        raise ValueError("monitor target port must be between 1 and 65535")
    if target.get("protocol") != "tcp":
        raise ValueError("monitor target protocol must be tcp")
    state_dir = config.get("state_dir")
    if (
        not isinstance(state_dir, str)
        or not state_dir.strip()
        or not Path(state_dir).expanduser().is_absolute()
    ):
        raise ValueError("monitor state_dir must be a non-empty absolute path")
    resolved_state = Path(os.path.abspath(Path(state_dir).expanduser()))
    expected_state = Path(os.path.abspath(expected_paths["state"].expanduser()))
    if resolved_state != expected_state:
        raise ValueError("monitor state_dir does not match the canonical scope path")
    if config["scope"] == "system":
        _validate_root_controlled_path(config_path, label="config")
        _validate_root_controlled_directory_chain(
            resolved_state,
            label="state directory",
        )
    elif os.name != "nt":
        config_info = config_path.lstat()
        if config_info.st_uid != _current_uid() or config_info.st_mode & 0o077:
            raise PermissionError("user monitor config ownership or mode is unsafe")
        _validate_user_controlled_directory_chain(
            config_path.parent,
            label="config directory",
        )
        _validate_user_controlled_directory_chain(
            resolved_state,
            label="state directory",
        )
    for candidate in _directory_chain(resolved_state):
        if os.path.lexists(candidate):
            _assert_real_directory(candidate)
    if resolved_state in {Path(resolved_state.anchor), Path.home().resolve()}:
        raise ValueError("monitor state_dir must be a dedicated NetOps directory")
    _assert_real_directory(resolved_state)
    marker = resolved_state / STATE_MARKER_NAME
    marker_content = _read_control_text(
        marker,
        label="monitor state ownership marker",
    )
    if marker_content != STATE_MARKER_CONTENT:
        raise ValueError("monitor state_dir has an invalid NetOps ownership marker")
    if os.name != "nt":
        expected_uid = 0 if config["scope"] == "system" else _current_uid()
        private_paths = [
            config_path,
            resolved_state,
            marker,
            resolved_state / STATE_MANIFEST_NAME,
        ]
        for candidate in private_paths:
            if not os.path.lexists(candidate):
                raise ValueError("monitor ownership manifest is incomplete")
            info = candidate.lstat()
            if info.st_uid != expected_uid or info.st_mode & 0o077:
                raise PermissionError("monitor control path ownership or mode is unsafe")
    _verify_owner_manifest(expected_paths, allow_missing=False)
    config["state_dir"] = str(resolved_state)
    return config


def _state_file(state_dir: Path) -> Path:
    return state_dir / "monitor-state.json"


def _load_state(state_dir: Path) -> dict[str, Any]:
    path = _state_file(state_dir)
    default = {
        "failure_count": 0,
        "last_full_epoch": 0,
        "incident_active": False,
        "last_status": "unknown",
    }
    if not os.path.lexists(path):
        return default
    payload = _read_regular_bytes(
        path,
        label="monitor state file",
        max_bytes=MAX_MONITOR_STATE_FILE_BYTES,
    )
    try:
        raw = parse_json_strict(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("monitor state file is invalid") from exc
    if not isinstance(raw, dict):
        return default
    state = dict(default)
    if (
        type(raw.get("failure_count")) is int
        and 0 <= raw["failure_count"] <= MAX_MONITOR_FAILURE_COUNT
    ):
        state["failure_count"] = raw["failure_count"]
    latest_plausible_epoch = time.time() + MAX_MONITOR_CLOCK_SKEW_SECONDS
    if (
        type(raw.get("last_full_epoch")) in {int, float}
        and math.isfinite(raw["last_full_epoch"])
        and 0 <= raw["last_full_epoch"] <= latest_plausible_epoch
    ):
        state["last_full_epoch"] = raw["last_full_epoch"]
    if type(raw.get("incident_active")) is bool:
        state["incident_active"] = raw["incident_active"]
    if raw.get("last_status") in {"ok", "failed", "unknown"}:
        state["last_status"] = raw["last_status"]
    if type(raw.get("incident_recovered")) is bool:
        state["incident_recovered"] = raw["incident_recovered"]
    if raw.get("last_error_code") == "sample-error":
        state["last_error_code"] = "sample-error"
    if (
        type(raw.get("last_error_epoch")) in {int, float}
        and math.isfinite(raw["last_error_epoch"])
        and 0 <= raw["last_error_epoch"] <= latest_plausible_epoch
    ):
        state["last_error_epoch"] = raw["last_error_epoch"]
    return state


def _snapshot_directory(state_dir: Path, *, create: bool) -> Path | None:
    """Return the owned snapshots directory without following a final symlink."""

    destination = state_dir / "snapshots"
    if os.path.lexists(destination):
        _secure_directory(destination, create=False, mode=0o700)
    elif not create:
        return None
    else:
        _secure_directory(destination, create=True, mode=0o700)
    return destination


def _write_snapshot_secure(
    snapshot_dir: Path,
    destination: Path,
    bundle: DiagnosticBundle,
) -> Path:
    with tempfile.TemporaryDirectory(prefix="netops-monitor-snapshot-") as temporary:
        staged = Path(temporary) / "snapshot.json"
        write_bundle(staged, bundle)
        payload = staged.read_bytes()
    if os.path.lexists(destination):
        raise FileExistsError(f"monitor snapshot already exists: {destination.name}")
    if os.name == "nt":
        _write_content(destination, payload)
        return destination
    directory_identity = _assert_real_directory(snapshot_dir)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_descriptor = os.open(snapshot_dir, directory_flags)
    created = False
    try:
        opened = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or (opened.st_dev, opened.st_ino) != directory_identity
        ):
            raise ValueError("monitor snapshots directory changed before write")
        descriptor = os.open(
            destination.name,
            flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        created = True
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            _assert_real_directory(snapshot_dir, identity=directory_identity)
        except ValueError:
            os.unlink(destination.name, dir_fd=directory_descriptor)
            created = False
            raise
    except Exception:
        if created:
            try:
                os.unlink(destination.name, dir_fd=directory_descriptor)
            except OSError:
                pass
        raise
    finally:
        os.close(directory_descriptor)
    return destination


def _save_snapshot(state_dir: Path, bundle: DiagnosticBundle, kind: str) -> Path:
    allowed_kinds = {
        "light",
        "full",
        "incident-trigger",
        "incident",
        "incident-recovery",
        "recovery",
    }
    if kind not in allowed_kinds:
        raise ValueError(f"unsupported monitor snapshot kind: {kind!r}")
    summary = _monitor_snapshot(bundle)
    validate_bundle_data(summary.to_dict())
    stamp = summary.started_at.replace(":", "").replace("-", "")
    _secure_directory(state_dir, create=True, mode=0o700)
    snapshot_dir = _snapshot_directory(state_dir, create=True)
    assert snapshot_dir is not None
    destination = snapshot_dir / f"{stamp}-{kind}-{summary.run_id[:8]}.json"
    return _write_snapshot_secure(snapshot_dir, destination, summary)


_MONITOR_METRICS = {
    "bitrate_bps",
    "bytes_received",
    "bytes_sent",
    "connect_ms",
    "count",
    "duration_ms",
    "handshake_ms",
    "http_status",
    "jitter_ms",
    "latency_ms",
    "loss_percent",
    "packet_loss_pct",
    "packet_loss_percent",
    "throughput_bps",
}
_MONITOR_SEGMENTS = {
    "access-network",
    "client-network",
    "compare",
    "destination",
    "dns",
    "node-ingress",
    "proxy-egress",
    "public-egress",
    "vps",
}
_MONITOR_PROBES = {
    "addresses",
    "bounded-route-snapshot",
    "congestion_control",
    "dns",
    "dns-file",
    "failed_services",
    "firewall_nft",
    "firewall_ufw",
    "getaddrinfo",
    "http-head",
    "interfaces",
    "listeners",
    "network_state",
    "qdisc",
    "routes",
    "rules",
    "services",
    "ssh-readonly-collector",
    "system_proxy",
    "tcp-connect",
    "tls-handshake",
}
_MONITOR_CURATED_PROBES = {
    "curated-tool:dnsdiag",
    "curated-tool:iperf3",
    "curated-tool:ipquality",
    "curated-tool:mtr",
    "curated-tool:nexttrace",
    "curated-tool:testssl",
}
_MONITOR_EXTERNAL_PROBES = {
    "external-identity:cloudflare-trace",
    "external-identity:ipify-v4",
}
_MONITOR_PROTOCOLS = {
    "http",
    "https",
    "icmp",
    "icmp-or-udp-tool-default",
    "ssh",
    "tcp",
    "tls",
    "udp",
}


def _safe_number(value: Any) -> int | float | bool | None:
    if type(value) is float and not math.isfinite(value):
        return None
    if type(value) in {int, float, bool}:
        return value
    return None


def _resource_summary(value: Any) -> Any:
    if type(value) is float and not math.isfinite(value):
        return None
    if type(value) in {int, float, bool}:
        return value
    if isinstance(value, list):
        items = [_resource_summary(item) for item in value]
        return [item for item in items if item is not None]
    if isinstance(value, dict):
        allowed = {
            "cpu_count",
            "disk_root",
            "free",
            "loadavg",
            "total",
            "used",
        }
        summary: dict[str, Any] = {}
        for key, item in value.items():
            if key not in allowed:
                continue
            summarized = _resource_summary(item)
            if summarized is not None:
                summary[key] = summarized
        return summary
    return None


def _monitor_environment(environment: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    platform = environment.get("platform")
    if isinstance(platform, dict):
        safe_platform = {
            key: value
            for key, value in platform.items()
            if key in {"id", "system", "machine"}
            and isinstance(value, str)
            and len(value) <= 64
        }
        if safe_platform:
            summary["platform"] = safe_platform
    network = environment.get("network_summary")
    if isinstance(network, dict):
        safe_network = {
            key: value
            for key, value in network.items()
            if key in {"ipv4_present", "ipv6_present", "ipv4_count", "ipv6_count"}
            and type(value) in {bool, int}
        }
        tun_hints = network.get("tun_hints")
        if isinstance(tun_hints, list):
            safe_network["tun_detected"] = bool(tun_hints)
        if safe_network:
            summary["network_summary"] = safe_network
    resources = _resource_summary(environment.get("resources"))
    if resources:
        summary["resources"] = resources
    commands = environment.get("commands")
    if isinstance(commands, dict):
        safe_commands: dict[str, dict[str, Any]] = {}
        for name, result in commands.items():
            if name not in _MONITOR_PROBES or not isinstance(result, dict):
                continue
            status = {
                key: value
                for key, value in result.items()
                if key in {"available", "returncode", "timed_out"}
                and type(value) in {bool, int}
            }
            if status:
                safe_commands[name] = status
        if safe_commands:
            summary["commands"] = safe_commands
    return summary


def _monitor_snapshot(bundle: DiagnosticBundle) -> DiagnosticBundle:
    """Return the anonymous, bounded record permitted for long-term monitoring."""

    summary = DiagnosticBundle(
        mode=(
            bundle.mode
            if bundle.mode in {"monitor-light", "monitor-full"}
            else "monitor-summary"
        ),
        vantage_points=["monitor"],
        environment=_monitor_environment(bundle.environment),
        limitations=["监控快照只保留匿名状态摘要，不包含原始命令输出或目标标识"],
        redactions=["monitor-anonymous-summary"],
        started_at=bundle.started_at,
        completed_at=bundle.completed_at,
        run_id=bundle.run_id,
        schema_version=bundle.schema_version,
    )
    for item in bundle.observations:
        metrics: dict[str, Any] = {}
        for key, value in item.metrics.items():
            safe_value = _safe_number(value)
            if key in _MONITOR_METRICS and safe_value is not None:
                metrics[key] = safe_value
        probe = item.probe
        if probe not in (
            _MONITOR_PROBES | _MONITOR_CURATED_PROBES | _MONITOR_EXTERNAL_PROBES
        ):
            probe = "other"
        summary.observations.append(
            Observation(
                vantage_point="monitor",
                segment=item.segment if item.segment in _MONITOR_SEGMENTS else "other",
                probe=probe,
                status=item.status,
                target=None,
                protocol=item.protocol if item.protocol in _MONITOR_PROTOCOLS else None,
                address_family=(
                    item.address_family
                    if item.address_family in {"ipv4", "ipv6"}
                    else None
                ),
                metrics=metrics,
                evidence={},
                confidence=item.confidence,
                limitations=[],
                observed_at=item.observed_at,
                observation_id=item.observation_id,
            )
        )
    path_statuses = {"observed", "partially-observed", "failed", "unknown", "ok"}
    observation_ids = {item.observation_id for item in summary.observations}
    summary.path_segments = [
        {
            "name": f"segment-{index}",
            "status": (
                segment.get("status")
                if isinstance(segment, dict) and segment.get("status") in path_statuses
                else "unknown"
            ),
            "evidence": [
                reference
                for reference in (
                    segment.get("evidence", []) if isinstance(segment, dict) else []
                )
                if isinstance(reference, str) and reference in observation_ids
            ],
            "limitations": [
                "监控快照只保留匿名推导的路径状态"
            ],
        }
        for index, segment in enumerate(bundle.path_segments, start=1)
    ]
    return summary.enrich_path_segments()


def _probe_failed(bundle: DiagnosticBundle) -> bool:
    dns = [item for item in bundle.observations if item.probe == "getaddrinfo"]
    if any(item.status == "failed" for item in dns):
        return True
    tcp = [item for item in bundle.observations if item.probe == "tcp-connect"]
    return not tcp or not any(item.status == "ok" for item in tcp)


def _merge(base: DiagnosticBundle, node: DiagnosticBundle) -> DiagnosticBundle:
    base.targets = node.targets
    base.observations.extend(node.observations)
    base.path_segments.extend(node.path_segments)
    base.findings.extend(node.findings)
    base.limitations.extend(node.limitations)
    base.completed_at = node.completed_at
    return base


def _single_sample(config: dict[str, Any], *, full: bool, trace: bool) -> DiagnosticBundle:
    target = config["target"]
    node = scan_node(
        target=target["host"],
        port=int(target["port"]),
        protocol=target.get("protocol", "tcp"),
        trace=trace,
        timeout=5,
    )
    if full:
        base = (
            scan_server_local(external=False)
            if config.get("profile") == "server"
            else scan_client(external=False)
        )
        base.mode = "monitor-full"
        return _merge(base, node).finish()
    node.mode = "monitor-light"
    return node.finish()


def _acquire_lock(
    state_dir: Path,
    maximum_age: int,
) -> tuple[Path, int, int | None, tuple[int, int]] | None:
    if type(maximum_age) is not int or maximum_age < 1:
        raise ValueError("monitor lock maximum age is invalid")
    lock = state_dir / "sample.lock"
    state_identity = _secure_directory(state_dir, create=True, mode=0o700)
    directory_descriptor: int | None = None
    if os.name != "nt":
        directory_descriptor = os.open(
            state_dir,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened_directory = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(opened_directory.st_mode)
            or (opened_directory.st_dev, opened_directory.st_ino) != state_identity
        ):
            os.close(directory_descriptor)
            raise ValueError("monitor state directory changed while being opened")
    flags = (
        os.O_CREAT
        | os.O_RDWR
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    before: os.stat_result | None = None
    if os.path.lexists(lock):
        before = lock.lstat()
        if (
            _is_link_like(lock)
            or not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
        ):
            raise ValueError("monitor sample lock must be an unlinked regular file")
    try:
        descriptor = os.open(
            lock.name if directory_descriptor is not None else lock,
            flags,
            0o600,
            **(
                {"dir_fd": directory_descriptor}
                if directory_descriptor is not None
                else {}
            ),
        )
    except OSError as exc:
        if directory_descriptor is not None:
            os.close(directory_descriptor)
        raise ValueError("monitor sample lock cannot be opened safely") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (
                before is not None
                and (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
            )
        ):
            raise ValueError("monitor sample lock changed while being opened")
        if os.name == "nt":
            import msvcrt

            if opened.st_size == 0:
                os.write(descriptor, b"\0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError:
                os.close(descriptor)
                if directory_descriptor is not None:
                    os.close(directory_descriptor)
                return None
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(descriptor)
                if directory_descriptor is not None:
                    os.close(directory_descriptor)
                return None
        return lock, descriptor, directory_descriptor, state_identity
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        if directory_descriptor is not None:
            try:
                os.close(directory_descriptor)
            except OSError:
                pass
        raise


def _release_lock(
    lock: tuple[Path, int, int | None, tuple[int, int]]
) -> None:
    _, descriptor, directory_descriptor, _identity = lock
    try:
        os.close(descriptor)
    except OSError:
        pass
    if directory_descriptor is not None:
        try:
            os.close(directory_descriptor)
        except OSError:
            pass


def _assert_locked_state_directory(
    lock: tuple[Path, int, int | None, tuple[int, int]]
) -> None:
    lock_path, _descriptor, directory_descriptor, identity = lock
    _assert_real_directory(lock_path.parent, identity=identity)
    if directory_descriptor is not None:
        info = os.fstat(directory_descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or (info.st_dev, info.st_ino) != identity
        ):
            raise ValueError("monitor state directory handle changed")


def _write_locked_monitor_state(
    lock: tuple[Path, int, int | None, tuple[int, int]],
    state: dict[str, Any],
) -> None:
    """Publish state relative to the directory handle held with the lock."""

    _assert_locked_state_directory(lock)
    lock_path, _descriptor, directory_descriptor, _identity = lock
    if directory_descriptor is None:
        write_json_atomic(_state_file(lock_path.parent), state)
        _assert_locked_state_directory(lock)
        return
    payload = (
        json.dumps(
            state,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    temporary_name = (
        f".monitor-state.json.{os.getpid()}.{os.urandom(12).hex()}.tmp"
    )
    descriptor = -1
    try:
        descriptor = os.open(
            temporary_name,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
            dir_fd=directory_descriptor,
        )
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(
            temporary_name,
            "monitor-state.json",
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        os.fsync(directory_descriptor)
    except Exception:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_descriptor)
        except FileNotFoundError:
            pass
        raise


def _snapshot_file_info(path: Path) -> os.stat_result:
    """Return a stable path-based identity for a regular snapshot file."""

    info = path.lstat()
    if _is_link_like(path) or not stat.S_ISREG(info.st_mode):
        raise ValueError("monitor snapshot must be an unlinked regular file")
    return info


def _scan_snapshot_files_by_path(
    snapshot_dir: Path,
) -> tuple[list[tuple[str, os.stat_result]], int]:
    """Scan without ``DirEntry.stat`` whose Windows identity fields are zero."""

    files: list[tuple[str, os.stat_result]] = []
    entries_seen = 0
    with os.scandir(snapshot_dir) as entries:
        for entry in entries:
            entries_seen += 1
            if entries_seen > MAX_SNAPSHOT_DIRECTORY_ENTRIES:
                raise ValueError(
                    "monitor snapshots directory exceeds the safe entry limit"
                )
            if not entry.name.endswith(".json"):
                continue
            path = snapshot_dir / entry.name
            try:
                info = _snapshot_file_info(path)
            except (OSError, ValueError):
                continue
            files.append((path.name, info))
    return files, entries_seen


def prune_snapshots(state_dir: Path, *, retention_days: int, max_bytes: int) -> dict[str, Any]:
    if type(retention_days) is not int or not 1 <= retention_days <= 365:
        raise ValueError("monitor retention_days must be an integer in 1..365")
    if type(max_bytes) is not int or not 1_048_576 <= max_bytes <= 10_737_418_240:
        raise ValueError("monitor max_bytes must be an integer in 1048576..10737418240")
    declared_state = Path(state_dir).expanduser()
    if not declared_state.is_absolute():
        raise ValueError("monitor state directory must be an absolute canonical path")
    state_dir = Path(os.path.abspath(declared_state))
    current = platform_id()
    candidate_scopes = ("user", "system") if current == "linux" else ("user",)
    owned_paths: dict[str, Path] | None = None
    for candidate_scope in candidate_scopes:
        candidate_paths = _monitor_paths(candidate_scope)
        expected_state = Path(
            os.path.abspath(candidate_paths["state"].expanduser())
        )
        if state_dir == expected_state:
            owned_paths = candidate_paths
            break
    if owned_paths is None:
        raise ValueError("monitor state directory does not match a canonical scope path")
    _assert_real_directory(state_dir)
    marker = state_dir / STATE_MARKER_NAME
    marker_content = _read_control_text(
        marker,
        label="monitor state ownership marker",
    )
    if marker_content != STATE_MARKER_CONTENT:
        raise ValueError("refusing to prune an inactive monitor state directory")
    if os.name != "nt":
        expected_uid = _current_uid()
        for candidate in (state_dir, marker):
            info = candidate.lstat()
            if info.st_uid != expected_uid or info.st_mode & 0o077:
                raise PermissionError(
                    "monitor prune ownership or control-path mode is unsafe"
                )
    _verify_owner_manifest(owned_paths, allow_missing=False)
    _secure_directory(state_dir, create=False, mode=0o700)
    snapshot_dir = _snapshot_directory(state_dir, create=False)
    if snapshot_dir is None:
        return {
            "removed": [],
            "removed_count": 0,
            "remaining_bytes": 0,
            "remaining_entries": 0,
        }
    now = time.time()
    cutoff = now - retention_days * 86400
    files: list[tuple[str, os.stat_result]] = []
    directory_descriptor: int | None = None
    directory_identity = _assert_real_directory(snapshot_dir)
    entries_seen = 0
    if os.name != "nt":
        flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        directory_descriptor = os.open(snapshot_dir, flags)
        opened = os.fstat(directory_descriptor)
        if (opened.st_dev, opened.st_ino) != directory_identity:
            os.close(directory_descriptor)
            raise ValueError("monitor snapshots directory changed before pruning")
        try:
            with os.scandir(directory_descriptor) as entries:
                for entry in entries:
                    entries_seen += 1
                    if entries_seen > MAX_SNAPSHOT_DIRECTORY_ENTRIES:
                        raise ValueError(
                            "monitor snapshots directory exceeds the safe entry limit"
                        )
                    if not entry.name.endswith(".json"):
                        continue
                    info = entry.stat(follow_symlinks=False)
                    if stat.S_ISREG(info.st_mode):
                        files.append((entry.name, info))
        except Exception:
            os.close(directory_descriptor)
            directory_descriptor = None
            raise
    else:
        files, entries_seen = _scan_snapshot_files_by_path(snapshot_dir)
    files.sort(key=lambda item: item[1].st_mtime)
    removed: list[str] = []
    removed_count = 0
    try:
        def remove_entry(item: tuple[str, os.stat_result]) -> bool:
            nonlocal removed_count
            name, expected = item
            if directory_descriptor is not None:
                current = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
                if (
                    not stat.S_ISREG(current.st_mode)
                    or (current.st_dev, current.st_ino)
                    != (expected.st_dev, expected.st_ino)
                ):
                    raise ValueError("monitor snapshot changed during pruning")
                os.unlink(name, dir_fd=directory_descriptor)
            else:
                path = snapshot_dir / name
                _assert_real_directory(snapshot_dir, identity=directory_identity)
                try:
                    current = _snapshot_file_info(path)
                except (OSError, ValueError) as exc:
                    raise ValueError(
                        "monitor snapshot changed during pruning"
                    ) from exc
                if (current.st_dev, current.st_ino) != (
                    expected.st_dev,
                    expected.st_ino,
                ):
                    raise ValueError("monitor snapshot changed during pruning")
                path.unlink()
            removed_count += 1
            if len(removed) < MAX_REPORTED_REMOVALS:
                removed.append(str((snapshot_dir / name).resolve()))
            return True

        expired = [item for item in files if item[1].st_mtime < cutoff]
        retained = [item for item in files if item[1].st_mtime >= cutoff]
        for item in expired:
            remove_entry(item)

        excess_count = max(0, len(retained) - MAX_SNAPSHOT_FILES)
        for item in retained[:excess_count]:
            remove_entry(item)
        retained = retained[excess_count:]

        total = sum(item[1].st_size for item in retained)
        size_index = 0
        while size_index < len(retained) and total > max_bytes:
            item = retained[size_index]
            remove_entry(item)
            total -= item[1].st_size
            size_index += 1
        _assert_real_directory(snapshot_dir, identity=directory_identity)
        return {
            "removed": removed,
            "removed_count": removed_count,
            "remaining_bytes": total,
            "remaining_entries": entries_seen - removed_count,
        }
    finally:
        if directory_descriptor is not None:
            os.close(directory_descriptor)


def run_sample(config_path: str | Path, *, allow_incident_loop: bool = True) -> dict[str, Any]:
    try:
        config = _load_config(config_path)
    except Exception:
        return {
            "status": "failed",
            "reason": "invalid-monitor-config",
            "error_redacted": True,
        }
    state_dir = Path(config["state_dir"]).expanduser()
    maximum_age = int(config["incident_duration_seconds"]) + 180
    try:
        lock = _acquire_lock(state_dir, maximum_age)
    except Exception:
        return {
            "status": "failed",
            "reason": "monitor-state-unavailable",
            "error_redacted": True,
        }
    if lock is None:
        return {"status": "skipped", "reason": "another sample is active"}
    state = {
        "failure_count": 0,
        "last_full_epoch": 0,
        "incident_active": False,
        "last_status": "unknown",
    }
    try:
        _assert_locked_state_directory(lock)
        state = _load_state(state_dir)
        pruning_removed_count = 0
        pruning_remaining_bytes = 0

        def save_pruned(sample: DiagnosticBundle, kind: str) -> Path:
            nonlocal pruning_removed_count, pruning_remaining_bytes
            for phase in ("before", "after"):
                _assert_locked_state_directory(lock)
                pruning_result = prune_snapshots(
                    state_dir,
                    retention_days=int(config["retention_days"]),
                    max_bytes=int(config["max_bytes"]),
                )
                pruning_removed_count += int(
                    pruning_result.get(
                        "removed_count",
                        len(pruning_result.get("removed", [])),
                    )
                )
                pruning_remaining_bytes = int(pruning_result["remaining_bytes"])
                if phase == "before":
                    if (
                        int(pruning_result.get("remaining_entries", 0))
                        >= MAX_SNAPSHOT_DIRECTORY_ENTRIES
                    ):
                        raise ValueError(
                            "monitor snapshots directory has no safe write headroom"
                        )
                    saved = _save_snapshot(state_dir, sample, kind)
                elif not saved.exists():
                    raise ValueError(
                        "monitor snapshot exceeded the configured retention bound"
                    )
            return saved

        now = time.time()
        full = now - float(state.get("last_full_epoch", 0)) >= int(
            config["full_interval_seconds"]
        )
        bundle = _single_sample(config, full=full, trace=False)
        failed = _probe_failed(bundle)
        path = save_pruned(bundle, "full" if full else "light")
        state["failure_count"] = int(state.get("failure_count", 0)) + 1 if failed else 0
        if full:
            state["last_full_epoch"] = now
        previous = state.get("last_status", "unknown")
        current = "failed" if failed else "ok"
        state["last_status"] = current
        state.pop("incident_recovered", None)
        incident_paths: list[Path] = []
        if (
            failed
            and state["failure_count"] >= int(config["failure_threshold"])
            and allow_incident_loop
        ):
            state["incident_active"] = True
            trigger = _single_sample(config, full=True, trace=False)
            incident_paths.append(save_pruned(trigger, "incident-trigger"))
            deadline = time.monotonic() + int(config["incident_duration_seconds"])
            recovered = False
            while time.monotonic() < deadline:
                remaining = deadline - time.monotonic()
                interval = int(config["incident_interval_seconds"])
                if remaining <= 0:
                    break
                time.sleep(min(interval, remaining))
                if time.monotonic() >= deadline:
                    break
                incident = _single_sample(config, full=False, trace=False)
                incident_paths.append(save_pruned(incident, "incident"))
                if _probe_failed(incident):
                    continue
                recovery = _single_sample(config, full=True, trace=False)
                incident_paths.append(
                    save_pruned(recovery, "incident-recovery")
                )
                if _probe_failed(recovery):
                    continue
                state["failure_count"] = 0
                state["last_status"] = "ok"
                current = "ok"
                recovered = True
                break
            state["incident_active"] = False
            state["incident_recovered"] = recovered
        elif previous == "failed" and current == "ok":
            recovery = _single_sample(config, full=True, trace=False)
            recovery_failed = _probe_failed(recovery)
            incident_paths.append(
                save_pruned(
                    recovery,
                    "incident" if recovery_failed else "recovery",
                )
            )
            if recovery_failed:
                state["failure_count"] = max(1, int(state.get("failure_count", 0)))
                state["last_status"] = "failed"
                current = "failed"
            state["incident_recovered"] = not recovery_failed
        state.pop("last_error_code", None)
        state.pop("last_error_epoch", None)
        _write_locked_monitor_state(lock, state)
        return {
            "status": current,
            "snapshot": f"snapshots/{path.name}",
            "incident_snapshots": [
                f"snapshots/{item.name}" for item in incident_paths
            ],
            "state": state,
            "pruning": {
                "removed_count": pruning_removed_count,
                "remaining_bytes": pruning_remaining_bytes,
            },
        }
    except Exception:
        state["failure_count"] = min(
            MAX_MONITOR_FAILURE_COUNT,
            int(state.get("failure_count", 0)) + 1,
        )
        state["last_status"] = "failed"
        state["incident_active"] = False
        state.pop("incident_recovered", None)
        state["last_error_code"] = "sample-error"
        state["last_error_epoch"] = int(time.time())
        try:
            _write_locked_monitor_state(lock, state)
        except Exception:
            pass
        return {
            "status": "failed",
            "reason": "sample-error",
            "error_redacted": True,
            "state": state,
        }
    finally:
        _release_lock(lock)
