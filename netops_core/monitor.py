from __future__ import annotations

import json
import os
import plistlib
import shlex
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from .models import DiagnosticBundle, load_bundle, utc_now, write_bundle, write_json_atomic
from .scanner import scan_client, scan_node, scan_server_local, trace_target
from .util import platform_id, run_command


DEFAULTS = {
    "interval_seconds": 60,
    "full_interval_seconds": 900,
    "failure_threshold": 3,
    "incident_interval_seconds": 5,
    "incident_duration_seconds": 600,
    "retention_days": 7,
    "max_bytes": 200 * 1024 * 1024,
}


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
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


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
    if not 1 <= port <= 65535:
        raise ValueError("port must be between 1 and 65535")
    settings = dict(DEFAULTS)
    if overrides:
        for key, value in overrides.items():
            if key not in settings:
                raise ValueError(f"unknown monitor setting: {key}")
            if not isinstance(value, int) or value <= 0:
                raise ValueError(f"monitor setting {key} must be a positive integer")
            settings[key] = value
    paths = _monitor_paths(scope)
    if platform_id() in {"macos", "windows"} and scope != "user":
        raise ValueError("macOS and Windows monitoring currently supports user scope only")
    entry = str(Path(entry_script).expanduser().resolve())
    config = {
        "schema_version": "1.0",
        "created_at": utc_now(),
        "profile": profile,
        "scope": scope,
        "target": {"host": target, "port": port, "protocol": protocol},
        "state_dir": str(paths["state"]),
        **settings,
    }
    command = [
        sys.executable,
        entry,
        "monitor",
        "sample",
        "--config",
        str(paths["config"]),
    ]
    files: dict[str, str | bytes] = {
        str(paths["config"]): json.dumps(
            config, ensure_ascii=False, indent=2, sort_keys=True
        )
        + "\n"
    }
    commands: list[list[str]] = []
    current = platform_id()
    if current == "linux":
        service = "\n".join(
            [
                "[Unit]",
                "Description=NetOps bounded network sample",
                "After=network-online.target",
                "",
                "[Service]",
                "Type=oneshot",
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
            "StandardOutPath": str(paths["state"] / "scheduler.out.log"),
            "StandardErrorPath": str(paths["state"] / "scheduler.err.log"),
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
                "1",
                "/F",
            ]
        )
    return {
        "platform": current,
        "scope": scope,
        "paths": {key: str(value) for key, value in paths.items()},
        "config": config,
        "files": files,
        "commands": commands,
    }


def subprocess_command_line(args: list[str]) -> str:
    if platform_id() == "windows":
        import subprocess

        return subprocess.list2cmdline(args)
    return " ".join(shlex.quote(item) for item in args)


def _write_content(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, bytes):
        temporary = path.with_name(f".{path.name}.tmp")
        temporary.write_bytes(content)
        temporary.replace(path)
        return
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)


def install_monitor(plan: dict[str, Any], *, authorized: bool, dry_run: bool) -> dict[str, Any]:
    if not authorized and not dry_run:
        raise PermissionError("monitor installation requires --authorized")
    if dry_run:
        return {"changed": False, "dry_run": True, "plan": serializable_plan(plan)}
    if plan["platform"] == "linux" and plan["scope"] == "system" and os.geteuid() != 0:
        raise PermissionError("system-scope Linux monitoring must run as root")
    state = Path(plan["paths"]["state"])
    state.mkdir(parents=True, exist_ok=True)
    changed_files: list[str] = []
    for raw_path, content in plan["files"].items():
        path = Path(raw_path)
        existing = path.read_bytes() if path.exists() else None
        desired = content if isinstance(content, bytes) else content.encode("utf-8")
        if existing != desired:
            _write_content(path, content)
            changed_files.append(str(path))
    command_results: list[dict[str, Any]] = []
    for command in plan["commands"]:
        result = run_command(command, timeout=30)
        command_results.append(result)
        # launchctl bootout is intentionally allowed to fail when no old job exists.
        expected_bootout_failure = (
            plan["platform"] == "macos"
            and len(command) > 1
            and command[1] == "bootout"
        )
        if result["returncode"] != 0 and not expected_bootout_failure:
            raise RuntimeError(
                f"scheduler command failed: {command[0]}: {result['stderr']}"
            )
    return {
        "changed": bool(changed_files),
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


def monitor_status(*, scope: str) -> dict[str, Any]:
    paths = _monitor_paths(scope)
    current = platform_id()
    result: dict[str, Any] = {
        "platform": current,
        "scope": scope,
        "config_exists": paths["config"].exists(),
        "state_exists": paths["state"].exists(),
        "paths": {key: str(value) for key, value in paths.items()},
    }
    if current == "linux":
        prefix = ["systemctl"] if scope == "system" else ["systemctl", "--user"]
        result["scheduler"] = run_command(
            [*prefix, "is-enabled", "netops-monitor.timer"], timeout=10
        )
        result["active"] = run_command(
            [*prefix, "is-active", "netops-monitor.timer"], timeout=10
        )
    elif current == "macos":
        result["scheduler"] = run_command(
            [
                "launchctl",
                "print",
                f"gui/{_current_uid()}/io.github.con-benksl.netops-monitor",
            ],
            timeout=10,
        )
    elif current == "windows":
        result["scheduler"] = run_command(
            ["schtasks", "/Query", "/TN", "NetOps Monitor"], timeout=10
        )
    return result


def remove_monitor(*, scope: str, authorized: bool, dry_run: bool) -> dict[str, Any]:
    if not authorized and not dry_run:
        raise PermissionError("monitor removal requires --authorized")
    paths = _monitor_paths(scope)
    current = platform_id()
    commands: list[list[str]] = []
    removable: list[Path] = [paths["config"]]
    if current == "linux":
        prefix = ["systemctl"] if scope == "system" else ["systemctl", "--user"]
        commands = [
            [*prefix, "disable", "--now", "netops-monitor.timer"],
            [*prefix, "daemon-reload"],
        ]
        removable.extend([paths["service"], paths["timer"]])
    elif current == "macos":
        commands = [
            [
                "launchctl",
                "bootout",
                f"gui/{_current_uid()}",
                str(paths["plist"]),
            ]
        ]
        removable.append(paths["plist"])
    elif current == "windows":
        commands = [["schtasks", "/Delete", "/TN", "NetOps Monitor", "/F"]]
    if dry_run:
        return {
            "dry_run": True,
            "commands": commands,
            "remove_files": [str(path) for path in removable],
            "preserve_state": str(paths["state"]),
        }
    if current == "linux" and scope == "system" and os.geteuid() != 0:
        raise PermissionError("system-scope Linux monitoring must run as root")
    command_results = [run_command(command, timeout=30) for command in commands[:1]]
    removed: list[str] = []
    for path in removable:
        if path.exists():
            path.unlink()
            removed.append(str(path))
    if current == "linux":
        command_results.append(run_command(commands[1], timeout=30))
    return {
        "removed_files": removed,
        "scheduler_commands": command_results,
        "preserved_state": str(paths["state"]),
    }


def _load_config(path: str | Path) -> dict[str, Any]:
    with Path(path).expanduser().open("r", encoding="utf-8") as handle:
        config = json.load(handle)
    if config.get("schema_version") != "1.0":
        raise ValueError("unsupported monitor config schema")
    for key in DEFAULTS:
        config.setdefault(key, DEFAULTS[key])
    return config


def _state_file(state_dir: Path) -> Path:
    return state_dir / "monitor-state.json"


def _load_state(state_dir: Path) -> dict[str, Any]:
    path = _state_file(state_dir)
    if not path.exists():
        return {
            "failure_count": 0,
            "last_full_epoch": 0,
            "incident_active": False,
            "last_status": "unknown",
        }
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _save_snapshot(state_dir: Path, bundle: DiagnosticBundle, kind: str) -> Path:
    stamp = bundle.started_at.replace(":", "").replace("-", "")
    destination = state_dir / "snapshots" / f"{stamp}-{kind}-{bundle.run_id[:8]}.json"
    return write_bundle(destination, bundle)


def _probe_failed(bundle: DiagnosticBundle) -> bool:
    dns = [item for item in bundle.observations if item.probe == "getaddrinfo"]
    if any(item.status == "failed" for item in dns):
        return True
    tcp = [item for item in bundle.observations if item.probe == "tcp-connect"]
    return bool(tcp) and not any(item.status == "ok" for item in tcp)


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


def _acquire_lock(state_dir: Path, maximum_age: int) -> Path | None:
    lock = state_dir / "sample.lock"
    state_dir.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        try:
            if time.time() - lock.stat().st_mtime > maximum_age:
                lock.unlink()
                return _acquire_lock(state_dir, maximum_age)
        except OSError:
            pass
        return None
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(f"{os.getpid()}\n")
    return lock


def prune_snapshots(state_dir: Path, *, retention_days: int, max_bytes: int) -> dict[str, Any]:
    snapshot_dir = state_dir / "snapshots"
    if not snapshot_dir.exists():
        return {"removed": [], "remaining_bytes": 0}
    now = time.time()
    cutoff = now - retention_days * 86400
    files = sorted(
        (path for path in snapshot_dir.glob("*.json") if path.is_file()),
        key=lambda path: path.stat().st_mtime,
    )
    removed: list[str] = []
    for path in list(files):
        if path.stat().st_mtime < cutoff:
            path.unlink()
            removed.append(str(path))
            files.remove(path)
    total = sum(path.stat().st_size for path in files)
    while files and total > max_bytes:
        path = files.pop(0)
        size = path.stat().st_size
        path.unlink()
        removed.append(str(path))
        total -= size
    return {"removed": removed, "remaining_bytes": total}


def run_sample(config_path: str | Path, *, allow_incident_loop: bool = True) -> dict[str, Any]:
    config = _load_config(config_path)
    state_dir = Path(config["state_dir"]).expanduser()
    maximum_age = int(config["incident_duration_seconds"]) + 180
    lock = _acquire_lock(state_dir, maximum_age)
    if lock is None:
        return {"status": "skipped", "reason": "another sample is active"}
    try:
        state = _load_state(state_dir)
        now = time.time()
        full = now - float(state.get("last_full_epoch", 0)) >= int(
            config["full_interval_seconds"]
        )
        bundle = _single_sample(config, full=full, trace=False)
        failed = _probe_failed(bundle)
        path = _save_snapshot(state_dir, bundle, "full" if full else "light")
        state["failure_count"] = int(state.get("failure_count", 0)) + 1 if failed else 0
        if full:
            state["last_full_epoch"] = now
        previous = state.get("last_status", "unknown")
        current = "failed" if failed else "ok"
        state["last_status"] = current
        incident_paths: list[str] = []
        if (
            failed
            and state["failure_count"] >= int(config["failure_threshold"])
            and allow_incident_loop
        ):
            state["incident_active"] = True
            trigger = _single_sample(config, full=True, trace=True)
            incident_paths.append(str(_save_snapshot(state_dir, trigger, "incident-trigger")))
            deadline = time.monotonic() + int(config["incident_duration_seconds"])
            recovered = False
            while time.monotonic() < deadline:
                time.sleep(int(config["incident_interval_seconds"]))
                incident = _single_sample(config, full=False, trace=False)
                incident_paths.append(str(_save_snapshot(state_dir, incident, "incident")))
                if _probe_failed(incident):
                    continue
                recovery = _single_sample(config, full=True, trace=True)
                incident_paths.append(
                    str(_save_snapshot(state_dir, recovery, "incident-recovery"))
                )
                state["failure_count"] = 0
                state["last_status"] = "ok"
                recovered = True
                break
            state["incident_active"] = False
            state["incident_recovered"] = recovered
        elif previous == "failed" and current == "ok":
            recovery = _single_sample(config, full=True, trace=True)
            incident_paths.append(str(_save_snapshot(state_dir, recovery, "recovery")))
        write_json_atomic(_state_file(state_dir), state)
        pruning = prune_snapshots(
            state_dir,
            retention_days=int(config["retention_days"]),
            max_bytes=int(config["max_bytes"]),
        )
        return {
            "status": current,
            "snapshot": str(path),
            "incident_snapshots": incident_paths,
            "state": state,
            "pruning": pruning,
        }
    finally:
        lock.unlink(missing_ok=True)
