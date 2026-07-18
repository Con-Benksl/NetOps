from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
from pathlib import Path
from typing import Any

from . import CHANGE_SCHEMA_VERSION
from .fleet import get_host, scp_invocation, ssh_invocation
from .models import utc_now, write_json_atomic
from .util import run_command


SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
PHASES = ("preflight", "apply", "validate", "verify", "rollback", "rollback_verify")


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _hash_file(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return {"size": path.stat().st_size, "sha256": digest.hexdigest()}


def _validate_command(command: dict[str, Any], index: int) -> None:
    if command.get("phase") not in PHASES:
        raise ValueError(f"operations[{index}].phase must be one of {PHASES}")
    if not isinstance(command.get("description"), str) or not command["description"].strip():
        raise ValueError(f"operations[{index}] needs a description")
    if not isinstance(command.get("command"), str) or not command["command"].strip():
        raise ValueError(f"operations[{index}] needs a command")
    timeout = command.get("timeout_seconds", 30)
    if not isinstance(timeout, int) or not 1 <= timeout <= 600:
        raise ValueError(f"operations[{index}].timeout_seconds must be 1..600")


def validate_change_spec(spec: dict[str, Any], *, source_dir: Path) -> dict[str, Any]:
    if spec.get("schema_version") != CHANGE_SCHEMA_VERSION:
        raise ValueError(f"change spec schema must be {CHANGE_SCHEMA_VERSION!r}")
    for key in ("name", "summary", "host_alias"):
        if not isinstance(spec.get(key), str) or not spec[key].strip():
            raise ValueError(f"change spec needs non-empty {key}")
    invariants = spec.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        raise ValueError("change spec needs at least one invariant")
    if not all(isinstance(item, str) and item.strip() for item in invariants):
        raise ValueError("every invariant must be a non-empty string")
    backup_paths = spec.get("backup_paths")
    if not isinstance(backup_paths, list) or not backup_paths:
        raise ValueError("change spec needs at least one backup path")
    for path in backup_paths:
        if not isinstance(path, str) or not path.startswith("/"):
            raise ValueError("backup paths must be absolute remote paths")
    operations = spec.get("operations") or []
    if not operations:
        raise ValueError("change spec needs operations")
    for index, command in enumerate(operations):
        if not isinstance(command, dict):
            raise ValueError(f"operations[{index}] must be an object")
        _validate_command(command, index)
    if not any(item["phase"] == "validate" for item in operations):
        raise ValueError("change spec needs at least one validate operation")
    if not any(item["phase"] == "verify" for item in operations):
        raise ValueError("change spec needs at least one verify operation")
    if not any(item["phase"] == "rollback_verify" for item in operations):
        raise ValueError("change spec needs at least one rollback_verify operation")
    services = spec.get("restart_services") or []
    for service in services:
        if not isinstance(service, str) or not SERVICE_RE.fullmatch(service):
            raise ValueError(f"invalid service name: {service!r}")
    normalized_payloads: list[dict[str, Any]] = []
    for index, payload in enumerate(spec.get("payloads") or []):
        if not isinstance(payload, dict):
            raise ValueError(f"payloads[{index}] must be an object")
        local = payload.get("local_path")
        remote = payload.get("remote_path")
        mode = payload.get("mode", "0644")
        if not isinstance(local, str) or not isinstance(remote, str):
            raise ValueError(f"payloads[{index}] needs local_path and remote_path")
        if not remote.startswith("/"):
            raise ValueError(f"payloads[{index}].remote_path must be absolute")
        if not re.fullmatch(r"0?[0-7]{3,4}", str(mode)):
            raise ValueError(f"payloads[{index}].mode must be an octal file mode")
        local_path = (source_dir / local).resolve()
        if not local_path.is_file():
            raise ValueError(f"payload file does not exist: {local_path}")
        normalized_payloads.append(
            {
                "local_path": str(local_path),
                "remote_path": remote,
                "mode": str(mode),
                **_hash_file(local_path),
            }
        )
    backup_root = spec.get("backup_root", "/var/backups/netops")
    if not isinstance(backup_root, str) or not backup_root.startswith("/"):
        raise ValueError("backup_root must be an absolute remote path")
    return {
        "schema_version": CHANGE_SCHEMA_VERSION,
        "name": spec["name"],
        "summary": spec["summary"],
        "host_alias": spec["host_alias"],
        "invariants": invariants,
        "backup_paths": list(dict.fromkeys(backup_paths)),
        "backup_root": backup_root.rstrip("/"),
        "payloads": normalized_payloads,
        "operations": [
            {
                "phase": item["phase"],
                "description": item["description"],
                "command": item["command"],
                "timeout_seconds": item.get("timeout_seconds", 30),
            }
            for item in operations
        ],
        "restart_services": services,
    }


def create_plan(
    spec_path: str | Path,
    fleet: dict[str, Any],
    output_path: str | Path,
) -> dict[str, Any]:
    source = Path(spec_path).expanduser().resolve()
    with source.open("r", encoding="utf-8") as handle:
        raw = json.load(handle)
    normalized = validate_change_spec(raw, source_dir=source.parent)
    host = get_host(fleet, normalized["host_alias"])
    plan_body = {
        **normalized,
        "host": {
            "alias": host["alias"],
            "management": host["management"],
            "ssh": {
                key: value
                for key, value in (host.get("ssh") or {}).items()
                if key
                in {
                    "user",
                    "port",
                    "config_host",
                    "identity_file",
                    "credential_reference",
                    "password_env",
                }
            },
        },
    }
    plan_id = hashlib.sha256(_canonical(plan_body)).hexdigest()[:16]
    plan = {
        **plan_body,
        "plan_id": plan_id,
        "created_at": utc_now(),
        "source_spec": str(source),
    }
    write_json_atomic(output_path, plan)
    return plan


def load_plan(path: str | Path) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    with source.open("r", encoding="utf-8") as handle:
        plan = json.load(handle)
    plan_id = plan.get("plan_id")
    body = {
        key: value
        for key, value in plan.items()
        if key not in {"plan_id", "created_at", "source_spec"}
    }
    expected = hashlib.sha256(_canonical(body)).hexdigest()[:16]
    if plan_id != expected:
        raise ValueError("change plan ID does not match its contents")
    for payload in plan.get("payloads", []):
        local = Path(payload["local_path"])
        if not local.is_file() or _hash_file(local)["sha256"] != payload["sha256"]:
            raise ValueError(f"payload changed after planning: {local}")
    return plan


def _remote_script(
    host: dict[str, Any],
    script: str,
    *,
    timeout: int,
) -> dict[str, Any]:
    command, transport_env = ssh_invocation(host)
    return run_command(
        [*command, "sh", "-s"],
        timeout=timeout,
        input_text="set -eu\n" + script.rstrip() + "\n",
        env=transport_env,
    )


def _run_phase(
    plan: dict[str, Any],
    host: dict[str, Any],
    phase: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for operation in plan.get("operations", []):
        if operation["phase"] != phase:
            continue
        result = _remote_script(
            host,
            operation["command"],
            timeout=int(operation["timeout_seconds"]),
        )
        results.append(
            {
                "phase": phase,
                "description": operation["description"],
                "returncode": result["returncode"],
                "stdout": result["stdout"],
                "stderr": result["stderr"],
                "duration_ms": result.get("duration_ms", 0),
            }
        )
        if result["returncode"] != 0:
            raise RuntimeError(
                f"{phase} failed: {operation['description']}: {result['stderr']}"
            )
    return results


def _backup(plan: dict[str, Any], host: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    backup_dir = f"{plan['backup_root']}/{plan['plan_id']}"
    archive = f"{backup_dir}/state.tar.gz"
    quoted_paths = " ".join(shlex.quote(path) for path in plan["backup_paths"])
    script = (
        f"install -d -m 0700 {shlex.quote(backup_dir)}\n"
        f"tar -czpf {shlex.quote(archive)} --absolute-names -- {quoted_paths}\n"
        f"test -s {shlex.quote(archive)}"
    )
    result = _remote_script(host, script, timeout=120)
    if result["returncode"] != 0:
        raise RuntimeError(f"backup failed: {result['stderr']}")
    return backup_dir, result


def _upload_payloads(
    plan: dict[str, Any],
    host: dict[str, Any],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for index, payload in enumerate(plan.get("payloads", [])):
        temporary = f"/tmp/netops-{plan['plan_id']}-{index}"
        upload_command, transport_env = scp_invocation(
            host, payload["local_path"], temporary
        )
        upload = run_command(upload_command, timeout=120, env=transport_env)
        if upload["returncode"] != 0:
            raise RuntimeError(f"payload upload failed: {upload['stderr']}")
        install_script = (
            f"install -m {shlex.quote(payload['mode'])} -- "
            f"{shlex.quote(temporary)} {shlex.quote(payload['remote_path'])}\n"
            f"rm -f -- {shlex.quote(temporary)}"
        )
        install = _remote_script(host, install_script, timeout=30)
        if install["returncode"] != 0:
            raise RuntimeError(f"payload install failed: {install['stderr']}")
        results.append(
            {
                "remote_path": payload["remote_path"],
                "sha256": payload["sha256"],
                "upload_returncode": upload["returncode"],
                "install_returncode": install["returncode"],
            }
        )
    return results


def _restart_services(plan: dict[str, Any], host: dict[str, Any]) -> dict[str, Any] | None:
    services = plan.get("restart_services") or []
    if not services:
        return None
    command = "systemctl restart -- " + " ".join(
        shlex.quote(service) for service in services
    )
    result = _remote_script(host, command, timeout=90)
    if result["returncode"] != 0:
        raise RuntimeError(f"service restart failed: {result['stderr']}")
    return result


def _restore(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    backup_dir: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    archive = f"{backup_dir}/state.tar.gz"
    restore = _remote_script(
        host,
        f"test -s {shlex.quote(archive)}\n"
        f"tar -xzpf {shlex.quote(archive)} -C /",
        timeout=120,
    )
    results.append(
        {
            "phase": "restore-backup",
            "returncode": restore["returncode"],
            "stdout": restore["stdout"],
            "stderr": restore["stderr"],
        }
    )
    if restore["returncode"] != 0:
        raise RuntimeError(f"backup restore failed: {restore['stderr']}")
    results.extend(_run_phase(plan, host, "rollback"))
    restarted = _restart_services(plan, host)
    if restarted is not None:
        results.append(
            {
                "phase": "rollback-restart",
                "returncode": restarted["returncode"],
                "stdout": restarted["stdout"],
                "stderr": restarted["stderr"],
            }
        )
    results.extend(_run_phase(plan, host, "rollback_verify"))
    return results


def _assert_host_unchanged(plan: dict[str, Any], host: dict[str, Any]) -> None:
    current = {
        "alias": host["alias"],
        "management": host["management"],
        "ssh": {
            key: value
            for key, value in (host.get("ssh") or {}).items()
            if key
            in {
                "user",
                "port",
                "config_host",
                "identity_file",
                "credential_reference",
                "password_env",
            }
        },
    }
    if current != plan.get("host"):
        raise ValueError(
            "fleet host metadata changed after planning; create and review a new plan"
        )


def apply_plan(
    plan_path: str | Path,
    fleet: dict[str, Any],
    *,
    authorized: bool,
    confirmed_plan_id: str,
    receipt_path: str | Path | None = None,
) -> dict[str, Any]:
    if not authorized:
        raise PermissionError("change apply requires --authorized")
    plan = load_plan(plan_path)
    if confirmed_plan_id != plan["plan_id"]:
        raise PermissionError("confirmed plan ID does not match the reviewed plan")
    host = get_host(fleet, plan["host_alias"])
    _assert_host_unchanged(plan, host)
    receipt: dict[str, Any] = {
        "schema_version": "1.0",
        "plan_id": plan["plan_id"],
        "host_alias": plan["host_alias"],
        "started_at": utc_now(),
        "status": "running",
        "steps": [],
    }
    backup_dir: str | None = None
    try:
        receipt["steps"].extend(_run_phase(plan, host, "preflight"))
        backup_dir, backup_result = _backup(plan, host)
        receipt["backup_dir"] = backup_dir
        receipt["steps"].append(
            {
                "phase": "backup",
                "returncode": backup_result["returncode"],
                "duration_ms": backup_result.get("duration_ms", 0),
            }
        )
        receipt["steps"].extend(_run_phase(plan, host, "apply"))
        receipt["payloads"] = _upload_payloads(plan, host)
        receipt["steps"].extend(_run_phase(plan, host, "validate"))
        restarted = _restart_services(plan, host)
        if restarted is not None:
            receipt["steps"].append(
                {
                    "phase": "restart",
                    "returncode": restarted["returncode"],
                    "duration_ms": restarted.get("duration_ms", 0),
                }
            )
        receipt["steps"].extend(_run_phase(plan, host, "verify"))
        receipt["status"] = "applied"
    except Exception as exc:
        receipt["status"] = "apply-failed"
        receipt["error"] = str(exc)
        if backup_dir:
            try:
                receipt["rollback_steps"] = _restore(
                    plan, host, backup_dir=backup_dir
                )
                receipt["status"] = "rolled-back"
            except Exception as rollback_exc:
                receipt["rollback_error"] = str(rollback_exc)
                receipt["status"] = "rollback-failed"
        raise
    finally:
        receipt["completed_at"] = utc_now()
        destination = (
            Path(receipt_path).expanduser().resolve()
            if receipt_path
            else Path(plan_path).expanduser().resolve().with_suffix(".receipt.json")
        )
        write_json_atomic(destination, receipt)
        receipt["receipt_path"] = str(destination)
    return receipt


def rollback_plan(
    plan_path: str | Path,
    fleet: dict[str, Any],
    *,
    backup_dir: str,
    authorized: bool,
    confirmed_plan_id: str,
    receipt_path: str | Path | None = None,
) -> dict[str, Any]:
    if not authorized:
        raise PermissionError("change rollback requires --authorized")
    plan = load_plan(plan_path)
    if confirmed_plan_id != plan["plan_id"]:
        raise PermissionError("confirmed plan ID does not match the reviewed plan")
    expected_prefix = f"{plan['backup_root']}/{plan['plan_id']}"
    if backup_dir.rstrip("/") != expected_prefix:
        raise ValueError("backup directory does not match this plan ID")
    host = get_host(fleet, plan["host_alias"])
    _assert_host_unchanged(plan, host)
    steps = _restore(plan, host, backup_dir=backup_dir)
    receipt = {
        "schema_version": "1.0",
        "plan_id": plan["plan_id"],
        "host_alias": plan["host_alias"],
        "status": "rolled-back",
        "completed_at": utc_now(),
        "backup_dir": backup_dir,
        "steps": steps,
    }
    destination = (
        Path(receipt_path).expanduser().resolve()
        if receipt_path
        else Path(plan_path).expanduser().resolve().with_suffix(".rollback-receipt.json")
    )
    write_json_atomic(destination, receipt)
    receipt["receipt_path"] = str(destination)
    return receipt
