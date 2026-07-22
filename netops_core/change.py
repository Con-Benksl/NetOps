from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import stat
import tempfile
import unicodedata
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable

from . import CHANGE_SCHEMA_VERSION
from .control_channel import (
    assess_control_channel,
    normalize_control_channel,
    normalize_remote_absolute_path,
    normalize_rollback_timer,
)
from .fleet import get_host, scp_invocation, ssh_invocation
from .models import utc_now
from .redaction import Redactor
from .util import load_json_limited, run_command


SERVICE_RE = re.compile(r"^[A-Za-z0-9_.@-]+$")
PLAN_ID_HEX_LENGTH = 32
PLAN_ID_RE = re.compile(rf"^[0-9a-f]{{{PLAN_ID_HEX_LENGTH}}}$")
EXECUTION_ID_RE = re.compile(r"^[0-9a-f]{12}$")
RESTORE_STRATEGY = (
    "exact-existing-files-content-mode-owner-mtime-acl-xattr-selinux"
)
MAX_REVIEW_TEXT_LENGTH = 2_048
MAX_SHELL_COMMAND_LENGTH = 16_384
MAX_CHANGE_ITEMS = 64
MAX_REMOTE_PATH_LENGTH = 4_096
MAX_PLAN_AGE_SECONDS = 86_400
MAX_CLOCK_SKEW_SECONDS = 300
MAX_CONTROL_CHANNEL_EVIDENCE_AGE_SECONDS = 900
TRUSTED_REMOTE_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
CONTROLLED_BACKUP_ROOT = "/var/backups/netops"
CHANGE_AUTHORIZATION_REQUIRED = (
    "remote change execution requires explicit authorization for the reviewed plan ID"
)
CHANGE_SPEC_KEYS = {
    "schema_version",
    "name",
    "summary",
    "host_alias",
    "invariants",
    "backup_paths",
    "backup_root",
    "payloads",
    "operations",
    "restart_services",
    "control_channel",
    "rollback_timer",
}
CHANGE_PLAN_KEYS = CHANGE_SPEC_KEYS | {
    "plan_id",
    "created_at",
    "source_spec",
    "host",
    "rollback_contract",
    "control_channel_guard",
}
PHASES = ("preflight", "apply", "validate", "verify", "rollback", "rollback_verify")
PREFLIGHT_CHECKS = (
    "path-exists",
    "file-exists",
    "file-sha256",
    "sqlite-query-sha256",
    "directory-exists",
    "command-exists",
    "service-exists",
    "service-active",
)
COMMAND_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")
SAFE_REMOTE_COMPONENT_RE = re.compile(r"^[A-Za-z0-9._-]+$")
SSH_USER_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$")
ENVIRONMENT_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
PLAN_HOST_KEYS = {"alias", "management", "ssh"}
PLAN_MANAGEMENT_KEYS = {"address", "panel_reference"}
PLAN_SSH_KEYS = {
    "user",
    "port",
    "config_host",
    "identity_file",
    "credential_reference",
    "password_env",
}
PSEUDO_FILESYSTEM_ROOTS = tuple(
    PurePosixPath(path) for path in ("/proc", "/sys", "/dev", "/run")
)
OVERBROAD_BACKUP_PATHS = {
    PurePosixPath(path)
    for path in ("/", "/boot", "/etc", "/home", "/opt", "/root", "/srv", "/tmp", "/usr", "/var")
}

_REMOTE_METADATA_PROGRAM = r"""
import base64
import hashlib
import json
import os
import stat
import sys


def metadata(path):
    status = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(status.st_mode):
        raise SystemExit("metadata target is not a regular file")
    attributes = []
    for name in sorted(
        os.listxattr(path, follow_symlinks=False), key=os.fsencode
    ):
        encoded_name = os.fsencode(name)
        value = os.getxattr(path, name, follow_symlinks=False)
        attributes.append(
            [
                base64.b64encode(encoded_name).decode("ascii"),
                base64.b64encode(value).decode("ascii"),
            ]
        )
    return {
        "file_type": stat.S_IFMT(status.st_mode),
        "uid": status.st_uid,
        "gid": status.st_gid,
        "mode": stat.S_IMODE(status.st_mode),
        "mtime_ns": status.st_mtime_ns,
        "xattrs": attributes,
    }


def selected_metadata(path, profile):
    values = metadata(path)
    if profile == "exact":
        comparable = ("file_type", "uid", "gid", "mode", "mtime_ns", "xattrs")
    elif profile == "stable":
        comparable = ("file_type", "uid", "gid", "mode", "xattrs")
    elif profile == "install":
        comparable = ("file_type", "uid", "gid", "xattrs")
    else:
        raise SystemExit("unsupported metadata comparison profile")
    return {key: values[key] for key in comparable}


action = sys.argv[1]
if action == "digest":
    profile = sys.argv[3] if len(sys.argv) > 3 else "exact"
    encoded = json.dumps(
        selected_metadata(sys.argv[2], profile),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    print(hashlib.sha256(encoded).hexdigest())
elif action == "compare":
    profile = sys.argv[4]
    source = selected_metadata(sys.argv[2], profile)
    candidate = selected_metadata(sys.argv[3], profile)
    if source != candidate:
        raise SystemExit("file metadata does not match")
else:
    raise SystemExit("unsupported metadata action")
""".strip()

_REMOTE_SQLITE_PROGRAM = r"""
import base64
import hashlib
import json
import sqlite3
import sys
from urllib.parse import quote


def read_only(path):
    uri = "file:" + quote(path, safe="/") + "?mode=ro"
    connection = sqlite3.connect(uri, uri=True, timeout=30)
    connection.execute("PRAGMA query_only=ON")
    return connection


def cell(value):
    if value is None:
        return ["null", None]
    if isinstance(value, int):
        return ["integer", value]
    if isinstance(value, float):
        return ["real", value.hex()]
    if isinstance(value, str):
        return ["text", value]
    if isinstance(value, bytes):
        return ["blob", base64.b64encode(value).decode("ascii")]
    raise SystemExit("unsupported SQLite result type")


def query_digest(path, query):
    connection = read_only(path)
    digest = hashlib.sha256()
    digest.update(b"[")
    first = True
    try:
        for row in connection.execute(query):
            if not first:
                digest.update(b",")
            digest.update(
                json.dumps(
                    [cell(value) for value in row],
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
            )
            first = False
    finally:
        connection.close()
    digest.update(b"]")
    return digest.hexdigest()


action = sys.argv[1]
if action == "digest":
    print(query_digest(sys.argv[2], sys.argv[3]))
elif action == "backup":
    source = read_only(sys.argv[2])
    destination = sqlite3.connect(sys.argv[3], timeout=30)
    try:
        with destination:
            source.backup(destination)
            integrity = [row[0] for row in destination.execute("PRAGMA integrity_check")]
            if integrity != ["ok"]:
                raise SystemExit("SQLite backup integrity check failed")
    finally:
        destination.close()
        source.close()
else:
    raise SystemExit("unsupported SQLite action")
""".strip()


def _safe_remote_output(value: Any) -> str:
    redactor = Redactor(
        include_network_identifiers=True,
        redact_hostnames=False,
    )
    raw = str(value or "")
    printable = "".join(
        " "
        if unicodedata.category(character) in {"Cc", "Cf"}
        or character in {"\u2028", "\u2029"}
        else character
        for character in raw
    )
    redacted = redactor.text(printable)
    return "".join(
        " " if unicodedata.category(character) in {"Cc", "Cf"} else character
        for character in redacted
    )[:4096]


def _canonical(data: dict[str, Any]) -> bytes:
    return json.dumps(
        data, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _parse_utc_timestamp(value: Any, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be a UTC ISO 8601 timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid UTC ISO 8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ValueError(f"{label} must use UTC")
    return parsed


def _age_seconds(value: Any, *, label: str) -> float:
    observed = _parse_utc_timestamp(value, label=label)
    return (datetime.now(timezone.utc) - observed).total_seconds()


def _assert_plan_fresh(plan: dict[str, Any]) -> None:
    age = _age_seconds(plan.get("created_at"), label="change plan created_at")
    if age < -MAX_CLOCK_SKEW_SECONDS:
        raise PermissionError("change plan created_at is too far in the future")
    if age > MAX_PLAN_AGE_SECONDS:
        raise PermissionError(
            "change plan is older than 24 hours; audit current state and review a new plan"
        )


def _require_exact_keys(
    value: dict[str, Any], allowed: set[str], *, label: str
) -> None:
    extras = sorted(set(value) - allowed)
    if extras:
        raise ValueError(f"{label} contains unsupported fields: {extras}")


def _contains_review_control(value: str) -> bool:
    return any(
        unicodedata.category(character) in {"Cc", "Cf"}
        or character in {"\u2028", "\u2029"}
        for character in value
    )


def _contains_shell_control(value: str) -> bool:
    return any(
        unicodedata.category(character) == "Cf"
        or character in {"\u2028", "\u2029"}
        or (
            unicodedata.category(character) == "Cc"
            and character not in {"\n", "\t"}
        )
        for character in value
    )


def _require_review_text(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    if len(value) > MAX_REVIEW_TEXT_LENGTH:
        raise ValueError(
            f"{label} exceeds the {MAX_REVIEW_TEXT_LENGTH}-character limit"
        )
    if _contains_review_control(value):
        raise ValueError(f"{label} contains Unicode control or format characters")
    redactor = Redactor(
        include_network_identifiers=True,
        redact_hostnames=False,
    )
    redactor.text(value)
    if redactor.actions:
        raise ValueError(f"{label} must not contain credentials or secret material")
    return value


def _require_shell_text(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty string")
    if len(value) > MAX_SHELL_COMMAND_LENGTH:
        raise ValueError(
            f"{label} exceeds the {MAX_SHELL_COMMAND_LENGTH}-character limit"
        )
    if _contains_shell_control(value):
        raise ValueError(f"{label} contains unsafe control or format characters")
    redactor = Redactor(
        include_network_identifiers=True,
        redact_hostnames=False,
    )
    redactor.text(value)
    if redactor.actions:
        raise ValueError(f"{label} must not contain credentials or secret material")
    return value


def _require_nonsecret_reference(
    value: Any, *, label: str, allow_home_path: bool = False
) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > MAX_REMOTE_PATH_LENGTH:
        raise ValueError(f"{label} must be a bounded non-empty string")
    redactor = Redactor(
        include_network_identifiers=True,
        redact_hostnames=False,
    )
    redactor.text(value)
    allowed_actions = {"home-path"} if allow_home_path else set()
    if redactor.actions - allowed_actions:
        raise ValueError(f"{label} must not contain credentials or secret material")
    return value


def _validate_plan_host_snapshot(plan: dict[str, Any]) -> None:
    host = plan.get("host")
    if not isinstance(host, dict):
        raise ValueError("change plan host must be an object")
    _require_exact_keys(host, PLAN_HOST_KEYS, label="change plan host")
    if host.get("alias") != plan.get("host_alias"):
        raise ValueError("change plan host alias does not match host_alias")
    management = host.get("management")
    if not isinstance(management, dict):
        raise ValueError("change plan host.management must be an object")
    _require_exact_keys(
        management, PLAN_MANAGEMENT_KEYS, label="change plan host.management"
    )
    if "address" not in management:
        raise ValueError("change plan host.management.address is required")
    _require_nonsecret_reference(
        management.get("address"), label="change plan host.management.address"
    )
    _require_nonsecret_reference(
        management.get("panel_reference"),
        label="change plan host.management.panel_reference",
    )
    ssh = host.get("ssh")
    if not isinstance(ssh, dict):
        raise ValueError("change plan host.ssh must be an object")
    _require_exact_keys(ssh, PLAN_SSH_KEYS, label="change plan host.ssh")
    if ssh.get("config_host") is not None:
        raise ValueError(
            "controlled change plans must not use mutable ssh.config_host aliases"
        )
    user = ssh.get("user")
    if user is not None and (
        not isinstance(user, str) or not SSH_USER_RE.fullmatch(user)
    ):
        raise ValueError("change plan host.ssh.user is invalid")
    port = ssh.get("port", 22)
    if type(port) is not int or not 1 <= port <= 65_535:
        raise ValueError("change plan host.ssh.port is invalid")
    password_env = ssh.get("password_env")
    if password_env is not None and (
        not isinstance(password_env, str)
        or not ENVIRONMENT_NAME_RE.fullmatch(password_env)
    ):
        raise ValueError("change plan host.ssh.password_env is invalid")
    _require_nonsecret_reference(
        ssh.get("config_host"), label="change plan host.ssh.config_host"
    )
    _require_nonsecret_reference(
        ssh.get("identity_file"),
        label="change plan host.ssh.identity_file",
        allow_home_path=True,
    )
    _require_nonsecret_reference(
        ssh.get("credential_reference"),
        label="change plan host.ssh.credential_reference",
        allow_home_path=True,
    )


def resolve_apply_receipt_path(
    plan_path: str | Path, receipt_path: str | Path | None = None
) -> Path:
    if receipt_path is not None:
        return Path(os.path.abspath(Path(receipt_path).expanduser()))
    return Path(plan_path).expanduser().resolve().with_suffix(".receipt.json")


def resolve_rollback_receipt_path(
    plan_path: str | Path, receipt_path: str | Path | None = None
) -> Path:
    if receipt_path is not None:
        return Path(os.path.abspath(Path(receipt_path).expanduser()))
    return Path(plan_path).expanduser().resolve().with_suffix(
        ".rollback-receipt.json"
    )


def _reserve_new_local_file(path: Path, *, label: str) -> tuple[int, int]:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError as exc:
        raise FileExistsError(f"{label} already exists; choose a new path: {path}") from exc
    else:
        try:
            reserved = os.fstat(descriptor)
            return reserved.st_dev, reserved.st_ino
        finally:
            os.close(descriptor)


def _remove_unchanged_empty_reservation(
    path: Path, reservation: tuple[int, int]
) -> None:
    """Remove only the exact empty regular file reserved by this process."""

    try:
        current = path.lstat()
    except FileNotFoundError:
        return
    if (
        (current.st_dev, current.st_ino) == reservation
        and current.st_size == 0
        and not path.is_symlink()
        and path.is_file()
    ):
        path.unlink()


def _local_file_identity(path: Path) -> tuple[int, int]:
    current = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(current.st_mode):
        raise FileExistsError(f"reserved output path was replaced: {path}")
    return current.st_dev, current.st_ino


def _write_reserved_json_atomic(
    path: Path,
    data: dict[str, Any],
    *,
    expected_identity: tuple[int, int],
) -> tuple[int, int]:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    staged_identity: tuple[int, int] | None = None
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(
                data,
                handle,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
                allow_nan=False,
            )
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
            staged = os.fstat(handle.fileno())
            staged_identity = (staged.st_dev, staged.st_ino)
        if _local_file_identity(path) != expected_identity:
            raise FileExistsError(f"reserved output path was replaced: {path}")
        os.replace(temporary, path)
        if os.name != "nt":
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        assert staged_identity is not None
        return staged_identity
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _hash_file(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return {"size": path.stat().st_size, "sha256": digest.hexdigest()}


def _normalize_remote_path(value: Any, *, label: str) -> str:
    normalized = normalize_remote_absolute_path(value, label=label)
    if len(normalized) > MAX_REMOTE_PATH_LENGTH:
        raise ValueError(
            f"{label} exceeds the {MAX_REMOTE_PATH_LENGTH}-character limit"
        )
    return normalized


def _path_covers(backup_path: str, target_path: str) -> bool:
    backup = PurePosixPath(backup_path)
    target = PurePosixPath(target_path)
    return backup == target or backup in target.parents


def _validate_backup_path(value: Any, *, label: str = "backup_paths") -> str:
    normalized = _normalize_remote_path(value, label=label)
    path = PurePosixPath(normalized)
    if path in OVERBROAD_BACKUP_PATHS:
        raise ValueError(f"{label} must not use an overbroad filesystem root: {path}")
    if any(root == path or root in path.parents for root in PSEUDO_FILESYSTEM_ROOTS):
        raise ValueError(f"{label} must not include a pseudo-filesystem path: {path}")
    return normalized


def _validate_backup_layout(backup_paths: list[str], backup_root: str) -> None:
    root = PurePosixPath(backup_root)
    if backup_root != CONTROLLED_BACKUP_ROOT:
        raise ValueError(
            f"backup_root must be the host-wide controlled root {CONTROLLED_BACKUP_ROOT}"
        )
    if root in OVERBROAD_BACKUP_PATHS or any(
        pseudo == root or pseudo in root.parents
        for pseudo in PSEUDO_FILESYSTEM_ROOTS
    ):
        raise ValueError("backup_root must be a dedicated persistent directory")
    if any(
        not SAFE_REMOTE_COMPONENT_RE.fullmatch(component)
        for component in root.parts[1:]
    ):
        raise ValueError(
            "backup_root components must use only letters, digits, dot, underscore, and hyphen"
        )
    containing = [path for path in backup_paths if _path_covers(path, backup_root)]
    if containing:
        raise ValueError(
            "backup_root must not be inside a path being archived: "
            + ", ".join(containing)
        )


def _normalize_sqlite_query(value: Any, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a non-empty SELECT query")
    if len(value) > MAX_SHELL_COMMAND_LENGTH:
        raise ValueError(
            f"{label} must be at most {MAX_SHELL_COMMAND_LENGTH} characters"
        )
    if any(
        unicodedata.category(character) in {"Cc", "Cf"}
        and character not in {"\n", "\t"}
        for character in value
    ):
        raise ValueError(f"{label} contains unsupported control characters")
    if not re.match(r"^\s*SELECT\b", value, flags=re.IGNORECASE):
        raise ValueError(f"{label} must start with SELECT")
    return value


def _normalize_operation(command: dict[str, Any], index: int) -> dict[str, Any]:
    phase = command.get("phase")
    if phase not in PHASES:
        raise ValueError(f"operations[{index}].phase must be one of {PHASES}")
    allowed = {"phase", "description", "timeout_seconds"}
    if phase == "preflight":
        allowed.update({"check", "target"})
        if command.get("check") in {"file-sha256", "sqlite-query-sha256"}:
            allowed.update({"sha256", "metadata_sha256"})
        if command.get("check") == "sqlite-query-sha256":
            allowed.add("query")
    else:
        allowed.add("command")
        if phase == "apply":
            allowed.add("affected_paths")
    if phase == "preflight" and "command" in command:
        raise ValueError(
            f"operations[{index}] preflight must use a typed check, not shell"
        )
    _require_exact_keys(command, allowed, label=f"operations[{index}]")
    description = _require_review_text(
        command.get("description"), label=f"operations[{index}].description"
    )
    timeout = command.get("timeout_seconds", 30)
    if type(timeout) is not int or not 1 <= timeout <= 600:
        raise ValueError(f"operations[{index}].timeout_seconds must be 1..600")
    normalized: dict[str, Any] = {
        "phase": phase,
        "description": description,
        "timeout_seconds": timeout,
    }
    if phase == "preflight":
        check = command.get("check")
        target = command.get("target")
        if check not in PREFLIGHT_CHECKS:
            raise ValueError(
                f"operations[{index}].check must be one of {PREFLIGHT_CHECKS}"
            )
        if not isinstance(target, str) or not target.strip():
            raise ValueError(f"operations[{index}] preflight needs a target")
        if check in {
            "path-exists",
            "file-exists",
            "file-sha256",
            "sqlite-query-sha256",
            "directory-exists",
        }:
            target = _normalize_remote_path(
                target, label=f"operations[{index}].target"
            )
        elif check == "command-exists":
            if not COMMAND_RE.fullmatch(target):
                raise ValueError(
                    f"operations[{index}].target must be a command name"
                )
        elif not SERVICE_RE.fullmatch(target):
            raise ValueError(f"operations[{index}].target is not a service name")
        normalized.update({"check": check, "target": target})
        if check in {"file-sha256", "sqlite-query-sha256"}:
            expected_sha256 = command.get("sha256")
            if not isinstance(expected_sha256, str) or not re.fullmatch(
                r"[0-9a-f]{64}", expected_sha256
            ):
                raise ValueError(
                    f"operations[{index}].sha256 must be a lowercase SHA-256 digest"
                )
            normalized["sha256"] = expected_sha256
            expected_metadata_sha256 = command.get("metadata_sha256")
            if not isinstance(expected_metadata_sha256, str) or not re.fullmatch(
                r"[0-9a-f]{64}", expected_metadata_sha256
            ):
                raise ValueError(
                    f"operations[{index}].metadata_sha256 must be a lowercase SHA-256 digest"
                )
            normalized["metadata_sha256"] = expected_metadata_sha256
        if check == "sqlite-query-sha256":
            normalized["query"] = _normalize_sqlite_query(
                command.get("query"), label=f"operations[{index}].query"
            )
        return normalized

    normalized["command"] = _require_shell_text(
        command.get("command"), label=f"operations[{index}].command"
    )
    if phase == "apply":
        affected_paths = command.get("affected_paths")
        if not isinstance(affected_paths, list) or not affected_paths:
            raise ValueError(
                f"operations[{index}] apply needs non-empty affected_paths"
            )
        if len(affected_paths) > MAX_CHANGE_ITEMS:
            raise ValueError(
                f"operations[{index}].affected_paths must contain at most "
                f"{MAX_CHANGE_ITEMS} paths"
            )
        normalized_paths = [
            _normalize_remote_path(
                path, label=f"operations[{index}].affected_paths"
            )
            for path in affected_paths
        ]
        if len(set(normalized_paths)) != len(normalized_paths):
            raise ValueError(
                f"operations[{index}].affected_paths must not contain duplicate paths"
            )
        normalized["affected_paths"] = normalized_paths
    elif "affected_paths" in command:
        raise ValueError(
            f"operations[{index}].affected_paths is only valid for apply"
        )
    return normalized


def _build_rollback_contract(
    *,
    backup_paths: list[str],
    payloads: list[dict[str, Any]],
    operations: list[dict[str, Any]],
    restart_services: list[str],
) -> dict[str, Any]:
    declared_targets = list(
        dict.fromkeys(
            [payload["remote_path"] for payload in payloads]
            + [
                path
                for operation in operations
                if operation["phase"] == "apply"
                for path in operation["affected_paths"]
            ]
        )
    )
    backup_path_set = set(backup_paths)
    covered_targets = [target for target in declared_targets if target in backup_path_set]
    uncovered_targets = [
        target for target in declared_targets if target not in covered_targets
    ]
    preflight_hashes: list[dict[str, str]] = []
    observed_hashes: dict[str, dict[str, str]] = {}
    for operation in operations:
        if operation["phase"] != "preflight" or operation["check"] not in {
            "file-sha256",
            "sqlite-query-sha256",
        }:
            continue
        target = operation["target"]
        current = {
            "target": target,
            "sha256": operation["sha256"],
            "metadata_sha256": operation["metadata_sha256"],
        }
        if operation["check"] == "sqlite-query-sha256":
            current["query"] = operation["query"]
        prior = observed_hashes.get(target)
        if prior is not None and prior != current:
            raise ValueError(
                "conflicting typed prestate checks for declared target: " + target
            )
        if prior is None:
            observed_hashes[target] = current
            preflight_hashes.append(current)
    preflight_file_targets = list(observed_hashes)
    unverified_targets = [
        target for target in declared_targets if target not in preflight_file_targets
    ]
    inexact_backup_paths = [
        path for path in backup_paths if path not in set(declared_targets)
    ]
    rollback_operations = sum(
        operation["phase"] == "rollback" for operation in operations
    )
    protected_seconds = sum(
        int(operation["timeout_seconds"])
        for operation in operations
        if operation["phase"] in {"apply", "validate", "verify"}
    )
    if payloads:
        # The timer is already active while the private stage is created and
        # removed. Each payload then has reserve, upload, install, and cleanup
        # timeout windows of 30 + 120 + 60 + 15 seconds.
        protected_seconds += 45 + len(payloads) * 225
    if restart_services:
        protected_seconds += 90
    # Marking the guarded start (15s), disarming both units (30s), and transport
    # jitter all occur while the timer is live. Keep an additional 90s margin.
    minimum_delay_seconds = protected_seconds + 15 + 30 + 90
    return {
        "declared_targets": declared_targets,
        "covered_targets": covered_targets,
        "uncovered_targets": uncovered_targets,
        "preflight_file_targets": preflight_file_targets,
        "preflight_hashes": preflight_hashes,
        "unverified_targets": unverified_targets,
        "inexact_backup_paths": inexact_backup_paths,
        "restore_strategy": RESTORE_STRATEGY,
        "rollback_operations": rollback_operations,
        "minimum_delay_seconds": minimum_delay_seconds,
        "executable": bool(declared_targets)
        and not uncovered_targets
        and not unverified_targets
        and not inexact_backup_paths,
    }


def validate_change_spec(spec: dict[str, Any], *, source_dir: Path) -> dict[str, Any]:
    if not isinstance(spec, dict):
        raise ValueError("change spec must be an object")
    _require_exact_keys(spec, CHANGE_SPEC_KEYS, label="change spec")
    if spec.get("schema_version") != CHANGE_SCHEMA_VERSION:
        raise ValueError(f"change spec schema must be {CHANGE_SCHEMA_VERSION!r}")
    for key in ("name", "summary", "host_alias"):
        if not isinstance(spec.get(key), str) or not spec[key].strip():
            raise ValueError(f"change spec needs non-empty {key}")
        _require_review_text(spec[key], label=f"change spec {key}")
    invariants = spec.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        raise ValueError("change spec needs at least one invariant")
    if len(invariants) > MAX_CHANGE_ITEMS:
        raise ValueError(
            f"change spec invariants must contain at most {MAX_CHANGE_ITEMS} items"
        )
    if not all(isinstance(item, str) and item.strip() for item in invariants):
        raise ValueError("every invariant must be a non-empty string")
    for index, invariant in enumerate(invariants):
        _require_review_text(invariant, label=f"invariants[{index}]")
    raw_backup_paths = spec.get("backup_paths")
    if not isinstance(raw_backup_paths, list) or not raw_backup_paths:
        raise ValueError("change spec needs at least one backup path")
    if len(raw_backup_paths) > MAX_CHANGE_ITEMS:
        raise ValueError(
            f"backup_paths must contain at most {MAX_CHANGE_ITEMS} paths"
        )
    backup_paths = [
        _normalize_remote_path(path, label="backup_paths")
        for path in raw_backup_paths
    ]
    if len(backup_paths) != len(set(backup_paths)):
        raise ValueError("backup_paths must not contain duplicate paths")
    operations = spec.get("operations") or []
    if not operations:
        raise ValueError("change spec needs operations")
    if not isinstance(operations, list) or len(operations) > MAX_CHANGE_ITEMS:
        raise ValueError(
            f"operations must contain at most {MAX_CHANGE_ITEMS} items"
        )
    normalized_operations: list[dict[str, Any]] = []
    for index, command in enumerate(operations):
        if not isinstance(command, dict):
            raise ValueError(f"operations[{index}] must be an object")
        normalized_operations.append(_normalize_operation(command, index))
    if not any(item["phase"] == "validate" for item in normalized_operations):
        raise ValueError("change spec needs at least one validate operation")
    if not any(item["phase"] == "verify" for item in normalized_operations):
        raise ValueError("change spec needs at least one verify operation")
    if not any(item["phase"] == "rollback" for item in normalized_operations):
        raise ValueError("change spec needs at least one executable rollback operation")
    if not any(item["phase"] == "rollback_verify" for item in normalized_operations):
        raise ValueError("change spec needs at least one rollback_verify operation")
    services = spec.get("restart_services") or []
    if not isinstance(services, list):
        raise ValueError("restart_services must be a list")
    if len(services) > MAX_CHANGE_ITEMS or len(services) != len(set(services)):
        raise ValueError(
            f"restart_services must contain at most {MAX_CHANGE_ITEMS} unique items"
        )
    for service in services:
        if not isinstance(service, str) or not SERVICE_RE.fullmatch(service):
            raise ValueError(f"invalid service name: {service!r}")
    raw_payloads = spec.get("payloads") or []
    if not isinstance(raw_payloads, list) or len(raw_payloads) > MAX_CHANGE_ITEMS:
        raise ValueError(
            f"payloads must contain at most {MAX_CHANGE_ITEMS} items"
        )
    normalized_payloads: list[dict[str, Any]] = []
    for index, payload in enumerate(raw_payloads):
        if not isinstance(payload, dict):
            raise ValueError(f"payloads[{index}] must be an object")
        _require_exact_keys(
            payload,
            {"local_path", "remote_path", "mode"},
            label=f"payloads[{index}]",
        )
        local = payload.get("local_path")
        remote = payload.get("remote_path")
        mode = payload.get("mode", "0644")
        if not isinstance(local, str):
            raise ValueError(f"payloads[{index}] needs local_path and remote_path")
        if not local or len(local) > MAX_REMOTE_PATH_LENGTH:
            raise ValueError(
                f"payloads[{index}].local_path must be 1..{MAX_REMOTE_PATH_LENGTH} characters"
            )
        remote = _normalize_remote_path(
            remote, label=f"payloads[{index}].remote_path"
        )
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
    remote_payload_paths = [payload["remote_path"] for payload in normalized_payloads]
    if len(remote_payload_paths) != len(set(remote_payload_paths)):
        raise ValueError("payloads must not contain duplicate remote_path values")
    backup_root = spec.get("backup_root", "/var/backups/netops")
    backup_paths = [
        _validate_backup_path(path, label="backup_paths") for path in backup_paths
    ]
    backup_root = _normalize_remote_path(backup_root, label="backup_root")
    _validate_backup_layout(backup_paths, backup_root)
    control_channel = normalize_control_channel(spec.get("control_channel"))
    rollback_timer = normalize_rollback_timer(spec.get("rollback_timer"))
    rollback_contract = _build_rollback_contract(
        backup_paths=backup_paths,
        payloads=normalized_payloads,
        operations=normalized_operations,
        restart_services=services,
    )
    if not rollback_contract["declared_targets"]:
        raise ValueError(
            "change spec needs at least one declared mutation target from a payload "
            "or apply.affected_paths"
        )
    if rollback_contract["uncovered_targets"]:
        raise ValueError(
            "backup_paths must exactly match declared mutation targets: "
            + ", ".join(rollback_contract["uncovered_targets"])
        )
    if rollback_contract["inexact_backup_paths"]:
        raise ValueError(
            "backup_paths must contain only exact declared file targets: "
            + ", ".join(rollback_contract["inexact_backup_paths"])
        )
    if rollback_contract["unverified_targets"]:
        raise ValueError(
            "every declared mutation target needs a typed file-sha256 preflight "
            "or sqlite-query-sha256 preflight: "
            + ", ".join(rollback_contract["unverified_targets"])
        )
    control_channel_guard = assess_control_channel(
        control_channel,
        rollback_timer,
        rollback_contract=rollback_contract,
    )
    return {
        "schema_version": CHANGE_SCHEMA_VERSION,
        "name": spec["name"],
        "summary": spec["summary"],
        "host_alias": spec["host_alias"],
        "invariants": invariants,
        "backup_paths": backup_paths,
        "backup_root": backup_root.rstrip("/") or "/",
        "payloads": normalized_payloads,
        "operations": normalized_operations,
        "restart_services": services,
        "control_channel": control_channel,
        "rollback_timer": rollback_timer,
        "rollback_contract": rollback_contract,
        "control_channel_guard": control_channel_guard,
    }


def create_plan(
    spec_path: str | Path,
    fleet: dict[str, Any],
    output_path: str | Path,
) -> dict[str, Any]:
    source = Path(spec_path).expanduser().resolve()
    destination = Path(os.path.abspath(Path(output_path).expanduser()))
    if os.path.lexists(destination):
        raise FileExistsError(
            f"change plan output already exists; choose a new path: {destination}"
        )
    raw = load_json_limited(source, max_bytes=4 * 1_048_576)
    normalized = validate_change_spec(raw, source_dir=source.parent)
    host = get_host(fleet, normalized["host_alias"])
    if (host.get("ssh") or {}).get("config_host") is not None:
        raise ValueError(
            "controlled changes require an explicit SSH destination; ssh.config_host is not supported"
        )
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
    plan_material = {
        **plan_body,
        "created_at": utc_now(),
        "source_spec": str(source),
    }
    plan_id = hashlib.sha256(_canonical(plan_material)).hexdigest()[
        :PLAN_ID_HEX_LENGTH
    ]
    plan = {**plan_material, "plan_id": plan_id}
    reservation = _reserve_new_local_file(destination, label="change plan output")
    try:
        _write_reserved_json_atomic(
            destination, plan, expected_identity=reservation
        )
    except Exception:
        _remove_unchanged_empty_reservation(destination, reservation)
        raise
    return plan


def load_plan(
    path: str | Path, *, verify_local_payloads: bool = True
) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    plan = load_json_limited(source, max_bytes=4 * 1_048_576)
    if not isinstance(plan, dict):
        raise ValueError("change plan must be an object")
    _require_exact_keys(plan, CHANGE_PLAN_KEYS, label="change plan")
    plan_id = plan.get("plan_id")
    body = {key: value for key, value in plan.items() if key != "plan_id"}
    expected = hashlib.sha256(_canonical(body)).hexdigest()[:PLAN_ID_HEX_LENGTH]
    if not isinstance(plan_id, str) or not PLAN_ID_RE.fullmatch(plan_id):
        raise ValueError("change plan ID must be a 128-bit lowercase hexadecimal digest")
    if plan_id != expected:
        raise ValueError("change plan ID does not match its contents")
    if plan.get("schema_version") != CHANGE_SCHEMA_VERSION:
        raise ValueError(f"change plan schema must be {CHANGE_SCHEMA_VERSION!r}")
    _parse_utc_timestamp(plan.get("created_at"), label="change plan created_at")
    if not isinstance(plan.get("source_spec"), str) or not plan["source_spec"]:
        raise ValueError("change plan source_spec must be a non-empty string")
    for key in ("name", "summary", "host_alias"):
        _require_review_text(plan.get(key), label=f"change plan {key}")
    _validate_plan_host_snapshot(plan)
    invariants = plan.get("invariants")
    if not isinstance(invariants, list) or not invariants:
        raise ValueError("change plan needs at least one invariant")
    if len(invariants) > MAX_CHANGE_ITEMS:
        raise ValueError(
            f"change plan invariants must contain at most {MAX_CHANGE_ITEMS} items"
        )
    for index, invariant in enumerate(invariants):
        _require_review_text(invariant, label=f"invariants[{index}]")
    raw_backup_paths = plan.get("backup_paths", [])
    if not isinstance(raw_backup_paths, list) or len(raw_backup_paths) > MAX_CHANGE_ITEMS:
        raise ValueError(
            f"change plan backup_paths must contain at most {MAX_CHANGE_ITEMS} paths"
        )
    backup_paths = [
        _validate_backup_path(value, label="backup_paths")
        for value in raw_backup_paths
    ]
    if not backup_paths:
        raise ValueError("change plan has no backup paths")
    if len(backup_paths) != len(set(backup_paths)):
        raise ValueError("change plan backup_paths contains duplicate paths")
    backup_root = _normalize_remote_path(plan.get("backup_root"), label="backup_root")
    _validate_backup_layout(backup_paths, backup_root)
    if backup_root != plan.get("backup_root"):
        raise ValueError("change plan backup_root is not normalized")
    operations = plan.get("operations")
    if not isinstance(operations, list) or not operations:
        raise ValueError("change plan has no operations")
    if len(operations) > MAX_CHANGE_ITEMS:
        raise ValueError(
            f"change plan operations must contain at most {MAX_CHANGE_ITEMS} items"
        )
    normalized_operations = [
        _normalize_operation(operation, index)
        for index, operation in enumerate(operations)
    ]
    if normalized_operations != operations:
        raise ValueError("change plan operations are not normalized")
    phases = {operation["phase"] for operation in normalized_operations}
    for required_phase in ("validate", "verify", "rollback", "rollback_verify"):
        if required_phase not in phases:
            raise ValueError(f"change plan is missing required {required_phase} phase")
    payloads = plan.get("payloads", [])
    if not isinstance(payloads, list):
        raise ValueError("change plan payloads must be a list")
    if len(payloads) > MAX_CHANGE_ITEMS:
        raise ValueError(
            f"change plan payloads must contain at most {MAX_CHANGE_ITEMS} items"
        )
    for index, payload in enumerate(payloads):
        if not isinstance(payload, dict):
            raise ValueError(f"payloads[{index}] must be an object")
        if set(payload) != {"local_path", "remote_path", "mode", "size", "sha256"}:
            raise ValueError(f"payloads[{index}] does not match the plan contract")
        remote_path = _normalize_remote_path(
            payload.get("remote_path"), label=f"payloads[{index}].remote_path"
        )
        if remote_path != payload.get("remote_path"):
            raise ValueError(f"payloads[{index}].remote_path is not normalized")
        if not re.fullmatch(r"[0-9a-f]{64}", str(payload.get("sha256", ""))):
            raise ValueError(f"payloads[{index}].sha256 is invalid")
        if not re.fullmatch(r"0?[0-7]{3,4}", str(payload.get("mode", ""))):
            raise ValueError(f"payloads[{index}].mode is invalid")
        if type(payload.get("size")) is not int or payload["size"] < 0:
            raise ValueError(f"payloads[{index}].size is invalid")
        if not isinstance(payload.get("local_path"), str):
            raise ValueError(f"payloads[{index}].local_path is invalid")
        if not payload["local_path"] or len(payload["local_path"]) > MAX_REMOTE_PATH_LENGTH:
            raise ValueError(f"payloads[{index}].local_path is too long")
        if verify_local_payloads:
            local = Path(payload["local_path"])
            current_hash = _hash_file(local) if local.is_file() else None
            if current_hash != {
                "size": payload.get("size"),
                "sha256": payload["sha256"],
            }:
                raise ValueError(f"payload changed after planning: {local}")
    remote_payload_paths = [payload["remote_path"] for payload in payloads]
    if len(remote_payload_paths) != len(set(remote_payload_paths)):
        raise ValueError("change plan payloads contain duplicate remote_path values")
    services = plan.get("restart_services", [])
    if not isinstance(services, list) or not all(
        isinstance(service, str) and SERVICE_RE.fullmatch(service)
        for service in services
    ):
        raise ValueError("change plan restart_services contains an invalid service")
    if len(services) > MAX_CHANGE_ITEMS or len(services) != len(set(services)):
        raise ValueError(
            f"change plan restart_services must contain at most {MAX_CHANGE_ITEMS} unique items"
        )
    expected_contract = _build_rollback_contract(
        backup_paths=backup_paths,
        payloads=payloads,
        operations=normalized_operations,
        restart_services=services,
    )
    if expected_contract != plan.get("rollback_contract"):
        raise ValueError(
            "rollback contract does not match the declared mutation targets"
        )
    if not expected_contract["executable"]:
        raise ValueError("change plan does not have an executable rollback contract")
    normalized_control = normalize_control_channel(plan.get("control_channel"))
    if normalized_control != plan.get("control_channel"):
        raise ValueError("change plan control_channel is not normalized")
    normalized_timer = normalize_rollback_timer(plan.get("rollback_timer"))
    if normalized_timer != plan.get("rollback_timer"):
        raise ValueError("change plan rollback_timer is not normalized")
    expected_guard = assess_control_channel(
        normalized_control,
        normalized_timer,
        rollback_contract=expected_contract,
    )
    if expected_guard != plan.get("control_channel_guard"):
        raise ValueError("control-channel guard does not match the plan contract")
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
        input_text=(
            "set -eu\n"
            f"PATH={TRUSTED_REMOTE_PATH}\n"
            "export PATH\n"
            + script.rstrip()
            + "\n"
        ),
        env=transport_env,
        inherit_env=False,
    )


def _run_phase(
    plan: dict[str, Any],
    host: dict[str, Any],
    phase: str,
    *,
    backup_dir: str | None = None,
    verify_prestate_before_first: bool = False,
    on_first_operation: Callable[[], None] | None = None,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    first_operation = True
    prestate_checked_targets: set[str] = set()
    for operation in plan.get("operations", []):
        if operation["phase"] != phase:
            continue
        command = operation.get("command")
        if phase == "preflight":
            command = _preflight_command(operation)
        elif backup_dir is not None:
            unchecked_targets = [
                target
                for target in operation.get("affected_paths", [])
                if target not in prestate_checked_targets
            ]
            if verify_prestate_before_first and unchecked_targets:
                command = "\n".join(
                    [*_expected_prestate_commands(plan, unchecked_targets), command]
                )
                prestate_checked_targets.update(unchecked_targets)
            command = _guarded_change_script(
                plan,
                backup_dir,
                command,
                timeout_seconds=int(operation["timeout_seconds"]),
            )
        if first_operation and on_first_operation is not None:
            on_first_operation()
        remote_timeout = int(operation["timeout_seconds"])
        if backup_dir is not None:
            remote_timeout += 10
        try:
            result = _remote_script(
                host,
                command,
                timeout=remote_timeout,
            )
        except BaseException as exc:
            failed_step = {
                "phase": phase,
                "description": operation["description"],
                "returncode": None,
                "stdout": "",
                "stderr": _safe_remote_output(exc),
                "duration_ms": 0,
            }
            results.append(failed_step)
            if on_result is not None:
                on_result(failed_step)
            setattr(exc, "partial_steps", list(results))
            raise
        step = {
                "phase": phase,
                "description": operation["description"],
                "returncode": result["returncode"],
                "stdout": _safe_remote_output(result["stdout"]),
                "stderr": _safe_remote_output(result["stderr"]),
                "duration_ms": result.get("duration_ms", 0),
            }
        results.append(step)
        if on_result is not None:
            on_result(step)
        if result["returncode"] != 0:
            error = RuntimeError(
                f"{phase} failed: {operation['description']}: "
                f"{_safe_remote_output(result['stderr'])}"
            )
            setattr(error, "partial_steps", list(results))
            raise error
        first_operation = False
    return results


def _preflight_command(operation: dict[str, Any]) -> str:
    check = operation["check"]
    target = shlex.quote(operation["target"])
    if check == "path-exists":
        return f"test -e {target}"
    if check == "file-exists":
        return f"test -f {target} && test ! -L {target}"
    if check == "file-sha256":
        expected = shlex.quote(operation["sha256"])
        return (
            f"test -f {target} && test ! -L {target} && "
            f'test "$(stat -c %h -- {target})" -eq 1 && '
            f"printf '%s  %s\\n' {expected} {target} | sha256sum -c - >/dev/null && "
            + _metadata_digest_check_command(
                operation["target"], operation["metadata_sha256"]
            )
        )
    if check == "sqlite-query-sha256":
        return (
            f"test -f {target} && test ! -L {target} && "
            f'test "$(stat -c %h -- {target})" -eq 1 && '
            + _metadata_digest_check_command(
                operation["target"],
                operation["metadata_sha256"],
                profile="stable",
            )
            + " && "
            + _sqlite_query_digest_check_command(
                operation["target"], operation["query"], operation["sha256"]
            )
        )
    if check == "directory-exists":
        return f"test -d {target}"
    if check == "command-exists":
        return f"command -v {target} >/dev/null"
    if check == "service-exists":
        return f"systemctl cat -- {target} >/dev/null"
    if check == "service-active":
        return f"systemctl is-active --quiet -- {target}"
    raise ValueError(f"unsupported preflight check: {check!r}")


def _metadata_digest_check_command(
    target: str, expected_digest: str, *, profile: str = "exact"
) -> str:
    if profile not in {"exact", "stable"}:
        raise ValueError("unsupported metadata digest profile")
    quoted_target = shlex.quote(target)
    quoted_expected = shlex.quote(expected_digest)
    quoted_profile = shlex.quote(profile)
    quoted_program = shlex.quote(_REMOTE_METADATA_PROGRAM)
    return (
        "command -v python3 >/dev/null && "
        f'test "$(python3 -c {quoted_program} digest {quoted_target} '
        f'{quoted_profile})" = '
        f"{quoted_expected}"
    )


def _sqlite_query_digest_check_command(
    target: str,
    query: str,
    expected_digest: str,
    *,
    target_is_shell_expression: bool = False,
) -> str:
    quoted_program = shlex.quote(_REMOTE_SQLITE_PROGRAM)
    target_argument = target if target_is_shell_expression else shlex.quote(target)
    return (
        "command -v python3 >/dev/null && "
        f'test "$(python3 -c {quoted_program} digest '
        f'{target_argument} {shlex.quote(query)})" = '
        f"{shlex.quote(expected_digest)}"
    )


def _sqlite_backup_command(source: str, destination: str) -> str:
    quoted_program = shlex.quote(_REMOTE_SQLITE_PROGRAM)
    return (
        f"python3 -c {quoted_program} backup "
        f"{shlex.quote(source)} {destination}"
    )


def _target_parent_directories(targets: list[str]) -> list[str]:
    """Return each lexical parent once, ordered root-first and target-first."""

    parents: list[str] = []
    for target in targets:
        for parent in reversed(PurePosixPath(target).parents):
            value = str(parent)
            if value != "/" and value not in parents:
                parents.append(value)
    return parents


def _path_directories(path: str) -> list[str]:
    current = PurePosixPath("/")
    directories: list[str] = []
    for component in PurePosixPath(path).parts[1:]:
        current /= component
        directories.append(str(current))
    return directories


def _secure_directory_function_lines() -> list[str]:
    return [
        "command -v stat >/dev/null",
        "command -v id >/dev/null",
        "real_directory() {",
        "  directory=$1",
        '  test -d "$directory" && test ! -L "$directory" || return 1',
        '  directory_mode=$(stat -c %a -- "$directory") || return 1',
        '  case "$directory_mode" in \'\'|*[!0-7]*) return 1 ;; esac',
        (
            '  test "$((0$directory_mode & 022))" -eq 0 || '
            'test "$((0$directory_mode & 01000))" -ne 0'
        ),
        "}",
        "private_directory() {",
        '  real_directory "$1" || return 1',
        '  test "$(stat -c %u -- "$1")" = "$(id -u)" || return 1',
        '  directory_mode=$(stat -c %a -- "$1") || return 1',
        '  test "$((0$directory_mode & 022))" -eq 0',
        "}",
        "trusted_target_directory() {",
        '  real_directory "$1" || return 1',
        '  directory_owner=$(stat -c %u -- "$1") || return 1',
        (
            '  test "$directory_owner" = "$(id -u)" || '
            'test "$directory_owner" = 0 || return 1'
        ),
        '  directory_mode=$(stat -c %a -- "$1") || return 1',
        '  test "$((0$directory_mode & 022))" -eq 0',
        "}",
    ]


def _secure_control_file_function_lines() -> list[str]:
    return [
        "private_control_file() {",
        '  control_file=$1',
        '  test -f "$control_file" && test ! -L "$control_file" || return 1',
        '  test "$(stat -c %u -- "$control_file")" = "$(id -u)" || return 1',
        '  test "$(stat -c %h -- "$control_file")" -eq 1 || return 1',
        '  control_mode=$(stat -c %a -- "$control_file") || return 1',
        '  case "$control_mode" in \'\'|*[!0-7]*) return 1 ;; esac',
        '  test "$((0$control_mode & 077))" -eq 0',
        "}",
    ]


def _guarded_change_script(
    plan: dict[str, Any],
    backup_dir: str,
    command: str,
    *,
    timeout_seconds: int | None = None,
) -> str:
    """Serialize one guarded step with the automatic rollback transaction."""

    backup_dir = _normalize_execution_backup_dir(plan, backup_dir)
    timed_command = (
        "timeout --signal=TERM --kill-after=5s "
        f"{int(timeout_seconds)}s /bin/sh -c {shlex.quote(command)}"
        if timeout_seconds is not None
        else command
    )
    if plan["control_channel"]["continuity_strategy"] != "automatic-rollback":
        return "\n".join(
            [
                *(
                    ["command -v timeout >/dev/null"]
                    if timeout_seconds is not None
                    else []
                ),
                timed_command,
            ]
        )
    state = f"{backup_dir}/rollback.state"
    lock = f"{backup_dir}/rollback.lock"
    lines = [
        *_backup_directory_guard_lines(plan, backup_dir),
        *_secure_control_file_function_lines(),
        "command -v flock >/dev/null",
        *(["command -v timeout >/dev/null"] if timeout_seconds is not None else []),
        f"STATE={shlex.quote(state)}",
        f"LOCK={shlex.quote(lock)}",
        'private_control_file "$STATE"',
        'private_control_file "$LOCK"',
        'exec 9<> "$LOCK"',
        "flock -w 5 9",
        'test "$(cat "$STATE")" = armed',
        timed_command,
    ]
    return "\n".join(lines)


def _metadata_function_lines() -> list[str]:
    quoted_program = shlex.quote(_REMOTE_METADATA_PROGRAM)
    return [
        "verify_file_metadata() {",
        f'  python3 -c {quoted_program} compare "$1" "$2" exact',
        "}",
        "verify_file_stable_metadata() {",
        f'  python3 -c {quoted_program} compare "$1" "$2" stable',
        "}",
        "verify_file_install_metadata() {",
        f'  python3 -c {quoted_program} compare "$1" "$2" install',
        "}",
    ]


def _required_archive_tool_lines() -> list[str]:
    return [
        "command -v tar >/dev/null",
        "command -v sha256sum >/dev/null",
        "command -v awk >/dev/null",
        "command -v cut >/dev/null",
        "command -v cmp >/dev/null",
        "command -v cp >/dev/null",
        "command -v mktemp >/dev/null",
        "command -v mv >/dev/null",
        "command -v python3 >/dev/null",
        "command -v pwd >/dev/null",
        "command -v sed >/dev/null",
        "command -v stat >/dev/null",
    ]


def _normalize_execution_backup_dir(plan: dict[str, Any], backup_dir: str) -> str:
    normalized = _normalize_remote_path(backup_dir, label="backup directory")
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str) or not PLAN_ID_RE.fullmatch(plan_id):
        raise ValueError("backup directory requires a valid 128-bit plan ID")
    expected_parent = PurePosixPath(plan["backup_root"]) / plan_id
    candidate = PurePosixPath(normalized)
    if candidate.parent != expected_parent or not EXECUTION_ID_RE.fullmatch(
        candidate.name
    ):
        raise ValueError(
            "backup directory must be this plan's 12-hex execution directory"
        )
    return normalized


def _active_change_lease(
    plan: dict[str, Any], backup_dir: str
) -> tuple[str, str]:
    normalized = _normalize_execution_backup_dir(plan, backup_dir)
    target_digest = hashlib.sha256(
        _canonical(
            {"targets": plan["rollback_contract"]["declared_targets"]}
        )
    ).hexdigest()
    token = f"{plan['plan_id']}:{PurePosixPath(normalized).name}:{target_digest}"
    return f"{plan['backup_root']}/.active-change", token


def _backup_directory_guard_lines(
    plan: dict[str, Any], backup_dir: str
) -> list[str]:
    normalized = _normalize_execution_backup_dir(plan, backup_dir)
    backup_root = plan["backup_root"]
    plan_dir = f"{backup_root}/{plan['plan_id']}"
    lines = _secure_directory_function_lines()
    lines.extend(_secure_control_file_function_lines())
    lines.append("real_directory /")
    lines.extend(
        f"real_directory {shlex.quote(directory)}"
        for directory in _path_directories(normalized)
    )
    lines.extend(
        f"private_directory {shlex.quote(directory)}"
        for directory in (backup_root, plan_dir, normalized)
    )
    lease_path, lease_token = _active_change_lease(plan, normalized)
    lines.extend(
        [
            f"ACTIVE_LEASE={shlex.quote(lease_path)}",
            f"ACTIVE_TOKEN={shlex.quote(lease_token)}",
            'private_control_file "$ACTIVE_LEASE"',
            'test "$(cat "$ACTIVE_LEASE")" = "$ACTIVE_TOKEN"',
        ]
    )
    return lines


def _prepare_execution_backup_lines(
    plan: dict[str, Any], *, execution_id: str
) -> tuple[str, list[str]]:
    if not EXECUTION_ID_RE.fullmatch(execution_id):
        raise ValueError("backup is missing a valid execution ID")
    backup_root = _normalize_remote_path(plan["backup_root"], label="backup_root")
    plan_id = plan.get("plan_id")
    if not isinstance(plan_id, str) or not PLAN_ID_RE.fullmatch(plan_id):
        raise ValueError("backup requires a valid 128-bit plan ID")
    root_path = PurePosixPath(backup_root)
    root_parent = str(root_path.parent)
    root_entry = f"./{root_path.name}"
    plan_dir = f"{backup_root}/{plan_id}"
    backup_dir = f"{plan_dir}/{execution_id}"
    lines = _secure_directory_function_lines()
    lines.extend(_secure_control_file_function_lines())
    lines.append("real_directory /")
    lines.extend(
        f"real_directory {shlex.quote(directory)}"
        for directory in _path_directories(root_parent)
    )
    lines.extend(
        [
            "(",
            f"  cd -P {shlex.quote(root_parent)}",
            f"  test \"$(pwd -P)\" = {shlex.quote(root_parent)}",
            f"  if [ ! -e {shlex.quote(root_entry)} ]; then",
            f"    mkdir -m 0700 -- {shlex.quote(root_entry)}",
            "  fi",
            f"  private_directory {shlex.quote(root_entry)}",
            ")",
        ]
    )
    lines.extend(
        f"real_directory {shlex.quote(directory)}"
        for directory in _path_directories(backup_root)
    )
    lines.append(f"private_directory {shlex.quote(backup_root)}")
    lease_path, lease_token = _active_change_lease(plan, backup_dir)
    lines.extend(
        [
            f"ACTIVE_LEASE={shlex.quote(lease_path)}",
            f"ACTIVE_TOKEN={shlex.quote(lease_token)}",
            "BACKUP_READY=0",
            "cleanup_failed_backup_lease() {",
            '  if [ "$BACKUP_READY" -eq 0 ] && [ -f "$ACTIVE_LEASE" ] && [ ! -L "$ACTIVE_LEASE" ]; then',
            '    if [ "$(cat "$ACTIVE_LEASE")" = "$ACTIVE_TOKEN" ]; then',
            '      rm -f -- "$ACTIVE_LEASE"',
            "    fi",
            "  fi",
            "}",
            "trap cleanup_failed_backup_lease EXIT",
            "trap 'exit 129' HUP",
            "trap 'exit 130' INT",
            "trap 'exit 143' TERM",
            f"cd -P {shlex.quote(backup_root)}",
            f"test \"$(pwd -P)\" = {shlex.quote(backup_root)}",
            "test ! -e ./.active-change && test ! -L ./.active-change",
            "umask 077",
            '(set -C; printf \'%s\\n\' "$ACTIVE_TOKEN" > ./.active-change)',
            "chmod 0600 ./.active-change",
            'private_control_file "$ACTIVE_LEASE"',
            'test "$(cat "$ACTIVE_LEASE")" = "$ACTIVE_TOKEN"',
        ]
    )
    lines.extend(
        [
            "(",
            f"  cd -P {shlex.quote(backup_root)}",
            f"  test \"$(pwd -P)\" = {shlex.quote(backup_root)}",
            f"  if [ ! -e {shlex.quote('./' + plan_id)} ]; then",
            f"    mkdir -m 0700 -- {shlex.quote('./' + plan_id)}",
            "  fi",
            f"  private_directory {shlex.quote('./' + plan_id)}",
            ")",
            f"real_directory {shlex.quote(plan_dir)}",
            f"private_directory {shlex.quote(plan_dir)}",
            "(",
            f"  cd -P {shlex.quote(plan_dir)}",
            f"  test \"$(pwd -P)\" = {shlex.quote(plan_dir)}",
            f"  test ! -e {shlex.quote('./' + execution_id)}",
            f"  mkdir -m 0700 -- {shlex.quote('./' + execution_id)}",
            f"  private_directory {shlex.quote('./' + execution_id)}",
            ")",
            f"real_directory {shlex.quote(backup_dir)}",
            f"private_directory {shlex.quote(backup_dir)}",
        ]
    )
    return backup_dir, lines


def _target_state_preflight_commands(
    targets: list[str], *, require_existing: bool
) -> list[str]:
    """Reject parent aliases and unsafe target entries before a backup or restore."""

    lines = [
        "# Preflight every declared target before target I/O.",
        "real_directory /",
    ]
    lines.extend(
        f"real_directory {shlex.quote(parent)}"
        for parent in _target_parent_directories(targets)
    )
    immediate_parents = list(
        dict.fromkeys(str(PurePosixPath(target).parent) for target in targets)
    )
    lines.extend(
        f"trusted_target_directory {shlex.quote(parent)}"
        for parent in immediate_parents
        if parent != "/"
    )
    for target in targets:
        quoted_target = shlex.quote(target)
        if require_existing:
            lines.extend(
                [
                    f"test -f {quoted_target} && test ! -L {quoted_target}",
                    f'test "$(stat -c %h -- {quoted_target})" -eq 1',
                ]
            )
        else:
            lines.extend(
                [
                    f"if [ -L {quoted_target} ]; then exit 1; fi",
                    (
                        f"if [ -e {quoted_target} ] && "
                        f"[ ! -f {quoted_target} ]; then exit 1; fi"
                    ),
                    (
                        f"if [ -e {quoted_target} ]; then "
                        f'test "$(stat -c %h -- {quoted_target})" -eq 1; fi'
                    ),
                ]
            )
    return lines


def _expected_prestate_commands(
    plan: dict[str, Any], targets: list[str] | None = None
) -> list[str]:
    expected = {
        item["target"]: item
        for item in plan["rollback_contract"]["preflight_hashes"]
    }
    selected = targets or plan["rollback_contract"]["declared_targets"]
    missing = [target for target in selected if target not in expected]
    if missing:
        raise ValueError(
            "missing reviewed typed prestate for target: " + ", ".join(missing)
        )
    lines: list[str] = []
    for target in selected:
        quoted_target = shlex.quote(target)
        state = expected[target]
        lines.extend(
            [
                f"test -f {quoted_target} && test ! -L {quoted_target}",
                f'test "$(stat -c %h -- {quoted_target})" -eq 1',
            ]
        )
        if "query" in state:
            lines.extend(
                [
                    _metadata_digest_check_command(
                        target, state["metadata_sha256"], profile="stable"
                    ),
                    _sqlite_query_digest_check_command(
                        target, state["query"], state["sha256"]
                    ),
                ]
            )
        else:
            lines.extend(
                [
                    "command -v sha256sum >/dev/null",
                    (
                        f"printf '%s  %s\\n' {shlex.quote(state['sha256'])} "
                        f"{quoted_target} | sha256sum -c - >/dev/null"
                    ),
                    _metadata_digest_check_command(
                        target, state["metadata_sha256"]
                    ),
                ]
            )
    return lines


def _normalize_backup_integrity(value: Any, *, label: str) -> dict[str, str]:
    if not isinstance(value, dict) or set(value) != {
        "archive_sha256",
        "manifest_sha256",
    }:
        raise ValueError(
            f"{label} must contain archive_sha256 and manifest_sha256 only"
        )
    normalized: dict[str, str] = {}
    for key in ("archive_sha256", "manifest_sha256"):
        digest = value.get(key)
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"{label}.{key} must be a lowercase SHA-256 digest")
        normalized[key] = digest
    return normalized


def _backup(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    execution_id: str,
) -> tuple[str, dict[str, Any]]:
    backup_dir, prepare_backup = _prepare_execution_backup_lines(
        plan, execution_id=execution_id
    )
    backup_targets = plan["rollback_contract"]["declared_targets"]
    reviewed_states = {
        item["target"]: item
        for item in plan["rollback_contract"]["preflight_hashes"]
    }
    relative_paths = [path[1:] for path in backup_targets]
    quoted_paths = " ".join(shlex.quote(path) for path in relative_paths)
    lines = ["set -eu", *prepare_backup, *_required_archive_tool_lines()]
    lines.extend(
        _target_state_preflight_commands(
            backup_targets, require_existing=True
        )
    )
    lines.extend(_expected_prestate_commands(plan, backup_targets))
    lines.extend(_metadata_function_lines())
    lines.extend(
        [
            "(",
            f"  cd -P {shlex.quote(backup_dir)}",
            f"  test \"$(pwd -P)\" = {shlex.quote(backup_dir)}",
            "  BACKUP_STAGE=",
            "  cleanup_backup_stage() {",
            '    if [ -n "$BACKUP_STAGE" ]; then',
            '      case "$BACKUP_STAGE" in',
            '        ./.backup-stage.*) rm -rf -- "$BACKUP_STAGE" ;;',
            "        *) return 1 ;;",
            "      esac",
            "    fi",
            "  }",
            "  trap cleanup_backup_stage EXIT",
            "  trap 'exit 129' HUP",
            "  trap 'exit 130' INT",
            "  trap 'exit 143' TERM",
            "  BACKUP_STAGE=$(mktemp -d -- ./.backup-stage.XXXXXX)",
            '  case "$BACKUP_STAGE" in ./.backup-stage.*) ;; *) exit 1 ;; esac',
            '  BACKUP_STAGE_ABSOLUTE="$PWD/${BACKUP_STAGE#./}"',
            '  BACKUP_STAGING_ROOT="$BACKUP_STAGE_ABSOLUTE/root"',
            '  mkdir -m 0700 -- "$BACKUP_STAGING_ROOT"',
        ]
    )
    staged_parents: list[str] = []
    for relative in relative_paths:
        parent = str(PurePosixPath(relative).parent)
        if parent != "." and parent not in staged_parents:
            staged_parents.append(parent)
    lines.extend(
        f'  mkdir -p -m 0700 -- "$BACKUP_STAGING_ROOT"/{shlex.quote(parent)}'
        for parent in staged_parents
    )
    for index, (target, relative) in enumerate(
        zip(backup_targets, relative_paths, strict=True)
    ):
        parent = str(PurePosixPath(target).parent)
        source_name = f"./{PurePosixPath(target).name}"
        staged_path = f'"$BACKUP_STAGING_ROOT"/{shlex.quote(relative)}'
        state = reviewed_states[target]
        lines.extend(
            [
                "  (",
                f"    cd -P {shlex.quote(parent)}",
                f"    test \"$(pwd -P)\" = {shlex.quote(parent)}",
                f"    test -f {shlex.quote(source_name)} && test ! -L {shlex.quote(source_name)}",
            ]
        )
        if "query" in state:
            lines.extend(
                [
                    (
                        "    cp --attributes-only --preserve=all --no-dereference -- "
                        f"{shlex.quote(source_name)} {staged_path}"
                    ),
                    "    "
                    + _sqlite_backup_command(source_name, staged_path),
                    f"    test -f {staged_path} && test ! -L {staged_path}",
                    "    "
                    + _sqlite_query_digest_check_command(
                        staged_path,
                        state["query"],
                        state["sha256"],
                        target_is_shell_expression=True,
                    ),
                    "    "
                    + _sqlite_query_digest_check_command(
                        source_name, state["query"], state["sha256"]
                    ),
                    "    "
                    + _metadata_digest_check_command(
                        target, state["metadata_sha256"], profile="stable"
                    ),
                    (
                        f"    verify_file_stable_metadata {shlex.quote(source_name)} "
                        f"{staged_path} backup-{index}"
                    ),
                ]
            )
        else:
            reviewed_sha256 = shlex.quote(state["sha256"])
            lines.extend(
                [
                    (
                        f"    cp --preserve=all --no-dereference -- "
                        f"{shlex.quote(source_name)} {staged_path}"
                    ),
                    f"    test -f {staged_path} && test ! -L {staged_path}",
                    (
                        f"    printf '%s  %s\\n' {reviewed_sha256} {staged_path} "
                        "| sha256sum -c - >/dev/null"
                    ),
                    (
                        f"    printf '%s  %s\\n' {reviewed_sha256} "
                        f"{shlex.quote(source_name)} | sha256sum -c - >/dev/null"
                    ),
                    "    "
                    + _metadata_digest_check_command(
                        target, state["metadata_sha256"]
                    ),
                    (
                        f"    verify_file_metadata {shlex.quote(source_name)} "
                        f"{staged_path} backup-{index}"
                    ),
                ]
            )
        lines.append("  )")
    lines.extend(
        [
            (
                f'  (cd "$BACKUP_STAGING_ROOT" && sha256sum -- {quoted_paths}) '
                "> ./target-state.sha256"
            ),
            "  chmod 0600 ./target-state.sha256",
            "  test -s ./target-state.sha256",
            (
                "  tar --acls --xattrs --selinux --numeric-owner -czpf "
                f'./state.tar.gz -C "$BACKUP_STAGING_ROOT" -- {quoted_paths}'
            ),
            "  chmod 0600 ./state.tar.gz",
            "  test -s ./state.tar.gz",
            "  sha256sum -- state.tar.gz > ./state.tar.gz.sha256",
            "  chmod 0600 ./state.tar.gz.sha256",
            "  test -s ./state.tar.gz.sha256",
            ")",
        ]
    )
    # Keep the validator's EXIT cleanup trap scoped to a child shell.  The
    # outer backup transaction owns the active-change lease cleanup trap; if
    # the validator replaced it, a late validation failure could strand the
    # host-wide lease before BACKUP_READY is recorded.
    lines.extend(
        [
            "(",
            _validated_archive_script(plan, backup_dir, restore=False),
            ")",
        ]
    )
    lines.extend(
        [
            f"cd -P {shlex.quote(backup_dir)}",
            f"test \"$(pwd -P)\" = {shlex.quote(backup_dir)}",
            (
                "printf 'archive_sha256=%s\\n' "
                '"$(sha256sum -- state.tar.gz | cut -d \' \' -f 1)"'
            ),
            (
                "printf 'manifest_sha256=%s\\n' "
                '"$(sha256sum -- target-state.sha256 | cut -d \' \' -f 1)"'
            ),
            "BACKUP_READY=1",
        ]
    )
    script = "\n".join(lines) + "\n"
    result = _remote_script(host, script, timeout=240)
    if result["returncode"] != 0:
        diagnostic_tail = str(result.get("stderr", ""))[-4096:]
        raise RuntimeError(
            f"backup failed: {_safe_remote_output(diagnostic_tail)}"
        )
    integrity: dict[str, str] = {}
    for line in str(result.get("stdout", "")).splitlines():
        if "=" not in line:
            raise RuntimeError("backup returned an invalid integrity receipt")
        key, value = line.split("=", 1)
        if key not in {"archive_sha256", "manifest_sha256"} or key in integrity:
            raise RuntimeError("backup returned an invalid integrity receipt")
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise RuntimeError("backup returned an invalid integrity digest")
        integrity[key] = value
    if set(integrity) != {"archive_sha256", "manifest_sha256"}:
        raise RuntimeError("backup did not return both integrity digests")
    result["integrity"] = integrity
    return backup_dir, result


def _validated_archive_script(
    plan: dict[str, Any],
    backup_dir: str,
    *,
    restore: bool,
    expected_integrity: dict[str, str] | None = None,
) -> str:
    """Validate a frozen archive in staging before optionally restoring targets."""

    targets = plan["rollback_contract"]["declared_targets"]
    if not targets:
        raise ValueError("rollback archive validation needs declared targets")
    relative_targets = [target[1:] for target in targets]
    expected_arguments = " ".join(shlex.quote(path) for path in relative_targets)
    backup_dir = _normalize_execution_backup_dir(plan, backup_dir)
    normalized_integrity = (
        _normalize_backup_integrity(
            expected_integrity, label="expected backup integrity"
        )
        if expected_integrity is not None
        else None
    )
    prepare_commands: list[str] = []
    commit_commands: list[str] = []
    cleanup_temporaries: list[str] = []
    if restore:
        for index, (target, relative) in enumerate(
            zip(targets, relative_targets, strict=True)
        ):
            variable = f"RESTORE_TEMP_{index}"
            digest_variable = f"RESTORE_SHA256_{index}"
            parent = str(PurePosixPath(target).parent)
            target_name = f"./{PurePosixPath(target).name}"
            template = f"./.netops-restore-{plan['plan_id']}-{index}.XXXXXX"
            quoted_parent = shlex.quote(parent)
            quoted_target_name = shlex.quote(target_name)
            quoted_relative = shlex.quote(relative)
            cleanup_temporaries.extend(
                [
                    f'  if [ -n "${{{variable}}}" ]; then',
                    "(",
                    f"  cd -P {quoted_parent}",
                    f"  test \"$(pwd -P)\" = {quoted_parent}",
                    f'  rm -f -- "${{{variable}}}"',
                    ")",
                    "  fi",
                ]
            )
            prepare_commands.extend(
                [
                    f"{variable}=$(",
                    f"  cd -P {quoted_parent}",
                    f"  test \"$(pwd -P)\" = {quoted_parent}",
                    f"  mktemp -- {shlex.quote(template)}",
                    ")",
                    "(",
                    f"  cd -P {quoted_parent}",
                    f"  test \"$(pwd -P)\" = {quoted_parent}",
                    f'  test -f "${{{variable}}}" && test ! -L "${{{variable}}}"',
                    (
                        f'  cp --preserve=all -- "$STAGING_ROOT"/{quoted_relative} '
                        f'"${{{variable}}}"'
                    ),
                    f'  cmp -s -- "$STAGING_ROOT"/{quoted_relative} "${{{variable}}}"',
                    (
                        f"  printf '%s  %s\\n' \"${{{digest_variable}}}\" "
                        f'"${{{variable}}}" | sha256sum -c - >/dev/null'
                    ),
                    (
                        f'  verify_file_metadata "$STAGING_ROOT"/{quoted_relative} '
                        f'"${{{variable}}}" prepare-{index}'
                    ),
                    ")",
                ]
            )
            commit_commands.extend(
                [
                    "(",
                    f"  cd -P {quoted_parent}",
                    f"  test \"$(pwd -P)\" = {quoted_parent}",
                    f"  if [ -L {quoted_target_name} ]; then exit 1; fi",
                    (
                        f"  if [ -e {quoted_target_name} ] && "
                        f"[ ! -f {quoted_target_name} ]; then exit 1; fi"
                    ),
                    f'  test -f "${{{variable}}}" && test ! -L "${{{variable}}}"',
                    (
                        f"  printf '%s  %s\\n' \"${{{digest_variable}}}\" "
                        f'"${{{variable}}}" | sha256sum -c - >/dev/null'
                    ),
                    (
                        f'  verify_file_metadata "$STAGING_ROOT"/{quoted_relative} '
                        f'"${{{variable}}}" commit-{index}'
                    ),
                    f'  mv -fT -- "${{{variable}}}" {quoted_target_name}',
                    ")",
                    f"{variable}=",
                ]
            )
    expected = '"$STAGE/expected-members"'
    members = '"$STAGE/archive-members"'
    verbose = '"$STAGE/archive-verbose"'
    manifest_members = '"$STAGE/manifest-members"'
    frozen_archive = '"$STAGE_ABSOLUTE/state.tar.gz"'
    frozen_archive_checksum = '"$STAGE_ABSOLUTE/state.tar.gz.sha256"'
    frozen_manifest = '"$STAGE_ABSOLUTE/target-state.sha256"'
    lines = [
        "set -eu",
        f"BACKUP_DIR={shlex.quote(backup_dir)}",
        *_backup_directory_guard_lines(plan, backup_dir),
        f"cd -P {shlex.quote(backup_dir)}",
        f"test \"$(pwd -P)\" = {shlex.quote(backup_dir)}",
        "ARCHIVE=./state.tar.gz",
        "ARCHIVE_CHECKSUM=./state.tar.gz.sha256",
        "MANIFEST=./target-state.sha256",
        "STAGE=",
        *(f"RESTORE_TEMP_{index}=" for index in range(len(targets)) if restore),
        "cleanup_restore_stage() {",
        *cleanup_temporaries,
        '  if [ -n "$STAGE" ]; then',
        '    case "$STAGE" in',
        '      ./.restore-stage.*) rm -rf -- "$STAGE" ;;',
        "      *) return 1 ;;",
        "    esac",
        "  fi",
        "}",
        "trap cleanup_restore_stage EXIT",
        "trap 'exit 129' HUP",
        "trap 'exit 130' INT",
        "trap 'exit 143' TERM",
        *_required_archive_tool_lines(),
        *_metadata_function_lines(),
        'test -f "$ARCHIVE" && test ! -L "$ARCHIVE"',
        'test -f "$ARCHIVE_CHECKSUM" && test ! -L "$ARCHIVE_CHECKSUM"',
        'test -f "$MANIFEST" && test ! -L "$MANIFEST"',
        *(
            [
                (
                    "printf '%s  %s\\n' "
                    f"{shlex.quote(normalized_integrity['archive_sha256'])} "
                    '"$ARCHIVE" | sha256sum -c - >/dev/null'
                ),
                (
                    "printf '%s  %s\\n' "
                    f"{shlex.quote(normalized_integrity['manifest_sha256'])} "
                    '"$MANIFEST" | sha256sum -c - >/dev/null'
                ),
            ]
            if normalized_integrity is not None
            else []
        ),
        'STAGE=$(mktemp -d -- ./.restore-stage.XXXXXX)',
        'case "$STAGE" in ./.restore-stage.*) ;; *) exit 1 ;; esac',
        'STAGE_ABSOLUTE="$BACKUP_DIR/${STAGE#./}"',
        f'cp -- "$ARCHIVE" {frozen_archive}',
        f'cp -- "$ARCHIVE_CHECKSUM" {frozen_archive_checksum}',
        f'cp -- "$MANIFEST" {frozen_manifest}',
        *(
            [
                (
                    "printf '%s  %s\\n' "
                    f"{shlex.quote(normalized_integrity['archive_sha256'])} "
                    f"{frozen_archive} | sha256sum -c - >/dev/null"
                ),
                (
                    "printf '%s  %s\\n' "
                    f"{shlex.quote(normalized_integrity['manifest_sha256'])} "
                    f"{frozen_manifest} | sha256sum -c - >/dev/null"
                ),
            ]
            if normalized_integrity is not None
            else []
        ),
        'printf \'%s\\n\' state.tar.gz > "$STAGE/expected-archive-member"',
        (
            f"cut -c 67- {frozen_archive_checksum} > "
            '"$STAGE/archive-checksum-member"'
        ),
        (
            'cmp -s -- "$STAGE/expected-archive-member" '
            '"$STAGE/archive-checksum-member"'
        ),
        '(cd "$STAGE_ABSOLUTE" && sha256sum -c state.tar.gz.sha256 >/dev/null)',
        f"printf '%s\\n' {expected_arguments} > {expected}",
        (
            "LC_ALL=C tar --acls --xattrs --selinux --numeric-owner "
            f"-tzf {frozen_archive} > {members}"
        ),
        f"cmp -s -- {expected} {members}",
        (
            "LC_ALL=C tar --acls --xattrs --selinux --numeric-owner "
            f"-tvzf {frozen_archive} > {verbose}"
        ),
        f"awk 'substr($0, 1, 1) != \"-\" {{ exit 1 }}' {verbose}",
        f"cut -c 67- {frozen_manifest} > {manifest_members}",
        f"cmp -s -- {expected} {manifest_members}",
        'STAGING_ROOT="$STAGE_ABSOLUTE/root"',
        'mkdir -m 0700 "$STAGING_ROOT"',
        (
            "tar --acls --xattrs --selinux --numeric-owner "
            f'-xzpf {frozen_archive} -C "$STAGING_ROOT"'
        ),
    ]
    lines.extend(
        f'test -f "$STAGING_ROOT"/{shlex.quote(path)} && '
        f'test ! -L "$STAGING_ROOT"/{shlex.quote(path)}'
        for path in relative_targets
    )
    lines.append(
        f'(cd "$STAGING_ROOT" && sha256sum -c {frozen_manifest} >/dev/null)'
    )
    if restore:
        for index in range(len(targets)):
            digest_variable = f"RESTORE_SHA256_{index}"
            lines.extend(
                [
                    (
                        f"{digest_variable}=$(awk 'NR == {index + 1} "
                        f"{{ print $1 }}' {frozen_manifest})"
                    ),
                    (
                        f'case "${{{digest_variable}}}" in '
                        f"''|*[!0-9a-f]*) exit 1 ;; esac"
                    ),
                    f'test "${{#{digest_variable}}}" -eq 64',
                ]
            )
    lines.extend(
        [
            f'cp --preserve=all -- {expected} "$STAGE/cp-capability"',
            f'cmp -s -- {expected} "$STAGE/cp-capability"',
            "printf '%s\\n' source > \"$STAGE/mv-source\"",
            "printf '%s\\n' target > \"$STAGE/mv-target\"",
            'mv -fT -- "$STAGE/mv-source" "$STAGE/mv-target"',
            "printf '%s\\n' source | cmp -s -- - \"$STAGE/mv-target\"",
        ]
    )
    if restore:
        lines.extend(
            _target_state_preflight_commands(targets, require_existing=False)
        )
        lines.extend(prepare_commands)
        lines.extend(
            _target_state_preflight_commands(targets, require_existing=False)
        )
        lines.extend(commit_commands)
    if restore:
        lines.extend(
            _target_state_preflight_commands(targets, require_existing=True)
        )
        for index, (target, relative) in enumerate(
            zip(targets, relative_targets, strict=True)
        ):
            digest_variable = f"RESTORE_SHA256_{index}"
            lines.extend(
                [
                    (
                        f"printf '%s  %s\\n' \"${{{digest_variable}}}\" "
                        f"{shlex.quote(relative)} | "
                        "(cd / && sha256sum -c - >/dev/null)"
                    ),
                    (
                        f'verify_file_metadata "$STAGING_ROOT"/{shlex.quote(relative)} '
                        f"{shlex.quote(target)} live-{index}"
                    ),
                ]
            )
    return "\n".join(line for line in lines if line) + "\n"


def _upload_payloads(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    execution_id: str,
    backup_dir: str,
    on_target_mutation: Callable[[], None] | None = None,
    on_result: Callable[[dict[str, Any]], None] | None = None,
) -> list[dict[str, Any]]:
    if not EXECUTION_ID_RE.fullmatch(execution_id):
        raise ValueError("payload upload is missing a valid execution ID")
    backup_dir = _normalize_execution_backup_dir(plan, backup_dir)
    if PurePosixPath(backup_dir).name != execution_id:
        raise ValueError("payload upload execution ID does not match backup directory")
    payloads = plan.get("payloads", [])
    if not payloads:
        return []
    payload_stage = f"{backup_dir}/.payload-stage"
    prepare_stage = [
        "set -eu",
        *_backup_directory_guard_lines(plan, backup_dir),
        f"cd -P {shlex.quote(backup_dir)}",
        f"test \"$(pwd -P)\" = {shlex.quote(backup_dir)}",
        "test ! -e ./.payload-stage && test ! -L ./.payload-stage",
        "mkdir -m 0700 -- ./.payload-stage",
        "private_directory ./.payload-stage",
    ]
    prepared = _remote_script(host, "\n".join(prepare_stage), timeout=30)
    if prepared["returncode"] != 0:
        raise RuntimeError(
            "payload staging directory creation failed: "
            f"{_safe_remote_output(prepared['stderr'])}"
        )
    results: list[dict[str, Any]] = []
    primary_error: Exception | None = None
    try:
        for index, payload in enumerate(payloads):
            temporary_name = f"payload-{index}-{payload['sha256'][:12]}"
            temporary = f"{payload_stage}/{temporary_name}"
            reserve_lines = [
                "set -eu",
                *_backup_directory_guard_lines(plan, backup_dir),
                f"private_directory {shlex.quote(payload_stage)}",
                f"cd -P {shlex.quote(payload_stage)}",
                f"test \"$(pwd -P)\" = {shlex.quote(payload_stage)}",
                "umask 077",
                f"(set -C; : > {shlex.quote('./' + temporary_name)})",
                (
                    f"test -f {shlex.quote('./' + temporary_name)} && "
                    f"test ! -L {shlex.quote('./' + temporary_name)}"
                ),
            ]
            reserved = _remote_script(host, "\n".join(reserve_lines), timeout=30)
            if reserved["returncode"] != 0:
                raise RuntimeError(
                    "payload staging file reservation failed: "
                    f"{_safe_remote_output(reserved['stderr'])}"
                )
            upload_command, transport_env = scp_invocation(
                host, payload["local_path"], temporary
            )
            try:
                upload = run_command(
                    upload_command,
                    timeout=120,
                    env=transport_env,
                    inherit_env=False,
                )
                if upload["returncode"] != 0:
                    raise RuntimeError(
                        "payload upload failed: "
                        f"{_safe_remote_output(upload['stderr'])}"
                    )
                target = payload["remote_path"]
                target_parent = str(PurePosixPath(target).parent)
                target_name = f"./{PurePosixPath(target).name}"
                install_temp = (
                    f"./.netops-install-{plan['plan_id']}-{index}.XXXXXX"
                )
                install_lines = [
                    "set -eu",
                    *_backup_directory_guard_lines(plan, backup_dir),
                    f"private_directory {shlex.quote(payload_stage)}",
                    *_target_state_preflight_commands(
                        [target], require_existing=True
                    ),
                    "command -v cat >/dev/null",
                    "command -v chmod >/dev/null",
                    "command -v cp >/dev/null",
                    "command -v mktemp >/dev/null",
                    "command -v mv >/dev/null",
                    "command -v python3 >/dev/null",
                    "command -v sha256sum >/dev/null",
                    *_metadata_function_lines(),
                    (
                        f"printf '%s  %s\\n' {shlex.quote(payload['sha256'])} "
                        f"{shlex.quote(temporary)} | sha256sum -c - >/dev/null"
                    ),
                    "(",
                    f"  cd -P {shlex.quote(target_parent)}",
                    f"  test \"$(pwd -P)\" = {shlex.quote(target_parent)}",
                    f"  if [ -L {shlex.quote(target_name)} ]; then exit 1; fi",
                    (
                        f"  if [ -e {shlex.quote(target_name)} ] && "
                        f"[ ! -f {shlex.quote(target_name)} ]; then exit 1; fi"
                    ),
                    "  INSTALL_TEMP=",
                    "  cleanup_install_temp() {",
                    '    [ -z "$INSTALL_TEMP" ] || rm -f -- "$INSTALL_TEMP"',
                    "  }",
                    "  trap cleanup_install_temp EXIT",
                    "  trap 'exit 129' HUP",
                    "  trap 'exit 130' INT",
                    "  trap 'exit 143' TERM",
                    f"  INSTALL_TEMP=$(mktemp -- {shlex.quote(install_temp)})",
                    (
                        f"  cat -- {shlex.quote(temporary)} > \"$INSTALL_TEMP\""
                    ),
                    (
                        "  cp --attributes-only --preserve=all --no-dereference -- "
                        f"{shlex.quote(target_name)} \"$INSTALL_TEMP\""
                    ),
                    f"  chmod {shlex.quote(payload['mode'])} -- \"$INSTALL_TEMP\"",
                    (
                        "  verify_file_install_metadata "
                        f"{shlex.quote(target_name)} \"$INSTALL_TEMP\""
                    ),
                    (
                        f"  printf '%s  %s\\n' {shlex.quote(payload['sha256'])} "
                        '"$INSTALL_TEMP" | sha256sum -c - >/dev/null'
                    ),
                    f"  mv -fT -- \"$INSTALL_TEMP\" {shlex.quote(target_name)}",
                    "  INSTALL_TEMP=",
                    ")",
                ]
                guarded_install = _guarded_change_script(
                    plan,
                    backup_dir,
                    "\n".join(
                        [*_expected_prestate_commands(plan, [target]), *install_lines]
                    ),
                    timeout_seconds=60,
                )
                if on_target_mutation is not None:
                    on_target_mutation()
                install = _remote_script(host, guarded_install, timeout=70)
                if install["returncode"] != 0:
                    raise RuntimeError(
                        "payload install failed: "
                        f"{_safe_remote_output(install['stderr'])}"
                    )
                payload_result = {
                        "remote_path": target,
                        "sha256": payload["sha256"],
                        "upload_returncode": upload["returncode"],
                        "install_returncode": install["returncode"],
                    }
                results.append(payload_result)
                if on_result is not None:
                    on_result(payload_result)
            except Exception as item_error:
                try:
                    _cleanup_payload_temp(
                        plan,
                        host,
                        backup_dir=backup_dir,
                        payload_stage=payload_stage,
                        temporary_name=temporary_name,
                    )
                except Exception as cleanup_error:
                    setattr(
                        item_error,
                        "payload_cleanup_error",
                        _safe_remote_output(cleanup_error),
                    )
                raise
            else:
                _cleanup_payload_temp(
                    plan,
                    host,
                    backup_dir=backup_dir,
                    payload_stage=payload_stage,
                    temporary_name=temporary_name,
                )
    except Exception as exc:
        primary_error = exc
        raise
    finally:
        try:
            _cleanup_payload_stage(
                plan,
                host,
                backup_dir=backup_dir,
                payload_stage=payload_stage,
            )
        except Exception as cleanup_error:
            if primary_error is None:
                raise
            existing = getattr(primary_error, "payload_cleanup_error", "")
            combined = " ".join(
                part
                for part in (existing, _safe_remote_output(cleanup_error))
                if part
            )
            setattr(primary_error, "payload_cleanup_error", combined)
    return results


def _cleanup_payload_temp(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    backup_dir: str,
    payload_stage: str,
    temporary_name: str,
) -> None:
    lines = [
        "set -eu",
        *_backup_directory_guard_lines(plan, backup_dir),
        f"private_directory {shlex.quote(payload_stage)}",
        f"cd -P {shlex.quote(payload_stage)}",
        f"test \"$(pwd -P)\" = {shlex.quote(payload_stage)}",
        f"test -f {shlex.quote('./' + temporary_name)}",
        f"test ! -L {shlex.quote('./' + temporary_name)}",
        f"rm -f -- {shlex.quote('./' + temporary_name)}",
        f"test ! -e {shlex.quote('./' + temporary_name)}",
        f"test ! -L {shlex.quote('./' + temporary_name)}",
    ]
    cleanup = _remote_script(
        host,
        "\n".join(lines),
        timeout=15,
    )
    if cleanup["returncode"] != 0:
        raise RuntimeError(
            "temporary payload cleanup failed: "
            f"{_safe_remote_output(cleanup['stderr'])}"
        )


def _cleanup_payload_stage(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    backup_dir: str,
    payload_stage: str,
) -> None:
    lines = [
        "set -eu",
        *_backup_directory_guard_lines(plan, backup_dir),
        f"private_directory {shlex.quote(payload_stage)}",
        f"cd -P {shlex.quote(backup_dir)}",
        f"test \"$(pwd -P)\" = {shlex.quote(backup_dir)}",
        "rmdir -- ./.payload-stage",
        "test ! -e ./.payload-stage && test ! -L ./.payload-stage",
    ]
    cleanup = _remote_script(host, "\n".join(lines), timeout=15)
    if cleanup["returncode"] != 0:
        raise RuntimeError(
            "payload staging directory cleanup failed: "
            f"{_safe_remote_output(cleanup['stderr'])}"
        )


def _restart_services(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    backup_dir: str | None = None,
) -> dict[str, Any] | None:
    services = plan.get("restart_services") or []
    if not services:
        return None
    command = "systemctl restart -- " + " ".join(
        shlex.quote(service) for service in services
    )
    if backup_dir is not None:
        command = _guarded_change_script(
            plan, backup_dir, command, timeout_seconds=90
        )
    result = _remote_script(
        host,
        command,
        timeout=(100 if backup_dir is not None else 90),
    )
    if result["returncode"] != 0:
        raise RuntimeError(
            f"service restart failed: {_safe_remote_output(result['stderr'])}"
        )
    return result


def _automatic_rollback_script(
    plan: dict[str, Any],
    backup_dir: str,
    expected_integrity: dict[str, str],
) -> str:
    backup_dir = _normalize_execution_backup_dir(plan, backup_dir)
    expected_integrity = _normalize_backup_integrity(
        expected_integrity, label="automatic rollback backup integrity"
    )
    started = f"{backup_dir}/change.started"
    state_path = f"{backup_dir}/rollback.state"
    lock = f"{backup_dir}/rollback.lock"
    status = f"{backup_dir}/automatic-rollback.status"
    validation_command = _validated_archive_script(
        plan,
        backup_dir,
        restore=False,
        expected_integrity=expected_integrity,
    )
    exact_restore_command = _validated_archive_script(
        plan,
        backup_dir,
        restore=True,
        expected_integrity=expected_integrity,
    )
    rollback_commands = [
        (operation["command"], int(operation.get("timeout_seconds", 30)))
        for operation in plan.get("operations", [])
        if operation["phase"] == "rollback"
    ]
    verify_commands = [
        (operation["command"], int(operation.get("timeout_seconds", 30)))
        for operation in plan.get("operations", [])
        if operation["phase"] == "rollback_verify"
    ]
    services = plan.get("restart_services") or []
    restart_command = (
        "systemctl restart -- "
        + " ".join(shlex.quote(service) for service in services)
        if services
        else None
    )

    def timed(command: str, timeout_seconds: int) -> str:
        return (
            "timeout --signal=TERM --kill-after=5s "
            f"{timeout_seconds}s /bin/sh -c "
            f"{shlex.quote(command)}"
        )

    transaction_lines = [
        "rc=0",
        "ARCHIVE_VALID=0",
        "FIRST_RESTORE=0",
        "SECOND_RESTORE=0",
        "EXACT_RESTORED=0",
        "record_failure() {",
        "  failure_code=$1",
        '  if [ "$rc" -eq 0 ]; then rc=$failure_code; fi',
        "}",
        f"if {timed(validation_command, 240)}; then",
        "  ARCHIVE_VALID=1",
        "else",
        "  command_rc=$?",
        '  record_failure "$command_rc"',
        "fi",
        'if [ "$ARCHIVE_VALID" -eq 1 ]; then',
    ]
    for command, timeout_seconds in rollback_commands:
        transaction_lines.extend(
            [
                f"  if {timed(command, timeout_seconds)}; then",
                "    :",
                "  else",
                "    command_rc=$?",
                '    record_failure "$command_rc"',
                "  fi",
            ]
        )
    transaction_lines.extend(
        [
            f"  if {timed(exact_restore_command, 240)}; then",
            "    FIRST_RESTORE=1",
            "  else",
            "    command_rc=$?",
            '    record_failure "$command_rc"',
            "    FIRST_RESTORE=0",
            "  fi",
        ]
    )
    if restart_command is not None:
        transaction_lines.extend(
            [
                '  if [ "$FIRST_RESTORE" -eq 1 ]; then',
                f"    if {timed(restart_command, 90)}; then",
                "      :",
                "    else",
                "      command_rc=$?",
                '      record_failure "$command_rc"',
                "    fi",
                "  fi",
            ]
        )
    for command, timeout_seconds in verify_commands:
        transaction_lines.extend(
            [
                '  if [ "$FIRST_RESTORE" -eq 1 ]; then',
                f"    if {timed(command, timeout_seconds)}; then",
                "      :",
                "    else",
                "      command_rc=$?",
                '      record_failure "$command_rc"',
                "    fi",
                "  fi",
            ]
        )
    transaction_lines.extend(
        [
            # A reviewed rollback or verification command may fail or mutate a
            # declared file. Always perform an exact restore after those commands.
            f"  if {timed(exact_restore_command, 240)}; then",
            "    SECOND_RESTORE=1",
            "  else",
            "    command_rc=$?",
            '    record_failure "$command_rc"',
            "  fi",
        ]
    )
    if restart_command is not None:
        transaction_lines.extend(
            [
                '  if [ "$SECOND_RESTORE" -eq 1 ]; then',
                f"    if {timed(restart_command, 90)}; then",
                "      :",
                "    else",
                "      command_rc=$?",
                '      record_failure "$command_rc"',
                "    fi",
                "  fi",
            ]
        )
    transaction_lines.extend(
        [
            # A restart may regenerate a declared file. Restore once more and
            # perform no target-affecting command after this point.
            f"  if {timed(exact_restore_command, 240)}; then",
            "    EXACT_RESTORED=1",
            "  else",
            "    command_rc=$?",
            '    record_failure "$command_rc"',
            "  fi",
            "fi",
        ]
    )
    guard = "\n".join(_backup_directory_guard_lines(plan, backup_dir))
    control_files = "\n".join(_secure_control_file_function_lines())
    transaction = "\n".join(transaction_lines)
    return (
        "#!/bin/sh\n"
        "set -eu\n"
        f"PATH={TRUSTED_REMOTE_PATH}\n"
        "export PATH\n"
        f"BACKUP_DIR={shlex.quote(backup_dir)}\n"
        f"{guard}\n"
        f"{control_files}\n"
        "command -v flock >/dev/null\n"
        "command -v mktemp >/dev/null\n"
        "command -v mv >/dev/null\n"
        f"STARTED={shlex.quote(started)}\n"
        f"STATE={shlex.quote(state_path)}\n"
        f"LOCK={shlex.quote(lock)}\n"
        f"STATUS={shlex.quote(status)}\n"
        "release_active_lease() {\n"
        '  private_control_file "$ACTIVE_LEASE"\n'
        '  test "$(cat "$ACTIVE_LEASE")" = "$ACTIVE_TOKEN"\n'
        '  rm -f -- "$ACTIVE_LEASE"\n'
        "}\n"
        "write_state() (\n"
        "  set -eu\n"
        '  temporary=$(mktemp -- "$BACKUP_DIR/.rollback-state.XXXXXX")\n'
        '  trap \'[ -z "$temporary" ] || rm -f -- "$temporary"\' HUP INT TERM EXIT\n'
        '  test -f "$temporary" && test ! -L "$temporary"\n'
        '  chmod 0600 "$temporary"\n'
        "  printf '%s\\n' \"$1\" > \"$temporary\"\n"
        "  mv -fT -- \"$temporary\" \"$STATE\"\n"
        "  temporary=\n"
        ")\n"
        'private_control_file "$LOCK"\n'
        'private_control_file "$STATE"\n'
        'if [ -e "$STATUS" ] || [ -L "$STATUS" ]; then private_control_file "$STATUS"; fi\n'
        'exec 9<> "$LOCK"\n'
        "flock 9\n"
        "trap 'exit 129' HUP\n"
        "trap 'exit 130' INT\n"
        "trap 'exit 143' TERM\n"
        "current=$(cat \"$STATE\")\n"
        "if [ \"$current\" != armed ]; then exit 0; fi\n"
        "if [ ! -e \"$STARTED\" ] && [ ! -L \"$STARTED\" ]; then\n"
        "  write_state expired-without-change\n"
        "  release_active_lease\n"
        "  exit 0\n"
        "fi\n"
        'private_control_file "$STARTED"\n'
        "write_state rolling-back\n"
        "set +e\n"
        f"{transaction}\n"
        "state=rollback-failed\n"
        'if [ "$EXACT_RESTORED" -eq 1 ] && [ "$rc" -eq 0 ]; then\n'
        "  state=rolled-back\n"
        'elif [ "$EXACT_RESTORED" -eq 1 ]; then\n'
        "  state=rolled-back-with-errors\n"
        "fi\n"
        "set -e\n"
        "write_state \"$state\"\n"
        'if [ "$EXACT_RESTORED" -eq 1 ]; then release_active_lease; fi\n'
        "completed_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf unknown)\n"
        'temporary=$(mktemp -- "$BACKUP_DIR/.rollback-status.XXXXXX")\n'
        'test -f "$temporary" && test ! -L "$temporary"\n'
        'chmod 0600 "$temporary"\n'
        "printf 'status=%s\\nreturncode=%s\\nexact_restore_completed=%s\\ncompleted_at=%s\\n' "
        '"$state" "$rc" "$EXACT_RESTORED" "$completed_at" > "$temporary"\n'
        'mv -fT -- "$temporary" "$STATUS"\n'
        'exit "$rc"\n'
    )


def _automatic_rollback_unit(plan: dict[str, Any], backup_dir: str) -> str:
    backup_dir = _normalize_execution_backup_dir(plan, backup_dir)
    execution_id = PurePosixPath(backup_dir).name
    return f"netops-rollback-{plan['plan_id']}-{execution_id}"


def _release_active_change_lease(
    plan: dict[str, Any], host: dict[str, Any], *, backup_dir: str
) -> dict[str, Any]:
    backup_dir = _normalize_execution_backup_dir(plan, backup_dir)
    lease_path, _ = _active_change_lease(plan, backup_dir)
    backup_root = plan["backup_root"]
    script = "\n".join(
        [
            *_backup_directory_guard_lines(plan, backup_dir),
            f"cd -P {shlex.quote(backup_root)}",
            f"test \"$(pwd -P)\" = {shlex.quote(backup_root)}",
            "rm -f -- ./.active-change",
            "test ! -e ./.active-change && test ! -L ./.active-change",
        ]
    )
    result = _remote_script(host, script, timeout=15)
    if result["returncode"] != 0:
        raise RuntimeError(
            "active change lease could not be safely released: "
            f"{_safe_remote_output(result['stderr'])}"
        )
    return {
        "phase": "release-active-change-lease",
        "returncode": result["returncode"],
        "duration_ms": result.get("duration_ms", 0),
        "lease_path": lease_path,
    }


def _arm_automatic_rollback(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    backup_dir: str,
    expected_integrity: dict[str, str],
) -> dict[str, Any] | None:
    if plan["control_channel"]["continuity_strategy"] != "automatic-rollback":
        return None
    delay = int(plan["rollback_timer"]["delay_seconds"])
    unit = _automatic_rollback_unit(plan, backup_dir)
    script_path = f"{backup_dir}/automatic-rollback.sh"
    started = f"{backup_dir}/change.started"
    state = f"{backup_dir}/rollback.state"
    lock = f"{backup_dir}/rollback.lock"
    status = f"{backup_dir}/automatic-rollback.status"
    content = _automatic_rollback_script(
        plan, backup_dir, expected_integrity
    )
    script = (
        "\n".join(_backup_directory_guard_lines(plan, backup_dir))
        + "\n"
        + "\n".join(_secure_control_file_function_lines())
        + "\ncommand -v systemd-run >/dev/null\n"
        "command -v flock >/dev/null\n"
        "command -v timeout >/dev/null\n"
        "test \"$(id -u)\" -eq 0\n"
        f"LOCK={shlex.quote(lock)}\n"
        'if [ ! -e "$LOCK" ] && [ ! -L "$LOCK" ]; then\n'
        '  (umask 077; set -C; : > "$LOCK") 2>/dev/null || true\n'
        "fi\n"
        'private_control_file "$LOCK"\n'
        'exec 9<> "$LOCK"\n'
        "flock -n 9 || exit 75\n"
        f"if systemctl is-active --quiet {shlex.quote(unit + '.timer')}; then "
        "exit 1; fi\n"
        f"if systemctl is-active --quiet {shlex.quote(unit + '.service')}; then "
        "exit 1; fi\n"
        f"test ! -e {shlex.quote(started)} && test ! -L {shlex.quote(started)}\n"
        f"test ! -e {shlex.quote(status)} && test ! -L {shlex.quote(status)}\n"
        f"test ! -e {shlex.quote(state)} && test ! -L {shlex.quote(state)}\n"
        f"test ! -e {shlex.quote(script_path)} && test ! -L {shlex.quote(script_path)}\n"
        "umask 077\n"
        f"(set -C; printf %s {shlex.quote(content)} > {shlex.quote(script_path)})\n"
        f"chmod 0700 {shlex.quote(script_path)}\n"
        f"(set -C; printf '%s\\n' armed > {shlex.quote(state)})\n"
        f"chmod 0600 {shlex.quote(state)}\n"
        f"systemd-run --quiet --unit={shlex.quote(unit)} "
        f"--on-active={delay}s /bin/sh {shlex.quote(script_path)}\n"
        f"systemctl is-active --quiet {shlex.quote(unit + '.timer')}"
    )
    result = _remote_script(host, script, timeout=30)
    if result["returncode"] != 0:
        raise RuntimeError(
            "automatic rollback timer failed to arm: "
            f"{_safe_remote_output(result['stderr'])}"
        )
    return {
        "phase": "arm-automatic-rollback",
        "returncode": result["returncode"],
        "duration_ms": result.get("duration_ms", 0),
        "unit": f"{unit}.timer",
        "delay_seconds": delay,
        "script_path": script_path,
    }


def _mark_change_started(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    backup_dir: str,
) -> dict[str, Any]:
    unit = _automatic_rollback_unit(plan, backup_dir)
    started = f"{backup_dir}/change.started"
    state = f"{backup_dir}/rollback.state"
    lock = f"{backup_dir}/rollback.lock"
    script = (
        "\n".join(_backup_directory_guard_lines(plan, backup_dir))
        + "\n"
        + "\n".join(_secure_control_file_function_lines())
        + f"\nSTATE={shlex.quote(state)}\n"
        f"LOCK={shlex.quote(lock)}\n"
        "command -v flock >/dev/null\n"
        'private_control_file "$STATE"\n'
        'private_control_file "$LOCK"\n'
        'exec 9<> "$LOCK"\n'
        "flock -n 9 || exit 75\n"
        "trap 'exit 129' HUP\n"
        "trap 'exit 130' INT\n"
        "trap 'exit 143' TERM\n"
        'test "$(cat "$STATE")" = armed\n'
        f"systemctl is-active --quiet {shlex.quote(unit + '.timer')}\n"
        f"test ! -e {shlex.quote(started)} && test ! -L {shlex.quote(started)}\n"
        "umask 077\n"
        f"(set -C; : > {shlex.quote(started)})\n"
        f"chmod 0600 {shlex.quote(started)}"
    )
    result = _remote_script(
        host,
        script,
        timeout=15,
    )
    if result["returncode"] != 0:
        raise RuntimeError(
            "failed to mark guarded change start: "
            f"{_safe_remote_output(result['stderr'])}"
        )
    return {
        "phase": "mark-change-started",
        "returncode": result["returncode"],
        "duration_ms": result.get("duration_ms", 0),
    }


def _disarm_automatic_rollback(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    backup_dir: str,
    reject_completed: bool = True,
) -> dict[str, Any]:
    unit = _automatic_rollback_unit(plan, backup_dir)
    disarmed = f"{backup_dir}/rollback.disarmed"
    state = f"{backup_dir}/rollback.state"
    lock = f"{backup_dir}/rollback.lock"
    status = f"{backup_dir}/automatic-rollback.status"
    state_gate = (
        'test "$current" = armed\n'
        if reject_completed
        else (
            'case "$current" in\n'
            "  armed|disarmed|expired-without-change|rolling-back|rollback-failed|"
            "rolled-back|rolled-back-with-errors) ;;\n"
            "  *) exit 1 ;;\n"
            "esac\n"
        )
    )
    script = (
        "\n".join(_backup_directory_guard_lines(plan, backup_dir))
        + "\n"
        + "\n".join(_secure_control_file_function_lines())
        + f"\nBACKUP_DIR={shlex.quote(backup_dir)}\n"
        f"STATE={shlex.quote(state)}\n"
        f"LOCK={shlex.quote(lock)}\n"
        f"STATUS={shlex.quote(status)}\n"
        "command -v flock >/dev/null\n"
        "command -v mktemp >/dev/null\n"
        "command -v mv >/dev/null\n"
        "write_state() (\n"
        "  set -eu\n"
        '  temporary=$(mktemp -- "$BACKUP_DIR/.rollback-state.XXXXXX")\n'
        '  trap \'[ -z "$temporary" ] || rm -f -- "$temporary"\' HUP INT TERM EXIT\n'
        '  test -f "$temporary" && test ! -L "$temporary"\n'
        '  chmod 0600 "$temporary"\n'
        "  printf '%s\\n' \"$1\" > \"$temporary\"\n"
        "  mv -fT -- \"$temporary\" \"$STATE\"\n"
        "  temporary=\n"
        ")\n"
        'private_control_file "$STATE"\n'
        'private_control_file "$LOCK"\n'
        'if [ -e "$STATUS" ] || [ -L "$STATUS" ]; then private_control_file "$STATUS"; fi\n'
        'exec 9<> "$LOCK"\n'
        "flock -w 300 9 || exit 75\n"
        "trap 'exit 129' HUP\n"
        "trap 'exit 130' INT\n"
        "trap 'exit 143' TERM\n"
        'private_control_file "$STATE"\n'
        'current=$(cat "$STATE")\n'
        + state_gate
        + f"systemctl stop -- {shlex.quote(unit + '.timer')} 2>/dev/null || true\n"
        f"systemctl stop -- {shlex.quote(unit + '.service')} 2>/dev/null || true\n"
        f"if systemctl is-active --quiet {shlex.quote(unit + '.timer')}; then exit 1; fi\n"
        f"if systemctl is-active --quiet {shlex.quote(unit + '.service')}; then exit 1; fi\n"
        'if [ "$current" != disarmed ]; then write_state disarmed; fi\n'
        f"if [ -e {shlex.quote(disarmed)} ] || [ -L {shlex.quote(disarmed)} ]; then\n"
        f"  private_control_file {shlex.quote(disarmed)}\n"
        "else\n"
        "  umask 077\n"
        f"  (set -C; : > {shlex.quote(disarmed)})\n"
        f"  chmod 0600 {shlex.quote(disarmed)}\n"
        "fi\n"
        "printf 'previous_state=%s\\n' \"$current\""
    )
    result = _remote_script(host, script, timeout=330)
    if result["returncode"] != 0:
        raise RuntimeError(
            "automatic rollback timer could not be safely disarmed: "
            f"{_safe_remote_output(result['stdout'])} "
            f"{_safe_remote_output(result['stderr'])}"
        )
    previous_state = None
    for line in str(result.get("stdout", "")).splitlines():
        if line.startswith("previous_state="):
            previous_state = line.split("=", 1)[1]
    return {
        "phase": "disarm-automatic-rollback",
        "returncode": result["returncode"],
        "duration_ms": result.get("duration_ms", 0),
        "unit": f"{unit}.timer",
        "previous_state": previous_state,
    }


def _restore(
    plan: dict[str, Any],
    host: dict[str, Any],
    *,
    backup_dir: str,
    expected_integrity: dict[str, str],
) -> list[dict[str, Any]]:
    backup_dir = _normalize_execution_backup_dir(plan, backup_dir)
    expected_integrity = _normalize_backup_integrity(
        expected_integrity, label="restore backup integrity"
    )
    results: list[dict[str, Any]] = []
    failures: list[str] = []

    def append_result(
        phase: str,
        result: dict[str, Any],
        *,
        description: str | None = None,
    ) -> None:
        item: dict[str, Any] = {
            "phase": phase,
            "returncode": result.get("returncode"),
            "stdout": _safe_remote_output(result.get("stdout", "")),
            "stderr": _safe_remote_output(result.get("stderr", "")),
            "duration_ms": result.get("duration_ms", 0),
        }
        if description is not None:
            item["description"] = description
        if phase in {"restore-backup", "final-restore-backup"}:
            item["restore_atomicity"] = (
                "two-phase-prepare-per-file-atomic-cross-directory-not-atomic"
            )
        results.append(item)

    def failed_result(exc: Exception) -> dict[str, Any]:
        return {
            "returncode": None,
            "stdout": "",
            "stderr": _safe_remote_output(exc),
            "duration_ms": 0,
        }

    def run_operation(operation: dict[str, Any]) -> dict[str, Any]:
        try:
            return _remote_script(
                host,
                operation["command"],
                timeout=int(operation["timeout_seconds"]),
            )
        except Exception as exc:
            return failed_result(exc)

    def run_exact_restore(phase: str) -> bool:
        try:
            result = _remote_script(
                host,
                _validated_archive_script(
                    plan,
                    backup_dir,
                    restore=True,
                    expected_integrity=expected_integrity,
                ),
                timeout=240,
            )
        except Exception as exc:
            result = failed_result(exc)
        append_result(phase, result)
        if result.get("returncode") != 0:
            failures.append(
                f"{phase}: {_safe_remote_output(result.get('stderr', ''))}"
            )
            return False
        return True

    def run_restart(phase: str) -> None:
        services = plan.get("restart_services") or []
        if not services:
            return
        command = "systemctl restart -- " + " ".join(
            shlex.quote(service) for service in services
        )
        try:
            result = _remote_script(host, command, timeout=90)
        except Exception as exc:
            result = failed_result(exc)
        append_result(phase, result)
        if result.get("returncode") != 0:
            failures.append(
                f"{phase}: {_safe_remote_output(result.get('stderr', ''))}"
            )

    validation = _remote_script(
        host,
        _validated_archive_script(
            plan,
            backup_dir,
            restore=False,
            expected_integrity=expected_integrity,
        ),
        timeout=240,
    )
    append_result("validate-backup-archive", validation)
    if validation.get("returncode") != 0:
        error = RuntimeError(
            "backup archive validation failed before rollback mutation: "
            f"{_safe_remote_output(validation.get('stderr', ''))}"
        )
        setattr(error, "rollback_steps", results)
        setattr(error, "exact_restore_completed", False)
        raise error

    for operation in plan.get("operations", []):
        if operation["phase"] != "rollback":
            continue
        result = run_operation(operation)
        append_result(
            "rollback", result, description=operation["description"]
        )
        if result.get("returncode") != 0:
            failures.append(
                "rollback operation failed: "
                + operation["description"]
                + ": "
                + _safe_remote_output(result.get("stderr", ""))
            )

    first_restored = run_exact_restore("restore-backup")
    if first_restored:
        run_restart("rollback-restart")
        for operation in plan.get("operations", []):
            if operation["phase"] != "rollback_verify":
                continue
            result = run_operation(operation)
            append_result(
                "rollback_verify", result, description=operation["description"]
            )
            if result.get("returncode") != 0:
                failures.append(
                    "rollback verification failed: "
                    + operation["description"]
                    + ": "
                    + _safe_remote_output(result.get("stderr", ""))
                )

    second_restored = run_exact_restore("post-verify-restore-backup")
    if second_restored:
        run_restart("final-rollback-restart")
    # Restart hooks can rewrite managed files. The final remote mutation must
    # therefore be an exact archive restore, with no service action afterward.
    final_restored = run_exact_restore("final-restore-backup")
    if failures:
        error = RuntimeError("; ".join(failure for failure in failures if failure))
        setattr(error, "rollback_steps", results)
        setattr(error, "exact_restore_completed", final_restored)
        raise error
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


def _load_apply_receipt_for_rollback(
    path: str | Path,
    *,
    plan: dict[str, Any],
    backup_dir: str,
) -> dict[str, Any]:
    source = Path(path).expanduser().resolve()
    receipt = load_json_limited(source, max_bytes=4 * 1_048_576)
    if not isinstance(receipt, dict):
        raise ValueError("apply receipt must be an object")
    if receipt.get("plan_id") != plan["plan_id"]:
        raise ValueError("apply receipt plan_id does not match the rollback plan")
    if receipt.get("host_alias") != plan["host_alias"]:
        raise ValueError("apply receipt host_alias does not match the rollback plan")
    if receipt.get("backup_dir") != backup_dir:
        raise ValueError("apply receipt backup_dir does not match the requested backup")
    execution_id = receipt.get("execution_id")
    if execution_id != PurePosixPath(backup_dir).name:
        raise ValueError("apply receipt execution_id does not match backup_dir")
    integrity = _normalize_backup_integrity(
        receipt.get("backup_integrity"), label="apply receipt backup_integrity"
    )
    return {
        "path": str(source),
        "plan_id": receipt["plan_id"],
        "host_alias": receipt["host_alias"],
        "execution_id": execution_id,
        "backup_dir": backup_dir,
        "backup_integrity": integrity,
        "apply_status": receipt.get("status"),
    }


def _normalize_control_channel_evidence(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict) or set(raw) != {"observed_at", "control_channel"}:
        raise ValueError(
            "current control-channel evidence needs observed_at and control_channel only"
        )
    age = _age_seconds(
        raw.get("observed_at"), label="control-channel evidence observed_at"
    )
    if age < -MAX_CLOCK_SKEW_SECONDS:
        raise ValueError("control-channel evidence is too far in the future")
    if age > MAX_CONTROL_CHANNEL_EVIDENCE_AGE_SECONDS:
        raise ValueError("control-channel evidence is older than 15 minutes")
    control = normalize_control_channel(raw.get("control_channel"))
    if control != raw.get("control_channel"):
        raise ValueError("control-channel evidence must be fully normalized")
    return {"observed_at": raw["observed_at"], "control_channel": control}


def apply_plan(
    plan_path: str | Path,
    fleet: dict[str, Any],
    *,
    authorized: bool,
    confirmed_plan_id: str,
    current_control_channel: dict[str, Any],
    receipt_path: str | Path | None = None,
) -> dict[str, Any]:
    if authorized is not True:
        raise PermissionError(CHANGE_AUTHORIZATION_REQUIRED)
    access_evidence = _normalize_control_channel_evidence(current_control_channel)
    plan = load_plan(plan_path)
    _assert_plan_fresh(plan)
    if confirmed_plan_id != plan["plan_id"]:
        raise PermissionError("confirmed plan ID does not match the reviewed plan")
    if "control_channel_guard" not in plan:
        raise PermissionError(
            "change plan predates the control-channel guard; create and review a new plan"
        )
    if access_evidence["control_channel"] != plan.get("control_channel"):
        raise ValueError(
            "current control-channel evidence differs from the reviewed plan; "
            "create and review a new plan"
        )
    guard = assess_control_channel(
        access_evidence["control_channel"],
        plan.get("rollback_timer", {}),
        rollback_contract=plan.get("rollback_contract"),
    )
    if guard != plan.get("control_channel_guard"):
        raise ValueError(
            "control-channel guard changed after planning; create and review a new plan"
        )
    if not guard["execution_available"]:
        raise PermissionError("remote change execution is unavailable")
    if not guard["can_apply"]:
        raise PermissionError(
            "control-channel guard blocked apply: " + " ".join(guard["reasons"])
        )
    host = get_host(fleet, plan["host_alias"])
    _assert_host_unchanged(plan, host)
    destination = resolve_apply_receipt_path(plan_path, receipt_path)
    receipt_identity = _reserve_new_local_file(
        destination, label="change apply receipt"
    )
    receipt: dict[str, Any] = {
        "schema_version": "1.0",
        "plan_id": plan["plan_id"],
        "host_alias": plan["host_alias"],
        "started_at": utc_now(),
        "status": "running",
        "steps": [],
        "control_channel_guard": guard,
        "current_control_channel": access_evidence,
        "receipt_path": str(destination),
    }
    execution_id = uuid.uuid4().hex[:12]
    receipt["execution_id"] = execution_id

    def checkpoint() -> None:
        nonlocal receipt_identity
        receipt_identity = _write_reserved_json_atomic(
            destination,
            receipt,
            expected_identity=receipt_identity,
        )

    def checkpoint_step(step: dict[str, Any]) -> None:
        receipt["steps"].append(step)
        checkpoint()

    def checkpoint_payload(payload: dict[str, Any]) -> None:
        receipt.setdefault("payloads", []).append(payload)
        checkpoint()

    checkpoint()
    backup_dir: str | None = None
    backup_integrity: dict[str, str] | None = None
    automatic_rollback_armed = False
    automatic_arm_attempted = False
    mutation_started = False

    def mark_mutation_started() -> None:
        nonlocal mutation_started
        if not mutation_started:
            mutation_started = True
            receipt["target_mutation_started"] = True
            checkpoint()

    try:
        _run_phase(plan, host, "preflight", on_result=checkpoint_step)
        backup_dir = (
            f"{plan['backup_root']}/{plan['plan_id']}/{execution_id}"
        )
        receipt["backup_dir"] = backup_dir
        receipt["backup_state"] = "starting"
        checkpoint()
        completed_backup_dir, backup_result = _backup(
            plan,
            host,
            execution_id=execution_id,
        )
        if completed_backup_dir != backup_dir:
            raise RuntimeError("backup returned an unexpected execution directory")
        backup_integrity = _normalize_backup_integrity(
            backup_result.get("integrity"), label="backup result integrity"
        )
        receipt["backup_state"] = "verified"
        receipt["backup_integrity"] = backup_integrity
        receipt["active_change_lease"] = "held"
        checkpoint_step(
            {
                "phase": "backup",
                "returncode": backup_result["returncode"],
                "duration_ms": backup_result.get("duration_ms", 0),
                "prestate_manifest": f"{backup_dir}/target-state.sha256",
                "archive_checksum": f"{backup_dir}/state.tar.gz.sha256",
                **backup_integrity,
                "restore_strategy": plan["rollback_contract"]["restore_strategy"],
                "restore_atomicity": (
                    "two-phase-prepare-per-file-atomic-cross-directory-not-atomic"
                ),
            }
        )
        automatic_arm_attempted = (
            plan["control_channel"]["continuity_strategy"]
            == "automatic-rollback"
        )
        armed = _arm_automatic_rollback(
            plan,
            host,
            backup_dir=backup_dir,
            expected_integrity=backup_integrity,
        )
        if armed is not None:
            automatic_rollback_armed = True
            receipt["rollback_timer_state"] = "armed"
            checkpoint_step(armed)
            checkpoint_step(_mark_change_started(plan, host, backup_dir=backup_dir))
        _run_phase(
            plan,
            host,
            "apply",
            backup_dir=backup_dir,
            verify_prestate_before_first=True,
            on_first_operation=mark_mutation_started,
            on_result=checkpoint_step,
        )
        receipt.setdefault("payloads", [])
        _upload_payloads(
            plan,
            host,
            execution_id=execution_id,
            backup_dir=backup_dir,
            on_target_mutation=mark_mutation_started,
            on_result=checkpoint_payload,
        )
        _run_phase(
            plan,
            host,
            "validate",
            backup_dir=backup_dir,
            on_result=checkpoint_step,
        )
        restarted = _restart_services(plan, host, backup_dir=backup_dir)
        if restarted is not None:
            checkpoint_step(
                {
                    "phase": "restart",
                    "returncode": restarted["returncode"],
                    "duration_ms": restarted.get("duration_ms", 0),
                }
            )
        _run_phase(
            plan,
            host,
            "verify",
            backup_dir=backup_dir,
            on_result=checkpoint_step,
        )
        if automatic_rollback_armed:
            checkpoint_step(
                _disarm_automatic_rollback(plan, host, backup_dir=backup_dir)
            )
            automatic_rollback_armed = False
            receipt["rollback_timer_state"] = "disarmed"
            checkpoint()
        checkpoint_step(
            _release_active_change_lease(plan, host, backup_dir=backup_dir)
        )
        receipt["active_change_lease"] = "released"
        receipt["status"] = "applied"
        checkpoint()
    except BaseException as exc:
        receipt["status"] = "apply-failed"
        receipt["error"] = _safe_remote_output(exc)
        cleanup_error = getattr(exc, "payload_cleanup_error", None)
        if cleanup_error:
            receipt["payload_cleanup_error"] = _safe_remote_output(cleanup_error)
        if backup_dir and backup_integrity:
            if automatic_rollback_armed or automatic_arm_attempted:
                # Never race a possibly armed remote timer by disarming it and
                # starting a second rollback transaction over the same files.
                receipt["status"] = "rollback-pending"
                receipt["rollback_timer_state"] = (
                    "armed" if automatic_rollback_armed else "uncertain"
                )
            elif mutation_started:
                try:
                    restored = _restore(
                        plan,
                        host,
                        backup_dir=backup_dir,
                        expected_integrity=backup_integrity,
                    )
                    receipt.setdefault("rollback_steps", []).extend(restored)
                    receipt.setdefault("rollback_steps", []).append(
                        _release_active_change_lease(
                            plan, host, backup_dir=backup_dir
                        )
                    )
                    receipt["active_change_lease"] = "released"
                    receipt["status"] = "rolled-back"
                except BaseException as rollback_exc:
                    receipt.setdefault("rollback_steps", []).extend(
                        getattr(rollback_exc, "rollback_steps", [])
                    )
                    exact_restored = bool(
                        getattr(rollback_exc, "exact_restore_completed", False)
                    )
                    receipt["rollback_exact_restore_completed"] = exact_restored
                    receipt["rollback_error"] = _safe_remote_output(rollback_exc)
                    if exact_restored:
                        try:
                            receipt.setdefault("rollback_steps", []).append(
                                _release_active_change_lease(
                                    plan, host, backup_dir=backup_dir
                                )
                            )
                            receipt["active_change_lease"] = "released"
                        except BaseException as lease_exc:
                            receipt["active_change_lease_error"] = (
                                _safe_remote_output(lease_exc)
                            )
                    receipt["status"] = (
                        "rolled-back-with-errors"
                        if exact_restored
                        else "rollback-failed"
                    )
            else:
                receipt["target_mutation_started"] = False
                try:
                    receipt.setdefault("steps", []).append(
                        _release_active_change_lease(
                            plan, host, backup_dir=backup_dir
                        )
                    )
                    receipt["active_change_lease"] = "released"
                except BaseException as lease_exc:
                    receipt["active_change_lease_error"] = _safe_remote_output(
                        lease_exc
                    )
        checkpoint()
        raise
    finally:
        receipt["completed_at"] = utc_now()
        checkpoint()
    return receipt


def rollback_plan(
    plan_path: str | Path,
    fleet: dict[str, Any],
    *,
    backup_dir: str,
    authorized: bool,
    confirmed_plan_id: str,
    apply_receipt_path: str | Path,
    current_control_channel: dict[str, Any],
    receipt_path: str | Path | None = None,
) -> dict[str, Any]:
    if authorized is not True:
        raise PermissionError(CHANGE_AUTHORIZATION_REQUIRED)
    plan = load_plan(plan_path, verify_local_payloads=False)
    if confirmed_plan_id != plan["plan_id"]:
        raise PermissionError("confirmed plan ID does not match the reviewed plan")
    normalized_backup_dir = _normalize_execution_backup_dir(plan, backup_dir)
    apply_receipt = _load_apply_receipt_for_rollback(
        apply_receipt_path,
        plan=plan,
        backup_dir=normalized_backup_dir,
    )
    access_evidence = _normalize_control_channel_evidence(current_control_channel)
    destination = resolve_rollback_receipt_path(plan_path, receipt_path)
    receipt_identity = _reserve_new_local_file(
        destination, label="change rollback receipt"
    )
    guard = assess_control_channel(
        access_evidence["control_channel"],
        plan.get("rollback_timer", {}),
        rollback_contract=plan.get("rollback_contract"),
        require_independent_path=True,
    )
    receipt: dict[str, Any] = {
        "schema_version": "1.0",
        "plan_id": plan["plan_id"],
        "host_alias": plan["host_alias"],
        "started_at": utc_now(),
        "status": "running",
        "backup_dir": normalized_backup_dir,
        "steps": [],
        "control_channel_guard": guard,
        "current_control_channel": access_evidence,
        "source_apply_receipt": apply_receipt,
        "receipt_path": str(destination),
    }
    def checkpoint() -> None:
        nonlocal receipt_identity
        receipt_identity = _write_reserved_json_atomic(
            destination,
            receipt,
            expected_identity=receipt_identity,
        )

    checkpoint()
    automatic_timer_uncertain = False
    try:
        if not guard["execution_available"]:
            receipt["status"] = "blocked"
            raise PermissionError("remote change rollback is unavailable")
        if not guard["can_apply"]:
            receipt["status"] = "blocked"
            raise PermissionError(
                "control-channel guard blocked rollback: "
                + " ".join(guard["reasons"])
            )
        host = get_host(fleet, plan["host_alias"])
        _assert_host_unchanged(plan, host)
        if (
            plan.get("control_channel", {}).get("continuity_strategy")
            == "automatic-rollback"
        ):
            automatic_timer_uncertain = True
            receipt["steps"].append(
                _disarm_automatic_rollback(
                    plan,
                    host,
                    backup_dir=normalized_backup_dir,
                    reject_completed=False,
                )
            )
            checkpoint()
            automatic_timer_uncertain = False
        for step in _restore(
                plan,
                host,
                backup_dir=normalized_backup_dir,
                expected_integrity=apply_receipt["backup_integrity"],
            ):
            receipt["steps"].append(step)
            checkpoint()
        receipt["steps"].append(
            _release_active_change_lease(
                plan, host, backup_dir=normalized_backup_dir
            )
        )
        receipt["active_change_lease"] = "released"
        receipt["status"] = "rolled-back"
        checkpoint()
    except BaseException as exc:
        receipt["steps"].extend(getattr(exc, "rollback_steps", []))
        exact_restored = bool(
            getattr(exc, "exact_restore_completed", False)
        )
        if exact_restored:
            receipt["rollback_exact_restore_completed"] = True
            try:
                receipt["steps"].append(
                    _release_active_change_lease(
                        plan, host, backup_dir=normalized_backup_dir
                    )
                )
                receipt["active_change_lease"] = "released"
            except BaseException as lease_exc:
                receipt["active_change_lease_error"] = _safe_remote_output(
                    lease_exc
                )
        if receipt["status"] != "blocked":
            receipt["status"] = (
                "rollback-pending"
                if automatic_timer_uncertain
                else (
                    "rolled-back-with-errors"
                    if exact_restored
                    else "rollback-failed"
                )
            )
        receipt["error"] = _safe_remote_output(exc)
        checkpoint()
        raise
    finally:
        receipt["completed_at"] = utc_now()
        checkpoint()
    return receipt
