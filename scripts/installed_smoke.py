#!/usr/bin/env python3
from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import netops_core.monitor as monitor_module
from netops_core.change import (
    CHANGE_AUTHORIZATION_REQUIRED,
    apply_plan,
    rollback_plan,
)
from netops_core.util import parse_json_strict, run_command


def _run(executable: str, arguments: list[str], *, cwd: Path) -> str:
    completed = run_command(
        [executable, *arguments],
        cwd=cwd,
        timeout=30,
        capture_limit=1_048_576,
    )
    if completed["returncode"] != 0:
        raise RuntimeError(
            f"installed netopsctl {' '.join(arguments)} failed: "
            f"{completed['stderr'].strip()}"
        )
    return completed["stdout"]


def _expect_cli_authorization_required(
    executable: str, arguments: list[str], *, cwd: Path
) -> None:
    completed = run_command(
        [executable, *arguments],
        cwd=cwd,
        timeout=30,
        capture_limit=1_048_576,
    )
    if completed["returncode"] != 2 or CHANGE_AUTHORIZATION_REQUIRED not in completed[
        "stderr"
    ]:
        raise RuntimeError("installed change execution CLI did not require authorization")


def _expect_cli_monitor_unavailable(
    executable: str, arguments: list[str], *, cwd: Path
) -> None:
    completed = run_command(
        [executable, *arguments],
        cwd=cwd,
        timeout=30,
        capture_limit=1_048_576,
    )
    if (
        completed["returncode"] != 2
        or "unavailable in this release" not in completed["stderr"]
    ):
        raise RuntimeError("installed scheduled-monitor CLI did not fail closed")


def _expect_api_authorization_required(callback) -> None:
    try:
        callback()
    except PermissionError as exc:
        if str(exc) != CHANGE_AUTHORIZATION_REQUIRED:
            raise RuntimeError("installed change API returned an unexpected error") from exc
    else:
        raise RuntimeError("installed change execution API did not require authorization")


def _expect_monitor_api_unavailable(callback) -> None:
    try:
        callback()
    except RuntimeError as exc:
        if "unavailable in this release" not in str(exc):
            raise RuntimeError(
                "installed scheduled-monitor API returned an unexpected error"
            ) from exc
    except Exception as exc:
        raise RuntimeError(
            "installed scheduled-monitor execution gate was reached too late"
        ) from exc
    else:
        raise RuntimeError(
            "installed scheduled-monitor execution API did not fail closed"
        )


def _check_monitor_api_gates(executable: str, *, cwd: Path) -> None:
    real_paths = monitor_module._monitor_paths("user")
    isolated_paths = {
        key: cwd / "monitor-api" / f"{index:02d}-{key}"
        for index, key in enumerate(real_paths)
    }

    def command_was_called(*_args, **_kwargs):
        raise AssertionError("monitor smoke attempted to execute a scheduler command")

    with (
        patch.object(
            monitor_module,
            "_monitor_paths",
            return_value=isolated_paths,
        ),
        patch.object(
            monitor_module,
            "run_command",
            side_effect=command_was_called,
        ),
    ):
        plan = monitor_module.build_install_plan(
            entry_script=executable,
            target="example.test",
            port=443,
            protocol="tcp",
            profile="server",
            scope="user",
        )
        install_review = monitor_module.install_monitor(
            plan,
            dry_run=True,
        )
        if not (
            install_review.get("dry_run") is True
            and install_review.get("changed") is False
            and install_review.get("execution_available") is False
        ):
            raise RuntimeError("installed monitor install dry-run contract is invalid")

        removal_review = monitor_module.remove_monitor(
            scope="user",
            dry_run=True,
        )
        if not (
            removal_review.get("dry_run") is True
            and removal_review.get("execution_available") is False
            and removal_review.get("commands_are_executable") is False
        ):
            raise RuntimeError("installed monitor remove dry-run contract is invalid")

        status = monitor_module.monitor_status(scope="user")
        if status.get("scheduler") != {
            "available": False,
            "reason": "unreleased",
        }:
            raise RuntimeError("installed monitor status implied scheduler state")

        _expect_monitor_api_unavailable(
            lambda: monitor_module.install_monitor(
                {}, dry_run=False
            )
        )
        _expect_monitor_api_unavailable(
            lambda: monitor_module.remove_monitor(
                scope="user", dry_run=False
            )
        )
        _expect_monitor_api_unavailable(
            lambda: monitor_module._install_monitor_unreleased(
                {}, authorized=True, dry_run=False
            )
        )
        _expect_monitor_api_unavailable(
            lambda: monitor_module._remove_monitor_unreleased(
                scope="invalid", authorized=True, dry_run=False
            )
        )
        _expect_monitor_api_unavailable(
            lambda: monitor_module._monitor_status_unreleased(scope="invalid")
        )
        _expect_monitor_api_unavailable(
            lambda: monitor_module._run_scheduler_command(
                ["systemctl", "disable", "--now", "netops-monitor.timer"],
                timeout=1,
            )
        )

    if (cwd / "monitor-api").exists():
        raise RuntimeError("installed monitor API smoke created filesystem state")


def main() -> int:
    executable = shutil.which("netopsctl")
    if not executable:
        print("installed netopsctl entry point was not found", file=sys.stderr)
        return 1
    try:
        with tempfile.TemporaryDirectory(prefix="netops-installed-smoke-") as raw:
            cwd = Path(raw)
            _run(executable, ["--help"], cwd=cwd)
            catalog = parse_json_strict(
                _run(executable, ["tools", "list"], cwd=cwd)
            )
            if len(catalog.get("tools", [])) != 6:
                raise RuntimeError("installed curated-tool catalog is incomplete")
            apply_receipt = cwd / "apply.receipt.json"
            rollback_receipt = cwd / "rollback.receipt.json"
            _expect_api_authorization_required(
                lambda: apply_plan(
                    cwd / "missing-plan.json",
                    {},
                    authorized=False,
                    confirmed_plan_id="not-a-plan",
                    current_control_channel={},
                    receipt_path=apply_receipt,
                )
            )
            _expect_api_authorization_required(
                lambda: rollback_plan(
                    cwd / "missing-plan.json",
                    {},
                    backup_dir="not-a-backup",
                    authorized=False,
                    confirmed_plan_id="not-a-plan",
                    apply_receipt_path=cwd / "missing-apply.receipt.json",
                    current_control_channel={},
                    receipt_path=rollback_receipt,
                )
            )
            _expect_cli_authorization_required(
                executable,
                [
                    "change",
                    "apply",
                    "--plan",
                    str(cwd / "missing-plan.json"),
                    "--fleet",
                    str(cwd / "missing-fleet.json"),
                    "--current-control-channel",
                    str(cwd / "missing-control.json"),
                    "--confirm-plan-id",
                    "not-a-plan",
                    "--receipt",
                    str(apply_receipt),
                ],
                cwd=cwd,
            )
            _expect_cli_authorization_required(
                executable,
                [
                    "change",
                    "rollback",
                    "--plan",
                    str(cwd / "missing-plan.json"),
                    "--fleet",
                    str(cwd / "missing-fleet.json"),
                    "--backup-dir",
                    "not-a-backup",
                    "--apply-receipt",
                    str(cwd / "missing-apply.receipt.json"),
                    "--current-control-channel",
                    str(cwd / "missing-control.json"),
                    "--confirm-plan-id",
                    "not-a-plan",
                    "--receipt",
                    str(rollback_receipt),
                ],
                cwd=cwd,
            )
            if apply_receipt.exists() or rollback_receipt.exists():
                raise RuntimeError("unauthorized change execution created a receipt")
            _check_monitor_api_gates(executable, cwd=cwd)
            monitor = parse_json_strict(
                _run(
                    executable,
                    [
                        "monitor",
                        "install",
                        "--target",
                        "example.test",
                        "--port",
                        "443",
                        "--scope",
                        "user",
                        "--dry-run",
                    ],
                    cwd=cwd,
                )
            )
            if not (
                monitor.get("dry_run") is True
                and monitor.get("changed") is False
                and monitor.get("execution_available") is False
            ):
                raise RuntimeError("installed monitor dry-run contract is invalid")
            removal = parse_json_strict(
                _run(
                    executable,
                    ["monitor", "remove", "--scope", "user", "--dry-run"],
                    cwd=cwd,
                )
            )
            if not (
                removal.get("dry_run") is True
                and removal.get("execution_available") is False
                and removal.get("commands_are_executable") is False
            ):
                raise RuntimeError("installed monitor removal dry-run contract is invalid")
            _expect_cli_monitor_unavailable(
                executable,
                [
                    "monitor",
                    "install",
                    "--target",
                    "example.test",
                    "--port",
                    "443",
                    "--scope",
                    "user",
                ],
                cwd=cwd,
            )
            _expect_cli_monitor_unavailable(
                executable,
                ["monitor", "remove", "--scope", "user"],
                cwd=cwd,
            )
    except (OSError, RuntimeError, UnicodeError, ValueError) as exc:
        print(f"installed smoke failed: {exc}", file=sys.stderr)
        return 1
    print(
        "installed smoke: arbitrary-cwd CLI, catalog, change authorization and "
        "scheduled-monitor gates, and monitor dry-run plans passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
