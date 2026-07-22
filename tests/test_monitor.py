import hashlib
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from netops_core.monitor import (
    STATE_MANIFEST_NAME,
    STATE_MARKER_CONTENT,
    STATE_MARKER_INSTALLING_CONTENT,
    STATE_MARKER_NAME,
    STATE_MARKER_REMOVED_CONTENT,
    _acquire_lock,
    _command_reports_absent,
    _load_config,
    _load_state,
    _probe_failed,
    _release_lock,
    _scheduler_executable,
    _validate_system_scope_launcher,
    _validate_system_scope_data_paths,
    _write_content,
    build_install_plan,
    install_monitor,
    monitor_status,
    prune_snapshots,
    remove_monitor,
    _scheduler_is_absent,
    _systemd_quote,
)
from netops_core.models import DiagnosticBundle, Observation


def mark_monitor_owned(paths: dict[str, Path]) -> None:
    state = paths["state"]
    state.mkdir(parents=True, exist_ok=True)
    files = {
        str(path): hashlib.sha256(path.read_bytes()).hexdigest()
        for key, path in paths.items()
        if key in {"config", "service", "timer", "plist"}
        and path.exists()
    }
    (state / STATE_MANIFEST_NAME).write_text(
        json.dumps({"schema_version": "1.0", "files": files}),
        encoding="utf-8",
    )
    (state / STATE_MARKER_NAME).write_text(
        STATE_MARKER_CONTENT,
        encoding="utf-8",
    )
    if os.name != "nt":
        state.chmod(0o700)
        (state / STATE_MANIFEST_NAME).chmod(0o600)
        (state / STATE_MARKER_NAME).chmod(0o600)
        for key in ("config", "service", "timer", "plist"):
            path = paths.get(key)
            if path is not None and path.exists():
                path.chmod(0o600)


def canonical_owned_linux_monitor(root: Path) -> dict[str, Path]:
    paths = {
        "config": root / "netops" / "monitor.json",
        "state": root / "state",
        "service": root / "netops-monitor.service",
        "timer": root / "netops-monitor.timer",
    }
    paths["config"].parent.mkdir(parents=True)
    for key in ("config", "service", "timer"):
        paths[key].write_text(f"owned-{key}\n", encoding="utf-8")
    mark_monitor_owned(paths)
    return paths


class MonitorTests(unittest.TestCase):
    def test_public_monitor_mutation_is_unavailable_before_io(self):
        with patch("netops_core.monitor.platform_id", return_value="linux"):
            plan = build_install_plan(
                entry_script="/opt/netops/scripts/netopsctl.py",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="client",
                scope="user",
            )
        with patch("netops_core.monitor._validate_install_plan_paths") as validator:
            with self.assertRaisesRegex(RuntimeError, "unavailable in this release"):
                install_monitor(plan, dry_run=False)
            validator.assert_not_called()
        with patch("netops_core.monitor._monitor_paths") as resolver:
            with self.assertRaisesRegex(RuntimeError, "unavailable in this release"):
                remove_monitor(scope="user", dry_run=False)
            resolver.assert_not_called()

    def test_system_scope_rejects_writable_data_directory_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "config": root / "etc" / "netops" / "monitor.json",
                "state": root / "var" / "lib" / "netops",
                "service": root / "systemd" / "netops-monitor.service",
                "timer": root / "systemd" / "netops-monitor.timer",
            }
            root.chmod(0o777)
            with self.assertRaisesRegex(
                PermissionError,
                "unsafe writable or unowned",
            ):
                _validate_system_scope_data_paths(
                    {"platform": "linux", "scope": "system"},
                    paths,
                )

    @unittest.skipIf(os.name == "nt", "POSIX directory mode contract")
    def test_scheduler_write_does_not_make_its_shared_parent_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            shared_parent = Path(temporary) / "systemd-system"
            shared_parent.mkdir(mode=0o755)
            shared_parent.chmod(0o755)

            _write_content(
                shared_parent / "netops-monitor.service",
                "[Unit]\nDescription=NetOps\n",
                private_parent=False,
            )

            self.assertEqual(shared_parent.stat().st_mode & 0o777, 0o755)

    def test_systemd_quote_escapes_percent_specifiers(self):
        self.assertEqual(_systemd_quote("/opt/100%/netops"), '"/opt/100%%/netops"')
        for unsafe in (
            "/opt/netops\nExecStart=/bin/false",
            "/opt/$HOME/netops",
            "/opt/netops\u2028next",
            "/opt/netops\u2029next",
            "/opt/netops\u202enext",
        ):
            with self.subTest(unsafe=unsafe), self.assertRaises(ValueError):
                _systemd_quote(unsafe)

    def test_scheduler_executable_is_absolute_and_system_scope_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            fake = Path(temporary) / "systemctl"
            fake.write_text("#!/bin/sh\n", encoding="utf-8")
            fake.chmod(0o755)
            with patch("netops_core.monitor.shutil.which", return_value=str(fake)):
                self.assertEqual(
                    _scheduler_executable("linux", system_scope=False),
                    str(fake.resolve()),
                )
                with self.assertRaisesRegex(PermissionError, "unsafe writable"):
                    _scheduler_executable("linux", system_scope=True)

    def test_nonlinux_remove_requires_verified_not_found_result(self):
        stopped = {"available": True, "returncode": 0, "stdout": "", "stderr": ""}
        denied = {
            "available": True,
            "returncode": 1,
            "stdout": "",
            "stderr": "permission denied",
        }
        for platform_name in ("macos", "windows"):
            with self.subTest(platform=platform_name):
                self.assertFalse(
                    _scheduler_is_absent(platform_name, stopped, denied)
                )

    def test_localized_windows_absence_is_recognized_but_truncation_fails_closed(self):
        missing = {
            "available": True,
            "returncode": 1,
            "stdout": "",
            "stderr": "错误: 系统找不到指定的文件。",
            "stdout_truncated": False,
            "stderr_truncated": False,
        }
        self.assertTrue(_command_reports_absent(missing))
        self.assertFalse(
            _command_reports_absent({**missing, "stderr_truncated": True})
        )

    def test_system_scope_validates_imported_package_tree(self):
        plan = {
            "platform": "linux",
            "scope": "system",
            "sample_command": [
                "/usr/bin/python3",
                "/usr/bin/netopsctl",
                "monitor",
                "sample",
                "--config",
                "/etc/netops/monitor.json",
            ],
        }
        with patch(
            "netops_core.monitor._validate_root_controlled_path"
        ) as path_validator, patch(
            "netops_core.monitor._validate_root_controlled_directory_tree"
        ) as package_validator:
            _validate_system_scope_launcher(plan)

        self.assertEqual(path_validator.call_count, 2)
        package_validator.assert_called_once()
        self.assertEqual(package_validator.call_args.kwargs["label"], "Python package")

    def test_monitor_status_does_not_return_raw_scheduler_output(self):
        paths = {
            "config": Path("/tmp/netops-monitor.json"),
            "state": Path("/tmp/netops-state"),
            "service": Path("/tmp/netops.service"),
            "timer": Path("/tmp/netops.timer"),
        }
        hostile = {
            "available": True,
            "returncode": 1,
            "stdout": "Authorization: " + "Bearer " + "secret\x1b[31m",
            "stderr": "host\u202ehidden",
            "duration_ms": 1,
            "timed_out": False,
        }
        with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
            "netops_core.monitor._monitor_paths", return_value=paths
        ), patch(
            "netops_core.monitor._scheduler_executable",
            return_value="/usr/bin/systemctl",
        ), patch("netops_core.monitor.run_command", return_value=hostile):
            result = monitor_status(scope="user")
        rendered = json.dumps(result, ensure_ascii=False)
        self.assertNotIn("secret", rendered)
        self.assertNotIn("stdout", rendered)
        self.assertNotIn("stderr", rendered)
        self.assertEqual(result["integrity"], "unowned")

    def test_monitor_status_reports_manifest_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "config": root / "monitor.json",
                "state": root / "state",
                "service": root / "netops.service",
                "timer": root / "netops.timer",
            }
            for key in ("config", "service", "timer"):
                paths[key].write_text("owned", encoding="utf-8")
                paths[key].chmod(0o600)
            mark_monitor_owned(paths)
            paths["state"].chmod(0o700)
            (paths["state"] / STATE_MANIFEST_NAME).chmod(0o600)
            (paths["state"] / STATE_MARKER_NAME).chmod(0o600)
            paths["config"].write_text("tampered", encoding="utf-8")
            scheduler = {
                "available": True,
                "returncode": 0,
                "stdout": "active",
                "stderr": "",
            }
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch(
                "netops_core.monitor._scheduler_executable",
                return_value="/usr/bin/systemctl",
            ), patch("netops_core.monitor.run_command", return_value=scheduler):
                result = monitor_status(scope="user")
            self.assertEqual(result["integrity"], "tampered")

    def test_monitor_config_and_state_are_bound_to_canonical_scope_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config_path = root / "attacker-monitor.json"
            state = root / "attacker-state"
            state.mkdir()
            (state / STATE_MARKER_NAME).write_text(
                STATE_MARKER_CONTENT,
                encoding="utf-8",
            )
            config_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "profile": "client",
                        "scope": "user",
                        "target": {
                            "host": "example.invalid",
                            "port": 443,
                            "protocol": "tcp",
                        },
                        "state_dir": str(state),
                    }
                ),
                encoding="utf-8",
            )
            canonical = {
                "config": root / "canonical" / "monitor.json",
                "state": root / "canonical-state",
            }
            with patch(
                "netops_core.monitor._monitor_paths",
                return_value=canonical,
            ), self.assertRaisesRegex(ValueError, "canonical scope path"):
                _load_config(config_path)

    def test_monitor_config_and_state_json_are_strict_and_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "monitor.json"
            state = root / "state"
            state.mkdir()

            for constant in ("NaN", "Infinity", "-Infinity"):
                with self.subTest(file="config", constant=constant):
                    config.write_text(
                        '{"schema_version":"1.0","value":' + constant + "}",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, "config is invalid"):
                        _load_config(config)
                with self.subTest(file="state", constant=constant):
                    (state / "monitor-state.json").write_text(
                        '{"failure_count":' + constant + "}",
                        encoding="utf-8",
                    )
                    with self.assertRaisesRegex(ValueError, "state file is invalid"):
                        _load_state(state)

            config.write_bytes(b" " * (1024 * 1024 + 1))
            with self.assertRaisesRegex(ValueError, "unexpectedly large"):
                _load_config(config)
            (state / "monitor-state.json").write_bytes(
                b" " * (256 * 1024 + 1)
            )
            with self.assertRaisesRegex(ValueError, "unexpectedly large"):
                _load_state(state)

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_install_rejects_mutated_scheduler_command_and_unit(self):
        with patch("netops_core.monitor.platform_id", return_value="linux"):
            plan = build_install_plan(
                entry_script="/opt/netops/scripts/netopsctl.py",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="client",
                scope="user",
            )
            plan["commands"] = [["systemctl", "reboot"]]
            with self.assertRaisesRegex(ValueError, "commands were mutated"):
                install_monitor(plan, authorized=True, dry_run=False)

            plan = build_install_plan(
                entry_script="/opt/netops/scripts/netopsctl.py",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="client",
                scope="user",
            )
            service = plan["paths"]["service"]
            plan["files"][service] += "ExecStart=/usr/bin/false\n"
            with self.assertRaisesRegex(ValueError, "files were mutated"):
                install_monitor(plan, authorized=True, dry_run=False)

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_install_rejects_empty_or_unverifiable_scheduler_plan(self):
        with patch("netops_core.monitor.platform_id", return_value="linux"):
            plan = build_install_plan(
                entry_script="/opt/netops/scripts/netopsctl.py",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="client",
                scope="user",
            )
        plan["commands"] = []
        with patch("netops_core.monitor.platform_id", return_value="linux"), self.assertRaisesRegex(
            ValueError, "canonical scheduler commands"
        ):
            install_monitor(plan, authorized=True, dry_run=False)

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_install_scheduler_ownership_probe_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "config": root / "netops" / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ):
                plan = build_install_plan(
                    entry_script=root / "netopsctl.py",
                    target="example.invalid",
                    port=443,
                    protocol="tcp",
                    profile="client",
                    scope="user",
                )
            denied = {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "permission denied",
            }
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch(
                "netops_core.monitor._scheduler_executable",
                return_value="/usr/bin/systemctl",
            ), patch("netops_core.monitor.run_command", return_value=denied):
                with self.assertRaisesRegex(RuntimeError, "could not be verified"):
                    install_monitor(plan, authorized=True, dry_run=False)
            self.assertFalse(paths["config"].exists())
            self.assertFalse(paths["service"].exists())

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    @unittest.skipIf(os.name == "nt", "symlink creation is not portable on Windows")
    def test_install_refuses_symlinked_config_or_state_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            paths = {
                "config": root / "netops" / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ):
                plan = build_install_plan(
                    entry_script=root / "netopsctl.py",
                    target="example.invalid",
                    port=443,
                    protocol="tcp",
                    profile="client",
                    scope="user",
                )
            (root / "netops").symlink_to(outside, target_is_directory=True)
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), self.assertRaisesRegex(ValueError, "real directory"):
                install_monitor(plan, authorized=True, dry_run=False)
            self.assertFalse((outside / "monitor.json").exists())

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    @unittest.skipIf(os.name == "nt", "symlink creation is not portable on Windows")
    def test_install_refuses_symlinked_state_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            paths = {
                "config": root / "netops" / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ):
                plan = build_install_plan(
                    entry_script=root / "netopsctl.py",
                    target="example.invalid",
                    port=443,
                    protocol="tcp",
                    profile="client",
                    scope="user",
                )
            paths["state"].symlink_to(outside, target_is_directory=True)
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), self.assertRaisesRegex(ValueError, "real directory"):
                install_monitor(plan, authorized=True, dry_run=False)
            self.assertEqual(list(outside.iterdir()), [])

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    @unittest.skipIf(os.name == "nt", "symlink creation is not portable on Windows")
    def test_install_refuses_symlinked_scheduler_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside.service"
            outside.write_text("unrelated", encoding="utf-8")
            paths = {
                "config": root / "netops" / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ):
                plan = build_install_plan(
                    entry_script=root / "netopsctl.py",
                    target="example.invalid",
                    port=443,
                    protocol="tcp",
                    profile="client",
                    scope="user",
                )
            paths["service"].symlink_to(outside)
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), self.assertRaisesRegex(ValueError, "regular file"):
                install_monitor(plan, authorized=True, dry_run=False)
            self.assertEqual(outside.read_text(encoding="utf-8"), "unrelated")

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_system_scope_rejects_user_writable_launcher_chain(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = root / "netopsctl.py"
            entry.write_text("print('unsafe')\n", encoding="utf-8")
            paths = {
                "config": root / "netops" / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ):
                plan = build_install_plan(
                    entry_script=entry,
                    target="example.invalid",
                    port=443,
                    protocol="tcp",
                    profile="server",
                    scope="system",
                )
            absent = {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "not found",
            }
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch("netops_core.monitor.os.geteuid", return_value=0), patch(
                "netops_core.monitor.run_command", return_value=absent
            ) as runner, self.assertRaisesRegex(
                PermissionError, "root-owned|unsafe|regular file"
            ):
                install_monitor(plan, authorized=True, dry_run=False)
            runner.assert_not_called()
    def test_dns_success_does_not_hide_tcp_failure(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.observations.extend(
            [
                Observation(
                    vantage_point="test",
                    segment="dns",
                    probe="getaddrinfo",
                    status="ok",
                ),
                Observation(
                    vantage_point="test",
                    segment="node-ingress",
                    probe="tcp-connect",
                    status="failed",
                ),
            ]
        )
        self.assertTrue(_probe_failed(bundle))

    def test_missing_tcp_observation_is_a_failed_monitor_sample(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.observations.append(
            Observation(
                vantage_point="test",
                segment="dns",
                probe="getaddrinfo",
                status="ok",
            )
        )
        self.assertTrue(_probe_failed(bundle))

    def test_monitor_refuses_generic_udp_health_claim(self):
        with patch("netops_core.monitor.platform_id", return_value="linux"):
            with self.assertRaisesRegex(ValueError, "protocol-aware"):
                build_install_plan(
                    entry_script="/opt/netops/scripts/netopsctl.py",
                    target="example.invalid",
                    port=443,
                    protocol="udp",
                    profile="server",
                    scope="system",
                )

    def test_linux_systemd_plan_uses_one_minute_timer(self):
        with patch("netops_core.monitor.platform_id", return_value="linux"):
            plan = build_install_plan(
                entry_script="/opt/netops/scripts/netopsctl.py",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="server",
                scope="system",
            )
        timer = next(
            content
            for path, content in plan["files"].items()
            if path.replace("\\", "/").endswith(
                "/etc/systemd/system/netops-monitor.timer"
            )
        )
        self.assertIn("OnUnitActiveSec=60s", timer)
        self.assertEqual(plan["config"]["retention_days"], 7)
        self.assertEqual(plan["config"]["max_bytes"], 200 * 1024 * 1024)
        with patch("netops_core.monitor.platform_id", return_value="linux"):
            result = install_monitor(plan, dry_run=True)
        self.assertTrue(result["dry_run"])
        self.assertFalse(result["execution_available"])
        self.assertFalse(result["changed"])

    def test_macos_plan_uses_launch_agent(self):
        with patch("netops_core.monitor.platform_id", return_value="macos"):
            plan = build_install_plan(
                entry_script="/opt/netops/scripts/netopsctl.py",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="client",
                scope="user",
            )
        self.assertIn("plist", plan["paths"])
        self.assertEqual(plan["commands"][-1][1], "bootstrap")
        plist = next(
            content for path, content in plan["files"].items() if path.endswith(".plist")
        )
        self.assertNotIn("scheduler.out.log", plist.decode("utf-8"))
        self.assertIn("/dev/null", plist.decode("utf-8"))

    def test_windows_plan_uses_task_scheduler(self):
        with patch("netops_core.monitor.platform_id", return_value="windows"):
            plan = build_install_plan(
                entry_script="C:/NetOps/scripts/netopsctl.py",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="client",
                scope="user",
                overrides={"interval_seconds": 300},
            )
        self.assertEqual(plan["commands"][0][0], "schtasks")
        self.assertIn("/Create", plan["commands"][0])
        command = plan["commands"][0]
        self.assertEqual(command[command.index("/MO") + 1], "5")

    def test_windows_installed_exe_launcher_is_executed_directly(self):
        with patch("netops_core.monitor.platform_id", return_value="windows"):
            plan = build_install_plan(
                entry_script="C:/Python/Scripts/netopsctl.exe",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="client",
                scope="user",
                overrides={"interval_seconds": 300},
            )
        task = plan["commands"][0]
        task_command = task[task.index("/TR") + 1]
        self.assertIn("netopsctl.exe", task_command)
        self.assertNotIn("python.exe", task_command.casefold())

    def test_windows_source_script_still_uses_python(self):
        with patch("netops_core.monitor.platform_id", return_value="windows"):
            plan = build_install_plan(
                entry_script="C:/NetOps/scripts/netopsctl.py",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="client",
                scope="user",
                overrides={"interval_seconds": 300},
            )
        task = plan["commands"][0]
        task_command = task[task.index("/TR") + 1]
        self.assertIn(Path(sys.executable).name, task_command)

    def test_monitor_plan_rejects_unbounded_or_unrepresentable_settings(self):
        with patch("netops_core.monitor.platform_id", return_value="linux"):
            for overrides in (
                {"interval_seconds": True},
                {"incident_duration_seconds": 100_000},
                {"incident_interval_seconds": 60, "incident_duration_seconds": 10},
            ):
                with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                    build_install_plan(
                        entry_script="/opt/netops/scripts/netopsctl.py",
                        target="example.invalid",
                        port=443,
                        protocol="tcp",
                        profile="server",
                        scope="system",
                        overrides=overrides,
                    )
        with patch("netops_core.monitor.platform_id", return_value="windows"):
            with self.assertRaisesRegex(ValueError, "whole minutes"):
                build_install_plan(
                    entry_script="C:/NetOps/scripts/netopsctl.py",
                    target="example.invalid",
                    port=443,
                    protocol="tcp",
                    profile="client",
                    scope="user",
                    overrides={"interval_seconds": 90},
                )

    def test_monitor_plan_rejects_option_like_target(self):
        with patch("netops_core.monitor.platform_id", return_value="linux"):
            with self.assertRaises(ValueError):
                build_install_plan(
                    entry_script="/opt/netops/scripts/netopsctl.py",
                    target="--help",
                    port=443,
                    protocol="tcp",
                    profile="server",
                    scope="system",
                )

    def test_pruning_enforces_age_and_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = canonical_owned_linux_monitor(Path(temporary))
            state = paths["state"]
            snapshots = state / "snapshots"
            snapshots.mkdir()
            if os.name != "nt":
                snapshots.chmod(0o700)
            old = snapshots / "old.json"
            recent = snapshots / "recent.json"
            old.write_bytes(b"x" * 10)
            recent.write_bytes(b"y" * 1_048_577)
            old_time = time.time() - 10 * 86400
            os.utime(old, (old_time, old_time))
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ):
                result = prune_snapshots(
                    state,
                    retention_days=7,
                    max_bytes=1_048_576,
                )
        self.assertIn(str(old.resolve()), result["removed"])
        self.assertIn(str(recent.resolve()), result["removed"])
        self.assertEqual(result["remaining_bytes"], 0)

    def test_pruning_enforces_bounded_file_count_in_linear_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            paths = canonical_owned_linux_monitor(Path(temporary))
            state = paths["state"]
            snapshots = state / "snapshots"
            snapshots.mkdir()
            if os.name != "nt":
                snapshots.chmod(0o700)
            for index in range(5):
                path = snapshots / f"{index}.json"
                path.write_text("{}", encoding="utf-8")
                os.utime(path, (time.time() + index, time.time() + index))
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch("netops_core.monitor.MAX_SNAPSHOT_FILES", 3):
                result = prune_snapshots(
                    state,
                    retention_days=7,
                    max_bytes=1_048_576,
                )
            self.assertEqual(result["removed_count"], 2)
            self.assertEqual(len(list(snapshots.glob("*.json"))), 3)

    def test_pruning_refuses_unmarked_state_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "config": root / "netops" / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            state = paths["state"]
            state.mkdir()
            if os.name != "nt":
                state.chmod(0o700)
            snapshots = state / "snapshots"
            snapshots.mkdir()
            sentinel = snapshots / "sentinel.json"
            sentinel.write_text("{}", encoding="utf-8")
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), self.assertRaisesRegex(ValueError, "inactive"):
                prune_snapshots(state, retention_days=1, max_bytes=1_048_576)
            self.assertTrue(sentinel.exists())

    def test_advisory_monitor_lock_distinguishes_live_contention_from_stale_text(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            lock = state / "sample.lock"
            active = _acquire_lock(state, maximum_age=1)
            self.assertIsNotNone(active)
            self.assertIsNone(_acquire_lock(state, maximum_age=1))
            assert active is not None
            _release_lock(active)

            lock.write_text("not-a-pid\n", encoding="utf-8")
            recovered = _acquire_lock(state, maximum_age=1)
            self.assertIsNotNone(recovered)
            self.assertEqual(lock.read_text(encoding="utf-8"), "not-a-pid\n")
            assert recovered is not None
            _release_lock(recovered)

    @unittest.skipIf(os.name == "nt", "symlink creation is not portable on Windows")
    def test_monitor_lock_corruption_is_an_error_not_live_contention(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            target = state / "target"
            target.write_text("unrelated", encoding="utf-8")
            (state / "sample.lock").symlink_to(target)
            with self.assertRaisesRegex(ValueError, "regular file"):
                _acquire_lock(state, maximum_age=1)

    def test_windows_remove_plan_ends_running_task_before_delete(self):
        paths = {"config": Path("C:/NetOps/monitor.json"), "state": Path("C:/NetOps/state")}
        with patch("netops_core.monitor.platform_id", return_value="windows"), patch(
            "netops_core.monitor._monitor_paths", return_value=paths
        ):
            plan = remove_monitor(scope="user", dry_run=True)
        self.assertEqual(plan["commands"], [])
        self.assertEqual(plan["preflight"]["decision"], "blocked")
        self.assertFalse(plan["commands_are_executable"])
        self.assertFalse(plan["execution_available"])

    @unittest.skipIf(os.name == "nt", "symlink creation is not portable on Windows")
    def test_pruning_refuses_symlinked_snapshot_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = canonical_owned_linux_monitor(root)
            state = paths["state"]
            outside = root / "outside"
            outside.mkdir()
            victim = outside / "old.json"
            victim.write_text("keep", encoding="utf-8")
            old_time = time.time() - 10 * 86400
            os.utime(victim, (old_time, old_time))
            (state / "snapshots").symlink_to(outside, target_is_directory=True)

            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), self.assertRaisesRegex(ValueError, "real directory"):
                prune_snapshots(state, retention_days=1, max_bytes=1_048_576)
            self.assertEqual(victim.read_text(encoding="utf-8"), "keep")

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_remove_monitor_keeps_files_when_scheduler_is_still_active(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "config": root / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            for key in ("config", "service", "timer"):
                paths[key].write_text("sentinel", encoding="utf-8")
            mark_monitor_owned(paths)
            stop_failure = {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "permission denied",
            }
            still_active = {
                "available": True,
                "returncode": 0,
                "stdout": "active\n",
                "stderr": "",
            }
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch("netops_core.monitor.os.geteuid", return_value=0), patch(
                "netops_core.monitor._scheduler_executable",
                return_value="/usr/bin/systemctl",
            ), patch(
                "netops_core.monitor.run_command",
                side_effect=[stop_failure, still_active],
            ):
                result = remove_monitor(
                    scope="system", authorized=True, dry_run=False
                )
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["removed_files"], [])
            for key in ("config", "service", "timer"):
                self.assertTrue(paths[key].exists())

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_remove_monitor_deletes_files_only_after_inactive_confirmation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "config": root / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            for key in ("config", "service", "timer"):
                paths[key].write_text("sentinel", encoding="utf-8")
            mark_monitor_owned(paths)
            stopped = {
                "available": True,
                "returncode": 0,
                "stdout": "",
                "stderr": "",
            }
            inactive = {
                "available": True,
                "returncode": 3,
                "stdout": "inactive\n",
                "stderr": "",
            }
            reloaded = dict(stopped)
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch("netops_core.monitor.os.geteuid", return_value=0), patch(
                "netops_core.monitor._scheduler_executable",
                return_value="/usr/bin/systemctl",
            ), patch(
                "netops_core.monitor.run_command",
                side_effect=[stopped, stopped, inactive, inactive, reloaded],
            ):
                result = remove_monitor(
                    scope="system", authorized=True, dry_run=False
                )
            self.assertEqual(result["status"], "removed")
            for key in ("config", "service", "timer"):
                self.assertFalse(paths[key].exists())
            self.assertEqual(
                (paths["state"] / STATE_MARKER_NAME).read_text(encoding="utf-8"),
                STATE_MARKER_REMOVED_CONTENT,
            )
            self.assertFalse((paths["state"] / STATE_MANIFEST_NAME).exists())

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_remove_refuses_tampered_owned_file_before_scheduler_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "config": root / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            for key in ("config", "service", "timer"):
                paths[key].write_text("owned", encoding="utf-8")
            mark_monitor_owned(paths)
            paths["config"].write_text("replaced", encoding="utf-8")
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch("netops_core.monitor.run_command") as runner:
                result = remove_monitor(scope="user", authorized=True, dry_run=False)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(
                result["reason"], "monitor-owned-files-modified-or-unverified"
            )
            runner.assert_not_called()
            self.assertEqual(paths["config"].read_text(encoding="utf-8"), "replaced")

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_removed_marker_does_not_authorize_later_same_name_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir()
            (state / STATE_MARKER_NAME).write_text(
                STATE_MARKER_REMOVED_CONTENT,
                encoding="utf-8",
            )
            paths = {
                "config": root / "monitor.json",
                "state": state,
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            paths["config"].write_text("unrelated", encoding="utf-8")
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch("netops_core.monitor.run_command") as runner:
                result = remove_monitor(scope="user", authorized=True, dry_run=False)
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["reason"], "removed-monitor-paths-were-reused")
            runner.assert_not_called()
            self.assertEqual(paths["config"].read_text(encoding="utf-8"), "unrelated")

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_remove_monitor_refuses_unowned_scheduler_and_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            paths = {
                "config": root / "monitor.json",
                "state": root / "state",
                "service": root / "netops-monitor.service",
                "timer": root / "netops-monitor.timer",
            }
            for key in ("config", "service", "timer"):
                paths[key].write_text("unrelated", encoding="utf-8")
            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch("netops_core.monitor.run_command") as runner:
                result = remove_monitor(
                    scope="user", authorized=True, dry_run=False
                )
            self.assertEqual(result["status"], "blocked")
            self.assertEqual(result["reason"], "monitor-ownership-unverified")
            runner.assert_not_called()
            for key in ("config", "service", "timer"):
                self.assertEqual(paths[key].read_text(), "unrelated")


if __name__ == "__main__":
    unittest.main()
