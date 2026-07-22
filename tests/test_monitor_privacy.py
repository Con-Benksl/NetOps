import contextlib
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netops_core.cli import main
from netops_core.models import DiagnosticBundle, Observation, load_bundle
from netops_core.monitor import (
    DEFAULTS,
    STATE_MANIFEST_NAME,
    STATE_MARKER_CONTENT,
    STATE_MARKER_INSTALLING_CONTENT,
    STATE_MARKER_NAME,
    _run_scheduler_command,
    _save_snapshot,
    build_install_plan,
    install_monitor,
    run_sample,
)


def canonical_linux_plan(root: Path) -> tuple[dict, dict[str, Path]]:
    paths = {
        "config": root / "netops" / "monitor.json",
        "state": root / "state",
        "service": root / "netops-monitor.service",
        "timer": root / "netops-monitor.timer",
    }
    with (
        patch("netops_core.monitor.platform_id", return_value="linux"),
        patch("netops_core.monitor._monitor_paths", return_value=paths),
    ):
        plan = build_install_plan(
            entry_script=root / "netopsctl.py",
            target="example.test",
            port=443,
            protocol="tcp",
            profile="client",
            scope="user",
        )
    return plan, paths


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


def activate_monitor_config(paths: dict[str, Path], config: dict) -> None:
    paths["config"].parent.mkdir(parents=True, exist_ok=True)
    paths["state"].mkdir(parents=True, exist_ok=True)
    paths["config"].write_text(json.dumps(config), encoding="utf-8")
    mark_monitor_owned(paths)


class MonitorPrivacyTests(unittest.TestCase):
    def test_scheduler_command_sink_is_unconditionally_unreleased(self):
        with patch("netops_core.monitor.run_command") as run:
            with self.assertRaisesRegex(RuntimeError, "unavailable in this release"):
                _run_scheduler_command(
                    ["systemctl", "disable", "--now", "netops-monitor.timer"],
                    timeout=1,
                )
        run.assert_not_called()

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_install_resumes_after_scheduler_failure_before_active_marker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, paths = canonical_linux_plan(root)
            absent = {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "not found",
            }
            success = {**absent, "returncode": 0, "stderr": ""}
            failure = {**absent, "stderr": "permission denied"}
            common = (
                patch("netops_core.monitor.platform_id", return_value="linux"),
                patch("netops_core.monitor._monitor_paths", return_value=paths),
                patch(
                    "netops_core.monitor._scheduler_executable",
                    return_value="/usr/bin/systemctl",
                ),
            )
            with common[0], common[1], common[2], patch(
                "netops_core.monitor.run_command",
                side_effect=[absent, success, failure],
            ), self.assertRaisesRegex(RuntimeError, "scheduler command failed"):
                install_monitor(plan, authorized=True, dry_run=False)

            marker = paths["state"] / STATE_MARKER_NAME
            self.assertEqual(
                marker.read_text(encoding="utf-8"),
                STATE_MARKER_INSTALLING_CONTENT,
            )

            with patch("netops_core.monitor.platform_id", return_value="linux"), patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch(
                "netops_core.monitor._scheduler_executable",
                return_value="/usr/bin/systemctl",
            ), patch(
                "netops_core.monitor.run_command",
                side_effect=[success, success],
            ):
                result = install_monitor(plan, authorized=True, dry_run=False)

            self.assertTrue(result["changed"])
            self.assertEqual(
                marker.read_text(encoding="utf-8"),
                STATE_MARKER_CONTENT,
            )

    def test_snapshot_persists_only_anonymous_summary(self):
        bundle = DiagnosticBundle(
            mode="monitor-full",
            vantage_points=["remote-server:private-hostname"],
        )
        bundle.environment = {
            "platform": {"hostname": "private-hostname", "system": "Linux"},
            "commands": {
                "routes": {
                    "stdout": "default via 192.0.2.1 secret-route-output",
                    "stderr": "raw-error-output",
                }
            },
            "resources": {"cpu_count": 4, "loadavg": [0.1, 0.2, 0.3]},
        }
        bundle.targets = [
            {"target": "private-target.example", "port": 443, "protocol": "tcp"}
        ]
        bundle.observations.append(
            Observation(
                vantage_point="remote-server:private-hostname",
                segment="access-network",
                probe="bounded-route-snapshot",
                status="failed",
                target="private-target.example",
                protocol="tcp",
                address_family="ipv4",
                metrics={"duration_ms": 120, "unsafe_text": "metric-secret"},
                evidence={
                    "stdout": "raw-trace-output private-target.example",
                    "headers": {"Set-Cookie": "session=monitor-cookie"},
                    "password": "monitor-password",
                },
                confidence="high",
                limitations=["private-target.example was not reachable"],
            )
        )
        bundle.path_segments = [
            {
                "name": "access-network",
                "status": "failed",
                "evidence": ["192.0.2.1", "private-target.example"],
            }
        ]
        bundle.redactions = ["private-target.example"]
        bundle.finish()

        with tempfile.TemporaryDirectory() as temporary:
            path = _save_snapshot(Path(temporary), bundle, "full")
            raw = path.read_text(encoding="utf-8")
            persisted = load_bundle(path)
            mode = stat.S_IMODE(os.stat(path).st_mode)
            directory_mode = stat.S_IMODE(os.stat(path.parent).st_mode)

        for private_value in (
            "private-hostname",
            "private-target.example",
            "192.0.2.1",
            "secret-route-output",
            "raw-error-output",
            "raw-trace-output",
            "metric-secret",
            "monitor-cookie",
            "monitor-password",
        ):
            self.assertNotIn(private_value, raw)
        self.assertEqual(persisted.vantage_points, ["monitor"])
        self.assertEqual(persisted.targets, [])
        self.assertEqual(persisted.observations[0].target, None)
        self.assertEqual(persisted.observations[0].evidence, {})
        self.assertEqual(persisted.observations[0].metrics, {"duration_ms": 120})
        self.assertEqual(len(persisted.path_segments), 1)
        path_segment = persisted.path_segments[0]
        self.assertEqual(path_segment["name"], "segment-1")
        self.assertEqual(path_segment["status"], "failed")
        self.assertEqual(path_segment["evidence"], [])
        self.assertEqual(path_segment["vantage_points"], ["monitor"])
        self.assertEqual(path_segment["confidence"], "low")
        self.assertEqual(
            path_segment["limitations"],
            ["监控快照只保留匿名推导的路径状态"],
        )
        self.assertIsInstance(path_segment["observed_at"], str)
        self.assertIn("monitor-anonymous-summary", persisted.redactions)
        self.assertEqual(
            persisted.redactions,
            ["monitor-anonymous-summary", "unicode-normalization"],
        )
        if os.name != "nt":
            self.assertEqual(mode, 0o600)
            self.assertEqual(directory_mode, 0o700)

    def test_snapshot_validates_identifiers_before_constructing_a_path(self):
        bundle = DiagnosticBundle(mode="monitor-light", vantage_points=["test"])
        bundle.started_at = "../../outside"
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "state"
            with self.assertRaises(ValueError):
                _save_snapshot(state, bundle, "light")
            self.assertFalse((Path(temporary) / "outside").exists())

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_install_uses_private_config_and_state_permissions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, paths = canonical_linux_plan(root)
            config = paths["config"]
            state = paths["state"]
            absent_scheduler = {
                "available": True,
                "returncode": 1,
                "stdout": "",
                "stderr": "not found",
            }
            with (
                patch("netops_core.monitor.platform_id", return_value="linux"),
                patch("netops_core.monitor._monitor_paths", return_value=paths),
                patch(
                    "netops_core.monitor._scheduler_executable",
                    return_value="/usr/bin/systemctl",
                ) as scheduler_resolver,
                patch(
                    "netops_core.monitor.run_command",
                    side_effect=[
                        absent_scheduler,
                        {**absent_scheduler, "returncode": 0, "stderr": ""},
                        {**absent_scheduler, "returncode": 0, "stderr": ""},
                    ],
                ) as scheduler_runner,
            ):
                result = install_monitor(plan, authorized=True, dry_run=False)
            scheduler_resolver.assert_called_once_with(
                "linux",
                system_scope=False,
            )
            self.assertTrue(scheduler_runner.call_args_list)
            self.assertTrue(
                all(
                    call.args[0][0] == "/usr/bin/systemctl"
                    for call in scheduler_runner.call_args_list
                )
            )
            config_mode = stat.S_IMODE(config.stat().st_mode)
            config_dir_mode = stat.S_IMODE(config.parent.stat().st_mode)
            state_mode = stat.S_IMODE(state.stat().st_mode)

        self.assertTrue(result["changed"])
        if os.name != "nt":
            self.assertEqual(config_mode, 0o600)
            self.assertEqual(config_dir_mode, 0o700)
            self.assertEqual(state_mode, 0o700)

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_install_refuses_nonempty_unmarked_state_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, paths = canonical_linux_plan(root)
            state = paths["state"]
            state.mkdir()
            (state / "unrelated.txt").write_text("keep", encoding="utf-8")
            with (
                patch("netops_core.monitor.platform_id", return_value="linux"),
                patch("netops_core.monitor._monitor_paths", return_value=paths),
                self.assertRaisesRegex(ValueError, "non-empty unmarked"),
            ):
                install_monitor(plan, authorized=True, dry_run=False)
            self.assertEqual((state / "unrelated.txt").read_text(), "keep")

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_install_refuses_mutated_paths_and_unowned_scheduler_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            base, paths = canonical_linux_plan(root)
            service = paths["service"]
            mutated = {**base, "paths": {**base["paths"], "config": str(root / "other")}}
            with (
                patch("netops_core.monitor.platform_id", return_value="linux"),
                patch("netops_core.monitor._monitor_paths", return_value=paths),
                self.assertRaisesRegex(ValueError, "paths do not match"),
            ):
                install_monitor(mutated, authorized=True, dry_run=False)

            service.write_text("unrelated", encoding="utf-8")
            with (
                patch("netops_core.monitor.platform_id", return_value="linux"),
                patch("netops_core.monitor._monitor_paths", return_value=paths),
                self.assertRaisesRegex(FileExistsError, "unowned"),
            ):
                install_monitor(base, authorized=True, dry_run=False)
            self.assertEqual(service.read_text(encoding="utf-8"), "unrelated")

    @unittest.skip("scheduled monitor mutation intentionally unreleased")
    def test_install_refuses_unowned_existing_config(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan, paths = canonical_linux_plan(root)
            config = paths["config"]
            config.parent.mkdir()
            config.write_text("unrelated", encoding="utf-8")
            with (
                patch("netops_core.monitor.platform_id", return_value="linux"),
                patch("netops_core.monitor._monitor_paths", return_value=paths),
                self.assertRaisesRegex(FileExistsError, "unowned"),
            ):
                install_monitor(plan, authorized=True, dry_run=False)
            self.assertEqual(config.read_text(encoding="utf-8"), "unrelated")

    def test_monitor_sample_exception_is_redacted_before_scheduler_output(self):
        private_target = "private-target.example"
        private_hostname = "private-hostname"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            config = {
                "schema_version": "1.0",
                "profile": "client",
                "scope": "user",
                "target": {"host": private_target, "port": 443, "protocol": "tcp"},
                "state_dir": str(state),
                **DEFAULTS,
            }
            config_path = root / "monitor.json"
            paths = {"config": config_path, "state": state}
            activate_monitor_config(paths, config)
            stdout = io.StringIO()
            stderr = io.StringIO()
            error = RuntimeError(
                f"connection to {private_target} from {private_hostname} failed"
            )
            with (
                patch(
                    "netops_core.monitor._monitor_paths",
                    return_value=paths,
                ),
                patch("netops_core.monitor._single_sample", side_effect=error),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                returncode = main(
                    ["monitor", "sample", "--config", str(config_path)]
                )
            output = stdout.getvalue()
            state_raw = (state / "monitor-state.json").read_text(encoding="utf-8")
            state_mode = stat.S_IMODE((state / "monitor-state.json").stat().st_mode)
            state_dir_mode = stat.S_IMODE(state.stat().st_mode)

        self.assertEqual(returncode, 1)
        self.assertEqual(stderr.getvalue(), "")
        self.assertNotIn(private_target, output)
        self.assertNotIn(private_hostname, output)
        self.assertNotIn(private_target, state_raw)
        self.assertNotIn(private_hostname, state_raw)
        self.assertEqual(json.loads(output)["reason"], "sample-error")
        if os.name != "nt":
            self.assertEqual(state_mode, 0o600)
            self.assertEqual(state_dir_mode, 0o700)

    @unittest.skipIf(os.name == "nt", "POSIX directory identity regression")
    def test_monitor_state_write_is_bound_to_the_locked_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            moved_state = root / "state-original"
            victim = root / "victim"
            victim.mkdir()
            config = {
                "schema_version": "1.0",
                "profile": "client",
                "scope": "user",
                "target": {"host": "example.test", "port": 443, "protocol": "tcp"},
                "state_dir": str(state),
                **DEFAULTS,
            }
            config_path = root / "monitor.json"
            paths = {"config": config_path, "state": state}
            activate_monitor_config(paths, config)

            def swap_state_directory(_state_dir):
                state.rename(moved_state)
                state.symlink_to(victim, target_is_directory=True)
                raise RuntimeError("simulated state directory swap")

            with patch(
                "netops_core.monitor._monitor_paths", return_value=paths
            ), patch(
                "netops_core.monitor._load_state", side_effect=swap_state_directory
            ):
                result = run_sample(config_path, allow_incident_loop=False)

            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["reason"], "sample-error")
            self.assertFalse((victim / "monitor-state.json").exists())
            self.assertFalse((moved_state / "monitor-state.json").exists())

    def test_monitor_discards_untrusted_fields_from_existing_state(self):
        poisoned_value = "private-target.example"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir()
            (state / "monitor-state.json").write_text(
                json.dumps(
                    {
                        "failure_count": 2,
                        "last_full_epoch": 0,
                        "incident_active": False,
                        "last_status": "failed",
                        "raw_target": poisoned_value,
                        "last_error_at": poisoned_value,
                    }
                ),
                encoding="utf-8",
            )
            config = {
                "schema_version": "1.0",
                "profile": "client",
                "scope": "user",
                "target": {"host": poisoned_value, "port": 443, "protocol": "tcp"},
                "state_dir": str(state),
                **DEFAULTS,
            }
            config_path = root / "monitor.json"
            paths = {"config": config_path, "state": state}
            activate_monitor_config(paths, config)
            sample = DiagnosticBundle(mode="monitor-light", vantage_points=["test"])
            sample.observations.append(
                Observation(
                    vantage_point="test",
                    segment="node-ingress",
                    probe="tcp-connect",
                    status="ok",
                    target=poisoned_value,
                )
            )
            sample.finish()
            with patch(
                "netops_core.monitor._monitor_paths",
                return_value=paths,
            ), patch("netops_core.monitor._single_sample", return_value=sample):
                result = run_sample(config_path, allow_incident_loop=False)
            persisted_state = (state / "monitor-state.json").read_text(encoding="utf-8")

        self.assertEqual(result["status"], "ok")
        self.assertNotIn(poisoned_value, json.dumps(result, sort_keys=True))
        self.assertNotIn(poisoned_value, persisted_state)

    def test_incident_recovery_returns_status_consistent_with_state(self):
        failed = DiagnosticBundle(mode="monitor-light", vantage_points=["test"])
        failed.observations.append(
            Observation(
                vantage_point="test",
                segment="node-ingress",
                probe="tcp-connect",
                status="failed",
            )
        )
        failed.finish()
        recovered = DiagnosticBundle(mode="monitor-light", vantage_points=["test"])
        recovered.observations.append(
            Observation(
                vantage_point="test",
                segment="node-ingress",
                probe="tcp-connect",
                status="ok",
            )
        )
        recovered.finish()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            config = {
                "schema_version": "1.0",
                "profile": "client",
                "scope": "user",
                "target": {"host": "example.test", "port": 443, "protocol": "tcp"},
                "state_dir": str(state),
                **DEFAULTS,
                "failure_threshold": 1,
                "incident_interval_seconds": 1,
                "incident_duration_seconds": 10,
            }
            config_path = root / "monitor.json"
            paths = {"config": config_path, "state": state}
            activate_monitor_config(paths, config)
            snapshots = iter(
                [
                    state / "snapshots/initial.json",
                    state / "snapshots/trigger.json",
                    state / "snapshots/incident.json",
                    state / "snapshots/recovery.json",
                ]
            )

            def save_next(*_args, **_kwargs):
                destination = next(snapshots)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("{}", encoding="utf-8")
                return destination

            with patch(
                "netops_core.monitor._monitor_paths",
                return_value=paths,
            ), patch(
                "netops_core.monitor._single_sample",
                side_effect=[failed, failed, recovered, recovered],
            ), patch(
                "netops_core.monitor._save_snapshot",
                side_effect=save_next,
            ), patch("netops_core.monitor.time.sleep"), patch(
                "netops_core.monitor.time.monotonic",
                side_effect=[0, 1, 1, 2],
            ), patch(
                "netops_core.monitor.prune_snapshots",
                return_value={
                    "removed": [],
                    "removed_count": 0,
                    "remaining_bytes": 0,
                    "remaining_entries": 0,
                },
            ):
                result = run_sample(config_path)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["state"]["last_status"], "ok")
        self.assertTrue(result["state"]["incident_recovered"])

    def test_failed_full_recovery_confirmation_does_not_return_ok(self):
        failed = DiagnosticBundle(mode="monitor-light", vantage_points=["test"])
        failed.observations.append(
            Observation(
                vantage_point="test",
                segment="node-ingress",
                probe="tcp-connect",
                status="failed",
            )
        )
        failed.finish()
        light_recovery = DiagnosticBundle(
            mode="monitor-light", vantage_points=["test"]
        )
        light_recovery.observations.append(
            Observation(
                vantage_point="test",
                segment="node-ingress",
                probe="tcp-connect",
                status="ok",
            )
        )
        light_recovery.finish()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            config = {
                "schema_version": "1.0",
                "profile": "client",
                "scope": "user",
                "target": {"host": "example.test", "port": 443, "protocol": "tcp"},
                "state_dir": str(state),
                **DEFAULTS,
                "failure_threshold": 1,
                "incident_interval_seconds": 1,
                "incident_duration_seconds": 10,
            }
            config_path = root / "monitor.json"
            paths = {"config": config_path, "state": state}
            activate_monitor_config(paths, config)
            snapshots = iter(
                [
                    state / "snapshots/initial.json",
                    state / "snapshots/trigger.json",
                    state / "snapshots/incident.json",
                    state / "snapshots/confirmation.json",
                ]
            )

            def save_next(*_args, **_kwargs):
                destination = next(snapshots)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_text("{}", encoding="utf-8")
                return destination

            with patch(
                "netops_core.monitor._monitor_paths",
                return_value=paths,
            ), patch(
                "netops_core.monitor._single_sample",
                side_effect=[failed, failed, light_recovery, failed],
            ), patch(
                "netops_core.monitor._save_snapshot",
                side_effect=save_next,
            ), patch("netops_core.monitor.time.sleep"), patch(
                "netops_core.monitor.time.monotonic",
                side_effect=[0, 1, 2, 3, 11],
            ), patch(
                "netops_core.monitor.prune_snapshots",
                return_value={
                    "removed": [],
                    "removed_count": 0,
                    "remaining_bytes": 0,
                    "remaining_entries": 0,
                },
            ):
                result = run_sample(config_path)

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["state"]["last_status"], "failed")
        self.assertFalse(result["state"]["incident_recovered"])


if __name__ == "__main__":
    unittest.main()
