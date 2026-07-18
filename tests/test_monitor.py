import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from netops_core.monitor import (
    _probe_failed,
    build_install_plan,
    install_monitor,
    prune_snapshots,
)
from netops_core.models import DiagnosticBundle, Observation


class MonitorTests(unittest.TestCase):
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
        result = install_monitor(plan, authorized=False, dry_run=True)
        self.assertTrue(result["dry_run"])

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

    def test_windows_plan_uses_task_scheduler(self):
        with patch("netops_core.monitor.platform_id", return_value="windows"):
            plan = build_install_plan(
                entry_script="C:/NetOps/scripts/netopsctl.py",
                target="example.invalid",
                port=443,
                protocol="tcp",
                profile="client",
                scope="user",
            )
        self.assertEqual(plan["commands"][0][0], "schtasks")
        self.assertIn("/Create", plan["commands"][0])

    def test_pruning_enforces_age_and_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary)
            snapshots = state / "snapshots"
            snapshots.mkdir()
            old = snapshots / "old.json"
            recent = snapshots / "recent.json"
            old.write_bytes(b"x" * 10)
            recent.write_bytes(b"y" * 100)
            old_time = time.time() - 10 * 86400
            os.utime(old, (old_time, old_time))
            result = prune_snapshots(state, retention_days=7, max_bytes=50)
        self.assertIn(str(old), result["removed"])
        self.assertIn(str(recent), result["removed"])
        self.assertEqual(result["remaining_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
