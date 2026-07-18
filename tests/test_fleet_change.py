import json
import os
import tempfile
import unittest
from pathlib import Path

from netops_core.change import apply_plan, create_plan, load_plan
from netops_core.fleet import load_fleet, ssh_invocation, validate_fleet


def fleet_data():
    return {
        "schema_version": "1.0",
        "fleet_name": "test",
        "hosts": [
            {
                "alias": "edge-a",
                "role": "test",
                "management": {"address": "192.0.2.1"},
                "ssh": {"user": "root", "port": 22},
                "domains": {"ipv4": [], "ipv6": [], "panel": []},
            }
        ],
    }


class FleetAndChangeTests(unittest.TestCase):
    def test_fleet_rejects_secret_fields(self):
        fleet = fleet_data()
        fleet["hosts"][0]["ssh"]["password"] = "do-not-store"
        with self.assertRaisesRegex(ValueError, "secret fields"):
            validate_fleet(fleet)

    def test_fleet_rejects_nested_secret_fields(self):
        fleet = fleet_data()
        fleet["hosts"][0]["labels"] = {"token": "do-not-store"}
        with self.assertRaisesRegex(ValueError, "secret fields"):
            validate_fleet(fleet)

    def test_password_transport_uses_environment_not_arguments(self):
        host = fleet_data()["hosts"][0]
        host["ssh"]["password_env"] = "NETOPS_TEST_SSH_PASSWORD"
        with self.assertRaisesRegex(ValueError, "is not set"):
            ssh_invocation(host)
        old = os.environ.get("NETOPS_TEST_SSH_PASSWORD")
        try:
            os.environ["NETOPS_TEST_SSH_PASSWORD"] = "sensitive-value"
            command, env = ssh_invocation(host)
        finally:
            if old is None:
                os.environ.pop("NETOPS_TEST_SSH_PASSWORD", None)
            else:
                os.environ["NETOPS_TEST_SSH_PASSWORD"] = old
        self.assertEqual(command[:2], ["sshpass", "-e"])
        self.assertNotIn("sensitive-value", command)
        self.assertEqual(env["SSHPASS"], "sensitive-value")

    def test_change_plan_is_hashed_and_authorization_gated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload.json"
            payload.write_text('{"ok": true}\n', encoding="utf-8")
            fleet_path = root / "fleet.json"
            fleet_path.write_text(json.dumps(fleet_data()), encoding="utf-8")
            spec = {
                "schema_version": "1.0",
                "name": "test",
                "summary": "test controlled plan",
                "host_alias": "edge-a",
                "invariants": ["default route unchanged"],
                "backup_paths": ["/etc/test.json"],
                "payloads": [
                    {
                        "local_path": "payload.json",
                        "remote_path": "/etc/test.json",
                        "mode": "0644",
                    }
                ],
                "operations": [
                    {"phase": "validate", "description": "validate", "command": "true"},
                    {"phase": "verify", "description": "verify", "command": "true"},
                    {
                        "phase": "rollback_verify",
                        "description": "verify rollback",
                        "command": "true",
                    },
                ],
            }
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            fleet = load_fleet(fleet_path)
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet, plan_path)
            loaded = load_plan(plan_path)
            self.assertEqual(loaded["plan_id"], plan["plan_id"])
            self.assertEqual(len(plan["plan_id"]), 16)
            with self.assertRaisesRegex(PermissionError, "authorized"):
                apply_plan(
                    plan_path,
                    fleet,
                    authorized=False,
                    confirmed_plan_id=plan["plan_id"],
                )
            changed_fleet = load_fleet(fleet_path)
            changed_fleet["hosts"][0]["management"]["address"] = "192.0.2.99"
            with self.assertRaisesRegex(ValueError, "changed after planning"):
                apply_plan(
                    plan_path,
                    changed_fleet,
                    authorized=True,
                    confirmed_plan_id=plan["plan_id"],
                )

    def test_change_plan_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload.json"
            payload.write_text("{}\n", encoding="utf-8")
            fleet_path = root / "fleet.json"
            fleet_path.write_text(json.dumps(fleet_data()), encoding="utf-8")
            spec = {
                "schema_version": "1.0",
                "name": "test",
                "summary": "test",
                "host_alias": "edge-a",
                "invariants": ["unchanged"],
                "backup_paths": ["/etc/test.json"],
                "payloads": [{"local_path": "payload.json", "remote_path": "/etc/test.json"}],
                "operations": [
                    {"phase": "validate", "description": "v", "command": "true"},
                    {"phase": "verify", "description": "v", "command": "true"},
                    {"phase": "rollback_verify", "description": "v", "command": "true"},
                ],
            }
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            create_plan(spec_path, load_fleet(fleet_path), plan_path)
            data = json.loads(plan_path.read_text(encoding="utf-8"))
            data["summary"] = "tampered"
            plan_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "plan ID"):
                load_plan(plan_path)


if __name__ == "__main__":
    unittest.main()
