import json
import os
import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netops_core import fleet as fleet_module
from netops_core.fleet import (
    SSH_ALIAS_RE,
    SSH_CONFIG_HOST_CONFLICT_FIELDS,
    SSH_USER_RE,
    load_fleet,
    ssh_invocation,
    validate_fleet,
)


def fleet_data() -> dict:
    return {
        "schema_version": "2.0",
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


class FleetContractTests(unittest.TestCase):
    def test_loaded_fleet_remains_valid_but_disk_metadata_stays_forbidden(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "fleet.json"
            path.write_text(json.dumps(fleet_data()), encoding="utf-8")

            loaded = load_fleet(path)
            self.assertNotIn("_source", loaded)
            validate_fleet(loaded)

            persisted_internal_metadata = fleet_data()
            persisted_internal_metadata["_source"] = str(path)
            path.write_text(
                json.dumps(persisted_internal_metadata), encoding="utf-8"
            )
            with self.assertRaisesRegex(ValueError, "unsupported fields"):
                load_fleet(path)

    def test_config_host_rejects_direct_destination_overrides(self):
        cases = {
            "user": "root",
            "port": 2222,
            "identity_file": "~/.ssh/edge-a",
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                fleet = fleet_data()
                fleet["hosts"][0]["ssh"] = {
                    "config_host": "edge-config",
                    field: value,
                }
                with self.assertRaisesRegex(ValueError, "cannot be combined"):
                    validate_fleet(fleet)
                with self.assertRaisesRegex(ValueError, "cannot be combined"):
                    ssh_invocation(fleet["hosts"][0])

    def test_config_host_allows_null_placeholders_and_password_environment(self):
        fleet = fleet_data()
        fleet["hosts"][0]["ssh"] = {
            "config_host": "edge-config",
            "user": None,
            "identity_file": None,
            "password_env": "NETOPS_TEST_SSH_PASSWORD",
        }
        validate_fleet(fleet)

        with patch.dict(
            os.environ, {"NETOPS_TEST_SSH_PASSWORD": "secret-value"}, clear=False
        ):
            command, environment = ssh_invocation(fleet["hosts"][0])

        self.assertEqual(command[:3], ["sshpass", "-e", "ssh"])
        self.assertEqual(command[-1], "edge-config")
        self.assertNotIn("-p", command)
        self.assertNotIn("-i", command)
        self.assertEqual(environment["SSHPASS"], "secret-value")
        self.assertTrue(set(environment) <= {"SSHPASS", *fleet_module.TRANSPORT_ENVIRONMENT_KEYS})

    def test_direct_mode_ignores_ssh_config_redirection(self):
        host = fleet_data()["hosts"][0]
        command, _ = ssh_invocation(host)

        self.assertIn("-F", command)
        self.assertEqual(command[command.index("-F") + 1], "none")
        self.assertIn(
            f"HostName={host['management']['address']}",
            command,
        )
        self.assertIn("ProxyCommand=none", command)
        self.assertIn("ProxyJump=none", command)

        alias_host = fleet_data()["hosts"][0]
        alias_host["ssh"] = {"config_host": "edge-config"}
        alias_command, _ = ssh_invocation(alias_host)
        self.assertNotIn("-F", alias_command)

    def test_fleet_schema_tracks_runtime_ssh_constraints(self):
        schema_path = Path(__file__).parents[1] / "schemas/fleet.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        ssh_schema = schema["properties"]["hosts"]["items"]["properties"]["ssh"]

        properties = ssh_schema["properties"]
        config_host = next(
            item
            for item in properties["config_host"]["anyOf"]
            if item.get("type") != "null"
        )
        user = next(
            item
            for item in properties["user"]["anyOf"]
            if item.get("type") != "null"
        )
        self.assertEqual(config_host["pattern"], SSH_ALIAS_RE.pattern)
        self.assertEqual(user["pattern"], SSH_USER_RE.pattern)

        exclusions = ssh_schema["allOf"][0]["then"]["not"]["anyOf"]
        excluded_fields = {item["required"][0] for item in exclusions}
        self.assertEqual(
            excluded_fields, set(SSH_CONFIG_HOST_CONFLICT_FIELDS)
        )
        self.assertNotIn("password_env", excluded_fields)

    def test_fleet_schema_preflight_rejects_runtime_incompatible_metadata(self):
        schema_path = Path(__file__).parents[1] / "schemas/fleet.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        reviewed_pattern = schema["$defs"]["reviewedText"]["pattern"]
        domain_patterns = [
            item["pattern"]
            for item in schema["$defs"]["domainName"]["allOf"]
            if "pattern" in item
        ]

        for unsafe in (
            "pass" + "word=do-not-persist",
            "Authorization: " + "Bearer " + "do-not-persist",
            "safe\u202eunsafe",
            "sk-proj-" + "A" * 48,
        ):
            with self.subTest(unsafe=unsafe):
                self.assertIsNone(re.fullmatch(reviewed_pattern, unsafe))
        for invalid_domain in ("192.0.2.9", "https://panel.example.test/"):
            with self.subTest(domain=invalid_domain):
                self.assertTrue(
                    any(
                        re.fullmatch(pattern, invalid_domain) is None
                        for pattern in domain_patterns
                    )
                )
        for valid_domain in ("edge.example.test", "例子.测试", "panel.example.test."):
            with self.subTest(domain=valid_domain):
                self.assertTrue(
                    all(
                        re.fullmatch(pattern, valid_domain) is not None
                        for pattern in domain_patterns
                    )
                )

    def test_fleet_rejects_invisible_controls_in_reviewed_references(self):
        for field in ("identity_file", "credential_reference"):
            with self.subTest(field=field):
                fleet = fleet_data()
                fleet["hosts"][0]["ssh"][field] = "safe\u202eexe.txt"
                with self.assertRaisesRegex(ValueError, "control characters"):
                    validate_fleet(fleet)

    def test_fleet_rejects_secret_material_in_persisted_metadata(self):
        mutations = {
            "panel reference": lambda host: host["management"].__setitem__(
                "panel_reference",
                "https://" + "user" + ":" + "secret" + "@example.test/",
            ),
            "role": lambda host: host.__setitem__(
                "role", "pass" + "word=do-not-persist"
            ),
            "label value": lambda host: host.__setitem__(
                "labels", {"notes": "Authorization: " + "Bearer " + "do-not-persist"}
            ),
            "authorization label": lambda host: host.__setitem__(
                "labels", {"authorization": "Bearer " + "do-not-persist"}
            ),
            "credential URI": lambda host: host["ssh"].__setitem__(
                "credential_reference", "ss" + "://" + "opaque-secret"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                fleet = fleet_data()
                mutate(fleet["hosts"][0])
                with self.assertRaisesRegex(ValueError, "secret|credentials"):
                    validate_fleet(fleet)

    def test_every_persisted_network_or_ssh_token_receives_secret_review(self):
        openai_token = "sk-proj-" + "a" * 40
        aws_token = "AKIA" + "A" * 16
        mutations = {
            "alias": lambda host: host.__setitem__("alias", openai_token),
            "management address": lambda host: host["management"].__setitem__(
                "address", openai_token
            ),
            "config host": lambda host: host["ssh"].__setitem__(
                "config_host", openai_token
            ),
            "ssh user": lambda host: host["ssh"].__setitem__("user", aws_token),
            "service": lambda host: host.__setitem__(
                "expected_services", [openai_token]
            ),
            "password environment": lambda host: host["ssh"].__setitem__(
                "password_env", "AKIA" + "A" * 16
            ),
            "uuid address": lambda host: host["management"].__setitem__(
                "address", "123e4567-e89b-42d3-a456-426614174000"
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                fleet = fleet_data()
                mutate(fleet["hosts"][0])
                with self.assertRaisesRegex(ValueError, "secret|credential"):
                    validate_fleet(fleet)

    def test_direct_ssh_invocation_rejects_credential_shaped_destinations(self):
        token = "sk-proj-" + "A" * 48
        for field in ("management", "config_host"):
            with self.subTest(field=field):
                host = fleet_data()["hosts"][0]
                if field == "management":
                    host["management"]["address"] = token
                else:
                    host["ssh"] = {"config_host": token}
                with self.assertRaisesRegex(ValueError, "secret|credential"):
                    ssh_invocation(host)

    def test_fleet_domain_and_service_metadata_is_bounded_and_typed(self):
        mutations = {
            "IP in domain list": lambda host: host["domains"]["ipv4"].append(
                "192.0.2.9"
            ),
            "URL in domain list": lambda host: host["domains"]["panel"].append(
                "https://panel.example.test/"
            ),
            "duplicate domain": lambda host: host["domains"].__setitem__(
                "ipv4", ["edge.example.test", "edge.example.test"]
            ),
            "unsafe service": lambda host: host.__setitem__(
                "expected_services", ["ssh\nforged"]
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                fleet = fleet_data()
                mutate(fleet["hosts"][0])
                with self.assertRaises(ValueError):
                    validate_fleet(fleet)

        valid = fleet_data()
        valid["hosts"][0]["domains"] = {
            "ipv4": ["edge4.example.test"],
            "ipv6": ["例子.测试"],
            "panel": ["panel.example.test."],
        }
        valid["hosts"][0]["expected_services"] = ["ssh", "x-ui.service"]
        validate_fleet(valid)


if __name__ == "__main__":
    unittest.main()
