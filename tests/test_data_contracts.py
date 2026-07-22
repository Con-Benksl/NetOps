import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from netops_core.bundle import export_bundle, inspect_bundle
from netops_core import bundle as bundle_module
from netops_core import models
from netops_core.models import (
    DiagnosticBundle,
    Observation,
    load_bundle,
    write_bundle,
    write_json_atomic,
)
from netops_core.redaction import Redactor


class DataContractTests(unittest.TestCase):
    def _valid_data(self) -> dict:
        return DiagnosticBundle(
            mode="node",
            vantage_points=["test"],
            observations=[
                Observation(
                    vantage_point="test",
                    segment="destination",
                    probe="http-head",
                    status="ok",
                )
            ],
        ).finish().to_dict()

    @unittest.skipIf(os.name == "nt", "symlink creation is not portable on Windows")
    def test_atomic_json_write_replaces_final_symlink_without_following_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protected = root / "protected.json"
            protected.write_text("sentinel", encoding="utf-8")
            destination = root / "output.json"
            destination.symlink_to(protected)

            write_json_atomic(destination, {"safe": True})

            self.assertEqual(protected.read_text(encoding="utf-8"), "sentinel")
            self.assertFalse(destination.is_symlink())
            self.assertEqual(json.loads(destination.read_text(encoding="utf-8")), {"safe": True})

    def test_recursive_redaction_understands_keys_headers_and_urls(self):
        secret_values = {
            "password": "password-value",
            "api_key": "api-key-value",
            "accessToken": "camel-token-value",
            "Authorization": "Bearer " + "authorization-value",
            "nested": {
                "headers": {
                    "Set-Cookie": "session=cookie-value",
                    "Proxy-Authorization": "Basic proxy-value",
                    "Content-Type": "application/json",
                },
                "header_pairs": [
                    {"name": "Authorization", "value": "object-header-value"},
                    ["Set-Cookie", "list-header-value"],
                    {"key": "Authorization", "val": "Basic alternate-field-secret"},
                    {"name": "Cookie", "payload": "session=payload-secret"},
                    {"header": "X-Api-Key", "data": "short-header-secret"},
                    {
                        "name": "Content-Type",
                        "header": "Authorization",
                        "payload": "Basic multi-name-secret",
                    },
                    {
                        "key": "Content-Type",
                        "name": "Cookie",
                        "payload": "session=second-name-secret",
                    },
                    {"name": "Content-Type", "value": "text/plain"},
                ],
                "url": (
                    "https://"
                    + "user"
                    + ":"
                    + "user-password"
                    + "@example.invalid/path?"
                    "token=query-value&safe=visible#"
                    "access_" + "token=fragment-value&fragment_safe=visible"
                ),
                "header_dump": (
                    "HTTP/1.1 200 OK\r\n"
                    "Set-Cookie: session=header-cookie-value\r\n"
                    "Content-Type: text/plain\r\n"
                ),
                "command": (
                    "curl -H 'Authorization: " + "Bearer " + "inline-header-value' "
                    "https://example.invalid/"
                ),
                "encoded_node": "vmess" + "://" + "eyJpZCI6InNlY3JldCJ9",
                "known_token": "ghp_" + "A" * 36,
                "malformed_url": (
                    "http://" + "bad-user:bad-pass@example.invalid:notaport/path"
                ),
            },
        }

        redactor = Redactor(include_network_identifiers=True)
        redacted = redactor.value(secret_values)
        serialized = json.dumps(redacted, sort_keys=True)

        for secret in (
            "password-value",
            "api-key-value",
            "camel-token-value",
            "authorization-value",
            "cookie-value",
            "proxy-value",
            "user-password",
            "query-value",
            "fragment-value",
            "header-cookie-value",
            "inline-header-value",
            "object-header-value",
            "list-header-value",
            "alternate-field-secret",
            "payload-secret",
            "short-header-secret",
            "multi-name-secret",
            "second-name-secret",
            "eyJpZCI6InNlY3JldCJ9",
            "ghp_" + "A" * 36,
            "bad-user",
            "bad-pass",
        ):
            self.assertNotIn(secret, serialized)
        self.assertNotIn("Set-Cookie", redacted["nested"]["headers"])
        self.assertNotIn("Proxy-Authorization", redacted["nested"]["headers"])
        self.assertEqual(
            redacted["nested"]["headers"]["Content-Type"], "application/json"
        )
        self.assertEqual(
            redacted["nested"]["header_pairs"],
            [{"name": "Content-Type", "value": "text/plain"}],
        )
        self.assertIn("safe=visible", redacted["nested"]["url"])
        self.assertIn("node-link", redactor.actions)
        self.assertTrue({"known-token", "secret-key"} & redactor.actions)
        self.assertIn("malformed-url", redactor.actions)

    def test_common_provider_credentials_are_redacted_in_values_and_mapping_keys(self):
        tokens = [
            "sk-proj-" + "A" * 48,
            "AKIA" + "B" * 16,
            "xoxb-" + "1234567890-ABCDEFGHIJ",
            "glpat-" + "C" * 24,
            "sk_live_" + "D" * 24,
            "AIza" + "E" * 35,
            "npm_" + "F" * 36,
            "hf_" + "G" * 24,
        ]
        redactor = Redactor(include_network_identifiers=True)
        redacted = redactor.value(
            {"message": " ".join(tokens), tokens[0]: "mapping-key"}
        )
        serialized = json.dumps(redacted, sort_keys=True)

        for token in tokens:
            self.assertNotIn(token, serialized)
        self.assertIn("known-token", redactor.actions)

    def test_jwt_google_oauth_putty_and_basic_credentials_are_removed(self):
        jwt = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0."
            "c2lnbmF0dXJlX3ZhbHVl"
        )
        oauth = "ya29." + "A" * 32
        basic = "Basic QWxhZGRpbjpPcGVuU2VzYW1l"
        putty = (
            "PuTTY-User-Key-File-3: ssh-rsa\n"
            "Encryption: none\nComment: test\nPublic-Lines: 1\nPUBLIC\n"
            "Private-Lines: 1\nSUPERPRIVATE\nPrivate-MAC: abcdef\n"
        )
        redactor = Redactor(include_network_identifiers=True)
        redacted = redactor.value(
            {"message": f"{jwt}\n{oauth}\n{basic}\n{putty}"}
        )
        serialized = json.dumps(redacted)
        for credential in (jwt, oauth, "QWxhZGRpbjpPcGVuU2VzYW1l", "SUPERPRIVATE"):
            self.assertNotIn(credential, serialized)
        self.assertTrue({"known-token", "private-key", "basic-auth"} <= redactor.actions)

        for short_basic in ("Basic YTpi", "Basic dTpw", "Basic Og=="):
            short = Redactor(include_network_identifiers=True)
            self.assertEqual(short.text(short_basic), "Basic <redacted>")
            self.assertIn("basic-auth", short.actions)

        for harmless in ("Basic connectivity", "Basic authentication", "basic networking"):
            clean = Redactor(include_network_identifiers=True)
            self.assertEqual(clean.text(harmless), harmless)
            self.assertFalse(clean.actions)

        bundle = DiagnosticBundle(
            mode="node",
            vantage_points=["local"],
            observations=[
                Observation(
                    vantage_point="local",
                    segment="destination",
                    probe="sample",
                    status="unknown",
                    evidence={"message": basic},
                )
            ],
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = write_bundle(Path(temporary) / "bundle.json", bundle)
            raw = path.read_text(encoding="utf-8")
            inspect_bundle(path)
        self.assertNotIn("QWxhZGRpbjpPcGVuU2VzYW1l", raw)

    def test_standard_cloud_and_command_credentials_are_removed(self):
        values = {
            "AWS_SECRET_ACCESS_KEY": "A" * 40,
            "secret_access_key": "B" * 40,
            "AccountKey": "QWxhZGRpbjpPcGVuU2VzYW1l",
            "SharedAccessKey": "U2hhcmVkQWNjZXNzS2V5VmFsdWU=",
            "SharedAccessSignature": "sv=2026-01-01&sig=TopSecretSignature",
            "AZURE_STORAGE_KEY": "QXp1cmVTdG9yYWdlS2V5VmFsdWU=",
            "SSHPASS": "hunter2",
            "PGPASSWORD": "postgres-secret",
            "MYSQL_PWD": "mysql-secret",
            "commands": [
                "sshpass -p hunter2 ssh host",
                "sshpass -phunter2 ssh host",
                "sshpass -p'hunter2' ssh host",
                "curl -u alice:hunter2 https://example.invalid",
                "curl --user=alice:hunter2 https://example.invalid",
                "curl -ualice:hunter2 https://example.invalid",
                "curl --proxy-user alice:proxypass https://example.invalid",
                "mysql -uroot -pmysql-secret",
                "http --auth alice:http-secret https://example.invalid",
            ],
        }

        redactor = Redactor(include_network_identifiers=True)
        redacted = redactor.value(values)
        rendered = json.dumps(redacted, sort_keys=True)

        for secret in (
            "A" * 40,
            "B" * 40,
            "QWxhZGRpbjpPcGVuU2VzYW1l",
            "U2hhcmVkQWNjZXNzS2V5VmFsdWU=",
            "TopSecretSignature",
            "QXp1cmVTdG9yYWdlS2V5VmFsdWU=",
            "hunter2",
            "postgres-secret",
            "mysql-secret",
            "proxypass",
            "http-secret",
        ):
            self.assertNotIn(secret, rendered)
        self.assertIn("<redacted>", rendered)

        for record in (
            {"field": "Authorization", "value": "FieldHeaderSecret"},
            {"name": ["X-Foo", "Authorization"], "value": "ListHeaderSecret"},
        ):
            self.assertIsNone(redactor.value(record))

        azure_text = redactor.text(
            "SharedAccess" + "Signature=sv=2026-01-01&sig=TopSecretSignature"
        )
        self.assertNotIn("TopSecretSignature", azure_text)

    def test_control_character_key_collisions_cannot_hide_credentials(self):
        secret = "UltraSecretValue"
        header_secret = "UltraHeaderSecret"
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.environment = {
            "collision": {
                "password": "decoy",
                "pass\u200bword": secret,
            },
            "header_records": [
                {
                    "name": "X-Foo",
                    "na\u200bme": "Authorization",
                    "value": header_secret,
                }
            ],
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            local = write_bundle(root / "bundle.json", bundle)
            local_raw = local.read_text(encoding="utf-8")
            archive = export_bundle(
                local,
                root / "support.zip",
                include_network_identifiers=True,
            )
            inspect_bundle(archive)
            with zipfile.ZipFile(archive) as handle:
                archive_raw = handle.read("bundle.json").decode("utf-8")

        for raw in (local_raw, archive_raw):
            self.assertNotIn(secret, raw)
            self.assertNotIn(header_secret, raw)

    def test_truncated_private_key_and_flat_header_arrays_are_removed(self):
        key_material = (
            "-----BE" + "GIN OPENSSH PRIVATE KEY-----\n"
            "SUPERSECRETTRUNCATED"
        )
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.environment = {
            "message": key_material,
            "rawHeaders": [
                "Content-Type",
                "text/plain",
                "Cookie",
                "session=abc123",
            ],
            "parallel": {
                "headerNames": ["Cookie"],
                "values": ["session=def456"],
            },
        }

        with tempfile.TemporaryDirectory() as temporary:
            path = write_bundle(Path(temporary) / "bundle.json", bundle)
            raw = path.read_text(encoding="utf-8")

        for secret in (
            "SUPERSECRETTRUNCATED",
            "session=abc123",
            "session=def456",
        ):
            self.assertNotIn(secret, raw)

    def test_home_redaction_respects_path_component_boundaries(self):
        redactor = Redactor(include_network_identifiers=True)
        redactor.home = "/Users/alice"
        values = [
            "/Users/alice/private",
            "/Users/alice smith/private",
            "/Users/alice-other/private",
            "/Users/alice2/private",
            "/Users/Other Person",
            "/home/other user",
            r"C:\Users\Other Person",
        ]

        rendered = json.dumps(redactor.value(values))

        for name in (
            "alice",
            "alice smith",
            "alice-other",
            "alice2",
            "Other Person",
            "other user",
        ):
            self.assertNotIn(name, rendered)

    def test_explicit_remote_identity_fields_are_pseudonymized(self):
        redactor = Redactor(include_network_identifiers=False)
        redacted = redactor.value(
            {
                "host_alias": "prod_vps",
                "config_host": "ssh_alias",
                "management_reference": "internalhost",
                "management_address": "internalhost",
                "ssh_host": "internalhost",
                "remote_address": "internalhost",
                "target_host": "internalhost",
                "server_alias": "internalhost",
                "panel_reference": "internalhost",
                "hоst": "internalhost",
                "РАSSWORD": "UppercaseConfusableSecret",
            }
        )

        rendered = json.dumps(redacted, sort_keys=True)
        self.assertNotIn("prod_vps", rendered)
        self.assertNotIn("ssh_alias", rendered)
        self.assertNotIn("internalhost", rendered)
        self.assertNotIn("UppercaseConfusableSecret", rendered)

        contextual = redactor.text(
            "host=internal_host; connected to 服务器; ssh root@internal_host; "
            r"scp internal_host:/etc/config; \\服务器\share"
        )
        self.assertNotIn("internal_host", contextual)
        self.assertNotIn("服务器", contextual)

    def test_semantic_secret_keys_are_redacted_without_hiding_token_count(self):
        payload = {
            "db_password": "database-secret",
            "ssh_password": "ssh-secret",
            "id_token": "identity-secret",
            "auth": "Bearer " + "auth-secret",
            "authorization_header": "Bearer " + "header-secret",
            "token_count": 17,
            "message": "db_password=text-secret token_count=17",
        }
        redactor = Redactor(include_network_identifiers=True)
        redacted = redactor.value(payload)
        serialized = json.dumps(redacted, sort_keys=True)

        for secret in (
            "database-secret",
            "ssh-secret",
            "identity-secret",
            "auth-secret",
            "header-secret",
            "text-secret",
        ):
            self.assertNotIn(secret, serialized)
        self.assertEqual(redacted["token_count"], 17)
        self.assertIn("token_count=17", redacted["message"])
        self.assertEqual(redactor.value(redacted), redacted)

        url_redactor = Redactor(include_network_identifiers=False)
        once = url_redactor.value(
            {"endpoint": "https://internalhost/path?id_token=url-secret"}
        )
        self.assertEqual(url_redactor.value(once), once)
        self.assertNotIn("internalhost", json.dumps(once))
        self.assertNotIn("url-secret", json.dumps(once))

        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.observations.append(
            Observation(
                vantage_point="test",
                segment="destination",
                probe="test",
                status="failed",
                evidence=payload,
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            persisted = write_bundle(Path(temporary) / "bundle.json", bundle)
            persisted_text = persisted.read_text(encoding="utf-8")
        for secret in (
            "database-secret",
            "ssh-secret",
            "identity-secret",
            "auth-secret",
            "header-secret",
            "text-secret",
        ):
            self.assertNotIn(secret, persisted_text)
        self.assertIn('"token_count": 17', persisted_text)

    def test_relative_http_path_credentials_never_reach_local_or_support_bundles(self):
        query_secret = "local-" + "query-secret-123"
        fragment_secret = "local-" + "fragment-secret-456"
        relative_path = (
            "/api?key="
            + query_secret
            + "&safe=visible#x-amz-signature="
            + fragment_secret
        )
        slack_secret = "opaque-" + "slack-path-secret"
        discord_secret = "opaque-" + "discord-path-secret"
        telegram_secret = "ABCdefghijklmnop"
        encoded_telegram_secret = "QRSTuvwxyzABCDEFGH"
        userinfo_secret = "relative-" + "userinfo-secret"
        encoded_absolute_secret = "encoded-" + "absolute-userinfo-secret"
        encoded_relative_secret = "encoded-" + "relative-userinfo-secret"
        encoded_assignment_secret = "encoded-" + "assignment-secret"
        encoded_target_secret = "encoded-" + "whole-target-secret"
        sensitive_paths = [
            relative_path,
            "/services/T123/B456/" + slack_secret,
            "/api/webhooks/123456/" + discord_secret,
            "/bot123456:" + telegram_secret + "/getMe",
            "/bot987654%3A" + encoded_telegram_secret + "/getMe",
            "//alice:" + userinfo_secret + "@example.invalid/private",
            (
                "/?next=https%3A%2F%2Falice%3A"
                + encoded_absolute_secret
                + "%40example.invalid%2Fprivate"
            ),
            (
                "/?continue=%2F%2Falice%3A"
                + encoded_relative_secret
                + "%40example.invalid%2Fprivate"
            ),
            "/?safe=token%3D" + encoded_assignment_secret,
            "/%3Ftoken%3D" + encoded_target_secret,
        ]
        secrets = (
            query_secret,
            fragment_secret,
            slack_secret,
            discord_secret,
            telegram_secret,
            encoded_telegram_secret,
            userinfo_secret,
            encoded_absolute_secret,
            encoded_relative_secret,
            encoded_assignment_secret,
            encoded_target_secret,
        )
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.targets = [
            {
                "target": "example.invalid",
                "port": 443,
                "protocol": "tcp",
                "http": True,
                "path": current_path,
            }
            for current_path in sensitive_paths
        ]
        bundle.observations = [
            Observation(
                vantage_point="test",
                segment="destination",
                probe="http-head",
                status="unknown",
                target="https://example.invalid" + current_path,
            )
            for current_path in sensitive_paths
        ]
        for current_path in sensitive_paths:
            self.assertIsNotNone(
                bundle_module._residual_credential_path({"path": current_path})
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            local_path = write_bundle(root / "bundle.json", bundle)
            local_text = local_path.read_text(encoding="utf-8")
            for secret in secrets:
                self.assertNotIn(secret, local_text)
            self.assertIn("safe=visible", local_text)
            self.assertIn("url-query-secret", local_text)
            self.assertIn("url-fragment-secret", local_text)
            self.assertIn("url-path-secret", local_text)
            self.assertIn("url-credentials", local_text)

            support_path = export_bundle(local_path, root / "support.zip")
            with zipfile.ZipFile(support_path) as archive:
                support_text = archive.read("bundle.json").decode("utf-8")
            for secret in secrets:
                self.assertNotIn(secret, support_text)
            self.assertIn("safe=visible", support_text)

        redactor = Redactor(include_network_identifiers=True)
        legacy = redactor.text("/api?safe=visible;code=" + query_secret)
        self.assertNotIn(query_secret, legacy)
        self.assertIn("safe=visible", legacy)

    def test_generic_api_bearer_and_cross_platform_home_paths_are_redacted(self):
        redactor = Redactor(include_network_identifiers=True)
        redactor.home = r"C:\Users\Alice"
        source = (
            "api" + "_key=" + "api-secret API-" + "KEY: second-secret "
            "Bearer " + "bare-token-value "
            r"C:/Users/Alice/private/config.json "
            r"c:\users\alice\private\key "
            "/home/bob/.ssh/config /root/.ssh/config "
            "/Users/Other Person/private/key /home/other user/private/key "
            r"C:\Users\Other Person\private\key"
        )

        redacted = redactor.text(source)

        for secret in (
            "api-secret",
            "second-secret",
            "bare-token-value",
            "Alice",
            "alice",
            "bob",
            "Other Person",
            "other user",
            "/root",
        ):
            self.assertNotIn(secret, redacted)
        self.assertIn("api-key", redactor.actions)
        self.assertIn("bearer-token", redactor.actions)
        self.assertIn("home-path", redactor.actions)

    def test_command_and_unc_single_label_hosts_are_redacted(self):
        source = (
            r"\\privatehost\share\folder"
            " ssh root@internalhost"
            " scp backuphost:/etc/config ."
            " rsync user@archivehost:/tmp/a ."
        )
        redactor = Redactor(include_network_identifiers=False)
        redacted = redactor.text(source)

        for hostname in ("privatehost", "internalhost", "backuphost", "archivehost"):
            self.assertNotIn(hostname, redacted)
        self.assertIn("hostname", redactor.actions)
        self.assertIn("<network-command-redacted>", redacted)
        self.assertIn("network-command", redactor.actions)

        bundle = DiagnosticBundle(
            mode="node",
            vantage_points=["local"],
            environment={"command_sample": source},
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            persisted = write_bundle(root / "source.json", bundle)
            archive = export_bundle(persisted, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                raw = handle.read("bundle.json").decode("utf-8")
            inspect_bundle(archive)
        for hostname in ("privatehost", "internalhost", "backuphost", "archivehost"):
            self.assertNotIn(hostname, raw)

    def test_uuid_redaction_preserves_only_bundle_contract_identifiers_end_to_end(self):
        free_text_uuids = [
            f"00000000-0000-{version}000-8000-{index:012x}"
            for index, version in enumerate("0123456789abcdef", start=1)
        ]
        root_run_id = "10000000-0000-7000-8000-000000000001"
        observation_id = "20000000-0000-8000-8000-000000000002"
        observation = Observation(
            vantage_point="local",
            segment="destination",
            probe="uuid-contract",
            status="failed",
            observation_id=observation_id,
            evidence={
                "nested": {
                    "run_id": free_text_uuids[0],
                    "plan_id": free_text_uuids[1],
                    "metadata": {"evidence": [free_text_uuids[2]]},
                }
            },
        )
        bundle = DiagnosticBundle(
            mode="node",
            vantage_points=["local"],
            run_id=root_run_id,
            environment={
                "message": " ".join(free_text_uuids),
                "nested": {
                    "run_id": free_text_uuids[3],
                    "plan_id": free_text_uuids[4],
                    "metadata": {"evidence": [free_text_uuids[5]]},
                },
            },
            observations=[observation],
            path_segments=[
                {
                    "name": "destination",
                    "status": "failed",
                    "evidence": [observation_id],
                    "limitations": ["single observation"],
                }
            ],
            findings=[
                {
                    "severity": "error",
                    "segment": "destination",
                    "title": "UUID contract regression",
                    "evidence": [observation_id],
                    "confidence": "medium",
                }
            ],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            local_data = json.loads(source.read_text(encoding="utf-8"))
            archive = export_bundle(source, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                archive_data = json.loads(handle.read("bundle.json"))
                archive_report = handle.read("report.md").decode("utf-8")
            inspected, inspected_report = inspect_bundle(archive)

        for data in (local_data, archive_data):
            serialized = json.dumps(data, sort_keys=True)
            self.assertEqual(data["run_id"], root_run_id)
            self.assertEqual(
                data["observations"][0]["observation_id"], observation_id
            )
            self.assertEqual(data["findings"][0]["evidence"], [observation_id])
            self.assertEqual(
                data["path_segments"][0]["evidence"], [observation_id]
            )
            for identifier in free_text_uuids:
                self.assertNotIn(identifier, serialized)
            nested = data["observations"][0]["evidence"]["nested"]
            self.assertNotEqual(nested["run_id"], free_text_uuids[0])
            self.assertNotEqual(nested["plan_id"], free_text_uuids[1])
            self.assertNotEqual(
                nested["metadata"]["evidence"][0], free_text_uuids[2]
            )

        self.assertEqual(inspected.run_id, root_run_id)
        self.assertEqual(inspected.observations[0].observation_id, observation_id)
        self.assertEqual(inspected.findings[0]["evidence"], [observation_id])
        self.assertEqual(inspected.path_segments[0]["evidence"], [observation_id])
        self.assertEqual(archive_report, inspected_report)
        for identifier in free_text_uuids:
            self.assertNotIn(identifier, archive_report)

    def test_support_export_redacts_commands_credentials_and_unusual_network_ids(self):
        commands = [
            "ssh -J jump.private -L 127.0.0.1:8443:db.private:443 user@app.private",
            "scp -o ProxyJump=jump.private app.private:/srv/private ./copy",
            "tracert.exe route.private",
            (
                "powershell.exe -NoProfile -Command "
                "Test-NetConnection win.private -Port 443"
            ),
        ]
        credentials = [
            "client --password long-option-secret",
            "agent --api" + "-key=equals-option-secret",
            "password plain-space-secret",
            'token "quoted-space-secret"',
        ]
        identifiers = [
            "例子。测试",
            "::ffff:192.0.2.128",
            "010.000.000.001",
            "127.1",
            "aa:bb:cc:dd:ee:ff:00:11",
            "aabb.ccdd.eeff.0011",
        ]
        secrets = [
            "long-option-secret",
            "equals-option-secret",
            "plain-space-secret",
            "quoted-space-secret",
        ]
        observation = Observation(
            vantage_point="local",
            segment="destination",
            probe="network-privacy",
            status="unknown",
            target=identifiers[0],
            protocol="tcp",
            address_family="IPv6",
            limitations=["synthetic privacy fixture"],
        )
        bundle = DiagnosticBundle(
            mode="node",
            vantage_points=["local"],
            environment={
                "commands": commands,
                "samples": credentials,
                "network_text": " ".join(identifiers),
            },
            targets=[{"target": identifier} for identifier in identifiers],
            observations=[observation],
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            local_raw = source.read_text(encoding="utf-8")
            archive = export_bundle(source, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                archive_raw = handle.read("bundle.json").decode("utf-8")
                archive_report = handle.read("report.md").decode("utf-8")
                manifest = json.loads(handle.read("manifest.json"))
            inspected, inspected_report = inspect_bundle(archive)

        for secret in secrets:
            self.assertNotIn(secret, local_raw)
            self.assertNotIn(secret, archive_raw)
            self.assertNotIn(secret, archive_report)
        for command in commands:
            self.assertNotIn(command, archive_raw)
        for sensitive_fragment in (
            "jump.private",
            "db.private",
            "app.private",
            "route.private",
            "win.private",
            "ProxyJump",
            "Test-NetConnection",
        ):
            self.assertNotIn(sensitive_fragment, archive_raw)
            self.assertNotIn(sensitive_fragment, archive_report)
        self.assertEqual(
            inspected.environment["commands"],
            ["<network-command-redacted>"] * len(commands),
        )
        for identifier in [*identifiers, "例子.测试"]:
            self.assertNotIn(identifier, archive_raw)
            self.assertNotIn(identifier, archive_report)
        self.assertEqual(archive_report, inspected_report)
        self.assertIn("network-command", manifest["redactions"])
        self.assertIn("command-credential", inspected.redactions)
        self.assertIn("unicode-normalization", inspected.redactions)
        self.assertIn("ip-address", inspected.redactions)
        self.assertIn("mac-address", inspected.redactions)

    def test_write_bundle_removes_sensitive_headers_and_values_before_persistence(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.targets = [{"target": "example.invalid", "protocol": "tcp"}]
        bundle.observations.append(
            Observation(
                vantage_point="local",
                segment="destination",
                probe="curl-via-proxy",
                status="ok",
                target="example.invalid",
                evidence={
                    "headers": {
                        "Set-Cookie": "session=persisted-cookie",
                        "Authorization": "Bearer " + "persisted-token",
                        "Content-Type": "text/plain",
                    },
                    "header_pairs": [
                        {"name": "Authorization", "value": "persisted-pair-token"},
                        ["Set-Cookie", "persisted-list-cookie"],
                    ],
                    "api_token": "persisted-api-token",
                },
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            path = write_bundle(Path(temporary) / "bundle.json", bundle)
            raw = path.read_text(encoding="utf-8")
            loaded = load_bundle(path)

        self.assertNotIn("persisted-cookie", raw)
        self.assertNotIn("persisted-token", raw)
        self.assertNotIn("persisted-api-token", raw)
        self.assertNotIn("persisted-pair-token", raw)
        self.assertNotIn("persisted-list-cookie", raw)
        headers = loaded.observations[0].evidence["headers"]
        self.assertNotIn("Set-Cookie", headers)
        self.assertNotIn("Authorization", headers)
        self.assertEqual(headers["Content-Type"], "text/plain")
        self.assertEqual(loaded.targets[0]["target"], "example.invalid")
        self.assertIn("sensitive-header", loaded.redactions)
        self.assertNotIn(
            "persisted-token",
            json.dumps(bundle.to_dict(), sort_keys=True),
        )

    def test_terminal_controls_cannot_split_a_sensitive_header_name(self):
        redactor = Redactor(include_network_identifiers=True)
        value = redactor.text(
            "Autho\x1b[31mrization: " + "Bearer " + "divided-value\x1b[0m\u202e"
        )
        self.assertNotIn("divided-value", value)
        self.assertNotIn("\x1b", value)
        self.assertNotIn("\u202e", value)
        self.assertIn("sensitive-header", redactor.actions)
        self.assertIn("terminal-control", redactor.actions)

    def test_write_bundle_redacts_header_object_casing_json_headers_and_node_uris(self):
        node_links = [
            "ssr" + "://" + "SSR-OPAQUE-SECRET",
            "hysteria" + "://" + "HYSTERIA-OPAQUE-SECRET",
            "tuic" + "://" + "user" + ":" + "TUIC-SECRET@example.test:443",
            "wireguard" + "://" + "WIREGUARD-PRIVATE-CONFIG",
            "anytls" + "://" + "ANYTLS-OPAQUE-SECRET",
        ]
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.observations.append(
            Observation(
                vantage_point="local",
                segment="destination",
                probe="header-and-node-sample",
                status="ok",
                evidence={
                    "header_pairs": [
                        {
                            "Name": "Authorization",
                            "Value": "Bearer " + "CASED-HEADER-SECRET",
                        }
                    ],
                    "stdout": (
                        'response headers: {"Authorization": '
                        '"Bearer ' + 'JSON-HEADER-SECRET", '
                        '"Content-Type": "application/json"}; '
                        'metadata: {Authorization: "Bearer ' + 'OBJECT-HEADER-SECRET"}'
                    ),
                    "node_links": node_links,
                },
            )
        )

        with tempfile.TemporaryDirectory() as temporary:
            path = write_bundle(Path(temporary) / "bundle.json", bundle)
            raw = path.read_text(encoding="utf-8")
            persisted = load_bundle(path)

        for secret in (
            "CASED-HEADER-SECRET",
            "JSON-HEADER-SECRET",
            "OBJECT-HEADER-SECRET",
            "SSR-OPAQUE-SECRET",
            "HYSTERIA-OPAQUE-SECRET",
            "TUIC-SECRET",
            "WIREGUARD-PRIVATE-CONFIG",
            "ANYTLS-OPAQUE-SECRET",
        ):
            self.assertNotIn(secret, raw)
        evidence = persisted.observations[0].evidence
        self.assertEqual(evidence["header_pairs"], [])
        self.assertTrue(
            all(value == "<node-link-redacted>" for value in evidence["node_links"])
        )
        self.assertIn("sensitive-header", persisted.redactions)
        self.assertIn("node-link", persisted.redactions)

    def test_bundle_contract_rejects_illegal_values_types_ids_and_timestamps(self):
        mutations = {
            "status": lambda data: data["observations"][0].__setitem__(
                "status", "banana"
            ),
            "confidence": lambda data: data["observations"][0].__setitem__(
                "confidence", "certain"
            ),
            "path_segments": lambda data: data.__setitem__("path_segments", "not-a-list"),
            "run_id": lambda data: data.__setitem__("run_id", "not-a-uuid"),
            "started_at": lambda data: data.__setitem__("started_at", "not-a-time"),
            "extra_property": lambda data: data.__setitem__("unexpected", True),
        }

        for name, mutate in mutations.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                data = self._valid_data()
                mutate(data)
                path = Path(temporary) / "invalid.json"
                path.write_text(json.dumps(data), encoding="utf-8")
                with self.assertRaises(ValueError):
                    load_bundle(path)

    def test_bundle_contract_rejects_excessive_depth_and_collection_size(self):
        deeply_nested: object = "leaf"
        for _ in range(models.MAX_BUNDLE_NESTING_DEPTH + 2):
            deeply_nested = [deeply_nested]
        deep_data = self._valid_data()
        deep_data["environment"] = {"nested": deeply_nested}
        with self.assertRaisesRegex(ValueError, "nesting depth"):
            models.validate_bundle_data(deep_data)

        wide_data = self._valid_data()
        wide_data["path_segments"] = [
            {"name": "dns", "status": "unknown"}
            for _ in range(models.MAX_BUNDLE_COLLECTION_ITEMS + 1)
        ]
        with self.assertRaisesRegex(ValueError, "too many items"):
            models.validate_bundle_data(wide_data)

    def test_write_bundle_rejects_invalid_in_memory_dataclass(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.observations.append(
            Observation(
                vantage_point="test",
                segment="destination",
                probe="test",
                status="banana",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ValueError):
                write_bundle(Path(temporary) / "invalid.json", bundle)

    def test_archive_inspection_validates_manifest_and_embedded_bundle(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"]).finish()
        with tempfile.TemporaryDirectory() as temporary:
            source = write_bundle(Path(temporary) / "source.json", bundle)
            archive = export_bundle(source, Path(temporary) / "valid.zip")

            with zipfile.ZipFile(archive) as handle:
                members = {name: handle.read(name) for name in handle.namelist()}

            invalid_bundle = json.loads(members["bundle.json"])
            invalid_bundle["path_segments"] = "not-a-list"
            members["bundle.json"] = json.dumps(invalid_bundle).encode()
            manifest = json.loads(members["manifest.json"])
            import hashlib

            manifest["files"]["bundle.json"] = hashlib.sha256(
                members["bundle.json"]
            ).hexdigest()
            members["manifest.json"] = json.dumps(manifest).encode()
            bad_bundle_archive = Path(temporary) / "bad-bundle.zip"
            with zipfile.ZipFile(bad_bundle_archive, "w") as handle:
                for name, content in members.items():
                    handle.writestr(name, content)
            with self.assertRaises(ValueError):
                inspect_bundle(bad_bundle_archive)

            manifest["network_identifiers_included"] = "yes"
            members["manifest.json"] = json.dumps(manifest).encode()
            bad_manifest_archive = Path(temporary) / "bad-manifest.zip"
            with zipfile.ZipFile(bad_manifest_archive, "w") as handle:
                for name, content in members.items():
                    handle.writestr(name, content)
            with self.assertRaises(ValueError):
                inspect_bundle(bad_manifest_archive)

    def test_archive_inspector_independently_rejects_a_forged_provider_token(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"]).finish()
        token = "sk-proj-" + "Z" * 48
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(
                source,
                root / "valid.zip",
                include_network_identifiers=True,
            )
            with zipfile.ZipFile(archive) as handle:
                members = {name: handle.read(name) for name in handle.namelist()}

            embedded = json.loads(members["bundle.json"])
            embedded["environment"] = {"message": token}
            forged = DiagnosticBundle.from_dict(embedded)
            members["bundle.json"] = (
                json.dumps(embedded, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8")
            from netops_core.report import render_report

            members["report.md"] = render_report(forged).encode("utf-8")
            manifest = json.loads(members["manifest.json"])
            import hashlib

            manifest["files"]["bundle.json"] = hashlib.sha256(
                members["bundle.json"]
            ).hexdigest()
            manifest["files"]["report.md"] = hashlib.sha256(
                members["report.md"]
            ).hexdigest()
            members["manifest.json"] = (
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8")
            forged_archive = root / "forged-token.zip"
            with zipfile.ZipFile(forged_archive, "w") as handle:
                for name, content in members.items():
                    handle.writestr(name, content)

            with self.assertRaisesRegex(ValueError, "credential"):
                inspect_bundle(forged_archive)

    def test_explicit_network_identifier_opt_in_preserves_hostname(self):
        hostname = "internalhost"
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.environment = {"platform": {"hostname": hostname}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(
                source,
                root / "included.zip",
                include_network_identifiers=True,
            )
            with zipfile.ZipFile(archive) as handle:
                raw = handle.read("bundle.json").decode("utf-8")
        self.assertIn(hostname, raw)

    def test_archive_cannot_falsely_claim_network_identifiers_were_removed(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.targets = [{"target": "example.invalid", "port": 443}]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(source, root / "redacted.zip")
            with zipfile.ZipFile(archive) as handle:
                members = {name: handle.read(name) for name in handle.namelist()}

            embedded = json.loads(members["bundle.json"])
            embedded["targets"] = [{"target": "192.0.2.44", "port": 443}]
            forged = DiagnosticBundle.from_dict(embedded)
            members["bundle.json"] = (
                json.dumps(embedded, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8")
            from netops_core.report import render_report

            members["report.md"] = render_report(forged).encode("utf-8")
            manifest = json.loads(members["manifest.json"])
            import hashlib

            manifest["files"]["bundle.json"] = hashlib.sha256(
                members["bundle.json"]
            ).hexdigest()
            manifest["files"]["report.md"] = hashlib.sha256(
                members["report.md"]
            ).hexdigest()
            members["manifest.json"] = (
                json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
                + "\n"
            ).encode("utf-8")
            forged_archive = root / "forged-redaction-claim.zip"
            with zipfile.ZipFile(forged_archive, "w") as handle:
                for name, content in members.items():
                    handle.writestr(name, content)

            with self.assertRaisesRegex(ValueError, "still contains"):
                inspect_bundle(forged_archive)

    def test_support_archive_redacts_single_label_idn_punycode_and_mac(self):
        identifiers = [
            "internalhost",
            "xn--fsqu00a.xn--0zwm56d",
            "例子.测试",
            "aa:bb:cc:dd:ee:ff",
            "0011.2233.4455",
        ]
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.targets = [{"target": value} for value in identifiers]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(source, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                raw = handle.read("bundle.json").decode("utf-8")
                manifest = json.loads(handle.read("manifest.json"))
            renamed = root / "support.data"
            renamed.write_bytes(archive.read_bytes())
            inspected, _ = inspect_bundle(renamed)

        for identifier in identifiers:
            self.assertNotIn(identifier, raw)
        self.assertIn('"target"', raw)
        self.assertFalse(manifest["network_identifiers_included"])
        self.assertEqual(len(inspected.targets), len(identifiers))

    def test_support_archive_redacts_identifiers_and_tokens_used_as_mapping_keys(self):
        hostname = "internalhost"
        address = "198.51.100.77"
        domain = "private.example.test"
        token = "gh" + "p_" + "A" * 24
        bundle = DiagnosticBundle(mode="node", vantage_points=[hostname])
        bundle.environment = {
            "latency_by_host": {
                address: "reachable",
                domain: "reachable",
                hostname: "reachable",
                token: "must-not-survive",
            }
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(source, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                raw = handle.read("bundle.json").decode("utf-8")
            inspect_bundle(archive)

        for secret in (hostname, address, domain, token):
            self.assertNotIn(secret, raw)

    def test_support_export_preserves_semantic_keys_outside_host_keyed_maps(self):
        bundle = DiagnosticBundle(
            mode="node",
            vantage_points=["local"],
            environment={
                "platform": {"system": "Linux", "release": "test"},
                "resources": {"cpu": 1},
            },
            observations=[
                Observation(
                    vantage_point="local",
                    segment="destination",
                    probe="sample",
                    status="unknown",
                    metrics={"count": 2, "total": 3},
                    evidence={"message": "ok", "answers": [], "requests": 1},
                )
            ],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(source, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                exported = json.loads(handle.read("bundle.json"))
            inspect_bundle(archive)

        self.assertEqual(
            exported["environment"]["platform"],
            {"system": "Linux", "release": "test"},
        )
        self.assertEqual(exported["environment"]["resources"], {"cpu": 1})
        self.assertEqual(exported["observations"][0]["metrics"], {"count": 2, "total": 3})
        self.assertEqual(
            exported["observations"][0]["evidence"],
            {"message": "ok", "answers": [], "requests": 1},
        )

    def test_support_archive_labels_are_consistent_only_within_one_archive(self):
        address = "10.23.45.67"
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.environment = {"sample_a": address, "sample_b": address}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            first = export_bundle(source, root / "first.zip")
            second = export_bundle(source, root / "second.zip")
            with zipfile.ZipFile(first) as handle:
                first_raw = handle.read("bundle.json").decode("utf-8")
            with zipfile.ZipFile(second) as handle:
                second_raw = handle.read("bundle.json").decode("utf-8")

        first_labels = re.findall(r"<ip-[0-9a-f]{12}>", first_raw)
        second_labels = re.findall(r"<ip-[0-9a-f]{12}>", second_raw)
        self.assertGreaterEqual(len(first_labels), 2)
        self.assertEqual(len(set(first_labels)), 1)
        self.assertEqual(len(set(second_labels)), 1)
        self.assertNotEqual(first_labels[0], second_labels[0])

    def test_open_evidence_mapping_keys_do_not_bypass_hostname_redaction(self):
        bundle = DiagnosticBundle(
            mode="node",
            vantage_points=["local"],
            observations=[
                Observation(
                    vantage_point="local",
                    segment="destination",
                    probe="sample",
                    status="unknown",
                    evidence={
                        "latency_by_host": {"server": {"duration_ms": 1}}
                    },
                )
            ],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(source, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                raw = handle.read("bundle.json").decode("utf-8")
            inspect_bundle(archive)

        self.assertNotIn('"server"', raw)

    def test_export_rejects_a_member_that_its_inspector_would_reject(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"]).finish()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            output = root / "too-large.zip"
            with patch(
                "netops_core.bundle.render_report",
                return_value="x" * (8 * 1024 * 1024 + 1),
            ):
                with self.assertRaisesRegex(ValueError, "report.md"):
                    export_bundle(source, output)
            self.assertFalse(output.exists())

    def test_inspector_rejects_oversized_container_before_parsing_zip_entries(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "oversized.zip"
            with source.open("wb") as handle:
                handle.write(b"PK\x03\x04")
                handle.truncate(48 * 1024 * 1024 + 1)
            with patch("netops_core.bundle.zipfile.ZipFile") as zip_file:
                with self.assertRaisesRegex(ValueError, "container size"):
                    inspect_bundle(source)
            zip_file.assert_not_called()

    @unittest.skipIf(os.name == "nt", "atomic path replacement semantics differ")
    def test_archive_preflight_and_zip_parse_are_bound_to_one_open_inode(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_source = write_bundle(
                root / "original.json",
                DiagnosticBundle(mode="node", vantage_points=["local"]).finish(),
            )
            replacement_source = write_bundle(
                root / "replacement.json",
                DiagnosticBundle(mode="client", vantage_points=["local"]).finish(),
            )
            inspected_path = export_bundle(original_source, root / "inspected.zip")
            replacement_valid = export_bundle(
                replacement_source, root / "replacement-valid.zip"
            )
            with zipfile.ZipFile(replacement_valid) as handle:
                replacement_members = {
                    name: handle.read(name) for name in handle.namelist()
                }
            oversized_central = root / "oversized-central.zip"
            with zipfile.ZipFile(oversized_central, "w") as handle:
                for name, content in replacement_members.items():
                    info = zipfile.ZipInfo(name)
                    info.comment = b"x" * 6_000
                    handle.writestr(info, content)

            original_preflight = bundle_module._preflight_zip_container

            def swap_after_preflight(opened):
                original_preflight(opened)
                os.replace(oversized_central, inspected_path)

            with patch(
                "netops_core.bundle._preflight_zip_container",
                side_effect=swap_after_preflight,
            ):
                inspected, _ = inspect_bundle(inspected_path)

        self.assertEqual(inspected.mode, "node")

    def test_support_archive_redacts_single_label_hosts_in_network_contexts(self):
        hostname = "internalhost"
        bundle = DiagnosticBundle(
            mode="node",
            vantage_points=[f"remote-server:{hostname}"],
        )
        bundle.observations.append(
            Observation(
                vantage_point=f"remote-server:{hostname}",
                segment="destination",
                probe="tcp-connect",
                status="ok",
                evidence={"stdout": f"connected to {hostname} successfully"},
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(source, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                bundle_text = handle.read("bundle.json").decode("utf-8")
                report_text = handle.read("report.md").decode("utf-8")
                manifest = json.loads(handle.read("manifest.json"))
            inspected, _ = inspect_bundle(archive)

        self.assertNotIn(hostname, bundle_text)
        self.assertNotIn(hostname, report_text)
        self.assertNotIn(hostname, json.dumps(inspected.to_dict(), sort_keys=True))
        self.assertFalse(manifest["network_identifiers_included"])
        self.assertIn("hostname", manifest["redactions"])

    def test_support_archive_redacts_single_label_ssh_destination_targets(self):
        hostname = "internalhost"
        bundle = DiagnosticBundle(mode="server", vantage_points=["remote"])
        bundle.observations.append(
            Observation(
                vantage_point="remote",
                segment="vps",
                probe="ssh-readonly-collector",
                status="ok",
                target=f"root@{hostname}",
                protocol="ssh",
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(source, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                raw = handle.read("bundle.json").decode("utf-8")
                manifest = json.loads(handle.read("manifest.json"))
            inspect_bundle(archive)

        self.assertNotIn(hostname, raw)
        self.assertIn("ssh-destination", manifest["redactions"])

    def test_support_archive_redacts_single_label_host_port_endpoints(self):
        hostname = "internalhost"
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.observations.append(
            Observation(
                vantage_point="local",
                segment="node-ingress",
                probe="endpoint-test",
                status="ok",
                evidence={"endpoint": f"{hostname}:443"},
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(source, root / "support.zip")
            with zipfile.ZipFile(archive) as handle:
                raw = handle.read("bundle.json").decode("utf-8")
                manifest = json.loads(handle.read("manifest.json"))
            inspect_bundle(archive)

        self.assertNotIn(hostname, raw)
        self.assertIn("network-endpoint", manifest["redactions"])

    def test_archive_network_claim_is_checked_independently_for_each_identifier_kind(self):
        identifiers = [
            "internalhost",
            "xn--fsqu00a.xn--0zwm56d",
            "例子.测试",
            "aa:bb:cc:dd:ee:ff",
        ]
        for index, identifier in enumerate(identifiers):
            with self.subTest(identifier=identifier), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
                bundle.targets = [{"target": identifier}]
                source = write_bundle(root / "source.json", bundle)
                archive = export_bundle(
                    source,
                    root / "included.zip",
                    include_network_identifiers=True,
                )
                with zipfile.ZipFile(archive) as handle:
                    members = {name: handle.read(name) for name in handle.namelist()}
                manifest = json.loads(members["manifest.json"])
                manifest["network_identifiers_included"] = False
                members["manifest.json"] = (
                    json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n"
                ).encode("utf-8")
                forged = root / f"forged-{index}.zip"
                with zipfile.ZipFile(forged, "w") as handle:
                    for name, content in members.items():
                        handle.writestr(name, content)
                with self.assertRaisesRegex(ValueError, "still contains"):
                    inspect_bundle(forged)

    def test_archive_network_claim_detects_contextual_single_label_hosts(self):
        hostname = "internalhost"
        for location in ("vantage-point", "stdout"):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
                if location == "vantage-point":
                    bundle.vantage_points = [f"remote-server:{hostname}"]
                else:
                    bundle.observations.append(
                        Observation(
                            vantage_point="test",
                            segment="destination",
                            probe="tcp-connect",
                            status="ok",
                            evidence={
                                "stdout": f"connected to {hostname} successfully"
                            },
                        )
                    )
                source = write_bundle(root / "source.json", bundle)
                archive = export_bundle(
                    source,
                    root / "included.zip",
                    include_network_identifiers=True,
                )
                with zipfile.ZipFile(archive) as handle:
                    members = {name: handle.read(name) for name in handle.namelist()}
                manifest = json.loads(members["manifest.json"])
                manifest["network_identifiers_included"] = False
                members["manifest.json"] = (
                    json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
                    + "\n"
                ).encode("utf-8")
                forged = root / f"forged-{location}.zip"
                with zipfile.ZipFile(forged, "w") as handle:
                    for name, content in members.items():
                        handle.writestr(name, content)

                with self.assertRaisesRegex(ValueError, "still contains"):
                    inspect_bundle(forged)

    def test_export_refuses_unsafe_output_paths_and_existing_archives(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            with self.assertRaisesRegex(ValueError, r"\.zip extension"):
                export_bundle(source, root / "support.data")

            existing = root / "existing.zip"
            existing.write_bytes(b"do-not-overwrite")
            with self.assertRaises(FileExistsError):
                export_bundle(source, existing)
            self.assertEqual(existing.read_bytes(), b"do-not-overwrite")

            if os.name != "nt":
                missing = root / "missing-archive.zip"
                dangling = root / "dangling.zip"
                dangling.symlink_to(missing)
                with self.assertRaises(FileExistsError):
                    export_bundle(source, dangling)
                self.assertFalse(missing.exists())

            zip_named_json = write_bundle(root / "source.zip", bundle)
            inspected, _ = inspect_bundle(zip_named_json)
            self.assertEqual(inspected.mode, "node")
            with self.assertRaisesRegex(ValueError, "differ from"):
                export_bundle(zip_named_json, zip_named_json)

    def test_packaged_contract_matches_repository_schema(self):
        schema_path = Path(__file__).parents[1] / "schemas/diagnostic-bundle.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(set(schema["required"]), models._BUNDLE_REQUIRED)
        self.assertEqual(set(schema["properties"]), models._BUNDLE_ALLOWED)
        observation = schema["properties"]["observations"]["items"]
        self.assertEqual(set(observation["required"]), models._OBSERVATION_REQUIRED)
        self.assertEqual(set(observation["properties"]), models._OBSERVATION_ALLOWED)
        self.assertEqual(
            set(observation["properties"]["status"]["enum"]),
            {"ok", "failed", "unknown"},
        )
        self.assertEqual(
            set(observation["properties"]["confidence"]["enum"]),
            {"high", "medium", "low"},
        )
        self.assertEqual(schema["properties"]["started_at"]["format"], "date-time")
        self.assertEqual(schema["properties"]["completed_at"]["format"], "date-time")
        self.assertEqual(
            observation["properties"]["observed_at"]["format"], "date-time"
        )
        self.assertEqual(
            schema["properties"]["observations"]["maxItems"],
            models.MAX_BUNDLE_COLLECTION_ITEMS,
        )
        self.assertEqual(
            schema["$defs"]["boundedJsonValue"]["anyOf"][1]["maxLength"],
            models.MAX_BUNDLE_STRING_CHARS,
        )

    def test_camel_case_credential_keys_are_removed_and_independently_detected(self):
        credential_fields = {
            "apiToken": "fixture-one",
            "authToken": "fixture-two",
            "proxyPassword": "fixture-three",
            "privateKey": "fixture-four",
            "secretAccessKey": "fixture-five",
            "sessionId": "fixture-six",
            "xApiKey": "fixture-seven",
            "xAuthToken": "fixture-eight",
            "AWSSecretAccessKey": "fixture-nine",
        }
        original = {"environment": {"thirdParty": credential_fields}}
        redactor = Redactor(include_network_identifiers=False)
        redacted = redactor.value(original)
        rendered = json.dumps(redacted, sort_keys=True)

        for value in credential_fields.values():
            self.assertNotIn(value, rendered)
        self.assertIsNotNone(bundle_module._residual_credential_path(original))

        bundle = DiagnosticBundle(
            mode="node",
            vantage_points=["test"],
            environment=original["environment"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            archive = export_bundle(source, root / "support.zip")
            inspected, _ = inspect_bundle(archive)
            exported = json.dumps(inspected.to_dict(), sort_keys=True)

        for value in credential_fields.values():
            self.assertNotIn(value, exported)

    def test_extended_command_header_and_url_credentials_are_removed(self):
        command_lines = [
            r"net use \\server\share /user:alice opaque-net-secret",
            "cmdkey /add:server /user:alice /pass:opaque-cmdkey-secret",
            "docker login registry.invalid -u alice -p opaque-docker-secret",
            "aws configure set aws_secret_access_key opaque-aws-secret",
            "openssl pkcs12 -in cert.p12 -passin pass:opaque-pkcs-secret",
            "smbclient //server/share -U alice%opaque-smb-secret",
            "PGPASSWORD opaque-pg-secret psql -h db.invalid",
            "az login -u alice -p opaque-azure-secret",
            "pscp -pw opaque-putty-secret file user@server:/tmp",
            "curl --cookie session=opaque-cookie-secret https://example.invalid",
        ]
        header_records = [
            {"name": name, "value": f"opaque-header-{index}"}
            for index, name in enumerate(
                (
                    "X-API-Token",
                    "Private-Token",
                    "X-Vault-Token",
                    "X-Amz-Security-Token",
                    "X-Goog-Api-Key",
                    "Cf-Access-Client-Secret",
                    "X-Hub-Signature-256",
                    "X-Webhook-Secret",
                    "Acme-Api-Key",
                    "Acme-Auth-Token",
                    "Acme-Signing-Secret",
                )
            )
        ]
        urls = [
            "https://hooks.slack.com/services/T1/B2/opaque-slack-secret",
            "https://discord.com/api/webhooks/123/opaque-discord-secret",
            "https://api.telegram.org/botopaque-telegram-secret/getMe",
            "https://storage.googleapis.com/object?x-goog-signature=opaque-gcs-secret",
        ]
        original = {
            "environment": {
                "command_lines": command_lines,
                "header_records": header_records,
                "urls": urls,
                "privateKeyMaterial": "opaque-private-key-material",
            }
        }
        all_secrets = re.findall(r"opaque-[a-z0-9-]+", json.dumps(original))
        self.assertIsNotNone(bundle_module._residual_credential_path(original))

        for include_network_identifiers in (False, True):
            redactor = Redactor(
                include_network_identifiers=include_network_identifiers,
                redact_hostnames=not include_network_identifiers,
            )
            redacted = redactor.value(original)
            rendered = json.dumps(redacted, sort_keys=True)
            for secret in all_secrets:
                self.assertNotIn(secret, rendered)
            self.assertIsNone(bundle_module._residual_credential_path(redacted))
            self.assertIn("command-credential", redactor.actions)

        diagnostic = DiagnosticBundle(
            mode="node",
            vantage_points=["test"],
            environment=original["environment"],
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", diagnostic)
            archive = export_bundle(source, root / "support.zip")
            inspected, report = inspect_bundle(archive)
            exported = json.dumps(inspected.to_dict(), sort_keys=True) + report
        for secret in all_secrets:
            self.assertNotIn(secret, exported)

    def test_legacy_ip_forms_numeric_fqdn_and_host_keyed_maps_are_removed(self):
        identifiers = [
            "2130706433",
            "017700000001",
            "0x7f000001",
            "127.0.0.1.",
        ]
        host_maps = {
            name: {"edge-router-7": {"latency_ms": 12}}
            for name in (
                "nodes",
                "routers",
                "gateways",
                "hops",
                "devices",
                "latency_by_node",
                "latency_by_router",
            )
        }
        original = {
            "environment": {
                "messages": [
                    f"target: {identifiers[0]}",
                    f"gateway={identifiers[1]}",
                    f"resolver: {identifiers[2]}",
                    f"target: {identifiers[3]}",
                    "https://2130706433/path",
                    "https://127.0.0.1./path",
                    "packet_count=2130706433",
                ],
                **host_maps,
            }
        }
        self.assertIsNotNone(bundle_module._network_identifier_path(original))
        redactor = Redactor(include_network_identifiers=False)
        redacted = redactor.value(original)
        rendered = json.dumps(redacted, sort_keys=True)

        redacted_messages = redacted["environment"]["messages"]
        for identifier in identifiers:
            self.assertNotIn(identifier, json.dumps(redacted_messages[:-1]))
        self.assertNotIn("edge-router-7", rendered)
        self.assertIn("packet_count=2130706433", rendered)
        self.assertIsNone(bundle_module._network_identifier_path(redacted))
        labels = re.findall(r"<ip-[0-9a-f]{12}>", rendered)
        self.assertGreaterEqual(len(labels), 6)
        self.assertEqual(len(set(labels)), 1)

    def test_inspector_rejects_hidden_zip_comments_and_entry_metadata(self):
        diagnostic = DiagnosticBundle(mode="node", vantage_points=["test"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", diagnostic)
            archive = export_bundle(source, root / "support.zip")
            comment_archive = root / "comment.zip"
            shutil.copy2(archive, comment_archive)
            with zipfile.ZipFile(comment_archive, "a") as handle:
                handle.comment = b"opaque-hidden-archive-secret"
            with self.assertRaisesRegex(ValueError, "comment"):
                inspect_bundle(comment_archive)

            with zipfile.ZipFile(archive) as handle:
                members = [(name, handle.read(name)) for name in handle.namelist()]
            metadata_archive = root / "metadata.zip"
            with zipfile.ZipFile(metadata_archive, "w", compression=zipfile.ZIP_STORED) as handle:
                for index, (name, payload) in enumerate(members):
                    info = zipfile.ZipInfo(name)
                    if index == 0:
                        info.comment = b"opaque-hidden-entry-secret"
                    handle.writestr(info, payload)
            with self.assertRaisesRegex(ValueError, "metadata"):
                inspect_bundle(metadata_archive)

    def test_contract_works_from_installed_package_without_schema_directory(self):
        repository = Path(__file__).parents[1]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installed = root / "installed"
            unrelated_cwd = root / "elsewhere"
            unrelated_cwd.mkdir()
            shutil.copytree(
                repository / "netops_core",
                installed / "netops_core",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
            )
            code = (
                "import sys;"
                f"sys.path.insert(0, {str(installed)!r});"
                "from netops_core.models import DiagnosticBundle, load_bundle, write_bundle;"
                "from pathlib import Path;"
                "item=DiagnosticBundle(mode='node', vantage_points=['test']);"
                "path=write_bundle(Path('bundle.json'), item);"
                "assert load_bundle(path).mode == 'node'"
            )
            result = subprocess.run(
                [sys.executable, "-c", code],
                cwd=unrelated_cwd,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse((installed / "schemas").exists())


if __name__ == "__main__":
    unittest.main()
