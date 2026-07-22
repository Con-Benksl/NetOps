import hashlib
import io
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from netops_core import CHANGE_SCHEMA_VERSION
from netops_core.change import (
    _active_change_lease,
    _automatic_rollback_script,
    _backup,
    _disarm_automatic_rollback,
    _preflight_command,
    _REMOTE_METADATA_PROGRAM,
    _REMOTE_SQLITE_PROGRAM,
    _remote_script,
    _safe_remote_output,
    _upload_payloads,
    _validated_archive_script,
    apply_plan,
    create_plan,
    load_plan,
    resolve_apply_receipt_path,
    resolve_rollback_receipt_path,
    rollback_plan,
    validate_change_spec,
)
from netops_core.fleet import load_fleet, ssh_invocation, validate_fleet


BACKUP_INTEGRITY_STDOUT = (
    f"archive_sha256={'c' * 64}\nmanifest_sha256={'d' * 64}\n"
)

ARCHIVE_VALIDATION_TOOLS = (
    "awk",
    "cmp",
    "cp",
    "cut",
    "mktemp",
    "mv",
    "python3",
    "pwd",
    "sed",
    "sha256sum",
    "stat",
    "tar",
)


def fleet_data():
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


def safe_control_channel():
    return {
        "control_channel": {
            "dependency": "independent",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "independent-path",
            "independent_path_verified": True,
            "operator_recovery_reviewed": True,
            "host_reboot_planned": False,
            "evidence": ["verified alternate management path"],
        },
        "rollback_timer": {"enabled": False, "delay_seconds": 600},
    }


def fresh_rollback_access_evidence(control_channel=None):
    return {
        "observed_at": datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
            "+00:00", "Z"
        ),
        "control_channel": control_channel or safe_control_channel()["control_channel"],
    }


def write_apply_receipt(root: Path, plan: dict, execution_id: str) -> Path:
    backup_dir = f"/var/backups/netops/{plan['plan_id']}/{execution_id}"
    path = root / f"apply-{execution_id}.receipt.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": "2.0",
                "plan_id": plan["plan_id"],
                "host_alias": plan["host_alias"],
                "execution_id": execution_id,
                "backup_dir": backup_dir,
                "backup_integrity": {
                    "archive_sha256": "c" * 64,
                    "manifest_sha256": "d" * 64,
                },
                "status": "running",
            }
        ),
        encoding="utf-8",
    )
    return path


def rehash_plan(data: dict) -> None:
    body = {key: value for key, value in data.items() if key != "plan_id"}
    encoded = json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    data["plan_id"] = hashlib.sha256(encoded).hexdigest()[:32]


def exact_file_preflight(path="/etc/test.json"):
    return {
        "phase": "preflight",
        "description": "confirm exact existing target",
        "check": "file-sha256",
        "target": path,
        "sha256": "a" * 64,
        "metadata_sha256": "b" * 64,
    }


def sqlite_query_preflight(path="/etc/x-ui/x-ui.db"):
    return {
        "phase": "preflight",
        "description": "confirm stable SQLite configuration state",
        "check": "sqlite-query-sha256",
        "target": path,
        "query": "SELECT id, remark FROM inbounds ORDER BY id",
        "sha256": "c" * 64,
        "metadata_sha256": "d" * 64,
    }


class FleetAndChangeTests(unittest.TestCase):
    def _base_spec(self, root: Path):
        payload = root / "payload.json"
        payload.write_text('{"ok": true}\n', encoding="utf-8")
        return {
            "schema_version": CHANGE_SCHEMA_VERSION,
            "name": "adversarial-test",
            "summary": "exercise the controlled change contract",
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
                exact_file_preflight(),
                {"phase": "validate", "description": "validate", "command": "true"},
                {"phase": "verify", "description": "verify", "command": "true"},
                {
                    "phase": "rollback",
                    "description": "restore runtime state",
                    "command": "true",
                },
                {
                    "phase": "rollback_verify",
                    "description": "verify rollback",
                    "command": "true",
                },
            ],
            **safe_control_channel(),
        }

    @staticmethod
    def _write_archive_fixture(root: Path, variant: str):
        target = (root / "live/target.conf").resolve()
        target.parent.mkdir(parents=True)
        original = b"original-state\n"
        target.write_bytes(original)
        target.chmod(0o640)
        backup_root = (root / "backup").resolve()
        plan_id = "a" * 32
        backup_dir = backup_root / plan_id / ("b" * 12)
        backup_dir.mkdir(mode=0o700, parents=True)
        relative = str(target)[1:]
        manifest = backup_dir / "target-state.sha256"
        manifest.write_text(
            f"{hashlib.sha256(original).hexdigest()}  {relative}\n",
            encoding="utf-8",
        )
        archive_path = backup_dir / "state.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            if variant in {"valid", "extra-absolute", "tampered"}:
                payload = b"tampered-state\n" if variant == "tampered" else original
                member = tarfile.TarInfo(relative)
                member.mode = 0o640
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            elif variant == "symlink":
                member = tarfile.TarInfo(relative)
                member.type = tarfile.SYMTYPE
                member.linkname = "/etc/passwd"
                archive.addfile(member)
            elif variant == "hardlink":
                member = tarfile.TarInfo(relative)
                member.type = tarfile.LNKTYPE
                member.linkname = "off-plan-target"
                archive.addfile(member)
            elif variant == "directory":
                member = tarfile.TarInfo(relative)
                member.type = tarfile.DIRTYPE
                archive.addfile(member)
            elif variant == "fifo":
                member = tarfile.TarInfo(relative)
                member.type = tarfile.FIFOTYPE
                archive.addfile(member)
            else:
                raise AssertionError(f"unknown archive fixture: {variant}")
            if variant == "extra-absolute":
                extra_payload = b"off-plan\n"
                extra = tarfile.TarInfo("/etc/netops-off-plan")
                extra.size = len(extra_payload)
                archive.addfile(extra, io.BytesIO(extra_payload))
        (backup_dir / "state.tar.gz.sha256").write_text(
            f"{hashlib.sha256(archive_path.read_bytes()).hexdigest()}  state.tar.gz\n",
            encoding="utf-8",
        )
        plan = {
            "plan_id": plan_id,
            "backup_root": str(backup_root),
            "rollback_contract": {"declared_targets": [str(target)]},
        }
        lease_path, lease_token = _active_change_lease(plan, str(backup_dir))
        Path(lease_path).write_text(lease_token + "\n", encoding="utf-8")
        Path(lease_path).chmod(0o600)
        return plan, backup_dir, target, original

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

    def test_fleet_rejects_secret_shaped_label_keys_with_suffixes(self):
        for key in (
            "dbPassword",
            "authToken",
            "bearerToken",
            "privateKeyMaterial",
            "proxyPasswordHint",
            "apiCredential",
        ):
            fleet = fleet_data()
            fleet["hosts"][0]["labels"] = {key: "must-not-be-stored"}
            with self.subTest(key=key), self.assertRaisesRegex(
                ValueError, "secret fields"
            ):
                validate_fleet(fleet)

    def test_fleet_runtime_contract_rejects_schema_drift_and_disguised_secrets(self):
        cases = []
        missing_role = fleet_data()
        missing_role["hosts"][0].pop("role")
        cases.append(missing_role)
        extra_root = fleet_data()
        extra_root["unexpected"] = True
        cases.append(extra_root)
        bool_port = fleet_data()
        bool_port["hosts"][0]["ssh"]["port"] = True
        cases.append(bool_port)
        bad_domains = fleet_data()
        bad_domains["hosts"][0]["domains"]["ipv4"] = "edge.example"
        cases.append(bad_domains)
        disguised_secret = fleet_data()
        disguised_secret["hosts"][0]["labels"] = {
            "accessToken": "must-not-be-stored"
        }
        cases.append(disguised_secret)
        for fleet in cases:
            with self.subTest(fleet=fleet), self.assertRaises(ValueError):
                validate_fleet(fleet)

    def test_ssh_invocation_rejects_bool_port_and_lowercase_password_env(self):
        host = fleet_data()["hosts"][0]
        host["ssh"]["port"] = True
        with self.assertRaisesRegex(ValueError, "ssh.port"):
            ssh_invocation(host)
        host["ssh"]["port"] = 22
        host["ssh"]["password_env"] = "lowercase_secret"
        with self.assertRaisesRegex(ValueError, "password_env"):
            ssh_invocation(host)

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

    def test_change_plan_is_hashed_and_execution_requires_authorization(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload.json"
            payload.write_text('{"ok": true}\n', encoding="utf-8")
            fleet_path = root / "fleet.json"
            fleet_path.write_text(json.dumps(fleet_data()), encoding="utf-8")
            spec = {
                "schema_version": CHANGE_SCHEMA_VERSION,
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
                    exact_file_preflight(),
                    {"phase": "validate", "description": "validate", "command": "true"},
                    {"phase": "verify", "description": "verify", "command": "true"},
                    {
                        "phase": "rollback",
                        "description": "restore runtime state",
                        "command": "true",
                    },
                    {
                        "phase": "rollback_verify",
                        "description": "verify rollback",
                        "command": "true",
                    },
                ],
                **safe_control_channel(),
            }
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            fleet = load_fleet(fleet_path)
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet, plan_path)
            loaded = load_plan(plan_path)
            self.assertEqual(loaded["plan_id"], plan["plan_id"])
            self.assertEqual(len(plan["plan_id"]), 32)
            changed_fleet = load_fleet(fleet_path)
            changed_fleet["hosts"][0]["management"]["address"] = "192.0.2.99"
            with patch("netops_core.change._remote_script") as remote, patch(
                "netops_core.change._reserve_new_local_file"
            ) as reserve:
                for current_fleet in (fleet, changed_fleet):
                    for authorization in (False, None, 0, "false"):
                        with self.subTest(
                            host=current_fleet["hosts"][0]["management"]["address"],
                            authorization=authorization,
                        ), self.assertRaisesRegex(
                            PermissionError, "requires explicit authorization"
                        ):
                            apply_plan(
                                plan_path,
                                current_fleet,
                                authorized=authorization,
                                confirmed_plan_id=plan["plan_id"],
                                current_control_channel={},
                            )
                remote.assert_not_called()
                reserve.assert_not_called()

            rollback_receipt = root / "must-not-exist.json"
            with patch("netops_core.change._remote_script") as remote, patch(
                "netops_core.change._reserve_new_local_file"
            ) as reserve:
                with self.assertRaisesRegex(
                    PermissionError, "requires explicit authorization"
                ):
                    rollback_plan(
                        root / "missing-plan.json",
                        {},
                        backup_dir="not-a-backup",
                        authorized=False,
                        confirmed_plan_id="not-a-plan",
                        apply_receipt_path=root / "missing-apply-receipt.json",
                        current_control_channel={},
                        receipt_path=rollback_receipt,
                    )
                remote.assert_not_called()
                reserve.assert_not_called()
                self.assertFalse(rollback_receipt.exists())

    def test_change_plan_detects_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "payload.json"
            payload.write_text("{}\n", encoding="utf-8")
            fleet_path = root / "fleet.json"
            fleet_path.write_text(json.dumps(fleet_data()), encoding="utf-8")
            spec = {
                "schema_version": CHANGE_SCHEMA_VERSION,
                "name": "test",
                "summary": "test",
                "host_alias": "edge-a",
                "invariants": ["unchanged"],
                "backup_paths": ["/etc/test.json"],
                "payloads": [{"local_path": "payload.json", "remote_path": "/etc/test.json"}],
                "operations": [
                    exact_file_preflight(),
                    {"phase": "validate", "description": "v", "command": "true"},
                    {"phase": "verify", "description": "v", "command": "true"},
                    {
                        "phase": "rollback",
                        "description": "restore runtime state",
                        "command": "true",
                    },
                    {"phase": "rollback_verify", "description": "v", "command": "true"},
                ],
                **safe_control_channel(),
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

    def test_rehashed_plan_cannot_bypass_required_rollback_semantics(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            create_plan(spec_path, fleet_data(), plan_path)
            data = json.loads(plan_path.read_text(encoding="utf-8"))
            data["operations"] = [
                operation
                for operation in data["operations"]
                if operation["phase"] != "rollback"
            ]
            body = {
                key: value
                for key, value in data.items()
                if key != "plan_id"
            }
            encoded = json.dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            data["plan_id"] = hashlib.sha256(encoded).hexdigest()[:32]
            plan_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "missing required rollback phase"):
                load_plan(plan_path)

    def test_rehashed_plan_cannot_hide_unicode_review_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            create_plan(spec_path, fleet_data(), plan_path)
            data = json.loads(plan_path.read_text(encoding="utf-8"))
            data["summary"] = "reviewed\u202egpj.exe"
            body = {
                key: value
                for key, value in data.items()
                if key != "plan_id"
            }
            encoded = json.dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            data["plan_id"] = hashlib.sha256(encoded).hexdigest()[:32]
            plan_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "control or format"):
                load_plan(plan_path)

    def test_change_apply_blocks_unknown_control_channel_before_ssh(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = {
                "schema_version": CHANGE_SCHEMA_VERSION,
                "name": "blocked",
                "summary": "missing control path evidence",
                "host_alias": "edge-a",
                "invariants": ["unchanged"],
                "backup_paths": ["/etc/test.json"],
                "operations": [
                    exact_file_preflight(),
                    {
                        "phase": "apply",
                        "description": "declare target",
                        "command": "true",
                        "affected_paths": ["/etc/test.json"],
                    },
                    {"phase": "validate", "description": "v", "command": "true"},
                    {"phase": "verify", "description": "v", "command": "true"},
                    {
                        "phase": "rollback",
                        "description": "restore runtime state",
                        "command": "true",
                    },
                    {"phase": "rollback_verify", "description": "v", "command": "true"},
                ],
            }
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            self.assertEqual(plan["control_channel_guard"]["decision"], "block")
            with self.assertRaisesRegex(PermissionError, "control-channel guard"):
                apply_plan(
                    plan_path,
                    fleet_data(),
                    authorized=True,
                    confirmed_plan_id=plan["plan_id"],
                    current_control_channel=fresh_rollback_access_evidence(
                        plan["control_channel"]
                    ),
                )

    def test_change_apply_requires_fresh_matching_control_channel_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec_path = root / "spec.json"
            spec_path.write_text(
                json.dumps(self._base_spec(root)), encoding="utf-8"
            )
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            stale = {
                "observed_at": "2020-01-01T00:00:00Z",
                "control_channel": plan["control_channel"],
            }
            changed = fresh_rollback_access_evidence(
                {
                    **plan["control_channel"],
                    "evidence": ["different current management-path evidence"],
                }
            )
            with patch("netops_core.change._remote_script") as remote:
                with self.assertRaisesRegex(ValueError, "older than 15 minutes"):
                    apply_plan(
                        plan_path,
                        fleet_data(),
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        current_control_channel=stale,
                    )
                with self.assertRaisesRegex(ValueError, "differs from the reviewed plan"):
                    apply_plan(
                        plan_path,
                        fleet_data(),
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        current_control_channel=changed,
                    )
            remote.assert_not_called()

    def test_shared_path_arms_and_disarms_remote_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = {
                "schema_version": CHANGE_SCHEMA_VERSION,
                "name": "guarded",
                "summary": "restart a shared remote proxy service",
                "host_alias": "edge-a",
                "invariants": ["old service can be restored"],
                "backup_paths": ["/etc/test.json"],
                "control_channel": {
                    "dependency": "shared",
                    "change_surfaces": ["remote-proxy-service"],
                    "continuity_strategy": "automatic-rollback",
                    "independent_path_verified": False,
                    "operator_recovery_reviewed": True,
                    "host_reboot_planned": False,
                    "evidence": ["shared management path confirmed"],
                },
                "rollback_timer": {"enabled": True, "delay_seconds": 600},
                "operations": [
                    exact_file_preflight(),
                    {
                        "phase": "apply",
                        "description": "declare target",
                        "command": "true",
                        "affected_paths": ["/etc/test.json"],
                    },
                    {"phase": "validate", "description": "v", "command": "true"},
                    {"phase": "verify", "description": "v", "command": "true"},
                    {
                        "phase": "rollback",
                        "description": "restore runtime state",
                        "command": "true",
                    },
                    {
                        "phase": "rollback_verify",
                        "description": "rv",
                        "command": "true",
                    },
                ],
                "restart_services": ["example.service"],
            }
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            success = {
                "available": True,
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "timed_out": False,
                "duration_ms": 1,
            }
            with patch("netops_core.change._remote_script", return_value=success):
                receipt = apply_plan(
                    plan_path,
                    fleet_data(),
                    authorized=True,
                    confirmed_plan_id=plan["plan_id"],
                    current_control_channel=fresh_rollback_access_evidence(
                        plan["control_channel"]
                    ),
                    receipt_path=root / "receipt.json",
                )
            phases = [item["phase"] for item in receipt["steps"]]
            self.assertEqual(receipt["status"], "applied")
            self.assertEqual(
                receipt["current_control_channel"]["control_channel"],
                plan["control_channel"],
            )
            self.assertRegex(
                receipt["backup_dir"],
                rf"/{plan['plan_id']}/[0-9a-f]{{12}}$",
            )
            self.assertIn("arm-automatic-rollback", phases)
            self.assertIn("mark-change-started", phases)
            self.assertIn("disarm-automatic-rollback", phases)

    def test_automatic_rollback_script_restores_and_verifies(self):
        plan = {
            "plan_id": "a" * 32,
            "backup_root": "/var/backups/netops",
            "rollback_contract": {
                "declared_targets": ["/etc/example.conf"],
            },
            "operations": [
                {
                    "phase": "rollback",
                    "description": "cleanup",
                    "command": "rm -f /tmp/example",
                },
                {
                    "phase": "rollback_verify",
                    "description": "verify",
                    "command": "test ! -e /tmp/example",
                },
            ],
            "restart_services": ["example.service"],
        }
        backup_dir = f"/var/backups/netops/{'a' * 32}/{'b' * 12}"
        script = _automatic_rollback_script(
            plan,
            backup_dir,
            {"archive_sha256": "c" * 64, "manifest_sha256": "d" * 64},
        )
        self.assertIn("state.tar.gz", script)
        self.assertIn("target-state.sha256", script)
        self.assertIn("sha256sum -c", script)
        self.assertIn("rm -f /tmp/example", script)
        self.assertIn("systemctl restart -- example.service", script)
        self.assertIn("test ! -e /tmp/example", script)
        self.assertGreater(
            script.rfind("sha256sum -c"),
            script.find("test ! -e /tmp/example"),
        )
        self.assertIn("automatic-rollback.status", script)
        self.assertIn("rollback.lock", script)
        self.assertIn("rollback.state", script)
        self.assertIn("expired-without-change", script)
        self.assertIn("write_state rolling-back", script)
        self.assertIn("expected-members", script)
        self.assertIn("archive-verbose", script)
        self.assertIn("STAGING_ROOT", script)
        self.assertIn("mv -fT", script)

    @unittest.skipUnless(
        Path("/bin/sh").is_file()
        and all(shutil.which(tool) for tool in ARCHIVE_VALIDATION_TOOLS),
        "archive validation integration needs its complete GNU/Linux toolchain",
    )
    def test_archive_validation_fails_closed_before_tampered_restore(self):
        mv_help = subprocess.run(
            ["mv", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        supports_atomic_replace = (
            mv_help.returncode == 0 and "--no-target-directory" in mv_help.stdout
        )
        if supports_atomic_replace:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan, backup_dir, target, original = self._write_archive_fixture(
                    root, "valid"
                )
                validation = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        _validated_archive_script(
                            plan, str(backup_dir), restore=False
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(validation.returncode, 0, validation.stderr)
                self.assertEqual(target.read_bytes(), original)

            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan, backup_dir, target, original = self._write_archive_fixture(
                    root, "valid"
                )
                target.write_bytes(b"changed-state\n")
                restored = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        _validated_archive_script(
                            plan, str(backup_dir), restore=True
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(restored.returncode, 0, restored.stderr)
                self.assertEqual(target.read_bytes(), original)
                self.assertEqual(target.stat().st_mode & 0o777, 0o640)
                self.assertEqual(list(backup_dir.glob(".restore-stage.*")), [])

        for variant in (
            "extra-absolute",
            "symlink",
            "hardlink",
            "directory",
            "fifo",
            "tampered",
        ):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan, backup_dir, target, original = self._write_archive_fixture(
                    root, variant
                )
                completed = subprocess.run(
                    [
                        "/bin/sh",
                        "-c",
                        _validated_archive_script(
                            plan, str(backup_dir), restore=True
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertEqual(target.read_bytes(), original)
                self.assertEqual(list(backup_dir.glob(".restore-stage.*")), [])

    def test_remote_output_removes_terminal_control_sequences(self):
        value = "\x1b]8;;https://evil.invalid\x07click\x1b]8;;\x07\x1b[31mRED\x1b[0m"
        sanitized = _safe_remote_output(value)
        self.assertNotIn("\x1b", sanitized)
        self.assertNotIn("\x07", sanitized)

    def test_plan_and_receipts_are_new_files_and_never_alias_reviewed_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "already exists"):
                create_plan(spec_path, fleet_data(), spec_path)

            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            self.assertEqual(
                resolve_apply_receipt_path(plan_path),
                (root / "plan.receipt.json").resolve(),
            )
            self.assertEqual(
                resolve_rollback_receipt_path(plan_path),
                (root / "plan.rollback-receipt.json").resolve(),
            )

            apply_receipt = root / "existing-apply.json"
            apply_receipt.write_text("do not overwrite", encoding="utf-8")
            with patch("netops_core.change._remote_script") as remote:
                with self.assertRaisesRegex(FileExistsError, "already exists"):
                    apply_plan(
                        plan_path,
                        fleet_data(),
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        current_control_channel=fresh_rollback_access_evidence(
                            plan["control_channel"]
                        ),
                        receipt_path=apply_receipt,
                    )
            remote.assert_not_called()
            self.assertEqual(
                apply_receipt.read_text(encoding="utf-8"), "do not overwrite"
            )

            rollback_receipt = root / "existing-rollback.json"
            rollback_receipt.write_text("do not overwrite", encoding="utf-8")
            rollback_execution = "a" * 12
            source_apply_receipt = write_apply_receipt(
                root, plan, rollback_execution
            )
            with patch("netops_core.change._remote_script") as remote:
                with self.assertRaisesRegex(FileExistsError, "already exists"):
                    rollback_plan(
                        plan_path,
                        fleet_data(),
                        backup_dir=f"/var/backups/netops/{plan['plan_id']}/{rollback_execution}",
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        apply_receipt_path=source_apply_receipt,
                        current_control_channel=fresh_rollback_access_evidence(),
                        receipt_path=rollback_receipt,
                    )
            remote.assert_not_called()
            self.assertEqual(
                rollback_receipt.read_text(encoding="utf-8"), "do not overwrite"
            )

    def test_disconnect_after_arming_is_recorded_as_rollback_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = {
                "schema_version": CHANGE_SCHEMA_VERSION,
                "name": "disconnect",
                "summary": "simulate a lost shared control path",
                "host_alias": "edge-a",
                "invariants": ["automatic rollback remains armed"],
                "backup_paths": ["/etc/test.json"],
                "control_channel": {
                    "dependency": "shared",
                    "change_surfaces": ["remote-proxy-service"],
                    "continuity_strategy": "automatic-rollback",
                    "independent_path_verified": False,
                    "operator_recovery_reviewed": True,
                    "host_reboot_planned": False,
                    "evidence": ["shared management path confirmed"],
                },
                "rollback_timer": {"enabled": True, "delay_seconds": 600},
                "operations": [
                    exact_file_preflight(),
                    {
                        "phase": "apply",
                        "description": "change target",
                        "command": "true",
                        "affected_paths": ["/etc/test.json"],
                    },
                    {
                        "phase": "validate",
                        "description": "connection drops",
                        "command": "false",
                    },
                    {"phase": "verify", "description": "v", "command": "true"},
                    {
                        "phase": "rollback",
                        "description": "restore runtime state",
                        "command": "true",
                    },
                    {
                        "phase": "rollback_verify",
                        "description": "rv",
                        "command": "true",
                    },
                ],
            }
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            success = {
                "available": True,
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "timed_out": False,
                "duration_ms": 1,
            }
            disconnected = {
                "available": True,
                "returncode": 255,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "connection lost",
                "timed_out": False,
                "duration_ms": 1,
            }
            receipt_path = root / "receipt.json"
            with patch(
                "netops_core.change._remote_script",
                side_effect=[
                    success,
                    success,
                    success,
                    success,
                    success,
                    disconnected,
                    disconnected,
                ],
            ):
                with self.assertRaisesRegex(RuntimeError, "validate failed"):
                    apply_plan(
                        plan_path,
                        fleet_data(),
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        current_control_channel=fresh_rollback_access_evidence(
                            plan["control_channel"]
                        ),
                        receipt_path=receipt_path,
                    )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "rollback-pending")
            self.assertEqual(receipt["rollback_timer_state"], "armed")

    def test_preflight_rejects_arbitrary_shell_and_accepts_typed_checks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["operations"].insert(
                0,
                {
                    "phase": "preflight",
                    "description": "must not mutate",
                    "command": "ip route del default",
                },
            )
            with self.assertRaisesRegex(ValueError, "typed check, not shell"):
                validate_change_spec(spec, source_dir=root)

            spec["operations"][0] = {
                "phase": "preflight",
                "description": "check the current file",
                "check": "file-exists",
                "target": "/etc/test.json",
            }
            normalized = validate_change_spec(spec, source_dir=root)
            self.assertNotIn("command", normalized["operations"][0])
            self.assertEqual(normalized["operations"][0]["check"], "file-exists")

            spec = self._base_spec(root)
            spec["operations"][0] = sqlite_query_preflight("/etc/test.json")
            normalized = validate_change_spec(spec, source_dir=root)
            self.assertEqual(
                normalized["operations"][0]["check"], "sqlite-query-sha256"
            )
            self.assertEqual(
                normalized["rollback_contract"]["preflight_hashes"][0]["query"],
                sqlite_query_preflight("/etc/test.json")["query"],
            )

            spec["operations"][0]["query"] = "UPDATE inbounds SET remark = 'bad'"
            with self.assertRaisesRegex(ValueError, "must start with SELECT"):
                validate_change_spec(spec, source_dir=root)

    def test_change_contract_rejects_boolean_timeouts_and_non_list_services(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["operations"][0]["timeout_seconds"] = True
            with self.assertRaisesRegex(ValueError, "timeout_seconds"):
                validate_change_spec(spec, source_dir=root)

            spec = self._base_spec(root)
            spec["restart_services"] = "example.service"
            with self.assertRaisesRegex(ValueError, "must be a list"):
                validate_change_spec(spec, source_dir=root)

    def test_backup_must_cover_every_declared_mutation_target(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["backup_paths"] = ["/etc/unrelated.json"]
            with self.assertRaisesRegex(ValueError, "exactly match"):
                validate_change_spec(spec, source_dir=root)

            spec = self._base_spec(root)
            spec["operations"].insert(
                0,
                {
                    "phase": "apply",
                    "description": "change a second file",
                    "command": "touch /etc/second.json",
                    "affected_paths": ["/etc/second.json"],
                },
            )
            with self.assertRaisesRegex(ValueError, "/etc/second.json"):
                validate_change_spec(spec, source_dir=root)

    def test_parent_directory_or_missing_file_preflight_cannot_claim_recovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["backup_paths"] = ["/etc/example-app"]
            spec["payloads"][0]["remote_path"] = "/etc/example-app/new.conf"
            spec["operations"][0]["target"] = "/etc/example-app/new.conf"
            with self.assertRaisesRegex(ValueError, "exactly match"):
                validate_change_spec(spec, source_dir=root)

            spec = self._base_spec(root)
            spec["operations"] = [
                operation
                for operation in spec["operations"]
                if operation["phase"] != "preflight"
            ]
            with self.assertRaisesRegex(ValueError, "file-sha256 preflight"):
                validate_change_spec(spec, source_dir=root)

    def test_backup_rejects_overbroad_pseudo_and_recursive_layouts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for unsafe in ("/", "/etc", "/proc/net", "/sys/kernel", "/dev", "/run"):
                with self.subTest(backup_path=unsafe):
                    spec = self._base_spec(root)
                    spec["backup_paths"] = [unsafe]
                    with self.assertRaisesRegex(
                        ValueError, "overbroad|pseudo-filesystem"
                    ):
                        validate_change_spec(spec, source_dir=root)

            for unsafe_root in ("/", "/etc", "/var", "/home", "/run/netops"):
                with self.subTest(backup_root=unsafe_root):
                    spec = self._base_spec(root)
                    spec["backup_root"] = unsafe_root
                    with self.assertRaisesRegex(
                        ValueError, "host-wide controlled root"
                    ):
                        validate_change_spec(spec, source_dir=root)

            spec = self._base_spec(root)
            spec["backup_paths"] = ["/var/backups/netops"]
            spec["payloads"][0]["remote_path"] = "/var/backups/netops/input.json"
            with self.assertRaisesRegex(ValueError, "inside a path being archived"):
                validate_change_spec(spec, source_dir=root)

    def test_all_remote_path_fields_reject_aliases_and_unicode_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                ("backup_paths", "//etc/test.json"),
                ("backup_root", "//var/backups/netops"),
                ("payload", "/etc//test.json"),
                ("preflight", "/etc/./test.json"),
                ("affected", "/etc/test\u202e.json"),
            )
            for field, unsafe in cases:
                with self.subTest(field=field, path=repr(unsafe)):
                    spec = self._base_spec(root)
                    if field == "backup_paths":
                        spec["backup_paths"] = [unsafe]
                    elif field == "backup_root":
                        spec["backup_root"] = unsafe
                    elif field == "payload":
                        spec["payloads"][0]["remote_path"] = unsafe
                    elif field == "preflight":
                        spec["operations"][0]["target"] = unsafe
                    else:
                        spec["operations"].insert(
                            1,
                            {
                                "phase": "apply",
                                "description": "declare target",
                                "command": "true",
                                "affected_paths": [unsafe],
                            },
                        )
                    with self.assertRaisesRegex(
                        ValueError, "leading slash|canonical|control"
                    ):
                        validate_change_spec(spec, source_dir=root)

    def test_review_fields_reject_format_controls_but_shell_allows_lf_and_tab(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = ("name", "summary", "invariant", "description", "command", "service")
            for field in cases:
                with self.subTest(field=field):
                    spec = self._base_spec(root)
                    if field == "name":
                        spec["name"] = "safe\u202ename"
                    elif field == "summary":
                        spec["summary"] = "safe\u200dsummary"
                    elif field == "invariant":
                        spec["invariants"][0] = "safe\u2028invariant"
                    elif field == "description":
                        spec["operations"][0]["description"] = "safe\x1bdescription"
                    elif field == "command":
                        spec["operations"][1]["command"] = "true\u2066false"
                    else:
                        spec["restart_services"] = ["example.service\u202e"]
                    with self.assertRaises(ValueError):
                        validate_change_spec(spec, source_dir=root)

            spec = self._base_spec(root)
            spec["operations"][1]["command"] = "printf ok\n\ttrue"
            normalized = validate_change_spec(spec, source_dir=root)
            self.assertEqual(
                normalized["operations"][1]["command"], "printf ok\n\ttrue"
            )

    def test_change_contract_requires_executable_rollback(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["operations"] = [
                operation
                for operation in spec["operations"]
                if operation["phase"] != "rollback"
            ]
            with self.assertRaisesRegex(ValueError, "executable rollback"):
                validate_change_spec(spec, source_dir=root)

    def test_guard_is_armed_before_any_declared_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec.pop("payloads")
            spec["control_channel"] = {
                "dependency": "shared",
                "change_surfaces": ["remote-network"],
                "continuity_strategy": "automatic-rollback",
                "independent_path_verified": False,
                "operator_recovery_reviewed": True,
                "host_reboot_planned": False,
                "evidence": ["shared route confirmed"],
            }
            spec["rollback_timer"] = {"enabled": True, "delay_seconds": 600}
            spec["operations"].insert(
                0,
                {
                    "phase": "preflight",
                    "description": "read only file check",
                    "check": "file-exists",
                    "target": "/etc/test.json",
                },
            )
            spec["operations"].insert(
                1,
                {
                    "phase": "apply",
                    "description": "declared mutation",
                    "command": "touch /etc/test.json",
                    "affected_paths": ["/etc/test.json"],
                },
            )
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            success = {
                "available": True,
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "timed_out": False,
                "duration_ms": 1,
            }
            scripts = []

            def remote_script(_host, script, *, timeout):
                scripts.append(script)
                return success

            with patch("netops_core.change._remote_script", side_effect=remote_script):
                receipt = apply_plan(
                    plan_path,
                    fleet_data(),
                    authorized=True,
                    confirmed_plan_id=plan["plan_id"],
                    current_control_channel=fresh_rollback_access_evidence(
                        plan["control_channel"]
                    ),
                    receipt_path=root / "receipt.json",
                )
            self.assertEqual(receipt["status"], "applied")
            preflight_index = next(
                index for index, script in enumerate(scripts) if "test -f" in script
            )
            self.assertIn("test ! -L", scripts[preflight_index])
            backup_index = next(
                index for index, script in enumerate(scripts) if "-czpf" in script
            )
            self.assertIn("target-state.sha256", scripts[backup_index])
            self.assertIn("sha256sum --", scripts[backup_index])
            self.assertIn("--acls --xattrs --selinux --numeric-owner -czpf", scripts[backup_index])
            self.assertIn('-C "$BACKUP_STAGING_ROOT" -- etc/test.json', scripts[backup_index])
            self.assertNotIn("tar --absolute-names", scripts[backup_index])
            self.assertIn("expected-members", scripts[backup_index])
            arm_index = next(
                index for index, script in enumerate(scripts) if "systemd-run" in script
            )
            marker_index = next(
                index
                for index, script in enumerate(scripts)
                if "change.started" in script and "systemd-run" not in script
            )
            mutation_index = next(
                index
                for index, script in enumerate(scripts)
                if "touch /etc/test.json" in script
            )
            self.assertLess(preflight_index, backup_index)
            self.assertLess(backup_index, arm_index)
            self.assertLess(arm_index, marker_index)
            self.assertLess(marker_index, mutation_index)

    def test_disarm_coordinates_timer_and_service_with_state_lock(self):
        plan = {
            "plan_id": "a" * 32,
            "backup_root": "/var/backups/netops",
            "rollback_contract": {"declared_targets": ["/etc/test.json"]},
        }
        backup_dir = f"/var/backups/netops/{plan['plan_id']}/{'b' * 12}"
        success = {
            "returncode": 0,
            "stdout": BACKUP_INTEGRITY_STDOUT,
            "stderr": "",
            "duration_ms": 1,
        }
        with patch("netops_core.change._remote_script", return_value=success) as remote:
            _disarm_automatic_rollback(plan, fleet_data()["hosts"][0], backup_dir=backup_dir)
        script = remote.call_args.args[1]
        unit = f"netops-rollback-{'a' * 32}-{'b' * 12}"
        self.assertIn("rollback.lock", script)
        self.assertIn("rollback.state", script)
        self.assertIn(f"systemctl stop -- {unit}.timer", script)
        self.assertIn(f"systemctl stop -- {unit}.service", script)
        self.assertIn("write_state disarmed", script)

    def test_fleet_rejects_ssh_option_injection(self):
        for field, value in (
            ("management", "-oProxyCommand=printf injected"),
            ("management", "user@example.invalid"),
            ("config_host", "-oProxyCommand=printf-injected"),
            ("config_host", "safe\n-oProxyCommand=bad"),
        ):
            with self.subTest(field=field, value=value):
                fleet = fleet_data()
                if field == "management":
                    fleet["hosts"][0]["management"]["address"] = value
                else:
                    fleet["hosts"][0]["ssh"]["config_host"] = value
                with self.assertRaises(ValueError):
                    validate_fleet(fleet)
                with self.assertRaises(ValueError):
                    ssh_invocation(fleet["hosts"][0])

    def test_payload_upload_sink_validates_and_uses_controlled_transports(self):
        with tempfile.TemporaryDirectory() as temporary:
            payload_path = Path(temporary) / "payload"
            payload_path.write_text("payload", encoding="utf-8")
            digest = hashlib.sha256(payload_path.read_bytes()).hexdigest()
            plan = {
                "plan_id": "a" * 32,
                "backup_root": "/var/backups/netops",
                "rollback_contract": {
                    "declared_targets": ["/etc/test.json"],
                    "preflight_hashes": [
                        {
                            "target": "/etc/test.json",
                            "sha256": "a" * 64,
                            "metadata_sha256": "b" * 64,
                        }
                    ],
                },
                "control_channel": {
                    "continuity_strategy": "independent-path"
                },
                "payloads": [
                    {
                        "local_path": str(payload_path),
                        "remote_path": "/etc/test.json",
                        "mode": "0644",
                        "sha256": digest,
                    }
                ],
            }
            success = {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "duration_ms": 1,
            }
            with patch(
                "netops_core.change.run_command", return_value=success
            ) as run, patch(
                "netops_core.change._remote_script", return_value=success
            ) as remote:
                result = _upload_payloads(
                    plan,
                    fleet_data()["hosts"][0],
                    execution_id="b" * 12,
                    backup_dir=f"/var/backups/netops/{'a' * 32}/{'b' * 12}",
                )
            self.assertTrue(result)
            run.assert_called_once()
            self.assertGreaterEqual(remote.call_count, 3)

    def test_remote_output_is_redacted_in_exception_and_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec.pop("payloads")
            spec["operations"].insert(
                0,
                {
                    "phase": "apply",
                    "description": "fail safely",
                    "command": "false",
                    "affected_paths": ["/etc/test.json"],
                },
            )
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            success = {
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "duration_ms": 1,
            }
            failure = {
                **success,
                "returncode": 1,
                "stderr": "pass" + "word=SUPERSECRET",
            }
            receipt_path = root / "receipt.json"
            with patch(
                "netops_core.change._remote_script",
                side_effect=[success, failure, success, success, success],
            ):
                with self.assertRaises(RuntimeError) as raised:
                    apply_plan(
                        plan_path,
                        fleet_data(),
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        current_control_channel=fresh_rollback_access_evidence(
                            plan["control_channel"]
                        ),
                        receipt_path=receipt_path,
                    )
            receipt_text = receipt_path.read_text(encoding="utf-8")
            self.assertNotIn("SUPERSECRET", str(raised.exception))
            self.assertNotIn("SUPERSECRET", receipt_text)

    def test_payload_cleanup_failure_preserves_root_cause_and_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            success = {
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "duration_ms": 1,
            }
            install_lost = {
                **success,
                "returncode": 255,
                "stderr": "install connection lost",
            }
            cleanup_lost = {
                **success,
                "returncode": 255,
                "stderr": "cleanup connection lost",
            }
            receipt_path = root / "receipt.json"

            def remote_result(_host, script, *, timeout):
                if "INSTALL_TEMP" in script:
                    return install_lost
                if "rm -f -- ./payload-" in script:
                    return cleanup_lost
                return success

            with patch("netops_core.change.run_command", return_value=success), patch(
                "netops_core.change._remote_script",
                side_effect=remote_result,
            ):
                with self.assertRaisesRegex(RuntimeError, "install connection lost"):
                    apply_plan(
                        plan_path,
                        fleet_data(),
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        current_control_channel=fresh_rollback_access_evidence(
                            plan["control_channel"]
                        ),
                        receipt_path=receipt_path,
                    )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertIn("install connection lost", receipt["error"])
            self.assertIn(
                "cleanup connection lost", receipt["payload_cleanup_error"]
            )
            self.assertEqual(receipt["status"], "rolled-back")

    def test_manual_rollback_does_not_require_local_apply_payload(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            (root / "payload.json").unlink()

            with self.assertRaisesRegex(ValueError, "payload changed after planning"):
                load_plan(plan_path)
            with patch("netops_core.change._remote_script") as remote:
                with self.assertRaisesRegex(ValueError, "payload changed after planning"):
                    apply_plan(
                        plan_path,
                        fleet_data(),
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        current_control_channel=fresh_rollback_access_evidence(
                            plan["control_channel"]
                        ),
                        receipt_path=root / "apply-receipt.json",
                    )
            remote.assert_not_called()

            success = {
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "duration_ms": 1,
            }
            with patch(
                "netops_core.change._remote_script", return_value=success
            ) as remote:
                rollback_execution = "c" * 12
                receipt = rollback_plan(
                    plan_path,
                    fleet_data(),
                    backup_dir=(
                        f"/var/backups/netops/{plan['plan_id']}/{rollback_execution}"
                    ),
                    authorized=True,
                    confirmed_plan_id=plan["plan_id"],
                    apply_receipt_path=write_apply_receipt(
                        root, plan, rollback_execution
                    ),
                    current_control_channel=fresh_rollback_access_evidence(),
                    receipt_path=root / "rollback-receipt.json",
                )
            self.assertEqual(receipt["status"], "rolled-back")
            self.assertGreaterEqual(remote.call_count, 1)

    def test_manual_rollback_rechecks_guard_and_writes_failure_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["control_channel"] = {
                "dependency": "unknown",
                "change_surfaces": ["remote-proxy-service"],
                "continuity_strategy": "manual-recovery",
                "independent_path_verified": False,
                "operator_recovery_reviewed": True,
                "host_reboot_planned": False,
                "evidence": ["dependency remains unknown"],
            }
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            receipt_path = root / "rollback-receipt.json"
            rollback_execution = "d" * 12
            with self.assertRaisesRegex(PermissionError, "blocked rollback"):
                rollback_plan(
                    plan_path,
                    fleet_data(),
                    backup_dir=f"/var/backups/netops/{plan['plan_id']}/{rollback_execution}",
                    authorized=True,
                    confirmed_plan_id=plan["plan_id"],
                    apply_receipt_path=write_apply_receipt(
                        root, plan, rollback_execution
                    ),
                    current_control_channel={
                        "observed_at": fresh_rollback_access_evidence()["observed_at"],
                        "control_channel": spec["control_channel"],
                    },
                    receipt_path=receipt_path,
                )
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(receipt["status"], "blocked")
            self.assertEqual(receipt["control_channel_guard"]["decision"], "block")

    def test_manual_rollback_remote_failure_is_receipted_and_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            receipt_path = root / "rollback-receipt.json"
            failure = {
                "returncode": 1,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "token=ROLLBACKSECRET",
                "duration_ms": 1,
            }
            rollback_execution = "e" * 12
            with patch("netops_core.change._remote_script", return_value=failure):
                with self.assertRaises(RuntimeError) as raised:
                    rollback_plan(
                        plan_path,
                        fleet_data(),
                        backup_dir=f"/var/backups/netops/{plan['plan_id']}/{rollback_execution}",
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        apply_receipt_path=write_apply_receipt(
                            root, plan, rollback_execution
                        ),
                        current_control_channel=fresh_rollback_access_evidence(),
                        receipt_path=receipt_path,
                    )
            receipt_text = receipt_path.read_text(encoding="utf-8")
            receipt = json.loads(receipt_text)
            self.assertEqual(receipt["status"], "rollback-failed")
            self.assertNotIn("ROLLBACKSECRET", str(raised.exception))
            self.assertNotIn("ROLLBACKSECRET", receipt_text)

    def test_reviewed_prestate_hashes_are_required_and_checked_before_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["operations"][0] = {
                "phase": "preflight",
                "description": "existence alone is insufficient",
                "check": "file-exists",
                "target": "/etc/test.json",
            }
            with self.assertRaisesRegex(ValueError, "file-sha256 preflight"):
                validate_change_spec(spec, source_dir=root)

            operation = exact_file_preflight()
            command = _preflight_command(operation)
            self.assertIn(operation["sha256"], command)
            self.assertIn(operation["metadata_sha256"], command)
            self.assertIn("python3 -c", command)
            self.assertIn("os.listxattr", command)
            self.assertNotIn("getfacl", command)
            self.assertNotIn("getfattr", command)
            self.assertIn("stat -c %h", command)
            shell = shutil.which("sh")
            if shell is not None:
                subprocess.run(
                    [shell, "-n"],
                    input=command,
                    text=True,
                    check=True,
                )

            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            stale = {
                "returncode": 1,
                "stdout": "",
                "stderr": "reviewed prestate no longer matches",
                "duration_ms": 1,
            }
            with patch(
                "netops_core.change._remote_script", return_value=stale
            ), patch("netops_core.change._backup") as backup:
                with self.assertRaisesRegex(RuntimeError, "preflight failed"):
                    apply_plan(
                        plan_path,
                        fleet_data(),
                        authorized=True,
                        confirmed_plan_id=plan["plan_id"],
                        current_control_channel=fresh_rollback_access_evidence(
                            plan["control_channel"]
                        ),
                        receipt_path=root / "stale.receipt.json",
                    )
            backup.assert_not_called()

    def test_remote_metadata_program_detects_mode_and_xattr_changes(self):
        if not all(
            hasattr(os, name) for name in ("listxattr", "getxattr", "setxattr")
        ):
            self.skipTest("platform does not expose xattr APIs")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            candidate = root / "candidate"
            source.write_bytes(b"metadata\n")
            shutil.copy2(source, candidate)

            exact = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    _REMOTE_METADATA_PROGRAM,
                    "compare",
                    str(source),
                    str(candidate),
                    "exact",
                ],
                check=False,
            )
            self.assertEqual(exact.returncode, 0)

            candidate.chmod(0o600)
            exact = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    _REMOTE_METADATA_PROGRAM,
                    "compare",
                    str(source),
                    str(candidate),
                    "exact",
                ],
                check=False,
            )
            install = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    _REMOTE_METADATA_PROGRAM,
                    "compare",
                    str(source),
                    str(candidate),
                    "install",
                ],
                check=False,
            )
            self.assertNotEqual(exact.returncode, 0)
            self.assertEqual(install.returncode, 0)

            try:
                os.setxattr(candidate, "user.netops-test", b"changed")
            except OSError:
                return
            install = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    _REMOTE_METADATA_PROGRAM,
                    "compare",
                    str(source),
                    str(candidate),
                    "install",
                ],
                check=False,
            )
            self.assertNotEqual(install.returncode, 0)

    def test_remote_sqlite_program_hashes_stable_query_and_creates_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "live.db"
            snapshot = root / "snapshot.db"
            with closing(sqlite3.connect(source)) as connection:
                with connection:
                    connection.executescript(
                        "CREATE TABLE config (id INTEGER PRIMARY KEY, value TEXT);"
                        "CREATE TABLE traffic (id INTEGER PRIMARY KEY, total INTEGER);"
                        "INSERT INTO config VALUES (1, 'kept');"
                        "INSERT INTO traffic VALUES (1, 10);"
                    )
            query = "SELECT id, value FROM config ORDER BY id"

            def digest() -> str:
                result = subprocess.run(
                    [
                        sys.executable,
                        "-c",
                        _REMOTE_SQLITE_PROGRAM,
                        "digest",
                        str(source),
                        query,
                    ],
                    text=True,
                    capture_output=True,
                    check=True,
                )
                return result.stdout.strip()

            reviewed = digest()
            encoded_rows = json.dumps(
                [[["integer", 1], ["text", "kept"]]],
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            self.assertEqual(reviewed, hashlib.sha256(encoded_rows).hexdigest())
            with closing(sqlite3.connect(source)) as connection:
                with connection:
                    connection.execute("UPDATE traffic SET total = total + 1")
            self.assertEqual(digest(), reviewed)

            subprocess.run(
                [
                    sys.executable,
                    "-c",
                    _REMOTE_SQLITE_PROGRAM,
                    "backup",
                    str(source),
                    str(snapshot),
                ],
                check=True,
            )
            with closing(sqlite3.connect(snapshot)) as connection:
                self.assertEqual(
                    connection.execute("PRAGMA integrity_check").fetchone(), ("ok",)
                )
                self.assertEqual(
                    connection.execute("SELECT total FROM traffic").fetchone(), (11,)
                )

            with closing(sqlite3.connect(source)) as connection:
                with connection:
                    connection.execute("UPDATE config SET value = 'changed'")
            self.assertNotEqual(digest(), reviewed)

    def test_sqlite_backup_uses_online_snapshot_and_stable_metadata(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["backup_paths"] = ["/etc/x-ui/x-ui.db"]
            spec["payloads"] = []
            spec["operations"][0] = sqlite_query_preflight()
            spec["operations"].insert(
                1,
                {
                    "phase": "apply",
                    "description": "merge one inbound transactionally",
                    "command": "true",
                    "affected_paths": ["/etc/x-ui/x-ui.db"],
                },
            )
            spec_path = root / "sqlite-spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan = create_plan(spec_path, fleet_data(), root / "sqlite-plan.json")
            success = {
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "duration_ms": 1,
            }
            with patch(
                "netops_core.change._remote_script", return_value=success
            ) as remote:
                _backup(plan, fleet_data()["hosts"][0], execution_id="e" * 12)
            script = remote.call_args.args[1]
            self.assertEqual(script.splitlines()[0], "set -eu")
            self.assertNotIn("set -eux", script)
            self.assertIn("source.backup(destination)", script)
            self.assertIn("cp --attributes-only --preserve=all", script)
            self.assertIn("verify_file_stable_metadata", script)
            self.assertIn(sqlite_query_preflight()["query"], script)
            shell = shutil.which("sh")
            if shell is not None:
                subprocess.run([shell, "-n"], input=script, text=True, check=True)

    def test_plan_id_binds_review_metadata_and_apply_rejects_stale_plan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            create_plan(spec_path, fleet_data(), plan_path)
            data = json.loads(plan_path.read_text(encoding="utf-8"))

            data["created_at"] = "2000-01-01T00:00:00Z"
            plan_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "plan ID"):
                load_plan(plan_path)

            rehash_plan(data)
            plan_path.write_text(json.dumps(data), encoding="utf-8")
            with patch("netops_core.change._remote_script") as remote:
                with self.assertRaisesRegex(PermissionError, "older than 24 hours"):
                    apply_plan(
                        plan_path,
                        fleet_data(),
                        authorized=True,
                        confirmed_plan_id=data["plan_id"],
                        current_control_channel=fresh_rollback_access_evidence(
                            data["control_channel"]
                        ),
                        receipt_path=root / "old.receipt.json",
                    )
            remote.assert_not_called()

    def test_arm_or_mark_failure_never_runs_rollback_before_target_mutation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["control_channel"] = {
                "dependency": "shared",
                "change_surfaces": ["remote-proxy-service"],
                "continuity_strategy": "automatic-rollback",
                "independent_path_verified": False,
                "operator_recovery_reviewed": True,
                "host_reboot_planned": False,
                "evidence": ["shared management route confirmed"],
            }
            spec["rollback_timer"] = {"enabled": True, "delay_seconds": 600}
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            execution_id = "e" * 12
            backup_dir = f"/var/backups/netops/{plan['plan_id']}/{execution_id}"
            backup_result = {
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "duration_ms": 1,
                "integrity": {
                    "archive_sha256": "c" * 64,
                    "manifest_sha256": "d" * 64,
                },
            }
            success = {
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "duration_ms": 1,
            }
            for failure_point in ("arm", "mark"):
                with self.subTest(failure_point=failure_point), patch(
                    "netops_core.change.uuid.uuid4"
                ) as generated, patch(
                    "netops_core.change._remote_script", return_value=success
                ), patch(
                    "netops_core.change._backup",
                    return_value=(backup_dir, backup_result),
                ), patch(
                    "netops_core.change._restore"
                ) as restore, patch(
                    "netops_core.change._arm_automatic_rollback"
                ) as arm, patch(
                    "netops_core.change._mark_change_started"
                ) as mark:
                    generated.return_value.hex = execution_id
                    arm.return_value = {
                        "phase": "arm-automatic-rollback",
                        "returncode": 0,
                    }
                    if failure_point == "arm":
                        arm.side_effect = RuntimeError("arm failed")
                    else:
                        mark.side_effect = RuntimeError("mark failed")
                    receipt_path = root / f"{failure_point}.receipt.json"
                    with self.assertRaisesRegex(RuntimeError, f"{failure_point} failed"):
                        apply_plan(
                            plan_path,
                            fleet_data(),
                            authorized=True,
                            confirmed_plan_id=plan["plan_id"],
                            current_control_channel=fresh_rollback_access_evidence(
                                plan["control_channel"]
                            ),
                            receipt_path=receipt_path,
                        )
                    restore.assert_not_called()
                    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
                    self.assertEqual(receipt["status"], "rollback-pending")
                    self.assertIsNot(receipt.get("target_mutation_started"), True)

    def test_backup_script_binds_global_lease_hash_metadata_and_hardlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            success = {
                "returncode": 0,
                "stdout": BACKUP_INTEGRITY_STDOUT,
                "stderr": "",
                "duration_ms": 1,
            }
            with patch(
                "netops_core.change._remote_script", return_value=success
            ) as remote:
                _backup(plan, fleet_data()["hosts"][0], execution_id="f" * 12)
            script = remote.call_args.args[1]
            self.assertIn("./.active-change", script)
            self.assertIn("set -C", script)
            self.assertIn("BACKUP_READY=1", script)
            self.assertIn("stat -c %h", script)
            self.assertIn("python3 -c", script)
            self.assertIn("os.listxattr", script)
            self.assertNotIn("getfacl", script)
            self.assertNotIn("getfattr", script)
            self.assertIn("cp --preserve=all --no-dereference", script)
            validator = _validated_archive_script(
                plan,
                f"/var/backups/netops/{plan['plan_id']}/{'f' * 12}",
                restore=False,
            )
            self.assertIn(f"(\n{validator}\n)", script)

    def test_automatic_rollback_uses_kernel_lock_kill_after_and_final_restore(self):
        plan = {
            "plan_id": "a" * 32,
            "backup_root": "/var/backups/netops",
            "rollback_contract": {
                "declared_targets": ["/etc/example.conf"],
            },
            "operations": [
                {
                    "phase": "rollback",
                    "description": "rollback",
                    "command": "trap '' TERM; sleep 999",
                    "timeout_seconds": 30,
                },
                {
                    "phase": "rollback_verify",
                    "description": "verify",
                    "command": "true",
                    "timeout_seconds": 30,
                },
            ],
            "restart_services": ["example.service"],
        }
        backup_dir = f"/var/backups/netops/{plan['plan_id']}/{'b' * 12}"
        script = _automatic_rollback_script(
            plan,
            backup_dir,
            {"archive_sha256": "c" * 64, "manifest_sha256": "d" * 64},
        )
        self.assertIn("flock 9", script)
        self.assertNotIn('mkdir "$LOCK"', script)
        self.assertIn("--kill-after=5s", script)
        self.assertGreater(
            script.rfind("EXACT_RESTORED=1"),
            script.rfind("systemctl restart -- example.service"),
        )
        self.assertIn("release_active_lease", script)

    def test_shared_plan_manual_rollback_uses_fresh_independent_evidence_and_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["control_channel"] = {
                "dependency": "shared",
                "change_surfaces": ["remote-proxy-service"],
                "continuity_strategy": "automatic-rollback",
                "independent_path_verified": False,
                "operator_recovery_reviewed": True,
                "host_reboot_planned": False,
                "evidence": ["shared route confirmed by read only audit"],
            }
            spec["rollback_timer"] = {"enabled": True, "delay_seconds": 600}
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            plan = create_plan(spec_path, fleet_data(), plan_path)
            execution_id = "1" * 12
            apply_receipt = write_apply_receipt(root, plan, execution_id)
            success = {
                "returncode": 0,
                "stdout": "previous_state=rolled-back\n",
                "stderr": "",
                "duration_ms": 1,
            }
            with patch("netops_core.change._remote_script", return_value=success):
                receipt = rollback_plan(
                    plan_path,
                    fleet_data(),
                    backup_dir=(
                        f"/var/backups/netops/{plan['plan_id']}/{execution_id}"
                    ),
                    authorized=True,
                    confirmed_plan_id=plan["plan_id"],
                    apply_receipt_path=apply_receipt,
                    current_control_channel=fresh_rollback_access_evidence(),
                    receipt_path=root / "manual.receipt.json",
                )
            self.assertEqual(receipt["status"], "rolled-back")
            self.assertEqual(
                receipt["current_control_channel"]["control_channel"]["dependency"],
                "independent",
            )
            self.assertEqual(
                receipt["source_apply_receipt"]["backup_integrity"]["archive_sha256"],
                "c" * 64,
            )

    def test_change_apply_rejects_mutable_ssh_config_alias(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            fleet = fleet_data()
            fleet["hosts"][0]["ssh"] = {"config_host": "edge-config"}
            with self.assertRaisesRegex(ValueError, "config_host"):
                create_plan(spec_path, fleet, root / "plan.json")

    def test_internal_remote_shell_sink_uses_validated_ssh_transport(self):
        host = fleet_data()["hosts"][0]
        success = {
            "returncode": 0,
            "stdout": "ok",
            "stderr": "",
            "duration_ms": 1,
        }
        with patch(
            "netops_core.change.ssh_invocation", return_value=(["ssh", "edge-a"], {})
        ) as ssh, patch(
            "netops_core.change.run_command", return_value=success
        ) as run:
            result = _remote_script(host, "true", timeout=10)
        self.assertEqual(result, success)
        ssh.assert_called_once_with(host)
        run.assert_called_once()

    def test_change_spec_rejects_unknown_fields_limits_and_secret_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec["unexpected"] = True
            with self.assertRaisesRegex(ValueError, "unsupported fields"):
                validate_change_spec(spec, source_dir=root)

            spec = self._base_spec(root)
            spec["operations"][1]["command"] = "pass" + "word=TOPSECRET true"
            with self.assertRaisesRegex(ValueError, "secret material"):
                validate_change_spec(spec, source_dir=root)

            spec = self._base_spec(root)
            spec["invariants"] = [f"invariant {index}" for index in range(65)]
            with self.assertRaisesRegex(ValueError, "at most 64"):
                validate_change_spec(spec, source_dir=root)

    def test_rehashed_plan_cannot_inject_secret_or_unknown_nested_host_field(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            spec = self._base_spec(root)
            spec_path = root / "spec.json"
            spec_path.write_text(json.dumps(spec), encoding="utf-8")
            plan_path = root / "plan.json"
            create_plan(spec_path, fleet_data(), plan_path)
            data = json.loads(plan_path.read_text(encoding="utf-8"))
            data["operations"][1]["command"] = (
                "Authorization: " + "Bearer " + "abcdefghijk"
            )
            rehash_plan(data)
            plan_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "secret material"):
                load_plan(plan_path)

            second_plan_path = root / "second-plan.json"
            create_plan(spec_path, fleet_data(), second_plan_path)
            data = json.loads(second_plan_path.read_text(encoding="utf-8"))
            data["host"]["ssh"]["password"] = "TOPSECRET"
            rehash_plan(data)
            second_plan_path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unsupported fields"):
                load_plan(second_plan_path)


if __name__ == "__main__":
    unittest.main()
