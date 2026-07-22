import json
import re
import unittest
from pathlib import Path

from netops_core.control_channel import (
    assess_control_channel,
    emergency_steps,
    normalize_control_channel,
    normalize_rollback_timer,
)


class ControlChannelTests(unittest.TestCase):
    @staticmethod
    def rollback_contract(**overrides):
        contract = {
            "declared_targets": ["/etc/example.conf"],
            "covered_targets": ["/etc/example.conf"],
            "uncovered_targets": [],
            "preflight_file_targets": ["/etc/example.conf"],
            "preflight_hashes": [
                {
                    "target": "/etc/example.conf",
                    "sha256": "a" * 64,
                    "metadata_sha256": "b" * 64,
                }
            ],
            "unverified_targets": [],
            "inexact_backup_paths": [],
            "restore_strategy": "exact-existing-files-content-mode-owner-mtime-acl-xattr-selinux",
            "rollback_operations": 1,
            "minimum_delay_seconds": 180,
            "executable": True,
        }
        contract.update(overrides)
        return contract

    def test_unknown_dependency_blocks_apply(self):
        control = normalize_control_channel(None)
        timer = normalize_rollback_timer(None)
        result = assess_control_channel(control, timer)
        self.assertFalse(result["can_apply"])
        self.assertEqual(result["decision"], "block")
        self.assertIn("尚未明确", result["reasons"][0])

    def test_safety_objects_reject_unknown_fields_instead_of_defaulting_typos(self):
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            normalize_control_channel({"host_reboot_planed": True})
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            normalize_rollback_timer(
                {"enabled": True, "delay_seconds": 600, "enabeld": False}
            )
        contract = self.rollback_contract(unexpected=True)
        control = {
            "dependency": "shared",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "automatic-rollback",
            "independent_path_verified": False,
            "operator_recovery_reviewed": True,
            "host_reboot_planned": False,
            "evidence": ["shared path verified by audit"],
        }
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            assess_control_channel(
                control,
                {"enabled": True, "delay_seconds": 600},
                rollback_contract=contract,
            )

    def test_independent_path_requires_verification_and_recovery_review(self):
        base = {
            "dependency": "independent",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "independent-path",
            "independent_path_verified": True,
            "operator_recovery_reviewed": False,
            "evidence": ["alternate path tested"],
        }
        blocked = assess_control_channel(base, {"enabled": False, "delay_seconds": 600})
        self.assertFalse(blocked["can_apply"])
        base["operator_recovery_reviewed"] = True
        allowed = assess_control_channel(base, {"enabled": False, "delay_seconds": 600})
        self.assertTrue(allowed["can_apply"])
        self.assertFalse(allowed["execution_available"])
        self.assertEqual(allowed["risk"], "guarded")
        self.assertIn("只生成计划并交接", allowed["next_action"])
        self.assertNotIn("按已审核计划执行", allowed["next_action"])

    def test_shared_path_needs_rollback(self):
        control = {
            "dependency": "shared",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "automatic-rollback",
            "independent_path_verified": False,
            "operator_recovery_reviewed": True,
            "evidence": ["shared path confirmed"],
        }
        blocked = assess_control_channel(
            control, {"enabled": False, "delay_seconds": 600}
        )
        self.assertFalse(blocked["can_apply"])
        allowed = assess_control_channel(
            control,
            {"enabled": True, "delay_seconds": 600},
            rollback_contract=self.rollback_contract(),
        )
        self.assertTrue(allowed["can_apply"])
        self.assertFalse(allowed["execution_available"])
        self.assertEqual(allowed["risk"], "guarded-high")
        self.assertIn("不会武装 timer 或执行变更", allowed["reasons"][-1])

    def test_manual_recovery_never_bypasses_automatic_guard(self):
        control = {
            "dependency": "shared",
            "change_surfaces": ["local-proxy-app", "local-tun"],
            "continuity_strategy": "manual-recovery",
            "independent_path_verified": False,
            "operator_recovery_reviewed": True,
            "evidence": ["shared local path confirmed"],
        }
        result = assess_control_channel(
            control, {"enabled": False, "delay_seconds": 600}
        )
        self.assertFalse(result["can_apply"])
        self.assertIn("本版本不会自动应用", result["reasons"][0])

    def test_remote_timer_cannot_guard_local_tun_changes(self):
        control = {
            "dependency": "shared",
            "change_surfaces": ["local-tun"],
            "continuity_strategy": "automatic-rollback",
            "independent_path_verified": False,
            "operator_recovery_reviewed": True,
            "evidence": ["shared local path confirmed"],
        }
        result = assess_control_channel(
            control, {"enabled": True, "delay_seconds": 600}
        )
        self.assertFalse(result["can_apply"])
        self.assertIn("不能恢复本机组件", result["reasons"][0])

    def test_transient_timer_cannot_guard_a_host_reboot(self):
        control = {
            "dependency": "shared",
            "change_surfaces": ["remote-network"],
            "continuity_strategy": "automatic-rollback",
            "independent_path_verified": False,
            "operator_recovery_reviewed": True,
            "host_reboot_planned": True,
            "evidence": ["shared host confirmed"],
        }
        result = assess_control_channel(
            control, {"enabled": True, "delay_seconds": 600}
        )
        self.assertFalse(result["can_apply"])
        self.assertIn("不能保护", result["reasons"][0])

    def test_emergency_steps_include_platform_specific_proxy_recovery(self):
        steps = emergency_steps("windows")
        self.assertTrue(any("网络和 Internet" in item for item in steps))
        self.assertTrue(any("手机热点" in item for item in steps))
        self.assertTrue(any("重新启动 Codex" in item for item in steps))

    def test_rejects_unknown_surface_and_unsafe_delay(self):
        with self.assertRaisesRegex(ValueError, "unsupported"):
            normalize_control_channel({"change_surfaces": ["anything"]})
        with self.assertRaisesRegex(ValueError, "120..3600"):
            normalize_rollback_timer({"enabled": True, "delay_seconds": 30})
        with self.assertRaisesRegex(ValueError, "120..3600"):
            normalize_rollback_timer({"enabled": True, "delay_seconds": True})

    def test_allow_requires_auditable_evidence(self):
        control = {
            "dependency": "independent",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "independent-path",
            "independent_path_verified": True,
            "operator_recovery_reviewed": True,
            "evidence": [],
        }
        result = assess_control_channel(
            control, {"enabled": False, "delay_seconds": 600}
        )
        self.assertFalse(result["can_apply"])
        self.assertIn("可审核证据", result["reasons"][0])

        control["evidence"] = ["x"]
        with self.assertRaisesRegex(ValueError, "8..500"):
            assess_control_channel(
                control, {"enabled": False, "delay_seconds": 600}
            )

        control["evidence"] = ["pass" + "word=do-not-store"]
        with self.assertRaisesRegex(ValueError, "non-secret audit reference"):
            assess_control_channel(
                control, {"enabled": False, "delay_seconds": 600}
            )

        control["evidence"] = ["vmess" + "://" + "encoded-node-secret"]
        with self.assertRaisesRegex(ValueError, "non-secret audit reference"):
            assess_control_channel(
                control, {"enabled": False, "delay_seconds": 600}
            )

        for unsafe in ("reviewed path \u202egpj.exe", "reviewed path a\u200db", "reviewed\u2028path"):
            with self.subTest(unsafe=repr(unsafe)):
                control["evidence"] = [unsafe]
                with self.assertRaisesRegex(ValueError, "printable characters"):
                    assess_control_channel(
                        control, {"enabled": False, "delay_seconds": 600}
                    )

    def test_automatic_rollback_requires_contract_and_sufficient_timer(self):
        control = {
            "dependency": "shared",
            "change_surfaces": ["remote-network"],
            "continuity_strategy": "automatic-rollback",
            "operator_recovery_reviewed": True,
            "evidence": ["shared route confirmed"],
        }
        missing = assess_control_channel(
            control, {"enabled": True, "delay_seconds": 600}
        )
        self.assertFalse(missing["can_apply"])
        self.assertIn("回滚合同", missing["reasons"][0])

        too_short = assess_control_channel(
            control,
            {"enabled": True, "delay_seconds": 120},
            rollback_contract=self.rollback_contract(minimum_delay_seconds=180),
        )
        self.assertFalse(too_short["can_apply"])
        self.assertIn("保护窗口", too_short["reasons"][0])

    def test_automatic_rollback_rejects_uncovered_targets(self):
        control = {
            "dependency": "shared",
            "change_surfaces": ["remote-firewall"],
            "continuity_strategy": "automatic-rollback",
            "operator_recovery_reviewed": True,
            "evidence": ["shared firewall host confirmed"],
        }
        result = assess_control_channel(
            control,
            {"enabled": True, "delay_seconds": 600},
            rollback_contract=self.rollback_contract(
                covered_targets=[],
                uncovered_targets=["/etc/firewall.conf"],
                executable=False,
            ),
        )
        self.assertFalse(result["can_apply"])
        self.assertIn("未覆盖目标", result["reasons"][0])

        unverified = assess_control_channel(
            control,
            {"enabled": True, "delay_seconds": 600},
            rollback_contract=self.rollback_contract(
                preflight_file_targets=[],
                preflight_hashes=[],
                unverified_targets=["/etc/example.conf"],
                executable=False,
            ),
        )
        self.assertFalse(unverified["can_apply"])
        self.assertIn("file-sha256", unverified["reasons"][0])

    def test_manual_remote_rollback_requires_an_independent_path(self):
        control = {
            "dependency": "shared",
            "change_surfaces": ["remote-network"],
            "continuity_strategy": "automatic-rollback",
            "operator_recovery_reviewed": True,
            "evidence": ["shared route confirmed"],
        }
        result = assess_control_channel(
            control,
            {"enabled": True, "delay_seconds": 600},
            rollback_contract=self.rollback_contract(),
            require_independent_path=True,
        )
        self.assertFalse(result["can_apply"])
        self.assertIn("手动远端回滚", result["reasons"][0])

    def test_rollback_contract_rejects_noncanonical_or_unsafe_paths(self):
        control = {
            "dependency": "shared",
            "change_surfaces": ["remote-network"],
            "continuity_strategy": "automatic-rollback",
            "operator_recovery_reviewed": True,
            "evidence": ["shared route confirmed"],
        }
        for unsafe in (
            "//etc/example.conf",
            "/etc//example.conf",
            "/etc/./example.conf",
            "/etc/example\\alias.conf",
            "/etc/example\u202e.conf",
        ):
            with self.subTest(path=repr(unsafe)):
                contract = self.rollback_contract(declared_targets=[unsafe])
                with self.assertRaisesRegex(
                    ValueError, "leading slash|canonical|control|backslash"
                ):
                    assess_control_channel(
                        control,
                        {"enabled": True, "delay_seconds": 600},
                        rollback_contract=contract,
                    )

    def test_change_schema_patterns_mirror_review_and_remote_path_guards(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("change-spec", "change-plan"):
            with self.subTest(schema=name):
                schema = json.loads(
                    (root / f"schemas/{name}.schema.json").read_text(encoding="utf-8")
                )
                path_pattern = re.compile(
                    schema["$defs"]["canonicalRemotePath"]["pattern"]
                )
                review_pattern = re.compile(schema["$defs"]["reviewText"]["pattern"])
                shell_pattern = re.compile(schema["$defs"]["shellCommand"]["pattern"])

                self.assertIsNotNone(path_pattern.fullmatch("/etc/example.conf"))
                for unsafe in (
                    "//etc/example.conf",
                    "/etc//example.conf",
                    "/etc/./example.conf",
                    "/etc/example\\alias.conf",
                    "/etc/example\u202e.conf",
                ):
                    self.assertIsNone(path_pattern.fullmatch(unsafe))
                self.assertIsNone(review_pattern.fullmatch("reviewed\u200dpath"))
                self.assertIsNone(shell_pattern.fullmatch("true\rfalse"))
                self.assertIsNone(shell_pattern.fullmatch("true\u202efalse"))
                self.assertIsNotNone(shell_pattern.fullmatch("true\n\ttrue"))


if __name__ == "__main__":
    unittest.main()
