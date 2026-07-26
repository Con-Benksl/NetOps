import json
import re
import unittest
from pathlib import Path

from netops_core.control_channel import (
    CONTROL_CHANNEL_KEYS,
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

    def test_unknown_dependency_warns_and_requires_consent(self):
        control = normalize_control_channel(None)
        timer = normalize_rollback_timer(None)
        result = assess_control_channel(control, timer)
        self.assertFalse(result["can_apply"])
        self.assertEqual(result["decision"], "warn")
        self.assertTrue(result["acknowledgment_required"])
        self.assertTrue(result["can_apply_with_acknowledgment"])
        self.assertIn("尚未明确", result["reasons"][0])

    def test_local_surfaces_cannot_be_acknowledged_into_remote_execution(self):
        control = normalize_control_channel(
            {
                "dependency": "shared",
                "change_surfaces": ["local-tun"],
                "continuity_strategy": "manual-recovery",
            }
        )
        timer = normalize_rollback_timer(None)
        result = assess_control_channel(control, timer)
        self.assertEqual(result["decision"], "warn")
        self.assertEqual(result["execution_mode"], "manual-local-control-plane")
        self.assertTrue(result["acknowledgment_required"])
        self.assertFalse(result["can_apply_with_acknowledgment"])

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

    def test_independent_target_requires_verification_and_recovery_review(self):
        base = {
            "dependency": "independent",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "independent-path",
            "target_independence_verified": True,
            "operator_recovery_reviewed": False,
            "evidence": ["target confirmed off the current path"],
        }
        blocked = assess_control_channel(base, {"enabled": False, "delay_seconds": 600})
        self.assertFalse(blocked["can_apply"])
        base["operator_recovery_reviewed"] = True
        allowed = assess_control_channel(base, {"enabled": False, "delay_seconds": 600})
        self.assertTrue(allowed["can_apply"])
        self.assertTrue(allowed["execution_available"])
        self.assertEqual(allowed["risk"], "guarded")
        self.assertEqual(allowed["execution_mode"], "direct-ssh-or-plan")
        self.assertIn("Codex 执行", allowed["next_action"])
        self.assertIn("明确授权", allowed["next_action"])
        self.assertIn("计划 ID", allowed["next_action"])

    def test_unrelated_target_allows_without_a_backup_channel_flag(self):
        control = {
            "dependency": "independent",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "independent-path",
            "target_independence_verified": True,
            "independent_path_verified": False,
            "operator_recovery_reviewed": True,
            "evidence": ["the current path does not traverse this VPS"],
        }
        result = assess_control_channel(
            control, {"enabled": False, "delay_seconds": 600}
        )
        self.assertTrue(result["can_apply"])
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["execution_mode"], "direct-ssh-or-plan")
        self.assertIn("不在当前 Codex 路径上", result["reasons"][-1])

    def test_target_independence_does_not_substitute_for_a_backup_channel(self):
        control = {
            "dependency": "shared",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "independent-path",
            "target_independence_verified": True,
            "independent_path_verified": False,
            "operator_recovery_reviewed": True,
            "evidence": ["the current path traverses this service"],
        }
        blocked = assess_control_channel(
            control, {"enabled": False, "delay_seconds": 600}
        )
        self.assertFalse(blocked["can_apply"])
        self.assertEqual(blocked["decision"], "warn")
        self.assertIn("independent_path_verified", blocked["reasons"][0])
        self.assertNotIn("target_independence_verified", blocked["reasons"][0])

        control["independent_path_verified"] = True
        allowed = assess_control_channel(
            control, {"enabled": False, "delay_seconds": 600}
        )
        self.assertTrue(allowed["can_apply"])
        self.assertEqual(allowed["execution_mode"], "direct-ssh-or-plan")
        self.assertIn("独立备用管理通道", allowed["reasons"][-1])

    def test_backup_channel_does_not_substitute_for_target_independence(self):
        control = {
            "dependency": "independent",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "independent-path",
            "target_independence_verified": False,
            "independent_path_verified": True,
            "operator_recovery_reviewed": True,
            "evidence": ["backup management channel tested"],
        }
        result = assess_control_channel(
            control, {"enabled": False, "delay_seconds": 600}
        )
        self.assertFalse(result["can_apply"])
        self.assertEqual(result["decision"], "warn")
        self.assertIn("target_independence_verified", result["reasons"][0])

    def test_independent_target_still_needs_a_declared_continuity_strategy(self):
        control = {
            "dependency": "independent",
            "change_surfaces": ["remote-proxy-service"],
            "continuity_strategy": "manual-recovery",
            "target_independence_verified": True,
            "operator_recovery_reviewed": True,
            "evidence": ["the current path does not traverse this VPS"],
        }
        result = assess_control_channel(
            control, {"enabled": False, "delay_seconds": 600}
        )
        self.assertFalse(result["can_apply"])
        self.assertIn("continuity_strategy", result["reasons"][0])

    def test_stale_specs_lose_the_allow_instead_of_inheriting_the_old_flag(self):
        stale = normalize_control_channel(
            {
                "dependency": "independent",
                "change_surfaces": ["remote-proxy-service"],
                "continuity_strategy": "independent-path",
                "independent_path_verified": True,
                "operator_recovery_reviewed": True,
                "evidence": ["alternate path tested"],
            }
        )
        self.assertFalse(stale["target_independence_verified"])
        self.assertTrue(stale["independent_path_verified"])
        result = assess_control_channel(
            stale, {"enabled": False, "delay_seconds": 600}
        )
        self.assertFalse(result["can_apply"])
        with self.assertRaisesRegex(ValueError, "target_independence_verified"):
            normalize_control_channel({"target_independence_verified": "yes"})

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
        self.assertTrue(allowed["execution_available"])
        self.assertEqual(allowed["risk"], "guarded-high")
        self.assertEqual(allowed["execution_mode"], "exact-plan")
        self.assertIn("首次写入前设置", allowed["reasons"][-1])

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
        self.assertEqual(result["execution_mode"], "manual-local-control-plane")
        self.assertIn("本机控制面", result["reasons"][0])

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
        self.assertEqual(result["execution_mode"], "manual-local-control-plane")
        self.assertIn("用户手动完成", result["reasons"][0])

    def test_verified_independent_target_does_not_automate_local_control_plane(self):
        control = {
            "dependency": "independent",
            "change_surfaces": ["local-tun"],
            "continuity_strategy": "independent-path",
            "target_independence_verified": True,
            "independent_path_verified": True,
            "operator_recovery_reviewed": True,
            "evidence": ["alternate management path verified"],
        }
        result = assess_control_channel(
            control, {"enabled": False, "delay_seconds": 600}
        )
        self.assertFalse(result["can_apply"])
        self.assertEqual(result["execution_mode"], "manual-local-control-plane")
        self.assertIn("远端 Linux 命令继续由 Codex 执行", result["next_action"])

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
            "target_independence_verified": True,
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
        self.assertIn("sqlite-query-sha256", unverified["reasons"][0])

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

    def test_schemas_and_example_carry_both_independence_flags(self):
        root = Path(__file__).resolve().parents[1]
        for name in ("change-spec", "change-plan"):
            with self.subTest(schema=name):
                schema = json.loads(
                    (root / f"schemas/{name}.schema.json").read_text(encoding="utf-8")
                )
                control = schema["properties"]["control_channel"]
                self.assertEqual(set(control["properties"]), CONTROL_CHANNEL_KEYS)
                self.assertIn("target_independence_verified", control["required"])
                self.assertIn("independent_path_verified", control["required"])

        example = json.loads(
            (root / "examples/change-spec.example.json").read_text(encoding="utf-8")
        )
        control_channel = normalize_control_channel(example["control_channel"])
        self.assertTrue(control_channel["target_independence_verified"])
        self.assertFalse(control_channel["independent_path_verified"])
        guard = assess_control_channel(
            control_channel, normalize_rollback_timer(example["rollback_timer"])
        )
        self.assertTrue(guard["can_apply"])
        self.assertEqual(guard["execution_mode"], "direct-ssh-or-plan")

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
