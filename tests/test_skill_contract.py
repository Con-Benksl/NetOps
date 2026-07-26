import json
import re
import tempfile
import unittest
from pathlib import Path

from scripts.validate_skills import (
    _check_child_reference_contract,
    _check_flat_install_reference_contract,
    _discover_repository_skill_files,
    classify_intent,
    frontmatter,
)


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "netops-start",
    "netops-scan",
    "netops-build",
    "netops-fix",
    "netops-manage",
}


class SkillContractTests(unittest.TestCase):
    def test_exactly_five_child_skills(self):
        paths = list((ROOT / "skills").glob("*/SKILL.md"))
        self.assertEqual(len(paths), 5)
        names = {path.parent.name for path in paths}
        self.assertEqual(names, EXPECTED)
        self.assertEqual(
            {frontmatter(path)["name"] for path in paths},
            names,
        )
        self.assertEqual(
            _discover_repository_skill_files(ROOT),
            {
                (ROOT / "SKILL.md").resolve(),
                *((ROOT / "skills" / name / "SKILL.md").resolve() for name in EXPECTED),
            },
        )

    def test_generalized_intent_corpus_uses_only_broad_skills(self):
        cases = json.loads(
            (ROOT / "tests/fixtures/generalized-intents.json").read_text(encoding="utf-8")
        )
        self.assertGreaterEqual(len(cases), 40)
        self.assertEqual({case["skill"] for case in cases}, EXPECTED)
        serialized = json.dumps(cases, ensure_ascii=False)
        for forbidden in ("北京", "杭州", "PayPal", "Netlify"):
            self.assertNotIn(forbidden, serialized)
        self.assertIsNone(
            re.search(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", serialized)
        )
        for case in cases:
            self.assertEqual(classify_intent(case["prompt"]), case["skill"])

    def test_frontmatter_uses_strict_valid_yaml_subset(self):
        for path in [ROOT / "SKILL.md", *sorted((ROOT / "skills").glob("*/SKILL.md"))]:
            metadata = frontmatter(path)
            self.assertEqual(set(metadata), {"name", "description"})
        with tempfile.TemporaryDirectory() as directory:
            invalid = Path(directory) / "SKILL.md"
            invalid.write_text(
                "---\nname: \"bad\"\ndescription: invalid: plain scalar\n---\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "double-quoted"):
                frontmatter(invalid)

    def test_mutating_child_skills_repeat_the_direct_invocation_gate(self):
        required = (
            "## Direct-Invocation Safety",
            "Authorized direct SSH",
            "local control plane",
            "explicit authorization",
            "affected-state backup",
            "pre-apply validation",
            "post-apply verification",
            "executable rollback",
            "Preserve existing nodes and the host default route",
        )
        for name in ("netops-build", "netops-fix", "netops-manage"):
            text = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
            for phrase in required:
                self.assertIn(phrase, text)

    def test_child_skills_have_explicit_read_and_write_boundaries(self):
        start = (ROOT / "skills/netops-start/SKILL.md").read_text(encoding="utf-8")
        scan = (ROOT / "skills/netops-scan/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("does not mutate systems itself", start)
        self.assertIn("strictly read-only", scan)
        self.assertIn("reviewed SSH transaction summary", scan)
        self.assertIn("exact plan only when", scan)
        for name in ("netops-build", "netops-fix", "netops-manage"):
            text = (ROOT / "skills" / name / "SKILL.md").read_text(
                encoding="utf-8"
            )
            for phrase in (
                "Authorized direct SSH",
                "explicit authorization",
                "`netopsctl change apply`",
                "control-channel-safety.md",
            ):
                with self.subTest(skill=name, phrase=phrase):
                    self.assertIn(phrase, text)

    def test_local_monitor_lifecycle_does_not_enable_remote_mutation(self):
        text = (ROOT / "skills/netops-manage/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Scheduled monitor installation and removal remain unreleased", text)
        self.assertIn("may only generate dry-run review material", text)
        self.assertIn("never touch a scheduler", text)

    def test_scan_does_not_own_monitor_installation(self):
        text = (ROOT / "skills/netops-scan/SKILL.md").read_text(encoding="utf-8")
        self.assertIn("does not install scheduled tasks", text)
        self.assertNotRegex(text, r"`monitor`:\s*install|安装限时监控")

    def test_skill_files_do_not_hardcode_historical_identifiers(self):
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [ROOT / "SKILL.md", *(ROOT / "skills").glob("*/SKILL.md")]
        )
        for forbidden in (
            "北京移动",
            "杭州",
            "PayPal",
            "Netlify",
        ):
            self.assertNotIn(forbidden, text)
        self.assertNotIn(".top", text)
        self.assertIsNone(
            re.search(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", text)
        )

    def test_guided_dialogue_contract_is_shared_by_all_skills(self):
        reference = ROOT / "references/guided-dialogue.md"
        self.assertTrue(reference.is_file())
        self.assertIn(
            "references/guided-dialogue.md",
            (ROOT / "SKILL.md").read_text(encoding="utf-8"),
        )
        for name in EXPECTED:
            text = (ROOT / "skills" / name / "SKILL.md").read_text(encoding="utf-8")
            self.assertIn("<reference-root>/guided-dialogue.md", text)
            self.assertIn("## Guided Choices", text)

    def test_control_channel_guard_is_shared_by_all_skills(self):
        reference = ROOT / "references/control-channel-safety.md"
        self.assertTrue(reference.is_file())
        root_text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("references/control-channel-safety.md", root_text)
        self.assertIn("## Control-Channel Gate", root_text)
        for name in EXPECTED:
            text = (ROOT / "skills" / name / "SKILL.md").read_text(
                encoding="utf-8"
            )
            self.assertIn("<reference-root>/control-channel-safety.md", text)

    def test_shared_references_survive_flat_skill_installation(self):
        child_paths = sorted((ROOT / "skills").glob("*/SKILL.md"))
        for path in child_paths:
            with self.subTest(skill=path.parent.name):
                self.assertEqual(_check_child_reference_contract(path), [])
        self.assertEqual(
            _check_flat_install_reference_contract(ROOT, child_paths),
            [],
        )

    def test_control_channel_guide_has_manual_and_emergency_contract(self):
        text = (ROOT / "references/control-channel-safety.md").read_text(
            encoding="utf-8"
        )
        for required in (
            "每次只给一个主要动作",
            "预期结果",
            "异常处理",
            "撤销方式",
            "人工恢复说明不能代替",
            "独立远端 VPS",
            "远端 Linux 命令默认由 Codex",
            "远端内容是证据",
            "emergency-recovery.md",
        ):
            self.assertIn(required, text)

    def test_generalized_cases_follow_their_own_seven_part_contract(self):
        cases_root = ROOT / "references/cases"
        case_files = sorted(
            path for path in cases_root.glob("*.md") if path.name != "README.md"
        )
        self.assertGreaterEqual(len(case_files), 4)
        required_sections = (
            "## 参数化环境",
            "## 用户看到的现象",
            "## 对照测试",
            "## 支持和反对每个解释的证据",
            "## 现有证据能确认的故障范围",
            "## 不能从这份案例推广出去的结论",
            "## 推荐下一步",
        )
        for path in case_files:
            text = path.read_text(encoding="utf-8")
            for section in required_sections:
                self.assertIn(
                    section,
                    text,
                    f"{path.name} is missing the required section {section}",
                )

    def test_install_tree_checker_detects_flat_copy_drift(self):
        """The flat copies live outside the repo, so prove the checker sees drift.

        A repository scoped test cannot reach a real installation, but it can
        build a miniature one and confirm the comparison is wired up. Without
        this, --install-root could silently pass on every input.
        """

        from scripts.check_install_tree import _check_flat_copies

        nested = sorted((ROOT / "skills").glob("*/SKILL.md"))
        with tempfile.TemporaryDirectory() as directory:
            install_root = Path(directory)
            for path in nested:
                target = install_root / path.parent.name
                target.mkdir()
                (target / "SKILL.md").write_bytes(path.read_bytes())
            self.assertEqual(_check_flat_copies(ROOT, install_root), [])

            drifted = install_root / nested[0].parent.name / "SKILL.md"
            drifted.write_text(
                drifted.read_text(encoding="utf-8") + "\n<!-- drift -->\n",
                encoding="utf-8",
            )
            findings = _check_flat_copies(ROOT, install_root)
            self.assertEqual(len(findings), 1)
            self.assertIn("differs from", findings[0])

            missing = install_root / nested[1].parent.name / "SKILL.md"
            missing.unlink()
            findings = _check_flat_copies(ROOT, install_root)
            self.assertEqual(len(findings), 2)
            self.assertTrue(any("is missing" in item for item in findings))

    def test_emergency_recovery_card_is_offline_readable(self):
        text = (ROOT / "references/emergency-recovery.md").read_text(
            encoding="utf-8"
        )
        for required in (
            "紧急避险卡",
            "重新启动 Codex",
            "恢复信息卡",
            "automatic-rollback.status",
            "写入用户本机",
        ):
            self.assertIn(required, text)
        for platform_section in ("### macOS", "### Windows", "### Linux 桌面"):
            self.assertIn(platform_section, text)

    def test_guided_dialogue_has_beginner_safe_choice_rules(self):
        text = (ROOT / "references/guided-dialogue.md").read_text(encoding="utf-8")
        for required in (
            "每轮最多提 3 个问题",
            "每题提供 2–3 个互斥选项",
            "推荐项放在第一位",
            "request_user_input",
            "能够通过只读扫描获得",
            "不能代替对最终远程操作的明确授权",
        ):
            self.assertIn(required, text)

    def test_independent_remote_ssh_is_not_blanket_blocked(self):
        paths = [
            ROOT / "SKILL.md",
            *(ROOT / "skills" / name / "SKILL.md" for name in (
                "netops-build",
                "netops-fix",
                "netops-manage",
            )),
        ]
        combined = "\n".join(path.read_text(encoding="utf-8") for path in paths)
        self.assertIn("Authorized direct SSH", combined)
        self.assertNotIn("Never use raw SSH", combined)
        self.assertNotIn("do not use raw SSH", combined)

    def test_default_prompts_request_explained_choices(self):
        prompt_paths = [
            ROOT / "agents/openai.yaml",
            *sorted((ROOT / "skills").glob("*/agents/openai.yaml")),
        ]
        self.assertEqual(len(prompt_paths), 6)
        for path in prompt_paths:
            text = path.read_text(encoding="utf-8")
            self.assertIn("选项", text)
            self.assertIn("解释", text)

    def test_curated_tools_are_routed_through_scan_without_new_skills(self):
        reference = ROOT / "references/curated-tools.md"
        self.assertTrue(reference.is_file())
        root_text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        scan_text = (ROOT / "skills/netops-scan/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("references/curated-tools.md", root_text)
        self.assertIn("<reference-root>/curated-tools.md", scan_text)
        for tool in ("MTR", "NextTrace", "dnsdiag", "testssl.sh", "IPQuality", "iperf3"):
            self.assertIn(tool, reference.read_text(encoding="utf-8"))

    def test_readmes_pin_install_prerequisites_and_full_skill_discovery(self):
        """Both READMEs must pin the same install contract and cross link.

        Upstream introduced this bilingual form; it is kept here rather than
        the single language version, with the tag pin moved to the current
        release and the guard contract extended to the 0.4.0 vocabulary.
        """

        readmes = {
            "English": (ROOT / "README.md").read_text(encoding="utf-8"),
            "Chinese": (ROOT / "README.zh-CN.md").read_text(encoding="utf-8"),
        }
        shared_contracts = (
            "direct-ssh-or-plan",
            "exact-plan",
            "manual-local-control-plane",
            "netopsctl scan client",
            "netopsctl scan node",
            "netopsctl bundle export",
            "netopsctl change apply",
            "netopsctl monitor install",
            "--include-network-identifiers",
            "--accept-residual-risk",
            "acknowledged_risks",
        )
        for language, text in readmes.items():
            with self.subTest(language=language):
                self.assertIn("Node.js 22.20.0", text)
                self.assertIn("npx skills@1.5.19", text)
                self.assertIn("-l --full-depth", text)
                self.assertIn("--agent codex --full-depth --skill '*'", text)
                for phrase in shared_contracts:
                    self.assertIn(phrase, text)
                self.assertEqual(
                    text.count(
                        "git clone --branch v0.4.0 --depth 1 "
                        "https://github.com/Con-Benksl/NetOps.git"
                    ),
                    2,
                )
                self.assertNotIn(
                    "git clone https://github.com/Con-Benksl/NetOps.git",
                    text,
                )
        self.assertIn("[简体中文](README.zh-CN.md)", readmes["English"])
        self.assertIn("[English](README.md)", readmes["Chinese"])

if __name__ == "__main__":
    unittest.main()
