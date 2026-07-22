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
            "reviewed exact plan ID",
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

    def test_every_child_skill_repeats_the_unreleased_remote_execution_boundary(self):
        required = (
            "This release stops",
            "plan",
            "review handoff",
            "`change apply`",
            "`change rollback`",
            "SSH mutation",
            "hidden execution path",
        )
        for name in EXPECTED:
            text = (ROOT / "skills" / name / "SKILL.md").read_text(
                encoding="utf-8"
            )
            for phrase in required:
                with self.subTest(skill=name, phrase=phrase):
                    self.assertIn(phrase, text)

    def test_local_monitor_lifecycle_does_not_enable_remote_mutation(self):
        text = (ROOT / "skills/netops-manage/SKILL.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("Scheduled monitor installation and removal are also unreleased", text)
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
            "紧急避险卡",
            "重新启动 Codex",
            "人工恢复说明不能代替",
            "automatic-rollback.status",
        ):
            self.assertIn(required, text)

    def test_guided_dialogue_has_beginner_safe_choice_rules(self):
        text = (ROOT / "references/guided-dialogue.md").read_text(encoding="utf-8")
        for required in (
            "每轮最多提 3 个问题",
            "每题提供 2–3 个互斥选项",
            "推荐项放在第一位",
            "request_user_input",
            "能够通过只读扫描获得",
            "不能代替对最终计划 ID 的明确授权",
        ):
            self.assertIn(required, text)

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

    def test_readme_pins_install_prerequisites_and_full_skill_discovery(self):
        text = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Node.js 22.20.0", text)
        self.assertIn("npx skills@1.5.19", text)
        self.assertIn("-l --full-depth", text)
        self.assertIn("--agent codex --full-depth --skill '*'", text)
        self.assertEqual(
            text.count(
                "git clone --branch v0.2.0 --depth 1 "
                "https://github.com/Con-Benksl/NetOps.git"
            ),
            2,
        )
        self.assertNotIn(
            "git clone https://github.com/Con-Benksl/NetOps.git",
            text,
        )


if __name__ == "__main__":
    unittest.main()
