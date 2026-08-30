import io
import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.validate_skills import (
    _check_agent_prompt_contract,
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


INSTALL_FIXTURE = {
    "SKILL.md": "root router\n",
    "README.md": "documentation\n",
    "agents/openai.yaml": "default_prompt: root\n",
    "docs/guide.md": "guide\n",
    "netops_core/core.py": "VALUE = 1\n",
    "references/policy.md": "policy\n",
    "scripts/check.py": "print('check')\n",
    "skills/netops-build/SKILL.md": "nested workflow\n",
    "skills/netops-build/agents/openai.yaml": "default_prompt: build\n",
    "tests/test_check.py": "pass\n",
}


def build_install_fixture(directory: str) -> tuple[Path, Path, set[str]]:
    """Create a complete miniature source plus dual installed layout."""

    temporary = Path(directory)
    source = temporary / "source"
    install_root = temporary / "installed-skills"
    tracked = set(INSTALL_FIXTURE)
    for relative, content in INSTALL_FIXTURE.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    for relative in tracked:
        source_path = source / relative
        target = install_root / "netops" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source_path, target)

    nested_prefix = Path("skills/netops-build")
    for relative in tracked:
        relative_path = Path(relative)
        if not relative_path.is_relative_to(nested_prefix):
            continue
        target = install_root / "netops-build" / relative_path.relative_to(
            nested_prefix
        )
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / relative_path, target)
    return source, install_root, tracked


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

    def test_current_incidents_route_to_fix_while_evidence_requests_route_to_scan(self):
        root = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        fix = (ROOT / "skills/netops-fix/SKILL.md").read_text(encoding="utf-8")
        scan = (ROOT / "skills/netops-scan/SKILL.md").read_text(encoding="utf-8")

        self.assertEqual(classify_intent("节点突然超时，帮我排查并恢复"), "netops-fix")
        self.assertEqual(classify_intent("只保存一份当前节点基线"), "netops-scan")
        self.assertIn("A current failure starts with `netops-fix`", root)
        self.assertIn("invoke `netops-scan`", fix)
        self.assertIn("requested outcome is evidence", scan)

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
        self.assertIn("does not change the configuration or service state", scan)
        self.assertIn("declared local machine-readable JSON bundle", scan)
        self.assertIn("Authorized SSH here is for scanning only", scan)
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

    def test_control_channel_guard_is_shared_by_all_skills(self):
        reference = ROOT / "references/control-channel-safety.md"
        self.assertTrue(reference.is_file())
        root_text = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("references/control-channel-safety.md", root_text)
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
            "远端 Linux 命令默认由 Agent",
            "远端内容是证据",
            "emergency-recovery.md",
        ):
            self.assertIn(required, text)
        self.assertIn("门禁判定需要离线恢复材料时", text)
        self.assertNotIn("常见故障的处理方式", text)

        root = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("A remote mutation uses the final execution card", root)
        self.assertIn(
            "A user-performed local control-plane action uses the reference's "
            "single-step five-part format",
            root,
        )

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

    def test_install_tree_checker_compares_flat_companion_files(self):
        from scripts.check_install_tree import _check_installed_copies

        with tempfile.TemporaryDirectory() as directory:
            source, install_root, tracked = build_install_fixture(directory)
            (source / "untracked-scratch.txt").write_text(
                "dirty checkout scratch\n", encoding="utf-8"
            )
            with patch(
                "scripts.check_install_tree._tracked_files", return_value=tracked
            ) as tracked_files:
                self.assertEqual(_check_installed_copies(source, install_root), [])
            tracked_files.assert_called_once_with(source)

            companion = install_root / "netops-build/agents/openai.yaml"
            companion.write_text("default_prompt: drifted\n", encoding="utf-8")
            findings = _check_installed_copies(source, install_root, tracked)
            self.assertEqual(len(findings), 1)
            self.assertIn(str(companion), findings[0])
            self.assertIn("content differs", findings[0])

    def test_install_tree_checker_detects_missing_root_file(self):
        from scripts.check_install_tree import _check_installed_copies

        with tempfile.TemporaryDirectory() as directory:
            source, install_root, tracked = build_install_fixture(directory)
            missing = install_root / "netops/SKILL.md"
            missing.unlink()
            findings = _check_installed_copies(source, install_root, tracked)
            self.assertTrue(
                any(
                    str(missing) in item and "managed file is missing" in item
                    for item in findings
                )
            )

    def test_install_tree_checker_rejects_unmanaged_extra_file(self):
        from scripts.check_install_tree import _check_installed_copies

        with tempfile.TemporaryDirectory() as directory:
            source, install_root, tracked = build_install_fixture(directory)
            extra = install_root / "netops/unmanaged.txt"
            extra.write_text("not tracked\n", encoding="utf-8")
            findings = _check_installed_copies(source, install_root, tracked)
            self.assertTrue(
                any(
                    str(extra) in item and "unmanaged extra regular file" in item
                    for item in findings
                )
            )

    @unittest.skipIf(os.name == "nt", "POSIX executable bits are unavailable")
    def test_install_tree_checker_detects_executable_bit_drift(self):
        from scripts.check_install_tree import _check_installed_copies

        with tempfile.TemporaryDirectory() as directory:
            source, install_root, tracked = build_install_fixture(directory)
            executable = source / "scripts/check.py"
            executable.chmod(executable.stat().st_mode | 0o111)
            installed = install_root / "netops/scripts/check.py"
            findings = _check_installed_copies(source, install_root, tracked)
            self.assertTrue(
                any(
                    str(installed) in item and "executable bits differ" in item
                    for item in findings
                )
            )

    @unittest.skipIf(os.name == "nt", "POSIX executable bits are unavailable")
    def test_install_tree_checker_accepts_normalized_executable_bits(self):
        from scripts.check_install_tree import _check_installed_copies

        with tempfile.TemporaryDirectory() as directory:
            source, install_root, tracked = build_install_fixture(directory)
            source_file = source / "scripts/check.py"
            installed_file = install_root / "netops/scripts/check.py"
            source_file.chmod(0o744)
            installed_file.chmod(0o755)
            findings = _check_installed_copies(source, install_root, tracked)
            self.assertFalse(
                any("executable bits differ" in item for item in findings),
                findings,
            )

    def test_install_tree_checker_rejects_caches_packaging_and_diagnostics(self):
        from scripts.check_install_tree import CACHE_DIRS, _check_installed_copies

        with tempfile.TemporaryDirectory() as directory:
            source, install_root, tracked = build_install_fixture(directory)
            forbidden = [
                *sorted(CACHE_DIRS),
                "dist",
                "package.egg-info",
                "diagnostics",
            ]
            for name in forbidden:
                (install_root / "netops" / name).mkdir()
            findings = _check_installed_copies(source, install_root, tracked)
            for name in forbidden:
                self.assertTrue(
                    any(
                        str(install_root / "netops" / name) in item
                        for item in findings
                    ),
                    f"installed residue {name!r} was not rejected: {findings}",
                )

    def test_install_tree_checker_rejects_generated_file_residue(self):
        from scripts.check_install_tree import _check_installed_copies

        with tempfile.TemporaryDirectory() as directory:
            source, install_root, tracked = build_install_fixture(directory)
            names = (
                ".DS_Store",
                ".coverage",
                ".coverage.worker",
                "module.pyc",
                "module.pyo",
                "package.egg",
                "package.tar.gz",
                "package.whl",
                "support.zip",
            )
            for name in names:
                (install_root / "netops" / name).write_bytes(b"residue")
            findings = _check_installed_copies(source, install_root, tracked)
            for name in names:
                self.assertTrue(
                    any(
                        str(install_root / "netops" / name) in item
                        and "forbidden generated file residue" in item
                        for item in findings
                    ),
                    f"installed residue {name!r} was not rejected: {findings}",
                )

    def test_source_tree_checker_allows_untracked_dirty_caches(self):
        from scripts.check_install_tree import _check_tree

        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            (source / ".git").mkdir()
            (source / ".pytest_cache").mkdir()
            with patch(
                "scripts.check_install_tree._tracked_files",
                return_value={"SKILL.md"},
            ):
                self.assertEqual(_check_tree(source), [])

    def test_install_tree_checker_rejects_symlink_without_following_it(self):
        from scripts.check_install_tree import _check_installed_copies

        with tempfile.TemporaryDirectory() as directory:
            source, install_root, tracked = build_install_fixture(directory)
            target = install_root / "netops/references/policy.md"
            target.unlink()
            try:
                target.symlink_to(source / "references/policy.md")
            except OSError as exc:
                self.skipTest(f"symlinks unavailable on this platform: {exc}")
            findings = _check_installed_copies(source, install_root, tracked)
            self.assertTrue(
                any(
                    str(target) in item
                    and "found symlink" in item
                    and "not followed" in item
                    for item in findings
                )
            )

    def test_install_tree_cli_rejects_symlink_install_root(self):
        from scripts.check_install_tree import main

        with tempfile.TemporaryDirectory() as directory:
            real_root = Path(directory) / "real-skills"
            real_root.mkdir()
            linked_root = Path(directory) / "linked-skills"
            try:
                linked_root.symlink_to(real_root, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable on this platform: {exc}")
            stderr = io.StringIO()
            with patch("sys.stderr", stderr):
                result = main([str(ROOT), "--install-root", str(linked_root)])
            self.assertEqual(result, 1)
            self.assertIn("found symlink; symlinks are not followed", stderr.getvalue())

    def test_emergency_recovery_card_is_offline_readable(self):
        text = (ROOT / "references/emergency-recovery.md").read_text(
            encoding="utf-8"
        )
        for required in (
            "紧急避险卡",
            "重新启动 Agent",
            "恢复信息卡",
            "automatic-rollback.status",
            "写入用户本机",
        ):
            self.assertIn(required, text)
        for platform_section in ("### macOS", "### Windows", "### Linux 桌面"):
            self.assertIn(platform_section, text)

    def test_guided_dialogue_asks_only_when_the_answer_changes_the_work(self):
        text = (ROOT / "references/guided-dialogue.md").read_text(encoding="utf-8")
        for required in (
            "目标、范围和授权边界明确时直接处理，不先展示流程菜单",
            "只有缺少的用户选择无法通过安全的只读检查获得",
            "默认一次只问一个问题",
            "不把讲解深度、扫描深度或流程阶段做成默认菜单",
            "不能代替对最终远程操作的明确授权",
        ):
            self.assertIn(required, text)

    def test_final_execution_card_binds_authorization_to_exact_scope(self):
        guided = (ROOT / "references/guided-dialogue.md").read_text(encoding="utf-8")
        control = (ROOT / "references/control-channel-safety.md").read_text(
            encoding="utf-8"
        )
        for required in (
            "## 唯一最终执行卡",
            "执行卡 ID",
            "完整计划 ID",
            "执行并接受本卡列出的残余风险",
            "只保留方案",
            "取消",
            "原授权立即失效",
            "生成新的执行卡 ID 并重新确认",
        ):
            self.assertIn(required, guided)
        self.assertLess(
            guided.index("执行并接受本卡列出的残余风险"),
            guided.index("只保留方案"),
        )
        self.assertLess(guided.index("只保留方案"), guided.index("`取消`"))
        self.assertIn("guided-dialogue.md", control)
        self.assertIn("同一张最终执行卡", control)

    def test_build_runbook_delegates_the_safety_contract(self):
        text = (ROOT / "references/build-runbook.md").read_text(encoding="utf-8")
        for reference in (
            "control-channel-safety.md",
            "independence-protocol.md",
            "guided-dialogue.md",
        ):
            self.assertIn(reference, text)
        self.assertIn("本手册不再定义上述门禁或执行合同", text)
        self.assertNotIn("共享控制通道未知时停止在计划阶段", text)
        self.assertNotIn("## 直接 SSH 事务合同", text)
        self.assertNotIn("## 执行与手动远端恢复的当前证据", text)

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

    def test_default_prompts_do_not_force_a_menu_before_work(self):
        prompt_paths = {"netops": ROOT / "agents/openai.yaml"}
        prompt_paths.update(
            {
                path.parents[1].name: path
                for path in sorted((ROOT / "skills").glob("*/agents/openai.yaml"))
            }
        )
        self.assertEqual(set(prompt_paths), {"netops", *EXPECTED})
        for name, path in prompt_paths.items():
            self.assertEqual(_check_agent_prompt_contract(path, name), [])

    def test_agent_short_description_length_contract_without_yaml_dependency(self):
        prompt = (
            '用 $netops 直接处理明确目标；'
            '只有缺少会改变结果的信息时才问一个问题。'
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "openai.yaml"
            for length, accepted in (
                (24, False),
                (25, True),
                (64, True),
                (65, False),
            ):
                with self.subTest(length=length):
                    path.write_text(
                        "interface:\n"
                        '  display_name: "NetOps"\n'
                        "  short_description: "
                        f"{json.dumps('网' * length, ensure_ascii=False)}\n"
                        f"  default_prompt: {json.dumps(prompt, ensure_ascii=False)}\n",
                        encoding="utf-8",
                    )
                    errors = _check_agent_prompt_contract(path, "netops")
                    length_errors = [
                        error for error in errors if "25-64 characters" in error
                    ]
                    self.assertEqual(length_errors == [], accepted, errors)

    def test_documented_output_contract_defaults_to_json_and_conversation(self):
        agents = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        english = (ROOT / "README.md").read_text(encoding="utf-8")
        chinese = (ROOT / "README.zh-CN.md").read_text(encoding="utf-8")

        self.assertIn("Ordinary questions create no artefact", agents)
        self.assertIn("formal scan writes machine readable JSON by default", agents)
        self.assertIn("current conversation", agents)
        self.assertIn("explicitly requests or exports one", agents)
        self.assertIn("Ordinary questions and configuration advice create", contributing)
        self.assertIn("bundle inspect client.json --report-output client-review.md", english)
        self.assertIn("bundle inspect client.json --report-output client-review.md", chinese)
        self.assertNotIn("Two files land", english)
        self.assertNotIn("每次扫描都会同时输出 JSON 和中文 Markdown 报告", chinese)

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

    def test_evidence_policy_and_cases_are_conditionally_disclosed(self):
        scan = (ROOT / "skills/netops-scan/SKILL.md").read_text(encoding="utf-8")
        model = (ROOT / "references/troubleshooting-model.md").read_text(
            encoding="utf-8"
        )
        cases = (ROOT / "references/cases/README.md").read_text(encoding="utf-8")

        self.assertIn("<reference-root>/source-policy.md", scan)
        self.assertIn("source-policy.md", model)
        self.assertIn("cases/README.md", model)
        self.assertIn("worked examples", model)
        for name in (
            "intermittent-shared-node.md",
            "dual-stack-tun.md",
            "destination-refusal.md",
            "per-node-egress.md",
        ):
            self.assertIn(name, cases)

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
                        "git clone --branch v0.5.1 --depth 1 "
                        "https://github.com/Con-Benksl/NetOps.git"
                    ),
                    2,
                )
                self.assertIn("[LINUX DO](https://linux.do)", text)
                self.assertNotIn(
                    "git clone https://github.com/Con-Benksl/NetOps.git",
                    text,
                )
        self.assertIn("[简体中文](README.zh-CN.md)", readmes["English"])
        self.assertIn("[English](README.md)", readmes["Chinese"])

if __name__ == "__main__":
    unittest.main()
