import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.release_check import (
    _check_change_execution_gate,
    _check_ci_contract,
    _check_example_contracts,
    _check_json_schemas,
    _check_manifest_contract,
    _check_monitor_execution_gate,
    _check_packaging_contract,
    _check_release_changelog,
    _check_release_mode,
    _check_versions,
    _load_json_documents,
)


ROOT = Path(__file__).resolve().parents[1]


def run_git(root: Path, *arguments: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=True,
    )


def write_release_fixture(root: Path, *, meaningful: bool = True) -> None:
    (root / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "1.2.3"\n',
        encoding="utf-8",
    )
    release_body = (
        "### Changed\n\n- Added a meaningful release integrity fixture."
        if meaningful
        else "Nothing yet."
    )
    (root / "CHANGELOG.md").write_text(
        "# Changelog\n\n"
        "## [Unreleased]\n\nNothing yet.\n\n"
        "## [1.2.3] - 2026-08-29\n\n"
        f"{release_body}\n\n"
        "[Unreleased]: https://example.test/compare/v1.2.3...HEAD\n"
        "[1.2.3]: https://example.test/compare/v1.2.2...v1.2.3\n",
        encoding="utf-8",
    )


class ReleaseIntegrityTests(unittest.TestCase):
    def test_all_shipped_json_documents_parse(self):
        self.assertEqual(_load_json_documents(ROOT), [])

    def test_package_versions_match(self):
        self.assertEqual(_check_versions(ROOT), [])

    def test_packaging_and_ci_release_contracts(self):
        self.assertEqual(_check_packaging_contract(ROOT), [])
        self.assertEqual(_check_manifest_contract(ROOT), [])
        self.assertEqual(_check_ci_contract(ROOT), [])

    def test_manifest_gate_rejects_an_incomplete_source_contract(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "MANIFEST.in").write_text("include README.md\n", encoding="utf-8")
            errors = _check_manifest_contract(root)
        self.assertTrue(errors)
        self.assertTrue(any("recursive-include tests *" in item for item in errors))

    def test_manifest_gate_rejects_a_contradictory_directive(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
            (root / "MANIFEST.in").write_text(
                manifest + "global-exclude *\n",
                encoding="utf-8",
            )
            errors = _check_manifest_contract(root)
        self.assertTrue(any("unexpected directive" in item for item in errors))

    def test_manifest_gate_requires_nested_forbidden_directory_prunes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
            manifest = manifest.replace("prune */*/.pytest_cache\n", "", 1)
            (root / "MANIFEST.in").write_text(manifest, encoding="utf-8")
            errors = _check_manifest_contract(root)
        self.assertTrue(
            any("prune */*/.pytest_cache" in item for item in errors),
            errors,
        )

    def test_manifest_gate_requires_agents_policy_in_sdist(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
            manifest = manifest.replace("include AGENTS.md\n", "", 1)
            (root / "MANIFEST.in").write_text(manifest, encoding="utf-8")
            errors = _check_manifest_contract(root)
        self.assertTrue(any("include AGENTS.md" in item for item in errors), errors)

    def test_manifest_gate_requires_only_the_github_contract_files(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
            manifest = manifest.replace(
                "include .github/PULL_REQUEST_TEMPLATE.md\n",
                "",
                1,
            )
            (root / "MANIFEST.in").write_text(manifest, encoding="utf-8")
            missing_errors = _check_manifest_contract(root)
            self.assertTrue(
                any(
                    "include .github/PULL_REQUEST_TEMPLATE.md" in item
                    for item in missing_errors
                ),
                missing_errors,
            )

            (root / "MANIFEST.in").write_text(
                (ROOT / "MANIFEST.in").read_text(encoding="utf-8")
                + "recursive-include .github *\n",
                encoding="utf-8",
            )
            broad_errors = _check_manifest_contract(root)
            self.assertTrue(
                any("unexpected directive" in item for item in broad_errors),
                broad_errors,
            )

    def test_release_mode_accepts_clean_exact_tag_with_release_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_release_fixture(root)
            run_git(root, "init")
            run_git(root, "config", "user.name", "NetOps Test")
            run_git(root, "config", "user.email", "netops-test@example.test")
            run_git(root, "add", ".")
            run_git(root, "commit", "-m", "release fixture")
            run_git(root, "tag", "v1.2.3")
            self.assertEqual(_check_release_mode(root), [])

    def test_release_mode_rejects_dirty_tree_and_same_version_drift(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_release_fixture(root)
            run_git(root, "init")
            run_git(root, "config", "user.name", "NetOps Test")
            run_git(root, "config", "user.email", "netops-test@example.test")
            run_git(root, "add", ".")
            run_git(root, "commit", "-m", "release fixture")
            run_git(root, "tag", "v1.2.3")

            (root / "dirty.txt").write_text("not committed\n", encoding="utf-8")
            dirty_errors = _check_release_mode(root)
            self.assertTrue(any("worktree changes" in item for item in dirty_errors))

            run_git(root, "add", "dirty.txt")
            run_git(root, "commit", "-m", "same version drift")
            drift_errors = _check_release_mode(root)
            self.assertTrue(any("already tagged" in item for item in drift_errors))
            self.assertTrue(any("only version tag" in item for item in drift_errors))

    def test_release_changelog_requires_meaningful_version_evidence(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_release_fixture(root, meaningful=False)
            errors = _check_release_changelog(root, "1.2.3")
        self.assertTrue(any("meaningful bullet-point" in item for item in errors), errors)

    def test_release_changelog_rejects_invalid_dates_and_duplicate_sections(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            write_release_fixture(root)
            changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
            (root / "CHANGELOG.md").write_text(
                changelog.replace("2026-08-29", "2026-99-99", 1),
                encoding="utf-8",
            )
            date_errors = _check_release_changelog(root, "1.2.3")
            self.assertTrue(
                any("invalid ISO release date" in item for item in date_errors),
                date_errors,
            )

            (root / "CHANGELOG.md").write_text(
                changelog
                + "\n## [Unreleased]\n\n- Duplicate unreleased section.\n"
                + "\n## [1.2.3] - 2026-08-29\n\n- Duplicate release section.\n",
                encoding="utf-8",
            )
            duplicate_errors = _check_release_changelog(root, "1.2.3")
            self.assertTrue(
                any("duplicate [Unreleased]" in item for item in duplicate_errors),
                duplicate_errors,
            )
            self.assertTrue(
                any("duplicate [1.2.3]" in item for item in duplicate_errors),
                duplicate_errors,
            )

    def test_ci_gate_requires_reproducible_builder_and_explicit_epoch(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workflow = (ROOT / ".github/workflows/test.yml").read_text(
                encoding="utf-8"
            )
            workflow = workflow.replace(
                "python scripts/reproducible_build.py .",
                "python -m build --sdist --wheel --outdir dist",
            ).replace('SOURCE_DATE_EPOCH: "1720000000"\n', "")
            workflow_path = root / ".github/workflows/test.yml"
            workflow_path.parent.mkdir(parents=True)
            workflow_path.write_text(workflow, encoding="utf-8")
            errors = _check_ci_contract(root)
        self.assertTrue(
            any("reproducible_build.py" in item for item in errors),
            errors,
        )
        self.assertTrue(
            any("SOURCE_DATE_EPOCH" in item for item in errors),
            errors,
        )


    def test_remote_change_execution_requires_explicit_authorization(self):
        self.assertEqual(_check_change_execution_gate(ROOT), [])

    def test_shipped_examples_match_runtime_contracts(self):
        self.assertEqual(_check_example_contracts(ROOT), [])

    def test_scheduled_monitor_mutation_remains_unreleased(self):
        self.assertEqual(_check_monitor_execution_gate(ROOT), [])

    def test_monitor_review_gates_reject_process_execution(self):
        import netops_core.monitor as monitor_module
        from scripts.installed_smoke import _check_monitor_api_gates

        original_status = monitor_module.monitor_status

        def status_with_process(*, scope):
            subprocess.run([sys.executable, "-c", "pass"], check=True)
            return original_status(scope=scope)

        with patch.object(monitor_module, "monitor_status", status_with_process):
            with self.subTest(gate="release"):
                errors = _check_monitor_execution_gate(ROOT)
                self.assertTrue(
                    any("attempted to start a process" in item for item in errors),
                    errors,
                )
            with self.subTest(gate="installed"), tempfile.TemporaryDirectory() as raw:
                with self.assertRaisesRegex(AssertionError, "attempted to start a process"):
                    _check_monitor_api_gates(str(ROOT / "netopsctl"), cwd=Path(raw))

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "optional release dependency jsonschema is not installed",
    )
    def test_draft_2020_12_schemas_and_examples(self):
        self.assertEqual(_check_json_schemas(ROOT), [])


if __name__ == "__main__":
    unittest.main()
