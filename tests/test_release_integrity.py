import importlib.util
import tempfile
import unittest
from pathlib import Path

from scripts.release_check import (
    _check_change_execution_gate,
    _check_ci_contract,
    _check_example_contracts,
    _check_json_schemas,
    _check_manifest_contract,
    _check_monitor_execution_gate,
    _check_packaging_contract,
    _check_versions,
    _load_json_documents,
)


ROOT = Path(__file__).resolve().parents[1]


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

    def test_ci_gate_requires_linux_archive_dependencies(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workflow = (ROOT / ".github/workflows/test.yml").read_text(
                encoding="utf-8"
            )
            workflow = workflow.replace(
                "          sudo apt-get install --no-install-recommends -y acl attr\n",
                "",
            )
            workflow_path = root / ".github/workflows/test.yml"
            workflow_path.parent.mkdir(parents=True)
            workflow_path.write_text(workflow, encoding="utf-8")
            errors = _check_ci_contract(root)
        self.assertTrue(
            any("apt-get install" in item for item in errors),
            errors,
        )

    def test_remote_change_execution_requires_explicit_authorization(self):
        self.assertEqual(_check_change_execution_gate(ROOT), [])

    def test_shipped_examples_match_runtime_contracts(self):
        self.assertEqual(_check_example_contracts(ROOT), [])

    def test_scheduled_monitor_mutation_remains_unreleased(self):
        self.assertEqual(_check_monitor_execution_gate(ROOT), [])

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema"),
        "optional release dependency jsonschema is not installed",
    )
    def test_draft_2020_12_schemas_and_examples(self):
        self.assertEqual(_check_json_schemas(ROOT), [])


if __name__ == "__main__":
    unittest.main()
