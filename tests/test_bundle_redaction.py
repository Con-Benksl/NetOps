import json
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from netops_core.bundle import export_bundle, inspect_bundle
from netops_core.models import DiagnosticBundle, Observation, write_bundle


class BundleRedactionTests(unittest.TestCase):
    def test_export_flushes_archive_through_writable_descriptor(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"]).finish()
        real_fsync = os.fsync
        fsync_calls: list[int] = []

        def require_writable_descriptor(descriptor: int) -> None:
            # A zero-byte write changes no archive data, but fails with EBADF
            # when the descriptor is read-only.  This reproduces Windows'
            # ``fsync`` access requirement on POSIX CI as well.
            os.write(descriptor, b"")
            real_fsync(descriptor)
            fsync_calls.append(descriptor)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = write_bundle(root / "source.json", bundle)
            with patch(
                "netops_core.bundle.os.fsync",
                side_effect=require_writable_descriptor,
            ):
                archive = export_bundle(source, root / "export.zip")

            self.assertTrue(archive.is_file())
            self.assertTrue(fsync_calls)

    def test_export_redacts_network_identity_and_credentials(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.environment = {"platform": {"hostname": "personal-laptop"}}
        bundle.targets = [
            {
                "target": "node.customer-example.com",
                "port": 443,
                "protocol": "tcp",
            }
        ]
        bundle.observations.append(
            Observation(
                vantage_point="local",
                segment="public-egress",
                probe="test",
                status="ok",
                target=(
                    "https://"
                    + "user"
                    + ":"
                    + "secret"
                    + "@node.customer-example.com/"
                ),
                evidence={"ip": "198.51.100.77", "path": str(Path.home() / "secret")},
            )
        )
        bundle.finish()
        with tempfile.TemporaryDirectory() as temporary:
            source = write_bundle(Path(temporary) / "source.json", bundle)
            archive = export_bundle(source, Path(temporary) / "export.zip")
            inspected, report = inspect_bundle(archive)
            with zipfile.ZipFile(archive) as handle:
                raw = handle.read("bundle.json").decode("utf-8")
                manifest = json.loads(handle.read("manifest.json"))
        self.assertNotIn("customer-example.com", raw)
        self.assertNotIn("198.51.100.77", raw)
        self.assertNotIn("user:secret", raw)
        self.assertNotIn(str(Path.home()), raw)
        self.assertNotIn("personal-laptop", raw)
        self.assertIn("ip-address", manifest["redactions"])
        self.assertIn("hostname", manifest["redactions"])
        self.assertEqual(inspected.run_id, bundle.run_id)
        self.assertEqual(inspected.schema_version, "2.0")
        self.assertIn("NetOps 诊断报告", report)


if __name__ == "__main__":
    unittest.main()
