import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from netops_core.bundle import export_bundle, inspect_bundle
from netops_core.models import DiagnosticBundle, Observation, write_bundle


class BundleRedactionTests(unittest.TestCase):
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
        self.assertEqual(inspected.schema_version, "1.0")
        self.assertIn("NetOps 诊断报告", report)


if __name__ == "__main__":
    unittest.main()
