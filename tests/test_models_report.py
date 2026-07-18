import tempfile
import unittest
from pathlib import Path

from netops_core.models import DiagnosticBundle, Observation, load_bundle, write_bundle
from netops_core.report import render_report


class ModelsAndReportTests(unittest.TestCase):
    def test_bundle_round_trip_and_report_order(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.targets = [{"target": "example.invalid", "port": 443, "protocol": "tcp"}]
        bundle.observations.append(
            Observation(
                vantage_point="test",
                segment="node-ingress",
                probe="tcp-connect",
                status="failed",
                evidence={"error": "timed out"},
                confidence="high",
            )
        )
        bundle.path_segments = [{"name": "node-ingress", "status": "failed"}]
        bundle.finish()
        with tempfile.TemporaryDirectory() as temporary:
            path = write_bundle(Path(temporary) / "bundle.json", bundle)
            loaded = load_bundle(path)
        self.assertEqual(loaded.run_id, bundle.run_id)
        report = render_report(loaded)
        headings = [
            "## 一句话结论",
            "## 检测到的环境",
            "## 可观测链路",
            "## 异常区段",
            "## 证据",
            "## 推荐下一步",
            "## 无法观测的部分",
            "## 进阶解释",
        ]
        positions = [report.index(item) for item in headings]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("置信度 高", report)

    def test_unknown_environment_is_not_guessed(self):
        bundle = DiagnosticBundle(mode="client", vantage_points=["test"]).finish()
        report = render_report(bundle)
        self.assertIn("不会据此猜测运营商、地区或接入方式", report)


if __name__ == "__main__":
    unittest.main()
