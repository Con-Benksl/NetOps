import tempfile
import unittest
from pathlib import Path

from netops_core.models import (
    DiagnosticBundle,
    Observation,
    load_bundle,
    validate_bundle_data,
    write_bundle,
)
from netops_core.report import render_report


class ModelsAndReportTests(unittest.TestCase):
    def test_report_localizes_builtin_severity_and_missing_evidence_limit(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.path_segments = [{"name": "dns", "status": "unknown"}]
        bundle.findings = [
            {
                "severity": "info",
                "segment": "dns",
                "title": "只读提示",
                "evidence": [],
                "confidence": "medium",
            }
        ]

        report = render_report(bundle.finish())

        self.assertIn("[信息]", report)
        self.assertNotIn("[info]", report)
        self.assertIn("当前没有可直接引用的观察证据", report)

    def test_failed_observations_are_sorted_by_instant_not_offset_text(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        later = Observation(
            vantage_point="test",
            segment="destination",
            probe="tcp-connect",
            status="failed",
            observed_at="2026-01-01T23:30:00Z",
        )
        earlier = Observation(
            vantage_point="test",
            segment="dns",
            probe="getaddrinfo",
            status="failed",
            observed_at="2026-01-02T00:15:00+02:00",
        )
        bundle.observations.extend([later, earlier])

        report = render_report(bundle.finish())

        self.assertLess(report.index("DNS"), report.index("目标服务"))

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

    def test_report_shows_observation_and_path_provenance_as_safe_markdown(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["fallback"])
        observation = Observation(
            vantage_point="edge|point\n## forged heading",
            segment="destination",
            probe="tcp|connect",
            status="failed",
            target="service|target",
            protocol="tcp|tls",
            address_family="IPv6\n# forged",
            confidence="high",
            observed_at="2026-07-20T12:34:56Z",
        )
        bundle.observations.append(observation)
        bundle.path_segments = [
            {
                "name": "destination",
                "status": "failed",
                "evidence": [observation.observation_id],
                "limitations": ["route|detail\n# forged limitation"],
            }
        ]

        report = render_report(bundle.finish())

        self.assertIn("| 观察点 | 观测时间 | 置信度 | 限制与证据 |", report)
        self.assertIn("edge\\|point \\#\\# forged heading", report)
        self.assertIn("service\\|target", report)
        self.assertIn("tcp\\|tls", report)
        self.assertIn("IPv6 \\# forged", report)
        self.assertIn("2026-07-20T12:34:56Z", report)
        self.assertIn("限制：route\\|detail \\# forged limitation", report)
        self.assertIn(f"证据 ID：{observation.observation_id}", report)
        self.assertNotIn("\n## forged heading", report)
        self.assertNotIn("\n# forged limitation", report)

    def test_unknown_environment_is_not_guessed(self):
        bundle = DiagnosticBundle(mode="client", vantage_points=["test"]).finish()
        report = render_report(bundle)
        self.assertIn("不会据此猜测运营商、地区或接入方式", report)
        self.assertIn("没有取得可验证观察", report)
        self.assertNotIn("均未发现明确异常", report)

    def test_failed_path_segment_cannot_be_reported_as_healthy_without_observation(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.path_segments = [{"name": "dns", "status": "failed"}]

        report = render_report(bundle.finish())

        self.assertIn("路径汇总标记", report)
        self.assertNotIn("均未发现明确异常", report)

    def test_incomplete_path_segment_cannot_be_called_a_normal_baseline(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.observations.append(
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="ok",
            )
        )
        bundle.path_segments = [
            {
                "name": "destination",
                "status": "unknown",
                "limitations": ["not observed"],
            }
        ]

        report = render_report(bundle.finish())

        self.assertIn("仍未完整观测", report)
        self.assertIn("不能判断是否正常", report)
        self.assertNotIn("本次正常基线", report)
        self.assertNotIn("本次已执行的检查均未发现明确异常", report)

    def test_invalid_finding_shapes_fail_closed_in_contract_and_report(self):
        bundle = DiagnosticBundle(mode="client", vantage_points=["local"])
        bundle.environment = {
            "platform": "Linux",
            "network_summary": ["unexpected"],
            "control_channel": {"proxy_environment": "unexpected"},
        }
        bundle.findings = [{"severity": [], "title": {"unexpected": True}}]

        report = render_report(bundle.finish())

        self.assertIn("NetOps 诊断报告", report)
        self.assertIn("需要处理的诊断发现", report)
        self.assertNotIn("均未发现明确异常", report)
        with self.assertRaisesRegex(ValueError, "findings"):
            validate_bundle_data(bundle.to_dict())

    def test_actionable_finding_controls_summary_and_next_step_even_when_probe_is_ok(self):
        for severity in ("warning", "HIGH"):
            with self.subTest(severity=severity):
                bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
                bundle.observations.append(
                    Observation(
                        vantage_point="local",
                        segment="destination",
                        probe="tcp-connect",
                        status="ok",
                    )
                )
                bundle.findings = [
                    {
                        "severity": severity,
                        "segment": "destination",
                        "title": "Critical vulnerability",
                        "evidence": [],
                        "confidence": "high",
                    }
                ]
                report = render_report(bundle.finish())
                self.assertIn("需要处理的诊断发现", report)
                self.assertIn("先核验并处理第一项诊断发现", report)
                self.assertNotIn("本次正常基线", report)
                if severity == "warning":
                    validate_bundle_data(bundle.to_dict())
                else:
                    with self.assertRaisesRegex(ValueError, "severity"):
                        validate_bundle_data(bundle.to_dict())

    def test_critical_high_confidence_finding_controls_headline_before_warning(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["local"])
        bundle.findings = [
            {
                "severity": "warning",
                "segment": "dns",
                "title": "minor warning",
                "evidence": [],
                "confidence": "low",
            },
            {
                "severity": "critical",
                "segment": "destination",
                "title": "critical outage",
                "evidence": [],
                "confidence": "high",
            },
        ]

        report = render_report(bundle.finish())

        headline = report.split("## 检测到的环境", 1)[0]
        self.assertIn("critical outage", headline)
        self.assertNotIn("minor warning", headline)

    def test_selected_curated_tool_is_visible_and_missing_tool_has_safe_next_step(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.environment = {"curated_tools": ["mtr"]}
        bundle.observations.append(
            Observation(
                vantage_point="test",
                segment="access-network",
                probe="curated-tool:mtr",
                status="unknown",
                evidence={"available": False},
                confidence="high",
            )
        )
        report = render_report(bundle.finish())
        self.assertIn("精选工具：mtr", report)
        self.assertIn("curated-tool:mtr", report)
        self.assertIn("先继续使用内置扫描", report)

    def test_client_report_marks_codex_dependency_as_unconfirmed(self):
        bundle = DiagnosticBundle(mode="client", vantage_points=["test"])
        bundle.environment = {
            "control_channel": {
                "codex_dependency": "unknown",
                "tun_detected": True,
                "system_proxy_enabled": False,
                "proxy_environment": {"set_variables": {}},
            }
        }
        report = render_report(bundle.finish())
        self.assertIn("Agent 控制通道：依赖关系未确认", report)
        self.assertIn("TUN 已检测到", report)


if __name__ == "__main__":
    unittest.main()
