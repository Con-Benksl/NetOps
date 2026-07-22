import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from netops_core.external_tools import (
    TOOL_INDEX,
    _compatibility_check,
    _json_value,
    _read_json_file,
    run_curated_tools,
    tool_catalog,
    tool_ids_for_mode,
    tool_status,
)


def command_result(
    stdout="",
    returncode=0,
    stderr="",
    *,
    stdout_truncated=False,
    stderr_truncated=False,
):
    return {
        "available": True,
        "returncode": returncode,
        "stdout": stdout,
        "stderr": stderr,
        "duration_ms": 12,
        "timed_out": False,
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
    }


def compatibility_result(command):
    rendered = " ".join(command)
    if "--version" in command:
        versions = {
            "mtr": "mtr 0.96",
            "nexttrace": "NextTrace 1.7.1",
            "testssl": "testssl.sh 3.2.4",
            "iperf3": "iperf 3.21",
        }
        for marker, version in versions.items():
            if marker in rendered:
                return command_result(version)
    if "--help" in command or "-h" in command:
        return command_result(
            "--json --report --report-cycles --no-dns --tcp --udp --port "
            "--no-color --no-rdns --data-provider --queries --parallel-requests "
            "--max-hops -c -p -s --quiet --warnings --color --jsonfile "
            "--protocols --server-defaults --client --time --bitrate --connect-timeout"
        )
    return None


def dnsdiag_output(*, responses=5, loss=0, rcode="NOERROR", latency=None):
    latency = latency or (1, 2, 3, 0.5)
    response_lines = "\n".join(
        f"75 bytes from resolver: seq={index} time={latency[1]} ms {rcode} [QR RD RA]"
        for index in range(1, responses + 1)
    )
    return (
        (response_lines + "\n" if response_lines else "")
        + f"5 requests transmitted, {responses} responses received, {loss}% lost\n"
        + f"min={latency[0]} ms, avg={latency[1]} ms, "
        + f"max={latency[2]} ms, stddev={latency[3]} ms\n"
    )


class CuratedToolTests(unittest.TestCase):
    def test_distribution_package_floors_are_accepted_only_with_capabilities(self):
        capability_output = (
            "--json --report --report-cycles --no-dns --tcp --udp --port "
            "--client --time --bitrate --connect-timeout"
        )
        cases = (
            ("mtr", "mtr 0.95"),
            ("iperf3", "iperf 3.16"),
        )
        for tool_id, version_output in cases:
            with self.subTest(tool=tool_id):
                calls = []

                def runner(command, **_kwargs):
                    calls.append(command)
                    if "--version" in command:
                        return command_result(version_output)
                    if "--help" in command:
                        return command_result(capability_output)
                    raise AssertionError("compatibility check must stay local")

                compatible, reason, details = _compatibility_check(
                    TOOL_INDEX[tool_id],
                    f"/usr/bin/{tool_id}",
                    "linux",
                    runner,
                )

                self.assertTrue(compatible)
                self.assertEqual(reason, "compatible")
                self.assertTrue(details["verified"])
                self.assertEqual(len(calls), 2)

    def test_tool_json_parser_rejects_non_finite_numbers(self):
        self.assertIsNone(_json_value('{"value": NaN}'))

    def test_structured_output_file_must_fit_entirely_within_its_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            output.write_text('{"ok":true}' + " " * 32, encoding="utf-8")
            self.assertIsNone(_read_json_file(output, limit=11))
            self.assertEqual(_read_json_file(output, limit=64), {"ok": True})

    @patch("netops_core.external_tools._discover", return_value=("/usr/bin/mtr", "PATH"))
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_truncated_structured_output_can_never_be_reported_healthy(
        self, _platform, _discover
    ):
        def runner(command, **kwargs):
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            return command_result(
                json.dumps(
                    {
                        "report": {
                            "mtr": {"dst": "192.0.2.1"},
                            "hubs": [
                                {
                                    "host": "192.0.2.1",
                                    "Loss%": 0,
                                    "Avg": 1,
                                    "Wrst": 2,
                                }
                            ],
                        }
                    }
                ),
                stdout_truncated=True,
            )

        observation = run_curated_tools(
            ["mtr"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
            runner=runner,
        )[0]

        self.assertEqual(observation.status, "unknown")
        self.assertFalse(observation.evidence["usable_result"])
        self.assertEqual(observation.evidence["execution_status"], "incomplete")
        self.assertTrue(observation.evidence["stdout_truncated"])

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/local/bin/dnsping", "PATH"),
    )
    @patch("netops_core.external_tools.importlib_metadata.version", return_value="2.9.4")
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_truncated_dns_summary_does_not_create_metrics(
        self, _platform, _version, _discover
    ):
        def runner(command, **kwargs):
            compatibility = compatibility_result(command)
            return compatibility or command_result(
                dnsdiag_output(), stderr_truncated=True
            )

        observation = run_curated_tools(
            ["dnsdiag"],
            mode="node",
            external=True,
            target="example.test",
            port=53,
            protocol="udp",
            resolver="resolver.example",
            runner=runner,
        )[0]

        self.assertEqual(observation.status, "unknown")
        self.assertEqual(observation.metrics, {"duration_ms": 12})
        self.assertFalse(observation.evidence["usable_result"])

    def test_catalog_is_curated_and_mode_aware(self):
        catalog = tool_catalog()
        ids = {item["tool_id"] for item in catalog["tools"]}
        self.assertEqual(
            ids,
            {"mtr", "nexttrace", "dnsdiag", "testssl", "ipquality", "iperf3"},
        )
        self.assertEqual(tool_ids_for_mode("client"), ("ipquality",))
        self.assertNotIn("ipquality", tool_ids_for_mode("node"))

    def test_external_consent_is_required_before_discovery_or_execution(self):
        runner_called = False

        def runner(*args, **kwargs):
            nonlocal runner_called
            runner_called = True
            return command_result()

        with self.assertRaisesRegex(PermissionError, "--external"):
            run_curated_tools(
                ["mtr"],
                mode="node",
                external=False,
                target="example.test",
                port=443,
                protocol="tcp",
                runner=runner,
            )
        self.assertFalse(runner_called)

    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_high_load_tool_has_separate_gate(self, _platform):
        with self.assertRaisesRegex(PermissionError, "--allow-load"):
            run_curated_tools(
                ["iperf3"],
                mode="node",
                external=True,
                target="example.test",
                port=5201,
                protocol="tcp",
            )

    @patch("netops_core.external_tools._discover", return_value=(None, "not-found"))
    def test_missing_tool_becomes_unknown_observation(self, _discover):
        observations = run_curated_tools(
            ["mtr"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
        )
        self.assertEqual(observations[0].status, "unknown")
        self.assertIn("install_hint_zh", observations[0].evidence)

    def test_only_one_curated_tool_is_allowed_per_scan(self):
        with self.assertRaisesRegex(ValueError, "exactly one"):
            run_curated_tools(
                ["mtr", "nexttrace"],
                mode="node",
                external=True,
                target="example.test",
                port=443,
                protocol="tcp",
            )

    @patch("netops_core.external_tools._discover", return_value=("/usr/bin/mtr", "PATH"))
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_mtr_adapter_is_bounded_and_uses_json(self, _platform, _discover):
        commands = []

        def runner(command, **kwargs):
            commands.append((command, kwargs))
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            return command_result(json.dumps({"report": {"hubs": []}}))

        observation = run_curated_tools(
            ["mtr"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
            runner=runner,
        )[0]
        command = commands[-1][0]
        self.assertEqual(observation.status, "unknown")
        self.assertEqual(observation.evidence["execution_status"], "succeeded")
        self.assertIn("--json", command)
        self.assertEqual(command[command.index("--report-cycles") + 1], "5")
        self.assertEqual(command[-1], "example.test")

    @patch("netops_core.external_tools._discover", return_value=("/usr/bin/mtr", "PATH"))
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_mtr_any_terminal_loss_is_failed(self, _platform, _discover):
        def runner(command, **kwargs):
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            return command_result(
                json.dumps(
                    {
                        "report": {
                            "hubs": [
                                {"Loss%": "99.0", "Avg": "50", "Wrst": "80"}
                            ]
                        }
                    }
                )
            )

        observation = run_curated_tools(
            ["mtr"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
            runner=runner,
        )[0]
        self.assertEqual(observation.status, "failed")
        self.assertEqual(observation.metrics["loss_percent"], 99.0)

    @patch("netops_core.external_tools._discover", return_value=("/usr/bin/mtr", "PATH"))
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_mtr_extreme_terminal_latency_is_not_healthy(self, _platform, _discover):
        def runner(command, **kwargs):
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            return command_result(
                json.dumps(
                    {
                        "report": {
                            "hubs": [
                                {"Loss%": 0, "Avg": 1500, "Wrst": 2500}
                            ]
                        }
                    }
                )
            )

        observation = run_curated_tools(
            ["mtr"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
            runner=runner,
        )[0]
        self.assertEqual(observation.status, "failed")
        self.assertIn("extreme", observation.evidence["health_interpretation"])

    @patch("netops_core.external_tools._discover", return_value=("/usr/bin/mtr", "PATH"))
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_mtr_zero_loss_intermediate_hop_is_not_reported_healthy(
        self, _platform, _discover
    ):
        def runner(command, **kwargs):
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            return command_result(
                json.dumps(
                    {
                        "report": {
                            "mtr": {"dst": "192.0.2.2"},
                            "hubs": [
                                {
                                    "host": "192.0.2.1",
                                    "Loss%": 0,
                                    "Avg": 10,
                                    "Wrst": 20,
                                }
                            ],
                        }
                    }
                )
            )

        observation = run_curated_tools(
            ["mtr"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
            runner=runner,
        )[0]

        self.assertEqual(observation.status, "unknown")
        self.assertFalse(observation.evidence["target_reached"])

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/local/bin/nexttrace", "PATH"),
    )
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_nexttrace_disables_third_party_geoip(self, _platform, _discover):
        commands = []

        def runner(command, **kwargs):
            commands.append(command)
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            return command_result(json.dumps({"hops": []}))

        observation = run_curated_tools(
            ["nexttrace"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
            runner=runner,
        )[0]
        command = commands[-1]
        self.assertEqual(observation.status, "unknown")
        provider_index = command.index("--data-provider")
        self.assertEqual(command[provider_index + 1], "disable-geoip")

    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_dnsdiag_requires_an_explicit_resolver(self, _platform):
        with self.assertRaisesRegex(ValueError, "--resolver"):
            run_curated_tools(
                ["dnsdiag"],
                mode="node",
                external=True,
                target="example.test",
                port=53,
                protocol="udp",
            )

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/local/bin/dnsping", "PATH"),
    )
    @patch("netops_core.external_tools.importlib_metadata.version", return_value="2.9.4")
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_dnsdiag_matches_declared_tcp_transport(
        self, _platform, _version, _discover
    ):
        commands = []

        def runner(command, **kwargs):
            commands.append(command)
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            return command_result(dnsdiag_output())

        observation = run_curated_tools(
            ["dnsdiag"],
            mode="node",
            external=True,
            target="example.test",
            port=53,
            protocol="tcp",
            resolver="resolver.example",
            runner=runner,
        )[0]
        self.assertEqual(observation.status, "ok")
        command = commands[-1]
        self.assertIn("--tcp", command)
        self.assertEqual(command[command.index("-p") + 1], "53")

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/local/bin/dnsping", "PATH"),
    )
    @patch("netops_core.external_tools.importlib_metadata.version", return_value="2.9.4")
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_dnsdiag_total_loss_is_failed_not_healthy(
        self, _platform, _version, _discover
    ):
        def runner(command, **kwargs):
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            return command_result(
                "5 requests transmitted, 0 responses received, 100% lost\n"
            )

        observation = run_curated_tools(
            ["dnsdiag"],
            mode="node",
            external=True,
            target="example.test",
            port=5353,
            protocol="udp",
            resolver="resolver.example",
            runner=runner,
        )[0]
        self.assertEqual(observation.status, "failed")
        self.assertEqual(observation.metrics["loss_percent"], 100.0)

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/local/bin/dnsping", "PATH"),
    )
    @patch("netops_core.external_tools.importlib_metadata.version", return_value="2.9.4")
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_dnsdiag_partial_loss_and_extreme_latency_are_failed(
        self, _platform, _version, _discover
    ):
        samples = (
            (
                dnsdiag_output(responses=4, loss=20),
                "dns-packet-loss-observed",
            ),
            (
                dnsdiag_output(latency=(1000, 1500, 2500, 500)),
                "extreme-dns-latency-observed",
            ),
        )
        for output, interpretation in samples:
            with self.subTest(interpretation=interpretation):
                def runner(command, **kwargs):
                    compatibility = compatibility_result(command)
                    return compatibility or command_result(output)

                observation = run_curated_tools(
                    ["dnsdiag"],
                    mode="node",
                    external=True,
                    target="example.test",
                    port=53,
                    protocol="udp",
                    resolver="resolver.example",
                    runner=runner,
                )[0]
                self.assertEqual(observation.status, "failed")
                self.assertEqual(
                    observation.evidence["health_interpretation"], interpretation
                )

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/local/bin/dnsping", "PATH"),
    )
    @patch("netops_core.external_tools.importlib_metadata.version", return_value="2.9.4")
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_dnsdiag_error_rcode_is_failed_despite_zero_packet_loss(
        self, _platform, _version, _discover
    ):
        def runner(command, **kwargs):
            compatibility = compatibility_result(command)
            return compatibility or command_result(dnsdiag_output(rcode="SERVFAIL"))

        observation = run_curated_tools(
            ["dnsdiag"],
            mode="node",
            external=True,
            target="example.test",
            port=53,
            protocol="udp",
            resolver="resolver.example",
            runner=runner,
        )[0]

        self.assertEqual(observation.status, "failed")
        self.assertEqual(observation.metrics["rcode_counts"], {"SERVFAIL": 5})
        self.assertEqual(
            observation.evidence["health_interpretation"],
            "dns-error-response-observed",
        )

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/local/bin/dnsping", "PATH"),
    )
    @patch("netops_core.external_tools.importlib_metadata.version", return_value="2.9.4")
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_dnsdiag_missing_rcode_is_not_reported_healthy(
        self, _platform, _version, _discover
    ):
        def runner(command, **kwargs):
            compatibility = compatibility_result(command)
            return compatibility or command_result(
                "5 requests transmitted, 5 responses received, 0% lost\n"
                "min=1 ms, avg=2 ms, max=3 ms, stddev=0.5 ms\n"
            )

        observation = run_curated_tools(
            ["dnsdiag"],
            mode="node",
            external=True,
            target="example.test",
            port=53,
            protocol="udp",
            resolver="resolver.example",
            runner=runner,
        )[0]

        self.assertEqual(observation.status, "unknown")

    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_testssl_requires_tls_declaration(self, _platform):
        with self.assertRaisesRegex(ValueError, "--tls"):
            run_curated_tools(
                ["testssl"],
                mode="node",
                external=True,
                target="example.test",
                port=443,
                protocol="tcp",
            )

    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_testssl_rejects_udp_even_when_tls_is_declared(self, _platform):
        with self.assertRaisesRegex(ValueError, "--protocol tcp"):
            run_curated_tools(
                ["testssl"],
                mode="node",
                external=True,
                target="example.test",
                port=443,
                protocol="udp",
                tls=True,
            )

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/local/bin/testssl.sh", "PATH"),
    )
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_testssl_brackets_an_ipv6_target(self, _platform, _discover):
        commands = []

        def runner(command, **kwargs):
            commands.append(command)
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            output = Path(command[command.index("--jsonfile") + 1])
            output.write_text(
                json.dumps([{"id": "protocol", "severity": "OK"}]),
                encoding="utf-8",
            )
            return command_result()

        observation = run_curated_tools(
            ["testssl"],
            mode="node",
            external=True,
            target="2001:db8::1",
            port=443,
            protocol="tcp",
            tls=True,
            runner=runner,
        )[0]
        self.assertEqual(observation.status, "ok")
        self.assertIn("[2001:db8::1]:443", commands[-1])

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/local/bin/testssl.sh", "PATH"),
    )
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_testssl_unknown_severity_is_not_reported_healthy(
        self, _platform, _discover
    ):
        def runner(command, **kwargs):
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            output = Path(command[command.index("--jsonfile") + 1])
            output.write_text(
                json.dumps([{"id": "unexpected", "severity": "UNKNOWN"}]),
                encoding="utf-8",
            )
            return command_result()

        observation = run_curated_tools(
            ["testssl"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
            tls=True,
            runner=runner,
        )[0]

        self.assertEqual(observation.status, "unknown")

    @patch(
        "netops_core.external_tools._discover",
        return_value=("/usr/bin/iperf3", "PATH"),
    )
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_iperf3_is_time_and_bitrate_bounded(self, _platform, _discover):
        commands = []

        def runner(command, **kwargs):
            commands.append(command)
            compatibility = compatibility_result(command)
            if compatibility:
                return compatibility
            return command_result(
                json.dumps(
                    {"end": {"sum_received": {"bits_per_second": 9_000_000}}}
                )
            )

        observation = run_curated_tools(
            ["iperf3"],
            mode="node",
            external=True,
            allow_load=True,
            target="example.test",
            port=5201,
            protocol="tcp",
            runner=runner,
        )[0]
        command = commands[-1]
        self.assertEqual(observation.status, "unknown")
        self.assertTrue(observation.evidence["usable_result"])
        self.assertEqual(command[command.index("--time") + 1], "5")
        self.assertEqual(command[command.index("--bitrate") + 1], "10M")
        self.assertNotIn("--omit", command)

    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_environment_override_is_a_single_readable_path(self, _platform):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "ipquality.sh"
            script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            with patch.dict(
                os.environ, {"NETOPS_TOOL_IPQUALITY": str(script)}
            ), patch(
                "netops_core.external_tools.run_command",
                return_value=command_result("GNU bash, version 5.2.0"),
            ):
                status = tool_status(["ipquality"])["tools"][0]
        self.assertTrue(status["detected"])
        self.assertFalse(status["available"])
        self.assertEqual(status["source"], "environment:NETOPS_TOOL_IPQUALITY")
        self.assertEqual(
            status["compatibility_reason"], "reviewed-content-hash-mismatch"
        )

    @patch("netops_core.external_tools.platform_id", return_value="macos")
    def test_ipquality_is_incompatible_with_stock_macos_bash(self, _platform):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "ipquality.sh"
            script.write_text("#!/usr/bin/env bash\n", encoding="utf-8")
            with patch.dict(
                os.environ, {"NETOPS_TOOL_IPQUALITY": str(script)}
            ), patch(
                "netops_core.external_tools.run_command",
                return_value=command_result("GNU bash, version 3.2.57"),
            ):
                status = tool_status(["ipquality"])["tools"][0]
        self.assertFalse(status["available"])
        self.assertEqual(status["compatibility_reason"], "bash-4-required")

    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_non_executable_override_is_rejected_for_binary_tools(self, _platform):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "mtr"
            binary.write_text("not executable\n", encoding="utf-8")
            with patch.dict(os.environ, {"NETOPS_TOOL_MTR": str(binary)}):
                status = tool_status(["mtr"])["tools"][0]
        self.assertFalse(status["available"])
        self.assertEqual(status["source"], "invalid-environment:NETOPS_TOOL_MTR")

    @patch("netops_core.external_tools._discover", return_value=("/usr/bin/mtr", "PATH"))
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_detected_tool_is_not_usable_until_compatibility_is_verified(
        self, _platform, _discover
    ):
        unchecked = tool_status(["mtr"], include_versions=False)["tools"][0]
        self.assertTrue(unchecked["detected"])
        self.assertTrue(unchecked["platform_supported"])
        self.assertFalse(unchecked["compatibility_checked"])
        self.assertIsNone(unchecked["compatible"])
        self.assertFalse(unchecked["usable"])
        self.assertFalse(unchecked["available"])

        with patch(
            "netops_core.external_tools.run_command",
            side_effect=lambda command, **_kwargs: compatibility_result(command)
            or command_result(),
        ):
            checked = tool_status(["mtr"], include_versions=True)["tools"][0]
        self.assertTrue(checked["compatibility_checked"])
        self.assertTrue(checked["compatibility_verified"])
        self.assertTrue(checked["compatible"])
        self.assertTrue(checked["usable"])
        self.assertTrue(checked["available"])

    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_option_like_target_is_rejected_before_execution(self, _platform):
        with self.assertRaisesRegex(ValueError, "must not start"):
            run_curated_tools(
                ["mtr"],
                mode="node",
                external=True,
                target="--help",
                port=443,
                protocol="tcp",
            )

    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_malformed_network_arguments_and_boolean_port_are_rejected(self, _platform):
        for target in ("example test", "example.test/path", "user@example.test"):
            with self.subTest(target=target), self.assertRaisesRegex(
                ValueError, "IP address or hostname"
            ):
                run_curated_tools(
                    ["mtr"],
                    mode="node",
                    external=True,
                    target=target,
                    port=443,
                    protocol="tcp",
                )
        with self.assertRaisesRegex(ValueError, "port must be"):
            run_curated_tools(
                ["mtr"],
                mode="node",
                external=True,
                target="example.test",
                port=True,
                protocol="tcp",
            )

    @patch("netops_core.external_tools._discover")
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_unicode_control_and_format_network_arguments_are_rejected_before_discovery(
        self, _platform, discover
    ):
        with self.assertRaisesRegex(ValueError, "control or format"):
            run_curated_tools(
                ["mtr"],
                mode="node",
                external=True,
                target="exam\u200dple.test",
                port=443,
                protocol="tcp",
            )
        with self.assertRaisesRegex(ValueError, "control or format"):
            run_curated_tools(
                ["dnsdiag"],
                mode="node",
                external=True,
                target="example.test",
                port=53,
                protocol="udp",
                resolver="resolver.test\u2029",
            )
        discover.assert_not_called()

    @patch("netops_core.external_tools._discover", return_value=("/usr/bin/mtr", "PATH"))
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_curated_processes_receive_only_allowlisted_environment(
        self, _platform, _discover
    ):
        calls = []

        def runner(command, **kwargs):
            calls.append((command, kwargs))
            compatibility = compatibility_result(command)
            return compatibility or command_result(
                json.dumps(
                    {"report": {"hubs": [{"Loss%": 0, "Avg": 1, "Wrst": 2}]}}
                )
            )

        with patch.dict(
            os.environ,
            {
                "UNRELATED_API_TOKEN": "must-not-reach-tool",
                "HTTPS_PROXY": "http://private-proxy.invalid:8080",
            },
        ):
            run_curated_tools(
                ["mtr"],
                mode="node",
                external=True,
                target="example.test",
                port=443,
                protocol="tcp",
                runner=runner,
            )

        self.assertTrue(calls)
        for _command, kwargs in calls:
            self.assertFalse(kwargs["inherit_env"])
            self.assertNotIn("UNRELATED_API_TOKEN", kwargs["env"])
            self.assertNotIn("HTTPS_PROXY", kwargs["env"])
            self.assertIn("PATH", kwargs["env"])

    @patch("netops_core.external_tools._windows_is_admin", return_value=False)
    @patch(
        "netops_core.external_tools._discover",
        return_value=("C:/Tools/nexttrace.exe", "PATH"),
    )
    @patch("netops_core.external_tools.platform_id", return_value="windows")
    def test_nexttrace_windows_requires_administrator(
        self, _platform, _discover, _admin
    ):
        observation = run_curated_tools(
            ["nexttrace"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
        )[0]
        self.assertEqual(observation.status, "unknown")
        self.assertIn("windows-administrator-required", observation.evidence["source"])

    @patch("netops_core.external_tools._discover", return_value=("/usr/bin/mtr", "PATH"))
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_old_mtr_version_is_blocked_before_network_probe(self, _platform, _discover):
        commands = []

        def runner(command, **kwargs):
            commands.append(command)
            if "--version" in command:
                return command_result("mtr 0.94")
            raise AssertionError("network probe must not run for an old version")

        observation = run_curated_tools(
            ["mtr"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
            runner=runner,
        )[0]
        self.assertEqual(observation.status, "unknown")
        self.assertIn("version-below", observation.evidence["source"])
        self.assertEqual(len(commands), 1)

    @patch("netops_core.external_tools._discover", return_value=("/usr/bin/mtr", "PATH"))
    @patch("netops_core.external_tools.platform_id", return_value="linux")
    def test_missing_used_capability_blocks_probe(self, _platform, _discover):
        commands = []

        def runner(command, **kwargs):
            commands.append(command)
            if "--version" in command:
                return command_result("mtr 0.96")
            if "--help" in command:
                return command_result("--json --tcp --udp --port")
            raise AssertionError("network probe must not run without --report-cycles")

        observation = run_curated_tools(
            ["mtr"],
            mode="node",
            external=True,
            target="example.test",
            port=443,
            protocol="tcp",
            runner=runner,
        )[0]
        self.assertEqual(observation.status, "unknown")
        self.assertIn("required-capability", observation.evidence["source"])
        self.assertIn(
            "--report-cycles",
            observation.evidence["compatibility"]["missing_capabilities"],
        )
        self.assertEqual(len(commands), 2)


if __name__ == "__main__":
    unittest.main()
