import json
import os
import socket
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import MagicMock, patch

from netops_core import __version__
from netops_core.models import DiagnosticBundle, Observation, write_bundle
from netops_core.report import render_report
from netops_core.scanner import (
    _URL_FETCH_SCRIPT,
    USER_AGENT,
    _command_observation,
    _external_identity,
    _http_probe,
    _isolated_json_payload,
    _local_resources,
    _proxy_http_probe,
    _proxy_environment_summary,
    _ResolvedHTTPSConnection,
    _resolve_target,
    _run_isolated_python,
    _system_proxy_enabled,
    compare_bundles,
    scan_client,
    scan_node,
    scan_server_local,
    scan_server_remote,
    trace_target,
)


class ScannerTests(unittest.TestCase):
    def test_local_resources_tolerates_platforms_without_getloadavg(self):
        with patch("netops_core.scanner.os.getloadavg", None, create=True):
            resources = _local_resources()
        self.assertIsNone(resources["loadavg"])
        self.assertIn("disk_root", resources)

    @unittest.skipIf(os.name == "nt", "POSIX executable fixture")
    def test_builtin_command_observation_ignores_polluted_path_and_secret_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "executed"
            executable = root / "ifconfig"
            executable.write_text(
                "#!/bin/sh\n"
                f"printf executed > {str(marker)!r}\n"
                "printf 'leaked:%s' \"$NETOPS_PRIVATE_TEST_TOKEN\"\n",
                encoding="utf-8",
            )
            executable.chmod(0o700)
            with patch.dict(
                os.environ,
                {
                    "PATH": temporary,
                    "NETOPS_PRIVATE_TEST_TOKEN": "opaque-private-value",
                },
                clear=False,
            ):
                observation, result = _command_observation(
                    "path-boundary",
                    ["ifconfig", "-a"],
                    segment="client",
                )

        rendered = json.dumps(
            {"observation": vars(observation), "result": result},
            sort_keys=True,
        )
        self.assertFalse(marker.exists())
        self.assertNotIn("opaque-private-value", rendered)

    def _listener(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]

        def accept_once():
            try:
                connection, _ = server.accept()
                connection.close()
            finally:
                server.close()

        thread = threading.Thread(target=accept_once, daemon=True)
        thread.start()
        return port, thread

    def _http_server(self, status):
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(status)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()

            def log_message(self, format, *args):
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_tcp_node_probe_uses_bounded_declared_target(self):
        port, thread = self._listener()
        bundle = scan_node(target="127.0.0.1", port=port, protocol="tcp")
        thread.join(timeout=2)
        tcp = [item for item in bundle.observations if item.probe == "tcp-connect"]
        self.assertTrue(tcp)
        self.assertIn("ok", {item.status for item in tcp})
        self.assertEqual(bundle.targets[0]["target"], "127.0.0.1")

    def test_udp_probe_does_not_claim_service_health(self):
        bundle = scan_node(target="localhost", port=443, protocol="udp")
        udp = [item for item in bundle.observations if item.probe == "udp-generic"]
        self.assertEqual(udp[0].status, "unknown")
        self.assertIn("理解对应协议", " ".join(udp[0].limitations))

    def test_udp_rejects_tcp_only_http_tls_and_proxy_options(self):
        for options in (
            {"http": True},
            {"tls": True},
            {"http": True, "proxy_env": "HTTPS_PROXY"},
        ):
            with self.subTest(options=options):
                with self.assertRaisesRegex(ValueError, "protocol tcp"):
                    scan_node(
                        target="localhost",
                        port=443,
                        protocol="udp",
                        **options,
                    )

    def test_http_policy_statuses_are_explicit_findings(self):
        for status in (401, 403, 407, 429):
            with self.subTest(status=status):
                server, thread = self._http_server(status)
                try:
                    bundle = scan_node(
                        target="127.0.0.1",
                        port=server.server_port,
                        protocol="tcp",
                        http=True,
                    )
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)
                observation = next(
                    item for item in bundle.observations if item.probe == "http-head"
                )
                self.assertEqual(observation.status, "failed")
                self.assertTrue(observation.evidence["transport_reachable"])
                self.assertEqual(
                    observation.evidence["application_outcome"],
                    "application-policy-rejection",
                )
                self.assertTrue(
                    any(f"HTTP {status}" in item["title"] for item in bundle.findings)
                )
                self.assertIn(f"HTTP {status}", render_report(bundle))

                destination = next(
                    item
                    for item in bundle.path_segments
                    if item["name"] == "destination"
                )
                self.assertEqual(destination["status"], "failed")
                self.assertEqual(destination["evidence"], [observation.observation_id])

    @patch("netops_core.scanner._resolve_target")
    def test_http_reuses_bounded_dns_answer_without_second_resolution(self, resolve):
        server, thread = self._http_server(204)
        resolve.return_value = (
            [{"family": "ipv4", "address": "127.0.0.1"}],
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="ok",
            ),
        )
        try:
            with patch(
                "netops_core.scanner.socket.getaddrinfo",
                side_effect=AssertionError("HTTP attempted a second DNS lookup"),
            ) as getaddrinfo:
                bundle = scan_node(
                    target="localhost",
                    port=server.server_port,
                    protocol="tcp",
                    http=True,
                    timeout=1,
                )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        getaddrinfo.assert_not_called()
        http_observation = next(
            item for item in bundle.observations if item.probe == "http-head"
        )
        self.assertEqual(http_observation.status, "ok")

    @patch("netops_core.scanner._resolve_target")
    def test_http_uses_declared_hostname_for_host_header(self, resolve):
        seen = {}

        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                seen["host"] = self.headers.get("Host")
                seen["user_agent"] = self.headers.get("User-Agent")
                self.send_response(204)
                self.end_headers()

            def log_message(self, format, *args):
                return

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        resolve.return_value = (
            [{"family": "ipv4", "address": "127.0.0.1"}],
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="ok",
            ),
        )
        try:
            scan_node(
                target="example.test",
                port=server.server_port,
                protocol="tcp",
                http=True,
                timeout=1,
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(seen["host"], f"example.test:{server.server_port}")
        self.assertEqual(seen["user_agent"], f"NetOps/{__version__}")

    def test_embedded_fetch_user_agent_matches_package_version(self):
        self.assertEqual(USER_AGENT, f"NetOps/{__version__}")
        self.assertIn(repr(USER_AGENT), _URL_FETCH_SCRIPT)
        self.assertNotIn("NetOps/0.1", _URL_FETCH_SCRIPT)

    def test_resolved_https_connection_preserves_declared_hostname_for_sni(self):
        context = MagicMock()
        raw_socket = MagicMock()
        wrapped_socket = MagicMock()
        context.wrap_socket.return_value = wrapped_socket
        connection = _ResolvedHTTPSConnection(
            "example.test",
            443,
            address={"family": "ipv4", "address": "192.0.2.1"},
            timeout=1,
            context=context,
        )
        with patch(
            "netops_core.scanner._connect_resolved_socket",
            return_value=raw_socket,
        ):
            connection.connect()
        context.wrap_socket.assert_called_once_with(
            raw_socket,
            server_hostname="example.test",
        )
        self.assertIs(connection.sock, wrapped_socket)

    @patch("netops_core.scanner._resolve_target")
    def test_http_without_a_dns_answer_does_not_claim_destination_observed(
        self, resolve
    ):
        resolve.return_value = (
            [],
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="failed",
            ),
        )
        bundle = scan_node(
            target="example.test",
            port=443,
            protocol="tcp",
            http=True,
            timeout=0.1,
        )
        destination = next(
            item for item in bundle.path_segments if item["name"] == "destination"
        )
        client_local = next(
            item for item in bundle.path_segments if item["name"] == "client-local"
        )
        self.assertEqual(destination["status"], "unknown")
        self.assertEqual(client_local["status"], "failed")
        self.assertTrue(destination["evidence"])

    @patch("netops_core.scanner._proxy_http_probe")
    @patch("netops_core.scanner._resolve_target")
    def test_proxy_policy_rejection_observes_proxy_path_but_fails_destination(
        self, resolve, proxy_probe
    ):
        resolve.return_value = (
            [],
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="failed",
            ),
        )
        proxy_observation = Observation(
            vantage_point="local",
            segment="proxy-egress",
            probe="curl-via-proxy",
            status="failed",
            evidence={
                "transport_reachable": True,
                "application_outcome": "application-policy-rejection",
            },
            metrics={"http_status": 403},
        )
        proxy_probe.return_value = proxy_observation

        bundle = scan_node(
            target="example.test",
            port=443,
            protocol="tcp",
            http=True,
            proxy_env="HTTPS_PROXY",
        )

        segments = {item["name"]: item for item in bundle.path_segments}
        self.assertEqual(
            segments["proxy-core-and-egress"]["status"],
            "partially-observed",
        )
        self.assertEqual(segments["destination"]["status"], "failed")
        self.assertEqual(
            segments["proxy-core-and-egress"]["evidence"],
            [proxy_observation.observation_id],
        )

    @patch("netops_core.scanner._proxy_http_probe")
    @patch("netops_core.scanner._resolve_target")
    def test_failed_proxy_probe_does_not_claim_proxy_or_destination_observed(
        self, resolve, proxy_probe
    ):
        resolve.return_value = (
            [],
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="failed",
            ),
        )
        proxy_probe.return_value = Observation(
            vantage_point="local",
            segment="proxy-egress",
            probe="curl-via-proxy",
            status="failed",
            evidence={
                "transport_reachable": False,
                "application_outcome": "not-observed",
            },
        )
        bundle = scan_node(
            target="example.test",
            port=443,
            protocol="tcp",
            http=True,
            proxy_env="HTTPS_PROXY",
        )
        segments = {item["name"]: item for item in bundle.path_segments}
        self.assertEqual(segments["proxy-core-and-egress"]["status"], "failed")
        self.assertEqual(segments["destination"]["status"], "failed")

    @patch("netops_core.scanner.run_command")
    def test_proxy_config_rejects_line_break_injection(self, run_command):
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": 'http://proxy.invalid\noutput = "/tmp/leak"'},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "CR, LF"):
                _proxy_http_probe(
                    "example.test", 443, "/", True, "HTTPS_PROXY", 1
                )
        run_command.assert_not_called()

    @patch("netops_core.scanner.run_command")
    def test_proxy_probe_disables_curlrc_globbing_and_no_proxy_bypass(
        self, run_command
    ):
        run_command.return_value = {
            "available": True,
            "returncode": 0,
            "stdout": "\nNETOPS_HTTP_STATUS=204\nNETOPS_CONTENT_TYPE=text/plain\n",
            "stderr": "",
            "duration_ms": 1,
            "timed_out": False,
        }
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": "http://127.0.0.1:8080"},
            clear=True,
        ):
            observation = _proxy_http_probe(
                "2001:db8::1",
                443,
                "/[1-100]",
                True,
                "HTTPS_PROXY",
                1,
            )
        command = run_command.call_args.args[0]
        self.assertEqual(command[:3], ["curl", "--disable", "--globoff"])
        no_proxy_index = command.index("--noproxy")
        self.assertEqual(command[no_proxy_index + 1], "")
        self.assertEqual(command[-1], "https://[2001:db8::1]:443/%5B1-100%5D")
        self.assertEqual(command.count(command[-1]), 1)
        self.assertEqual(observation.target, command[-1])
        self.assertFalse(run_command.call_args.kwargs["inherit_env"])
        self.assertNotIn("HTTPS_PROXY", run_command.call_args.kwargs["env"])

    @patch("netops_core.scanner._ResolvedHTTPConnection")
    def test_direct_http_formats_ipv6_and_idna_hosts_as_network_urls(
        self, connection_class
    ):
        response = MagicMock()
        response.status = 204
        response.reason = "No Content"
        response.getheader.return_value = None
        connection = MagicMock()
        connection.getresponse.return_value = response
        connection_class.return_value = connection
        address = {"family": "ipv6", "address": "2001:db8::1"}

        ipv6_observation = _http_probe(
            "2001:db8::1", 8080, "/", False, 1, address
        )
        self.assertEqual(ipv6_observation.target, "http://[2001:db8::1]:8080/")
        connection_class.assert_called_with(
            "2001:db8::1",
            8080,
            address=address,
            timeout=1,
        )

        idna_address = {"family": "ipv4", "address": "192.0.2.1"}
        idna_observation = _http_probe(
            "例子.测试", 80, "/路径", False, 1, idna_address
        )
        self.assertEqual(
            idna_observation.target,
            "http://xn--fsqu00a.xn--0zwm56d:80/%E8%B7%AF%E5%BE%84",
        )
        self.assertEqual(
            connection_class.call_args.args[:2],
            ("xn--fsqu00a.xn--0zwm56d", 80),
        )

    def test_node_probe_rejects_invalid_port_before_network_use(self):
        with self.assertRaisesRegex(ValueError, "port must be"):
            scan_node(target="localhost", port=70000, protocol="tcp")
        with self.assertRaisesRegex(ValueError, "port must be"):
            scan_node(target="localhost", port=True, protocol="tcp")

    def test_node_probe_rejects_unbounded_timeout_and_invalid_target(self):
        for timeout in (float("nan"), float("inf"), float("-inf"), 0, 61, True):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(
                ValueError, "finite value"
            ):
                scan_node(
                    target="localhost", port=443, protocol="tcp", timeout=timeout
                )
        for target in (
            "example test",
            "example.test/path",
            "user@example.test",
            "[2001:db8::1]",
            "bad_label.example",
        ):
            with self.subTest(target=target), self.assertRaisesRegex(
                ValueError, "valid IP address or hostname"
            ):
                scan_node(target=target, port=443, protocol="tcp")

    @patch("netops_core.scanner._run_isolated_python")
    def test_node_inputs_reject_unicode_controls_before_network_use(self, isolated):
        for target in (
            "exam\u200dple.test",
            "example\u202etest",
            "example.test\u2028",
        ):
            with self.subTest(target=target), self.assertRaisesRegex(
                ValueError, "control or format"
            ):
                scan_node(target=target, port=443, protocol="tcp")
        with self.assertRaisesRegex(ValueError, "control or format"):
            scan_node(
                target="example.test",
                port=443,
                protocol="tcp",
                http=True,
                path="/safe\u2060path",
            )
        isolated.assert_not_called()

    @patch("netops_core.scanner.run_command")
    def test_proxy_url_rejects_unicode_format_characters_before_execution(
        self, run_command
    ):
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": "http://proxy.exa\u200dmple"},
            clear=True,
        ):
            with self.assertRaisesRegex(ValueError, "control/format"):
                _proxy_http_probe(
                    "example.test", 443, "/", True, "HTTPS_PROXY", 1
                )
        run_command.assert_not_called()

    def test_proxy_probe_accepts_only_declared_proxy_environment_names(self):
        with self.assertRaisesRegex(ValueError, "standard proxy variable"):
            scan_node(
                target="localhost",
                port=443,
                protocol="tcp",
                http=True,
                proxy_env="AWS_SECRET_ACCESS_KEY",
            )

    @patch("netops_core.scanner._proxy_http_probe")
    @patch("netops_core.scanner._resolve_target")
    def test_proxy_endpoint_snapshot_is_credential_free_and_uses_one_value(
        self, resolve, proxy_probe
    ):
        resolve.return_value = (
            [],
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="failed",
            ),
        )
        proxy_probe.return_value = Observation(
            vantage_point="local",
            segment="proxy-egress",
            probe="curl-via-proxy",
            status="unknown",
        )
        proxy_value = "http://" + "user:password@" + "Proxy.Example:8443"
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": proxy_value},
            clear=True,
        ):
            bundle = scan_node(
                target="example.test",
                port=443,
                protocol="tcp",
                http=True,
                proxy_env="HTTPS_PROXY",
            )
        identity = bundle.targets[0]["proxy_endpoint"]
        self.assertEqual(
            identity,
            {
                "state": "configured",
                "source": "environment:HTTPS_PROXY",
                "scheme": "http",
                "host": "proxy.example",
                "port": 8443,
                "credentials_present": True,
            },
        )
        self.assertNotIn("user", json.dumps(bundle.targets))
        self.assertNotIn("password", json.dumps(bundle.targets))
        self.assertEqual(proxy_probe.call_args.kwargs["proxy_url"], proxy_value)

    @patch("netops_core.scanner._proxy_http_probe")
    @patch("netops_core.scanner._resolve_target")
    def test_proxy_endpoint_unset_and_invalid_states_are_explicit_without_execution(
        self, resolve, proxy_probe
    ):
        resolve.return_value = (
            [],
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="failed",
            ),
        )
        proxy_probe.return_value = Observation(
            vantage_point="local",
            segment="proxy-egress",
            probe="curl-via-proxy",
            status="unknown",
        )
        with patch.dict("os.environ", {}, clear=True):
            unset_bundle = scan_node(
                target="example.test",
                port=443,
                protocol="tcp",
                http=True,
                proxy_env="HTTPS_PROXY",
            )
        self.assertEqual(
            unset_bundle.targets[0]["proxy_endpoint"]["state"],
            "unset",
        )
        self.assertIsNone(proxy_probe.call_args.kwargs["proxy_url"])

        proxy_probe.reset_mock()
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": "http://[bad"},
            clear=True,
        ):
            invalid_bundle = scan_node(
                target="example.test",
                port=443,
                protocol="tcp",
                http=True,
                proxy_env="HTTPS_PROXY",
            )
        self.assertEqual(
            invalid_bundle.targets[0]["proxy_endpoint"]["state"],
            "invalid",
        )
        proxy_probe.assert_not_called()
        self.assertNotIn("http://[bad", str(invalid_bundle.to_dict()))

    @patch("netops_core.scanner.run_command")
    def test_trace_rejects_option_and_line_break_targets_before_execution(
        self, run_command
    ):
        for target in ("--help", "example.test\n--help"):
            with self.subTest(target=target):
                with self.assertRaises(ValueError):
                    trace_target(target)
        run_command.assert_not_called()

    @patch("netops_core.scanner.platform_id", return_value="linux")
    @patch("netops_core.scanner.shutil.which", return_value="/usr/bin/tracepath")
    @patch("netops_core.scanner.run_command")
    def test_trace_command_success_is_observation_not_health(
        self, run_command, _which, _platform
    ):
        run_command.return_value = {
            "available": True,
            "returncode": 0,
            "stdout": "1: 192.0.2.1\n",
            "stderr": "",
            "duration_ms": 1,
            "timed_out": False,
        }
        observation = trace_target("example.test")
        self.assertEqual(observation.status, "unknown")
        self.assertTrue(observation.evidence["path_observed"])

    @patch("netops_core.scanner.trace_target")
    @patch("netops_core.scanner._resolve_target")
    def test_node_trace_uses_the_declared_timeout(self, resolve_target, trace):
        resolve_target.return_value = (
            [],
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="failed",
            ),
        )
        trace.return_value = Observation(
            vantage_point="local",
            segment="access-network",
            probe="bounded-route-snapshot",
            status="unknown",
        )

        scan_node(
            target="example.test",
            port=443,
            protocol="tcp",
            trace=True,
            timeout=1.25,
        )

        resolve_target.assert_called_once_with("example.test", 443, "tcp", 1.25)
        trace.assert_called_once_with("example.test", timeout=1.25)

    def test_proxy_environment_summary_does_not_store_proxy_value(self):
        proxy_url = "http://" + "user" + ":" + "password" + "@127.0.0.1:8080"
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": proxy_url},
            clear=True,
        ):
            summary = _proxy_environment_summary()
        serialized = str(summary)
        self.assertIn("HTTPS_PROXY", summary["set_variables"])
        self.assertTrue(
            summary["set_variables"]["HTTPS_PROXY"]["contains_credentials"]
        )
        self.assertNotIn("password", serialized)
        self.assertNotIn("127.0.0.1", serialized)

    def test_proxy_environment_summary_fails_closed_for_malformed_url(self):
        malformed = "http://[bad"
        with patch.dict(
            "os.environ",
            {"HTTP_PROXY": malformed},
            clear=True,
        ):
            summary = _proxy_environment_summary()
        item = summary["set_variables"]["HTTP_PROXY"]
        self.assertFalse(item["valid"])
        self.assertEqual(item["scheme"], "invalid")
        self.assertIsNone(item["contains_credentials"])
        self.assertNotIn(malformed, str(summary))

    def test_isolated_network_process_is_terminated_at_timeout(self):
        started = time.monotonic()
        result = _run_isolated_python(
            "import time; time.sleep(5)",
            [],
            timeout=0.1,
        )
        elapsed = time.monotonic() - started
        self.assertTrue(result["timed_out"])
        self.assertLess(elapsed, 2.5)

    def test_isolated_json_rejects_non_finite_numbers(self):
        with self.assertRaisesRegex(ValueError, "invalid JSON"):
            _isolated_json_payload(
                {
                    "available": True,
                    "returncode": 0,
                    "stdout": '{"ok": NaN}',
                    "stderr": "",
                    "timed_out": False,
                }
            )

    def test_external_identity_fetch_refuses_redirects(self):
        hits = []

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                hits.append(self.path)
                if self.path == "/":
                    self.send_response(302)
                    self.send_header("Location", "/unexpected")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"ip":"8.8.8.8"}')

            def log_message(self, format, *args):
                return

        server = HTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        proxy_environment = {
            "HTTP_PROXY": "",
            "HTTPS_PROXY": "",
            "ALL_PROXY": "",
            "http_proxy": "",
            "https_proxy": "",
            "all_proxy": "",
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
        }
        try:
            with patch.dict("os.environ", proxy_environment, clear=False):
                result = _run_isolated_python(
                    _URL_FETCH_SCRIPT,
                    [f"http://127.0.0.1:{server.server_port}/", "3"],
                    timeout=3,
                )
            payload = _isolated_json_payload(result)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertFalse(payload["ok"])
        self.assertEqual(hits, ["/"])

    @patch("netops_core.scanner._run_isolated_python")
    def test_dns_timeout_is_a_failed_bounded_observation(self, isolated):
        isolated.return_value = {
            "available": True,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "duration_ms": 100,
            "timed_out": True,
        }
        answers, observation = _resolve_target(
            "example.test",
            443,
            "tcp",
            0.1,
        )
        self.assertEqual(answers, [])
        self.assertEqual(observation.status, "failed")
        self.assertTrue(observation.evidence["timed_out"])
        self.assertEqual(isolated.call_args.kwargs["timeout"], 0.1)
        self.assertFalse(
            isolated.call_args.kwargs.get("include_proxy_environment", False)
        )

    @patch("netops_core.scanner._run_isolated_python")
    def test_external_identity_requires_valid_public_ip_content(self, isolated):
        isolated.side_effect = [
            {
                "available": True,
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "ok": True,
                        "status": 200,
                        "body": json.dumps({"ip": "127.0.0.1"}),
                    }
                ),
                "stderr": "",
                "duration_ms": 1,
                "timed_out": False,
            },
            {
                "available": True,
                "returncode": 0,
                "stdout": json.dumps(
                    {"ok": True, "status": 200, "body": "loc=US\nwarp=off\n"}
                ),
                "stderr": "",
                "duration_ms": 1,
                "timed_out": False,
            },
        ]
        observations = _external_identity(timeout=0.25)
        self.assertEqual([item.status for item in observations], ["failed", "failed"])
        self.assertTrue(
            all(call.kwargs["timeout"] == 0.25 for call in isolated.call_args_list)
        )
        self.assertTrue(
            all(
                call.kwargs["include_proxy_environment"]
                for call in isolated.call_args_list
            )
        )

    @patch("netops_core.scanner._run_isolated_python")
    def test_external_identity_timeout_cannot_claim_egress_observed(self, isolated):
        isolated.return_value = {
            "available": True,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "duration_ms": 100,
            "timed_out": True,
        }
        observations = _external_identity(timeout=0.1)
        self.assertEqual([item.status for item in observations], ["failed", "failed"])
        self.assertTrue(
            all(item.evidence["timed_out"] for item in observations)
        )
        limitations = " ".join(observations[0].limitations)
        self.assertIn("代理环境变量", limitations)
        self.assertIn("拒绝跳转", limitations)

    @patch("netops_core.scanner._run_isolated_python")
    def test_external_identity_accepts_only_valid_global_addresses(self, isolated):
        isolated.side_effect = [
            {
                "available": True,
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "ok": True,
                        "status": 200,
                        "body": json.dumps({"ip": "8.8.8.8"}),
                    }
                ),
                "stderr": "",
                "duration_ms": 1,
                "timed_out": False,
            },
            {
                "available": True,
                "returncode": 0,
                "stdout": json.dumps(
                    {
                        "ok": True,
                        "status": 200,
                        "body": "ip=2606:4700:4700::1111\nloc=US\nwarp=off\n",
                    }
                ),
                "stderr": "",
                "duration_ms": 1,
                "timed_out": False,
            },
        ]
        observations = _external_identity(timeout=0.25)
        self.assertEqual([item.status for item in observations], ["ok", "ok"])
        self.assertEqual(observations[0].evidence["ip"], "8.8.8.8")
        self.assertEqual(
            observations[1].evidence["ip"], "2606:4700:4700::1111"
        )

    def test_system_proxy_state_is_parsed_without_assuming_probe_success(self):
        enabled = Observation(
            vantage_point="local",
            segment="client-network",
            probe="system_proxy",
            status="ok",
            evidence={"stdout": "HTTPEnable : 1\n"},
        )
        disabled = Observation(
            vantage_point="local",
            segment="client-network",
            probe="system_proxy",
            status="ok",
            evidence={"stdout": "HTTPEnable : 0\n"},
        )
        self.assertTrue(_system_proxy_enabled(enabled))
        self.assertFalse(_system_proxy_enabled(disabled))
        redacted = Observation(
            vantage_point="local",
            segment="client-network",
            probe="system_proxy",
            status="ok",
            evidence={"enabled": True, "details_redacted": True},
        )
        self.assertTrue(_system_proxy_enabled(redacted))
        unavailable = Observation(
            vantage_point="local",
            segment="client-network",
            probe="system_proxy",
            status="unknown",
            evidence={"available": False, "returncode": None},
        )
        self.assertIsNone(_system_proxy_enabled(unavailable))

    @patch("netops_core.scanner._tls_probe")
    @patch("netops_core.scanner._tcp_probe")
    @patch("netops_core.scanner._resolve_target")
    def test_tls_failure_is_not_hidden_by_successful_tcp_connect(
        self, resolve_target, tcp_probe, tls_probe
    ):
        address = {"family": "ipv4", "address": "192.0.2.1"}
        resolve_target.return_value = (
            [address],
            Observation(
                vantage_point="local",
                segment="dns",
                probe="getaddrinfo",
                status="ok",
            ),
        )
        tcp_probe.return_value = Observation(
            vantage_point="local",
            segment="node-ingress",
            probe="tcp-connect",
            status="ok",
        )
        tls_probe.return_value = Observation(
            vantage_point="local",
            segment="node-ingress",
            probe="tls-handshake",
            status="failed",
        )

        bundle = scan_node(
            target="example.test",
            port=443,
            protocol="tcp",
            tls=True,
        )

        ingress = next(
            segment
            for segment in bundle.path_segments
            if segment["name"] == "node-ingress"
        )
        self.assertEqual(ingress["status"], "failed")

    @patch("netops_core.scanner.run_curated_tools")
    def test_missing_curated_route_tool_does_not_claim_path_observation(self, tools):
        tools.return_value = [
            Observation(
                vantage_point="local",
                segment="access-network",
                probe="curated-tool:mtr",
                status="unknown",
                evidence={"available": False},
            )
        ]
        bundle = scan_node(
            target="localhost",
            port=1,
            protocol="tcp",
            tools=["mtr"],
            external=True,
        )
        access = next(
            item for item in bundle.path_segments if item["name"] == "access-network"
        )
        self.assertEqual(access["status"], "unknown")

    @patch("netops_core.scanner.run_curated_tools")
    def test_each_failed_curated_observation_gets_a_finding(self, tools):
        tools.return_value = [
            Observation(
                vantage_point="local",
                segment="dns",
                probe="curated-tool:dnsdiag",
                status="failed",
                metrics={"loss_percent": 20},
                evidence={"health_interpretation": "dns-packet-loss-observed"},
                confidence="high",
            )
        ]
        bundle = scan_node(
            target="localhost",
            port=1,
            protocol="tcp",
            tools=["dnsdiag"],
            resolver="127.0.0.1",
            external=True,
        )
        self.assertTrue(
            any(
                item["title"] == "curated-tool:dnsdiag 未通过"
                for item in bundle.findings
            )
        )

    @patch("netops_core.scanner._external_identity")
    @patch("netops_core.scanner._platform_commands", return_value={})
    @patch("netops_core.scanner.run_curated_tools", return_value=[])
    def test_curated_tool_consent_does_not_query_identity_providers(
        self, curated, _commands, external_identity
    ):
        scan_client(
            external=False,
            tools=["ipquality"],
            tools_external=True,
        )
        external_identity.assert_not_called()
        self.assertTrue(curated.call_args.kwargs["external"])

    @patch("netops_core.scanner._external_identity")
    def test_identity_consent_is_not_reused_for_curated_tool(self, external_identity):
        with self.assertRaisesRegex(PermissionError, "separate --tool-external"):
            scan_client(
                external=True,
                tools=["ipquality"],
                tools_external=False,
            )
        external_identity.assert_not_called()

    def test_client_local_segment_is_derived_from_real_command_outcome(self):
        failed_observation = Observation(
            vantage_point="local",
            segment="client-network",
            probe="addresses",
            status="unknown",
            evidence={"execution_status": "failed", "timed_out": False},
        )
        result = {
            "available": True,
            "returncode": 1,
            "stdout": "",
            "stderr": "failed",
            "duration_ms": 1,
            "timed_out": False,
        }
        with patch(
            "netops_core.scanner._platform_commands",
            return_value={"addresses": ["probe"]},
        ), patch(
            "netops_core.scanner._command_observation",
            return_value=(failed_observation, result),
        ), patch("netops_core.scanner.platform_id", return_value="unknown"):
            bundle = scan_client()
        segments = {item["name"]: item for item in bundle.path_segments}
        self.assertEqual(segments["client-local"]["status"], "failed")
        self.assertEqual(
            segments["client-local"]["evidence"],
            [failed_observation.observation_id],
        )
        self.assertEqual(segments["access-network"]["status"], "unknown")

    def test_server_segments_require_successful_local_and_egress_observations(self):
        local_observation = Observation(
            vantage_point="local",
            segment="vps",
            probe="routes",
            status="unknown",
            evidence={"execution_status": "succeeded", "timed_out": False},
        )
        local_result = {
            "available": True,
            "returncode": 0,
            "stdout": "route evidence",
            "stderr": "",
            "duration_ms": 1,
            "timed_out": False,
        }
        egress_observation = Observation(
            vantage_point="local",
            segment="public-egress",
            probe="external-identity:ipify-v4",
            status="failed",
            evidence={"error": "invalid provider response"},
        )
        with patch(
            "netops_core.scanner._platform_commands",
            return_value={"routes": ["probe"]},
        ), patch(
            "netops_core.scanner._command_observation",
            return_value=(local_observation, local_result),
        ), patch(
            "netops_core.scanner._external_identity",
            return_value=[egress_observation],
        ), patch(
            "netops_core.scanner._local_resources",
            return_value={},
        ), patch("netops_core.scanner.platform_id", return_value="unknown"):
            bundle = scan_server_local(external=True)
        segments = {item["name"]: item for item in bundle.path_segments}
        self.assertEqual(segments["vps-local"]["status"], "observed")
        self.assertEqual(
            segments["vps-local"]["evidence"],
            [local_observation.observation_id],
        )
        self.assertEqual(segments["vps-egress"]["status"], "failed")
        self.assertEqual(
            segments["vps-egress"]["evidence"],
            [egress_observation.observation_id],
        )

    @patch("netops_core.scanner.run_command")
    @patch("netops_core.scanner.ssh_invocation")
    def test_remote_server_scan_uses_only_minimized_transport_environment(
        self, ssh_invocation, run_command
    ):
        transport_environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": "/private/empty",
        }
        ssh_invocation.return_value = (
            ["ssh", "example-host"],
            transport_environment,
        )
        run_command.return_value = {
            "available": True,
            "returncode": 0,
            "stdout": json.dumps(
                {
                    "platform": {"system": "Linux"},
                    "large_valid_collector_field": "x" * 70_000,
                }
            ),
            "stderr": "",
            "duration_ms": 1,
            "timed_out": False,
        }
        bundle = scan_server_remote({"alias": "example"}, authorized=True)
        call = run_command.call_args
        self.assertEqual(call.kwargs["env"], transport_environment)
        self.assertFalse(call.kwargs["inherit_env"])
        self.assertEqual(call.kwargs["capture_limit"], 1_048_576)
        self.assertEqual(bundle.observations[0].status, "ok")
        self.assertEqual(
            len(bundle.environment["large_valid_collector_field"]),
            70_000,
        )

    @patch("netops_core.scanner.run_command")
    @patch("netops_core.scanner.ssh_invocation")
    def test_remote_server_rejects_non_finite_collector_json(
        self, ssh_invocation, run_command
    ):
        ssh_invocation.return_value = (["ssh", "example-host"], {"PATH": "/bin"})
        run_command.return_value = {
            "available": True,
            "returncode": 0,
            "stdout": '{"platform":{"load":NaN}}',
            "stderr": "",
            "duration_ms": 1,
            "timed_out": False,
        }
        bundle = scan_server_remote({"alias": "example"}, authorized=True)
        self.assertEqual(bundle.observations[0].status, "failed")
        self.assertIn("parse_error", bundle.observations[0].evidence)

    def test_path_segment_evidence_references_existing_observations_only(self):
        bundle = scan_node(target="127.0.0.1", port=1, protocol="tcp")
        observation_ids = {item.observation_id for item in bundle.observations}
        for segment in bundle.path_segments:
            with self.subTest(segment=segment["name"]):
                self.assertTrue(
                    set(segment.get("evidence", [])).issubset(observation_ids)
                )

    def test_compare_requires_same_target(self):
        first = scan_node(target="localhost", port=1, protocol="tcp")
        second = scan_node(target="localhost", port=2, protocol="tcp")
        with tempfile.TemporaryDirectory() as temporary:
            left = write_bundle(Path(temporary) / "left.json", first)
            right = write_bundle(Path(temporary) / "right.json", second)
            with self.assertRaisesRegex(ValueError, "target fields differ"):
                compare_bundles(left, right)

    def test_compare_accepts_same_target_and_time_window(self):
        first = scan_node(target="localhost", port=1, protocol="tcp")
        second = scan_node(target="localhost", port=1, protocol="tcp")
        with tempfile.TemporaryDirectory() as temporary:
            left = write_bundle(Path(temporary) / "left.json", first)
            right = write_bundle(Path(temporary) / "right.json", second)
            comparison = compare_bundles(left, right)
        self.assertEqual(comparison.mode, "compare")
        self.assertEqual(comparison.targets[0]["port"], 1)

    @patch("netops_core.scanner._proxy_http_probe")
    @patch("netops_core.scanner._resolve_target")
    def test_compare_rejects_same_proxy_variable_with_different_endpoints(
        self, resolve, proxy_probe
    ):
        def dns_failure(*_args):
            return (
                [],
                Observation(
                    vantage_point="local",
                    segment="dns",
                    probe="getaddrinfo",
                    status="failed",
                ),
            )

        resolve.side_effect = dns_failure
        proxy_probe.side_effect = lambda *_args, **_kwargs: Observation(
            vantage_point="local",
            segment="proxy-egress",
            probe="curl-via-proxy",
            status="unknown",
        )
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": "http://proxy-one.example:8080"},
            clear=True,
        ):
            first = scan_node(
                target="example.test",
                port=443,
                protocol="tcp",
                http=True,
                proxy_env="HTTPS_PROXY",
            )
        with patch.dict(
            "os.environ",
            {"HTTPS_PROXY": "http://proxy-two.example:8080"},
            clear=True,
        ):
            second = scan_node(
                target="example.test",
                port=443,
                protocol="tcp",
                http=True,
                proxy_env="HTTPS_PROXY",
            )
        with tempfile.TemporaryDirectory() as temporary:
            left = write_bundle(Path(temporary) / "left.json", first)
            right = write_bundle(Path(temporary) / "right.json", second)
            with self.assertRaisesRegex(ValueError, "proxy_endpoint"):
                compare_bundles(left, right)

    def test_compare_requires_two_node_bundles(self):
        target = {"target": "example.test", "port": 443, "protocol": "tcp"}
        node = DiagnosticBundle(
            mode="node",
            vantage_points=["node"],
            targets=[target],
        ).finish()
        for unsupported_mode in ("client", "server", "compare"):
            with self.subTest(mode=unsupported_mode):
                unsupported = DiagnosticBundle(
                    mode=unsupported_mode,
                    vantage_points=[unsupported_mode],
                    targets=[target],
                ).finish()
                with tempfile.TemporaryDirectory() as temporary:
                    left = write_bundle(Path(temporary) / "left.json", node)
                    right = write_bundle(
                        Path(temporary) / "right.json",
                        unsupported,
                    )
                    with self.assertRaisesRegex(ValueError, "two node"):
                        compare_bundles(left, right)

    def test_compare_detects_large_latency_and_loss_divergence(self):
        first = DiagnosticBundle(mode="node", vantage_points=["left"])
        second = DiagnosticBundle(mode="node", vantage_points=["right"])
        target = {"target": "example.test", "port": 443, "protocol": "tcp"}
        first.targets = [target]
        second.targets = [target]
        first.observations.append(
            Observation(
                vantage_point="left",
                segment="access-network",
                probe="latency-sample",
                status="ok",
                metrics={"duration_ms": 1, "loss_percent": 0},
            )
        )
        second.observations.append(
            Observation(
                vantage_point="right",
                segment="access-network",
                probe="latency-sample",
                status="ok",
                metrics={"duration_ms": 5000, "loss_percent": 99},
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            left = write_bundle(Path(temporary) / "left.json", first)
            right = write_bundle(Path(temporary) / "right.json", second)
            comparison = compare_bundles(left, right)
        finding = comparison.findings[0]
        self.assertEqual(finding["title"], "两份诊断结果存在差异")
        compared = next(
            item for item in comparison.observations if item.probe == "compare:latency-sample"
        )
        fields = {item["field"] for item in compared.evidence["differences"]}
        self.assertIn("metrics.duration_ms", fields)
        self.assertIn("metrics.loss_percent", fields)

    def test_compare_rejects_different_http_path_or_diagnostic_configuration(self):
        first = DiagnosticBundle(mode="node", vantage_points=["left"])
        second = DiagnosticBundle(mode="node", vantage_points=["right"])
        common = {
            "target": "example.test",
            "port": 443,
            "protocol": "tcp",
            "tls": True,
            "http": True,
            "proxy": None,
            "trace": False,
            "resolver": None,
            "curated_tools": [],
        }
        first.targets = [{**common, "path": "/checkout"}]
        second.targets = [{**common, "path": "/account"}]
        with tempfile.TemporaryDirectory() as temporary:
            left = write_bundle(Path(temporary) / "left.json", first)
            right = write_bundle(Path(temporary) / "right.json", second)
            with self.assertRaisesRegex(ValueError, "path"):
                compare_bundles(left, right)

        second.targets = [{**common, "path": "/checkout", "tls": False}]
        with tempfile.TemporaryDirectory() as temporary:
            left = write_bundle(Path(temporary) / "left.json", first)
            right = write_bundle(Path(temporary) / "right.json", second)
            with self.assertRaisesRegex(ValueError, "tls"):
                compare_bundles(left, right)

    def test_compare_does_not_report_matching_failures_as_healthy(self):
        first = DiagnosticBundle(mode="node", vantage_points=["left"])
        second = DiagnosticBundle(mode="node", vantage_points=["right"])
        target = {"target": "example.test", "port": 443, "protocol": "tcp"}
        first.targets = [target]
        second.targets = [target]
        for bundle, vantage in ((first, "left"), (second, "right")):
            bundle.observations.append(
                Observation(
                    vantage_point=vantage,
                    segment="node-ingress",
                    probe="tcp-connect",
                    status="failed",
                    evidence={"error": "connection refused"},
                )
            )
        with tempfile.TemporaryDirectory() as temporary:
            left = write_bundle(Path(temporary) / "left.json", first)
            right = write_bundle(Path(temporary) / "right.json", second)
            comparison = compare_bundles(left, right)

        compared = comparison.observations[0]
        self.assertEqual(compared.status, "failed")
        self.assertEqual(compared.evidence["differences"], [])
        self.assertEqual(
            comparison.findings[0]["title"],
            "两份诊断结果一致，但均包含失败观察",
        )

    def test_compare_detects_different_observed_routes(self):
        first = DiagnosticBundle(mode="node", vantage_points=["left"])
        second = DiagnosticBundle(mode="node", vantage_points=["right"])
        target = {
            "target": "example.test",
            "port": 443,
            "protocol": "tcp",
            "trace": True,
        }
        first.targets = [target]
        second.targets = [target]
        first.observations.append(
            Observation(
                vantage_point="left",
                segment="access-network",
                probe="bounded-route-snapshot",
                status="unknown",
                evidence={"path_observed": True, "path_hops": ["192.0.2.1"]},
            )
        )
        second.observations.append(
            Observation(
                vantage_point="right",
                segment="access-network",
                probe="bounded-route-snapshot",
                status="unknown",
                evidence={"path_observed": True, "path_hops": ["192.0.2.2"]},
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            left = write_bundle(Path(temporary) / "left.json", first)
            right = write_bundle(Path(temporary) / "right.json", second)
            comparison = compare_bundles(left, right)

        fields = {
            difference["field"]
            for difference in comparison.observations[0].evidence["differences"]
        }
        self.assertIn("evidence.path_hops", fields)

    def test_report_renders_findings_even_without_failed_observation(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.findings.append(
            {
                "severity": "warning",
                "segment": "destination",
                "title": "目标站策略限制",
                "evidence": [],
                "confidence": "high",
            }
        )
        report = render_report(bundle.finish())
        self.assertIn("## 诊断发现", report)
        self.assertIn("目标站策略限制", report)
        self.assertNotIn("均未发现明确异常", report)

    def test_report_neutralizes_markdown_and_newline_injection(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.targets = [
            {
                "target": "safe.test\n## forged heading | <script>",
                "port": 443,
                "protocol": "tcp",
            }
        ]
        bundle.findings.append(
            {
                "severity": "warning",
                "segment": "destination",
                "title": "[click](https://malicious.test)\n## injected",
                "evidence": [],
                "confidence": "high",
            }
        )
        bundle.limitations.append("ok\n## fake instructions <b>run me</b> | column")
        report = render_report(bundle.finish())
        self.assertNotIn("\n## forged heading", report)
        self.assertNotIn("\n## injected", report)
        self.assertNotIn("\n## fake instructions", report)
        self.assertNotIn("<script>", report)
        self.assertNotIn("<b>", report)
        self.assertNotIn("[click](", report)
        self.assertIn("\\|", report)

    def test_report_neutralizes_control_characters_and_nested_path_labels(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.path_segments = [
            {"name": ["nested\x00name"], "status": {"value": "\x1b[31mfailed"}}
        ]
        bundle.findings.append(
            {
                "severity": "warning",
                "segment": "destination",
                "title": "safe\x00\x1b[31munsafe\u202efake\u2028heading",
                "evidence": [],
                "confidence": "high",
            }
        )

        report = render_report(bundle.finish())

        self.assertNotIn("\x00", report)
        self.assertNotIn("\x1b", report)
        self.assertNotIn("\u202e", report)
        self.assertNotIn("\u2028", report)
        self.assertIn("nested", report)


if __name__ == "__main__":
    unittest.main()
