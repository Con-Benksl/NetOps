import io
import inspect
import json
import os
import tempfile
import unittest
import unicodedata
from pathlib import Path
from unittest.mock import patch

import netops_core.cli as cli
import netops_core.change as change
import netops_core.monitor as monitor
from netops_core.models import DiagnosticBundle, Observation


class CliContractTests(unittest.TestCase):
    def test_monitor_help_hides_compatibility_sampler_and_has_no_authorization_flag(self):
        output = io.StringIO()
        with patch("sys.stdout", output), self.assertRaises(SystemExit) as exit_info:
            cli.build_parser().parse_args(["monitor", "--help"])
        self.assertEqual(exit_info.exception.code, 0)
        rendered = output.getvalue()
        self.assertNotIn("sample", rendered)
        self.assertNotIn("SUPPRESS", rendered)
        self.assertNotIn("authorized", rendered)

        with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(
                [
                    "monitor",
                    "remove",
                    "--dry-run",
                    "--authorized",
                ]
            )
        self.assertNotIn(
            "authorized", inspect.signature(monitor.install_monitor).parameters
        )
        self.assertNotIn(
            "authorized", inspect.signature(monitor.remove_monitor).parameters
        )

    def test_scan_output_cannot_overwrite_report_at_same_path(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"]).finish()
        with tempfile.TemporaryDirectory() as temporary:
            for suffix in (".md", ".MD", ".Md"):
                with self.subTest(suffix=suffix):
                    output = Path(temporary) / f"result{suffix}"
                    with self.assertRaisesRegex(ValueError, "must not end in .md"):
                        cli._write_scan(bundle, str(output))
                    self.assertFalse(output.exists())

    def test_scan_output_and_report_are_distinct(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"]).finish()
        with tempfile.TemporaryDirectory() as temporary:
            result = cli._write_scan(bundle, str(Path(temporary) / "result.json"))
            self.assertNotEqual(result["bundle"], result["report"])
            self.assertTrue(Path(result["bundle"]).is_file())
            self.assertTrue(Path(result["report"]).is_file())
            if os.name != "nt":
                self.assertEqual(
                    Path(result["report"]).stat().st_mode & 0o777,
                    0o600,
                )

    def test_scan_refuses_to_overwrite_bundle_or_derived_report(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"]).finish()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "result.json"
            report = root / "result.md"
            report.write_text("sentinel", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "derived Markdown report"):
                cli._write_scan(bundle, str(output))
            self.assertEqual(report.read_text(encoding="utf-8"), "sentinel")
            self.assertFalse(output.exists())

            report.unlink()
            output.write_text("sentinel", encoding="utf-8")
            with self.assertRaisesRegex(FileExistsError, "diagnostic bundle"):
                cli._write_scan(bundle, str(output))
            self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")

    @unittest.skipIf(os.name == "nt", "symlink creation is not generally available")
    def test_scan_and_report_outputs_reject_dangling_symlinks(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"]).finish()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = root / "missing-target.json"
            output = root / "result.json"
            output.symlink_to(missing)
            with self.assertRaisesRegex(FileExistsError, "diagnostic bundle"):
                cli._write_scan(bundle, str(output))
            self.assertFalse(missing.exists())

            output.unlink()
            report = root / "result.md"
            report.symlink_to(root / "missing-report.md")
            with self.assertRaisesRegex(FileExistsError, "derived Markdown report"):
                cli._write_scan(bundle, str(output))
            self.assertFalse((root / "missing-report.md").exists())
            self.assertFalse(output.exists())

    def test_report_is_rendered_from_persisted_sanitized_bundle(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"])
        bundle.observations.append(
            Observation(
                vantage_point="test",
                segment="destination",
                probe="header-sample",
                status="unknown",
                evidence={"Authorization": "Bearer " + "REPORT_SECRET"},
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = cli._write_scan(
                bundle, str(Path(temporary) / "result.json")
            )
            report = Path(result["report"]).read_text(encoding="utf-8")
            persisted = Path(result["bundle"]).read_text(encoding="utf-8")
        self.assertNotIn("REPORT_SECRET", report)
        self.assertNotIn("REPORT_SECRET", persisted)

    @patch("netops_core.cli.scan_client")
    def test_scan_conflict_is_rejected_before_any_probe(self, scan_client):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            output.write_text("sentinel", encoding="utf-8")
            args = cli.build_parser().parse_args(
                ["scan", "client", "--output", str(output)]
            )
            with self.assertRaisesRegex(FileExistsError, "diagnostic bundle"):
                cli.execute(args)
            self.assertEqual(output.read_text(encoding="utf-8"), "sentinel")
        scan_client.assert_not_called()

    @patch("netops_core.cli.scan_client")
    def test_derived_report_conflict_is_rejected_before_any_probe(self, scan_client):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            report = output.with_suffix(".md")
            report.write_text("sentinel", encoding="utf-8")
            args = cli.build_parser().parse_args(
                ["scan", "client", "--output", str(output)]
            )
            with self.assertRaisesRegex(FileExistsError, "derived Markdown report"):
                cli.execute(args)
            self.assertFalse(output.exists())
            self.assertEqual(report.read_text(encoding="utf-8"), "sentinel")
        scan_client.assert_not_called()

    @patch("netops_core.cli.scan_client", side_effect=RuntimeError("probe failed"))
    def test_failed_scan_releases_both_output_reservations(self, _scan_client):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            report = output.with_suffix(".md")
            args = cli.build_parser().parse_args(
                ["scan", "client", "--output", str(output)]
            )
            with self.assertRaisesRegex(RuntimeError, "probe failed"):
                cli.execute(args)
            self.assertFalse(output.exists())
            self.assertFalse(report.exists())

    @unittest.skipIf(os.name == "nt", "symlink creation is not generally available")
    def test_scan_publish_rejects_replaced_reservation_without_following_symlink(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"]).finish()
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            victim = Path(temporary) / "victim.md"
            victim.write_text("sentinel", encoding="utf-8")
            reservations = cli._reserve_scan_outputs("node", str(output))
            report = output.with_suffix(".md")
            report.unlink()
            report.symlink_to(victim)

            with self.assertRaisesRegex(FileExistsError, "replaced"):
                cli._write_scan(
                    bundle,
                    str(output),
                    reservations=reservations,
                )

            self.assertEqual(victim.read_text(encoding="utf-8"), "sentinel")
            self.assertFalse(output.exists())
            self.assertTrue(report.is_symlink())

    def test_partial_scan_publish_removes_its_own_json_and_reservation(self):
        bundle = DiagnosticBundle(mode="node", vantage_points=["test"]).finish()
        original_publish = cli._publish_reserved_output
        calls = 0

        def fail_second_publish(staged, destination, reservation):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("simulated report publish failure")
            return original_publish(staged, destination, reservation)

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.json"
            report = output.with_suffix(".md")
            with patch(
                "netops_core.cli._publish_reserved_output",
                side_effect=fail_second_publish,
            ):
                with self.assertRaisesRegex(OSError, "report publish failure"):
                    cli._write_scan(bundle, str(output))
            self.assertFalse(output.exists())
            self.assertFalse(report.exists())

    @unittest.skipIf(os.name == "nt", "chmod branch is POSIX-only")
    def test_new_text_output_is_removed_if_pre_publish_hardening_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.md"
            with patch(
                "netops_core.cli.os.fchmod", side_effect=OSError("chmod failed")
            ):
                with self.assertRaisesRegex(OSError, "chmod failed"):
                    cli._write_text_new(output, "report", label="test report")
            self.assertFalse(output.exists())

    def test_tool_option_may_be_supplied_only_once(self):
        parser = cli.build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "scan",
                    "node",
                    "--target",
                    "example.test",
                    "--port",
                    "443",
                    "--tool",
                    "mtr",
                    "--tool",
                    "nexttrace",
                ]
            )

    @patch("netops_core.cli._write_scan", return_value={})
    @patch("netops_core.cli.scan_client")
    def test_client_tool_consent_is_separate_from_identity_lookup(
        self, scan_client, _write_scan
    ):
        scan_client.return_value = DiagnosticBundle(
            mode="client", vantage_points=["test"]
        ).finish()
        args = cli.build_parser().parse_args(
            [
                "scan",
                "client",
                "--tool",
                "ipquality",
                "--tool-external",
            ]
        )
        self.assertEqual(cli.execute(args), 0)
        scan_client.assert_called_once_with(
            external=False,
            tools=["ipquality"],
            tools_external=True,
        )

    @patch("netops_core.cli._json")
    @patch("netops_core.cli.assess_control_channel", return_value={"decision": "block"})
    @patch("netops_core.cli.normalize_rollback_timer", return_value={})
    @patch("netops_core.cli.normalize_control_channel", side_effect=lambda value: value)
    def test_safety_assess_passes_repeatable_non_secret_evidence(
        self, normalize, _timer, _assess, _json
    ):
        args = cli.build_parser().parse_args(
            [
                "safety",
                "assess",
                "--evidence",
                "second management path verified",
                "--evidence",
                "rollback console tested",
            ]
        )
        self.assertEqual(cli.execute(args), 0)
        value = normalize.call_args.args[0]
        self.assertEqual(
            value["evidence"],
            ["second management path verified", "rollback console tested"],
        )

    def test_safety_evidence_rejects_placeholder_text(self):
        args = cli.build_parser().parse_args(
            ["safety", "assess", "--evidence", "x"]
        )
        with self.assertRaisesRegex(ValueError, "8..500"):
            cli.execute(args)

    def test_change_execution_cli_is_unconditionally_unreleased(self):
        parser_help = cli.build_parser().format_help()
        self.assertIn("Plan a controlled remote change", parser_help)
        self.assertIn("unavailable in this release", parser_help)
        for mode in ("apply", "rollback"):
            output = io.StringIO()
            with patch("sys.stdout", output), self.assertRaises(SystemExit) as exit_info:
                cli.build_parser().parse_args(["change", mode, "--help"])
            self.assertEqual(exit_info.exception.code, 0)
            self.assertNotIn("--authorized", output.getvalue())
        self.assertNotIn(
            "authorized", inspect.signature(change.apply_plan).parameters
        )
        self.assertNotIn(
            "authorized", inspect.signature(change.rollback_plan).parameters
        )
        with patch("sys.stderr", io.StringIO()), self.assertRaises(SystemExit):
            cli.build_parser().parse_args(
                [
                    "change",
                    "apply",
                    "--plan",
                    "missing-plan.json",
                    "--fleet",
                    "missing-fleet.json",
                    "--authorized",
                    "--confirm-plan-id",
                    "not-a-plan-id",
                ]
            )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                [
                    "change",
                    "apply",
                    "--plan",
                    str(root / "missing-plan.json"),
                    "--fleet",
                    str(root / "missing-fleet.json"),
                    "--confirm-plan-id",
                    "not-a-plan-id",
                    "--receipt",
                    str(root / "apply.receipt.json"),
                ],
                [
                    "change",
                    "rollback",
                    "--plan",
                    str(root / "missing-plan.json"),
                    "--fleet",
                    str(root / "missing-fleet.json"),
                    "--backup-dir",
                    "not-a-backup",
                    "--apply-receipt",
                    str(root / "missing-apply.receipt.json"),
                    "--current-control-channel",
                    str(root / "missing-control.json"),
                    "--confirm-plan-id",
                    "not-a-plan-id",
                    "--receipt",
                    str(root / "rollback.receipt.json"),
                ],
            )
            for arguments in cases:
                with self.subTest(mode=arguments[1]), patch(
                    "netops_core.cli.load_fleet"
                ) as load_fleet, patch(
                    "netops_core.cli.create_plan"
                ) as create_plan, patch(
                    "netops_core.cli.load_json_limited"
                ) as load_json, patch(
                    "netops_core.change._remote_script"
                ) as remote, patch(
                    "netops_core.cli.resolve_apply_receipt_path"
                ) as resolve_apply, patch(
                    "netops_core.cli.resolve_rollback_receipt_path"
                ) as resolve_rollback, patch(
                    "netops_core.cli.os.path.lexists"
                ) as lexists:
                    stderr = io.StringIO()
                    with patch.object(cli.sys, "stderr", stderr):
                        self.assertEqual(cli.main(arguments), 2)
                    self.assertIn(
                        "remote change execution is unavailable in this release",
                        stderr.getvalue(),
                    )
                    load_fleet.assert_not_called()
                    create_plan.assert_not_called()
                    load_json.assert_not_called()
                    remote.assert_not_called()
                    resolve_apply.assert_not_called()
                    resolve_rollback.assert_not_called()
                    lexists.assert_not_called()
            self.assertFalse((root / "apply.receipt.json").exists())
            self.assertFalse((root / "rollback.receipt.json").exists())

    def test_installed_entry_point_is_resolved_independently_of_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installed = root / "bin" / (
                "netopsctl.exe" if os.name == "nt" else "netopsctl"
            )
            module_file = root / "site-packages" / "netops_core" / "cli.py"
            with patch.object(cli, "__file__", str(module_file)), patch.object(
                cli.sys, "argv", ["netopsctl"]
            ), patch.object(cli.shutil, "which", return_value=str(installed)):
                self.assertEqual(cli._entry_script(), installed.resolve())

    @patch(
        "netops_core.cli.execute",
        side_effect=ValueError(
            "Authorization: " + "Bearer " + "SCHEDULER_SECRET for target.example"
        ),
    )
    def test_main_redacts_errors_before_scheduler_stderr(self, _execute):
        stderr = io.StringIO()
        with patch.object(cli.sys, "stderr", stderr):
            result = cli.main(["tools", "list"])
        self.assertEqual(result, 2)
        output = stderr.getvalue()
        self.assertNotIn("SCHEDULER_SECRET", output)
        self.assertNotIn("target.example", output)
        self.assertIn("sensitive-header-removed", output)

    def test_main_redacts_user_value_from_argparse_errors(self):
        stderr = io.StringIO()
        with patch.object(cli.sys, "stderr", stderr):
            result = cli.main(
                [
                    "scan",
                    "node",
                    "--target",
                    "example.test",
                    "--port",
                    "ARGPARSE_SECRET",
                ]
            )
        self.assertEqual(result, 2)
        output = stderr.getvalue()
        self.assertNotIn("ARGPARSE_SECRET", output)
        self.assertIn("<redacted-input>", output)
        self.assertIn("--port", output)

    def test_main_redacts_multiline_unrecognized_argument(self):
        stderr = io.StringIO()
        with patch.object(cli.sys, "stderr", stderr):
            result = cli.main(["tools", "list", "--FIRST_SECRET\nSECOND_SECRET"])
        self.assertEqual(result, 2)
        output = stderr.getvalue()
        self.assertNotIn("FIRST_SECRET", output)
        self.assertNotIn("SECOND_SECRET", output)
        self.assertIn("unrecognized arguments: <redacted-input>", output)

    def test_main_redacts_multiline_invalid_choice(self):
        stderr = io.StringIO()
        with patch.object(cli.sys, "stderr", stderr):
            result = cli.main(
                [
                    "scan",
                    "node",
                    "--target",
                    "example.test",
                    "--port",
                    "443",
                    "--protocol",
                    "BAD_PROTOCOL\nSECOND_SECRET",
                ]
            )
        self.assertEqual(result, 2)
        output = stderr.getvalue()
        self.assertNotIn("BAD_PROTOCOL", output)
        self.assertNotIn("SECOND_SECRET", output)
        self.assertIn("invalid choice: <redacted-input>", output)

    @patch(
        "netops_core.cli.execute",
        side_effect=ValueError(
            "safe\x1b[31m colored\x1b[0m\x00\x07\u200d\u2028\u2029text"
        ),
    )
    def test_main_removes_terminal_and_unicode_controls_from_stderr(self, _execute):
        stderr = io.StringIO()
        with patch.object(cli.sys, "stderr", stderr):
            result = cli.main(["tools", "list"])
        self.assertEqual(result, 2)
        output = stderr.getvalue()
        self.assertIn("safe colored text", output)
        self.assertNotIn("\x1b", output)
        self.assertNotIn("\u2028", output)
        self.assertNotIn("\u2029", output)
        self.assertTrue(
            all(
                unicodedata.category(character) not in {"Cc", "Cf"}
                for character in output
            )
        )

    @unittest.skip("change execution receipts are intentionally unreleased")
    def test_main_surfaces_change_receipt_status_after_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "apply.receipt.json"

            def fail_with_receipt(_args):
                receipt.write_text(
                    json.dumps({"status": "rollback-pending"}),
                    encoding="utf-8",
                )
                raise RuntimeError("connection lost")

            stderr = io.StringIO()
            with patch("netops_core.cli.execute", side_effect=fail_with_receipt), patch.object(
                cli.sys, "stderr", stderr
            ):
                result = cli.main(
                    [
                        "change",
                        "apply",
                        "--plan",
                        str(root / "plan.json"),
                        "--fleet",
                        str(root / "fleet.json"),
                        "--confirm-plan-id",
                        "0123456789abcdef",
                        "--receipt",
                        str(receipt),
                    ]
                )
        self.assertEqual(result, 2)
        output = stderr.getvalue()
        self.assertIn("rollback-pending", output)
        self.assertIn("path=", output)
        self.assertIn("apply.receipt.json", output)
        self.assertIn("do not retry", output)

    @unittest.skip("change execution receipts are intentionally unreleased")
    def test_main_treats_non_finite_change_receipt_as_unreadable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "apply.receipt.json"

            def fail_with_invalid_receipt(_args):
                receipt.write_text('{"status": NaN}', encoding="utf-8")
                raise RuntimeError("connection lost")

            stderr = io.StringIO()
            with patch(
                "netops_core.cli.execute",
                side_effect=fail_with_invalid_receipt,
            ), patch.object(cli.sys, "stderr", stderr):
                result = cli.main(
                    [
                        "change",
                        "apply",
                        "--plan",
                        str(root / "plan.json"),
                        "--fleet",
                        str(root / "fleet.json"),
                        "--confirm-plan-id",
                        "0123456789abcdef",
                        "--receipt",
                        str(receipt),
                    ]
                )
        self.assertEqual(result, 2)
        self.assertIn("status=unreadable", stderr.getvalue())

    def test_main_does_not_misreport_a_preexisting_receipt_as_current(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / "old-receipt.json"
            receipt.write_text(
                json.dumps({"status": "rollback-pending"}), encoding="utf-8"
            )
            stderr = io.StringIO()
            with patch(
                "netops_core.cli.execute",
                side_effect=FileExistsError("receipt already exists"),
            ), patch.object(cli.sys, "stderr", stderr):
                result = cli.main(
                    [
                        "change",
                        "apply",
                        "--plan",
                        str(root / "plan.json"),
                        "--fleet",
                        str(root / "fleet.json"),
                        "--confirm-plan-id",
                        "0123456789abcdef",
                        "--receipt",
                        str(receipt),
                    ]
                )
        self.assertEqual(result, 2)
        self.assertNotIn("rollback-pending", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
