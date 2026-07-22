import unittest
import sys
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

from netops_core.util import (
    load_json_limited,
    parse_json_strict,
    read_text_limited,
    run_command,
    trusted_system_environment,
)


class UtilityBoundaryTests(unittest.TestCase):
    def test_trusted_system_environment_excludes_caller_path_and_secrets(self):
        with patch.dict(
            os.environ,
            {
                "PATH": "/untrusted/bin",
                "AWS_SESSION_TOKEN": "opaque-session-value",
                "HTTP_PROXY": "http://proxy.invalid",
                "SSH_AUTH_SOCK": "/tmp/agent.sock",
            },
            clear=False,
        ):
            environment = trusted_system_environment()
            ssh_environment = trusted_system_environment(include_ssh_auth=True)

        self.assertNotIn("/untrusted/bin", environment["PATH"])
        self.assertNotIn("AWS_SESSION_TOKEN", environment)
        self.assertNotIn("HTTP_PROXY", environment)
        self.assertNotIn("SSH_AUTH_SOCK", environment)
        self.assertEqual(ssh_environment["SSH_AUTH_SOCK"], "/tmp/agent.sock")

    def test_windows_trusted_environment_uses_only_system_search_directories(self):
        with patch.dict(
            os.environ,
            {"SYSTEMROOT": r"C:\Windows", "PATH": r"C:\Users\mallory\bin"},
            clear=False,
        ):
            environment = trusted_system_environment(platform_name="windows")

        self.assertEqual(
            environment["PATH"],
            ";".join(
                (
                    r"C:\Windows\System32\OpenSSH",
                    r"C:\Windows\System32",
                    r"C:\Windows\System32\WindowsPowerShell\v1.0",
                    r"C:\Windows",
                )
            ),
        )
        self.assertNotIn("mallory", environment["PATH"].casefold())

    @unittest.skipIf(os.name == "nt", "POSIX executable fixture")
    def test_command_resolution_uses_the_child_environment_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            executable = Path(temporary) / "netops-safe-path-test"
            executable.write_text("#!/bin/sh\nprintf resolved", encoding="utf-8")
            executable.chmod(0o700)
            result = run_command(
                ["netops-safe-path-test"],
                env={"PATH": temporary},
                inherit_env=False,
            )

        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["stdout"], "resolved")

    def test_minimal_child_environment_does_not_receive_application_tokens(self):
        with patch.dict(
            os.environ,
            {"NETOPS_PRIVATE_TEST_TOKEN": "must-not-reach-child"},
            clear=False,
        ):
            result = run_command(
                [
                    sys.executable,
                    "-c",
                    "import os; print(os.environ.get('NETOPS_PRIVATE_TEST_TOKEN', 'absent'))",
                ],
                env=trusted_system_environment(),
                inherit_env=False,
            )

        self.assertEqual(result["returncode"], 0)
        self.assertEqual(result["stdout"].strip(), "absent")

    def test_limited_text_reader_never_requests_the_whole_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "tool-output.json"
            source.write_text("abcdef", encoding="utf-8")
            self.assertEqual(read_text_limited(source, 3), "abc")

    @unittest.skipUnless(os.name == "posix", "FIFO and symlink contract")
    def test_bounded_readers_reject_nonregular_and_link_inputs_without_blocking(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            regular = root / "regular.json"
            regular.write_text('{"ok": true}', encoding="utf-8")
            link = root / "linked.json"
            link.symlink_to(regular)
            fifo = root / "input.pipe"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(ValueError, "regular file"):
                load_json_limited(link)
            self.assertEqual(read_text_limited(link), '{"ok": true}')
            with self.assertRaisesRegex(ValueError, "regular file"):
                load_json_limited(fifo)
            self.assertEqual(read_text_limited(fifo), "")

    def test_limited_text_reader_rejects_invalid_limits(self):
        for value in (-1, 1_048_577, 1.5, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                read_text_limited("tool-output.json", value)  # type: ignore[arg-type]

    def test_command_output_is_decoded_and_terminal_controls_are_removed(self):
        result = run_command(
            [
                sys.executable,
                "-c",
                (
                    "import sys;"
                    "sys.stdout.buffer.write("
                    "b'visible\\x1b[31m-red\\x1b[0m\\x00\\xff\\r\\n'"
                    ");"
                    "sys.stderr.write('safe\\u202eforged')"
                ),
            ],
            timeout=5,
        )

        self.assertEqual(result["returncode"], 0)
        self.assertNotIn("\x1b", result["stdout"])
        self.assertNotIn("\x00", result["stdout"])
        self.assertIn("visible-red", result["stdout"])
        self.assertIn("\ufffd", result["stdout"])
        self.assertNotIn("\u202e", result["stderr"])

    def test_command_capture_limit_is_explicit_bounded_and_per_call(self):
        result = run_command(
            [sys.executable, "-c", "print('x' * 100)"],
            timeout=5,
            capture_limit=17,
        )
        self.assertEqual(result["stdout"], "x" * 16 + "\n")
        for value in (0, 1_048_577, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                run_command(
                    [sys.executable, "-c", "pass"],
                    capture_limit=value,  # type: ignore[arg-type]
                )

    def test_command_output_is_streamed_to_a_bounded_tail(self):
        result = run_command(
            [
                sys.executable,
                "-c",
                "import sys; sys.stdout.write('a' * 200000 + 'TAIL')",
            ],
            timeout=5,
            capture_limit=1024,
        )
        self.assertEqual(len(result["stdout"]), 1024)
        self.assertTrue(result["stdout"].endswith("TAIL"))
        self.assertTrue(result["stdout_truncated"])
        self.assertFalse(result["stderr_truncated"])

        complete = run_command(
            [sys.executable, "-c", "print('complete')"],
            timeout=5,
            capture_limit=1024,
        )
        self.assertFalse(complete["stdout_truncated"])
        self.assertFalse(complete["stderr_truncated"])

    @unittest.skipUnless(
        os.name in {"posix", "nt"}, "supported descendant-containment contract"
    )
    def test_successful_parent_cannot_leave_a_background_probe_running(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "background-marker"
            child = (
                "import pathlib,time;"
                "time.sleep(0.5);"
                f"pathlib.Path({str(marker)!r}).write_text('escaped')"
            )
            parent = (
                "import subprocess,sys;"
                f"subprocess.Popen([sys.executable, '-c', {child!r}])"
            )
            result = run_command([sys.executable, "-c", parent], timeout=5)
            self.assertEqual(result["returncode"], 0)
            time.sleep(0.7)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(
        os.name in {"posix", "nt"}, "supported descendant-containment contract"
    )
    def test_timeout_terminates_background_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "timeout-marker"
            child = (
                "import pathlib,time;"
                "time.sleep(0.5);"
                f"pathlib.Path({str(marker)!r}).write_text('escaped')"
            )
            parent = (
                "import subprocess,sys,time;"
                f"subprocess.Popen([sys.executable, '-c', {child!r}]);"
                "time.sleep(10)"
            )
            result = run_command([sys.executable, "-c", parent], timeout=0.1)
            self.assertTrue(result["timed_out"])
            self.assertIsNone(result["returncode"])
            time.sleep(0.7)
            self.assertFalse(marker.exists())

    def test_command_timeout_and_input_boundaries_are_validated(self):
        for value in (0, -1, float("nan"), float("inf"), True):
            with self.subTest(timeout=value), self.assertRaises(ValueError):
                run_command(
                    [sys.executable, "-c", "pass"],
                    timeout=value,  # type: ignore[arg-type]
                )
        with self.assertRaises(ValueError):
            run_command(
                [sys.executable, "-c", "pass"],
                input_text=1,  # type: ignore[arg-type]
            )

    def test_strict_json_reader_is_bounded_and_rejects_non_finite_numbers(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_text('{"value": 1}', encoding="utf-8")
            self.assertEqual(load_json_limited(path, max_bytes=12), {"value": 1})
            with self.assertRaisesRegex(ValueError, "exceeds"):
                load_json_limited(path, max_bytes=5)
        for value in (
            '{"value": NaN}',
            '{"value": Infinity}',
            '{"value": 1e9999}',
            '{"value": 1, "value": 2}',
            '{"value": ' + "9" * 129 + '}',
        ):
            with self.subTest(value=value), self.assertRaisesRegex(
                ValueError, "non-finite|duplicate|digit"
            ):
                parse_json_strict(value)
        with self.assertRaises(UnicodeDecodeError):
            parse_json_strict('{"value": 1}'.encode("utf-16"))

    def test_strict_json_parser_converts_excessive_nesting_to_a_controlled_error(self):
        deeply_nested = "[" * 2_000 + "0" + "]" * 2_000
        with self.assertRaisesRegex(ValueError, "nesting|depth"):
            parse_json_strict(deeply_nested)


if __name__ == "__main__":
    unittest.main()
