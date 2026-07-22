import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from netops_core.remote_collector import REMOTE_COLLECTOR


def load_collector_namespace():
    namespace = {"__name__": "netops_remote_collector_test"}
    exec(REMOTE_COLLECTOR, namespace)
    return namespace


class RemoteCollectorProcessTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "requires the Windows system API")
    def test_windows_environment_keeps_required_system_context_only(self):
        environment = {
            "SYSTEMROOT": r"C:\Users\attacker\fake-windows",
            "COMSPEC": r"C:\Users\attacker\cmd.exe",
            "PATHEXT": ".EVIL",
            "PATH": r"C:\Users\attacker\bin",
            "TEMP": r"C:\Users\attacker\temp",
            "TMP": r"C:\Users\attacker\tmp",
            "APPLICATION_TOKEN": "must-not-leak",
        }
        with patch.dict(os.environ, environment, clear=True):
            collector = load_collector_namespace()

        child_environment = collector["SYSTEM_ENVIRONMENT"]
        trusted_root = child_environment["SYSTEMROOT"]
        self.assertEqual(
            set(child_environment),
            {
                "PATH",
                "SYSTEMROOT",
                "SystemRoot",
                "WINDIR",
                "COMSPEC",
                "PATHEXT",
            },
        )
        self.assertNotIn(r"C:\Users\attacker", trusted_root)
        self.assertEqual(
            child_environment["PATH"],
            ";".join(
                (
                    trusted_root + r"\System32\OpenSSH",
                    trusted_root + r"\System32",
                    trusted_root + r"\System32\WindowsPowerShell\v1.0",
                    trusted_root,
                )
            ),
        )
        self.assertEqual(
            child_environment["COMSPEC"], trusted_root + r"\System32\cmd.exe"
        )
        self.assertEqual(child_environment["PATHEXT"], ".COM;.EXE;.BAT;.CMD")
        self.assertNotIn("APPLICATION_TOKEN", child_environment)

    def test_launch_error_marks_command_unavailable(self):
        collector = load_collector_namespace()
        with patch.object(
            collector["shutil"], "which", return_value="/test/probe"
        ), patch.object(
            collector["subprocess"], "Popen", side_effect=OSError("exec denied")
        ):
            result = collector["run"](["probe"])

        self.assertFalse(result["available"])
        self.assertIsNone(result["returncode"])
        self.assertIn("exec denied", result["stderr"])

    def test_run_streams_large_output_into_bounded_tails(self):
        collector = load_collector_namespace()
        command = (
            "import os\n"
            "os.write(1, b'A' * 2_000_000 + b'OUT-END')\n"
            "os.write(2, b'B' * 2_000_000 + b'ERR-END')\n"
        )

        result = collector["run"]([sys.executable, "-c", command], timeout=5)

        self.assertEqual(result["returncode"], 0, result)
        self.assertLessEqual(len(result["stdout"]), collector["MAX_CHARS"])
        self.assertLessEqual(len(result["stderr"]), collector["MAX_CHARS"])
        self.assertTrue(result["stdout"].endswith("OUT-END"))
        self.assertTrue(result["stderr"].endswith("ERR-END"))

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_timeout_kills_background_process_group(self):
        collector = load_collector_namespace()
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "background-survived"
            child = (
                "from pathlib import Path\n"
                "import sys, time\n"
                "time.sleep(1.0)\n"
                "Path(sys.argv[1]).write_text('survived', encoding='utf-8')\n"
            )
            parent = (
                "import signal, subprocess, sys\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]])\n"
                "print('spawned', flush=True)\n"
            )

            started = time.monotonic()
            result = collector["run"](
                [sys.executable, "-c", parent, child, str(marker)],
                timeout=0.2,
            )
            duration = time.monotonic() - started
            time.sleep(0.8)

            self.assertIsNone(result["returncode"])
            self.assertIn("timed out", result["stderr"])
            self.assertLess(duration, 2.0)
            self.assertFalse(marker.exists())

    def test_timeout_remains_bounded_after_process_closes_both_pipes(self):
        collector = load_collector_namespace()
        command = (
            "import os, time\n"
            "os.close(1)\n"
            "os.close(2)\n"
            "time.sleep(5)\n"
        )

        started = time.monotonic()
        result = collector["run"]([sys.executable, "-c", command], timeout=0.2)
        duration = time.monotonic() - started

        self.assertIsNone(result["returncode"], result)
        self.assertIn("timed out", result["stderr"])
        self.assertLess(duration, 2.0)

    def test_stalled_pipe_reader_fails_closed_instead_of_returning(self):
        collector = load_collector_namespace()
        release = collector["threading"].Event()
        stopped = collector["threading"].Event()
        original_drain = collector["drain_stream"]
        stopped_count = 0
        stopped_lock = collector["threading"].Lock()

        def stalled_drain(stream, buffer):
            nonlocal stopped_count
            release.wait(timeout=5)
            try:
                original_drain(stream, buffer)
            finally:
                with stopped_lock:
                    stopped_count += 1
                    if stopped_count == 2:
                        stopped.set()

        collector["drain_stream"] = stalled_drain
        try:
            with self.assertRaisesRegex(
                RuntimeError, "collector pipe reader did not terminate"
            ):
                collector["run"](
                    [sys.executable, "-c", "pass"],
                    timeout=0.05,
                )
        finally:
            release.set()
            self.assertTrue(stopped.wait(timeout=2))


if __name__ == "__main__":
    unittest.main()
