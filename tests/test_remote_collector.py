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

        self.assertEqual(result["returncode"], 0)
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

        self.assertIsNone(result["returncode"])
        self.assertIn("timed out", result["stderr"])
        self.assertLess(duration, 2.0)


if __name__ == "__main__":
    unittest.main()
