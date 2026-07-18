import socket
import tempfile
import threading
import unittest
from pathlib import Path

from netops_core.models import write_bundle
from netops_core.scanner import compare_bundles, scan_node


class ScannerTests(unittest.TestCase):
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
        self.assertIn("protocol-aware", " ".join(udp[0].limitations))

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


if __name__ == "__main__":
    unittest.main()
