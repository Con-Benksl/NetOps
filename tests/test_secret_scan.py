import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from scripts import check_secrets
from netops_core.redaction import CREDENTIAL_URI_SCHEMES


class SecretScanTests(unittest.TestCase):
    def test_secret_scanner_and_runtime_redactor_cover_the_same_node_schemes(self):
        self.assertEqual(
            set(check_secrets.NODE_LINK_SCHEMES),
            set(CREDENTIAL_URI_SCHEMES),
        )

    def _scan_text(self, value: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "sample.txt").write_text(value, encoding="utf-8")
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = check_secrets.main([str(root)])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_git_sha1_is_not_misclassified_as_cloudflare_token(self):
        result, stdout, stderr = self._scan_text(
            "44c35cca002782ddd6364e039be2949a2535d1cc"
        )
        self.assertEqual(result, 0)
        self.assertIn("secret scan: clean", stdout)
        self.assertEqual(stderr, "")

    def test_labeled_cloudflare_token_is_rejected(self):
        label = "CLOUDFLARE_" + "API_TOKEN="
        token = "a" * 40
        result, stdout, stderr = self._scan_text(label + token)
        self.assertEqual(result, 1)
        self.assertEqual(stdout, "")
        self.assertIn("cloudflare-token", stderr)

    def test_all_supported_credential_uri_schemes_are_rejected(self):
        for scheme in (
            "ss",
            "ssr",
            "hysteria",
            "hysteria2",
            "tuic",
            "wireguard",
            "anytls",
        ):
            with self.subTest(scheme=scheme):
                result, stdout, stderr = self._scan_text(
                    scheme + ":" + "//opaque-credential-material"
                )
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertIn("node-link", stderr)

    def test_runtime_provider_token_families_are_rejected(self):
        tokens = {
            "openai": "sk-" + "proj-" + "A" * 32,
            "aws": "AKIA" + "B" * 16,
            "slack": "xoxb-" + "1234567890-ABCDEFGHIJ",
            "gitlab": "glpat-" + "C" * 24,
            "google-oauth": "ya29." + "D" * 32,
        }
        for label, token in tokens.items():
            with self.subTest(label=label):
                result, stdout, stderr = self._scan_text(token)
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertIn("provider-token", stderr)

    def test_bearer_and_secret_assignments_are_rejected(self):
        for value, expected in (
            ("Authorization: " + "Bearer " + "abcdefghijk", "bearer-credential"),
            ("pass" + "word=UltraSecretValue", "secret-assignment"),
            ("AWS_SECRET_ACCESS_KEY=" + "A" * 40, "secret-assignment"),
            ("SharedAccessKey=" + "B" * 40, "secret-assignment"),
            (
                "SharedAccess" + "Signature=sv=2026-01-01&sig=TopSecretSignature",
                "secret-assignment",
            ),
        ):
            with self.subTest(expected=expected):
                result, stdout, stderr = self._scan_text(value)
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertIn(expected, stderr)


if __name__ == "__main__":
    unittest.main()
