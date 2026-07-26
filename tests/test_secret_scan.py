import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from scripts import check_secrets
from netops_core.redaction import CREDENTIAL_URI_SCHEMES, UUID_RE


class SecretScanTests(unittest.TestCase):
    def test_secret_scanner_and_runtime_redactor_cover_the_same_node_schemes(self):
        self.assertEqual(
            set(check_secrets.NODE_LINK_SCHEMES),
            set(CREDENTIAL_URI_SCHEMES),
        )

    def test_secret_scanner_and_runtime_redactor_share_the_uuid_pattern(self):
        self.assertEqual(check_secrets.UUID_RE.pattern, UUID_RE.pattern)

    def _client_uuid(self) -> str:
        """Build a credential shaped uuid4 without storing one in this file."""

        return "d3c7f1a9-" + "4b2e-" + "4c88-" + "9f10-" + "6a5e2b7c41d9"

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


    def test_bare_client_uuid_in_a_node_config_fragment_is_rejected(self):
        client_uuid = self._client_uuid()
        fragments = {
            "markdown": (
                "节点配置片段：\n\n```json\n"
                '{"id": "' + client_uuid + '", "flow": "xtls-rprx-vision"}\n'
                "```\n"
            ),
            "json": '{"clients": [{"id": "' + client_uuid + '"}]}',
            "yaml": "clients:\n  - id: " + client_uuid + "\n",
            "bare": client_uuid,
        }
        for name, fragment in fragments.items():
            with self.subTest(name=name):
                result, stdout, stderr = self._scan_text(fragment)
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertIn("credential-uuid", stderr)

    def test_diagnostic_foreign_key_uuids_are_not_flagged(self):
        client_uuid = self._client_uuid()
        for name, fragment in (
            ("json run id", '{"run_id": "' + client_uuid + '"}'),
            ("json observation id", '{"observation_id": "' + client_uuid + '"}'),
            (
                "evidence reference list",
                '{"evidence": ["' + client_uuid + '", "' + client_uuid + '"]}',
            ),
            (
                "multiline evidence reference list",
                '{"evidence": [\n  "' + client_uuid + '",\n  "'
                + client_uuid
                + '"\n]}',
            ),
            ("python fixture", 'root_run_id = "' + client_uuid + '"'),
            ("yaml run id", "run_id: " + client_uuid),
        ):
            with self.subTest(name=name):
                result, stdout, stderr = self._scan_text(fragment)
                self.assertEqual(result, 0, stderr)
                self.assertIn("secret scan: clean", stdout)
                self.assertEqual(stderr, "")

    def test_evidence_allowlist_requires_a_reference_list(self):
        client_uuid = self._client_uuid()
        for name, fragment in (
            ("json scalar", '{"evidence": "' + client_uuid + '"}'),
            ("python scalar", 'evidence = "' + client_uuid + '"'),
            ("yaml scalar", "evidence: " + client_uuid),
        ):
            with self.subTest(name=name):
                result, stdout, stderr = self._scan_text(fragment)
                self.assertEqual(result, 1)
                self.assertEqual(stdout, "")
                self.assertIn("credential-uuid", stderr)

    def test_documentation_placeholder_uuids_are_not_flagged(self):
        for name, value in (
            ("nil", "00000000-0000-0000-0000-000000000000"),
            ("rfc example", "123e4567-e89b-12d3-a456-426614174000"),
            ("fleet fixture", "123e4567-e89b-42d3-a456-426614174000"),
            ("hand numbered run id", "10000000-0000-7000-8000-000000000001"),
            ("hand numbered observation id", "20000000-0000-8000-8000-000000000002"),
        ):
            with self.subTest(name=name):
                result, stdout, stderr = self._scan_text('{"id": "' + value + '"}')
                self.assertEqual(result, 0, stderr)
                self.assertIn("secret scan: clean", stdout)
                self.assertEqual(stderr, "")

    def test_shipped_examples_scan_clean(self):
        examples = Path(__file__).resolve().parents[1] / "examples"
        stdout = StringIO()
        stderr = StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = check_secrets.main([str(examples)])
        self.assertEqual(result, 0, stderr.getvalue())
        self.assertIn("secret scan: clean", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
