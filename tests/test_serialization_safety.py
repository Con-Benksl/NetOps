import unittest

from netops_core.models import DiagnosticBundle
from netops_core.redaction import Redactor


class SerializationSafetyTests(unittest.TestCase):
    def test_cyclic_open_evidence_fails_as_a_contract_error(self):
        cyclic: dict[str, object] = {}
        cyclic["self"] = cyclic
        bundle = DiagnosticBundle(
            mode="local",
            vantage_points=["local"],
            environment=cyclic,
        )

        with self.assertRaisesRegex(ValueError, "cyclic or excessively nested"):
            bundle.to_dict()

    def test_equivalent_network_spellings_share_one_archive_pseudonym(self):
        redactor = Redactor()
        cases = (
            ("ip", "127.1", "127.0.0.1"),
            ("ip", "::ffff:192.0.2.1", "::ffff:c000:201"),
            ("host", "例子。测试", "xn--fsqu00a.xn--0zwm56d"),
            ("mac", "aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        )

        for kind, first, second in cases:
            with self.subTest(kind=kind, first=first):
                self.assertEqual(
                    redactor._label(kind, first),
                    redactor._label(kind, second),
                )


if __name__ == "__main__":
    unittest.main()
