import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {
    "netops-start",
    "netops-scan",
    "netops-build",
    "netops-fix",
    "netops-manage",
}


class SkillContractTests(unittest.TestCase):
    def test_exactly_five_child_skills(self):
        names = {
            path.parent.name
            for path in (ROOT / "skills").glob("*/SKILL.md")
        }
        self.assertEqual(names, EXPECTED)

    def test_generalized_intent_corpus_uses_only_broad_skills(self):
        cases = json.loads(
            (ROOT / "tests/fixtures/generalized-intents.json").read_text(encoding="utf-8")
        )
        self.assertGreaterEqual(len(cases), 40)
        self.assertEqual({case["skill"] for case in cases}, EXPECTED)
        serialized = json.dumps(cases, ensure_ascii=False)
        for forbidden in ("北京", "杭州", "PayPal", "Netlify"):
            self.assertNotIn(forbidden, serialized)
        self.assertIsNone(
            re.search(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", serialized)
        )

    def test_skill_files_do_not_hardcode_historical_identifiers(self):
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in [ROOT / "SKILL.md", *(ROOT / "skills").glob("*/SKILL.md")]
        )
        for forbidden in (
            "北京移动",
            "杭州",
            "PayPal",
            "Netlify",
        ):
            self.assertNotIn(forbidden, text)
        self.assertNotIn(".top", text)
        self.assertIsNone(
            re.search(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", text)
        )


if __name__ == "__main__":
    unittest.main()
