from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SecurityPropertyDocumentationTests(unittest.TestCase):
    def test_core_methodology_terms(self):
        content = (ROOT / "docs/methodology/README.md").read_text(encoding="utf-8")
        for term in ("Invariant", "Reproduce", "Measure", "Harden", "Regress"):
            self.assertIn(term, content)


if __name__ == "__main__":
    unittest.main()
