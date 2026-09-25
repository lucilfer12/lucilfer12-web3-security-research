import unittest
class SecurityPropertyDocumentationTests(unittest.TestCase):
    def test_core_methodology_terms(self):
        text = open("docs/methodology/README.md", encoding="utf-8").read()
        for term in ("Invariant", "Reproduce", "Measure", "Harden", "Regress"):
            self.assertIn(term, text)
if __name__ == "__main__":
    unittest.main()