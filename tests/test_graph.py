import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from w3sec.graph import AttackPath


class AttackPathTests(unittest.TestCase):
    def test_default_edges_follow_research_chain(self):
        path = AttackPath("actor", "entry", "auth", "mutation", "invariant", "impact")
        self.assertEqual(
            [("actor", "entry"), ("entry", "auth"), ("auth", "mutation"),
             ("mutation", "invariant"), ("invariant", "impact")],
            path.as_edges(),
        )


if __name__ == "__main__":
    unittest.main()
