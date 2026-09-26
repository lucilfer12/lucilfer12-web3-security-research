import unittest

from w3sec.differential import run_differential


class DifferentialTests(unittest.TestCase):
    def test_detects_divergence(self):
        result = run_differential(
            0,
            ["add", "add"],
            lambda state, action: state + 1,
            lambda state, action: state + (2 if action == "add" else 0),
        )
        self.assertIsNotNone(result.divergence)
        self.assertEqual(1, result.divergence.step)

    def test_matching_implementations_have_no_divergence(self):
        step = lambda state, action: state + 1
        result = run_differential(0, ["a", "b"], step, step)
        self.assertIsNone(result.divergence)


if __name__ == "__main__":
    unittest.main()
