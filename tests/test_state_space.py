import unittest

from w3sec.state_space import Transition, explore, minimize_trace


class StateSpaceTests(unittest.TestCase):
    def test_explore_finds_minimal_depth_failure(self):
        transitions = [
            Transition("increment", lambda state: state + 1),
            Transition("double", lambda state: state * 2),
        ]
        result = explore(0, transitions, lambda state: state < 3, max_depth=3)
        self.assertIsNotNone(result.counterexample)
        self.assertEqual(("increment", "increment", "increment"), result.counterexample.actions)

    def test_minimize_trace_removes_irrelevant_action(self):
        transitions = {
            "noop": lambda state: state,
            "inc": lambda state: state + 1,
        }
        actions = ["noop", "inc", "noop", "inc", "noop"]
        minimized = minimize_trace(0, transitions, actions, lambda state: state < 2)
        self.assertEqual(["inc", "inc"], minimized)


if __name__ == "__main__":
    unittest.main()
