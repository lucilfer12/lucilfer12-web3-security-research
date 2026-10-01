import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from w3sec.isolation import ATTEST_ENV
from w3sec.proof_verifier import proof_marker, run_proof_verification


class ProofVerification(unittest.TestCase):
    def _target(self, root: Path, state: str) -> Path:
        project = root / state
        project.mkdir()
        (project / "pyproject.toml").write_text(
            "[project]\nname='atlas-proof-fixture'\n",
            encoding="utf-8",
        )
        (project / "state.txt").write_text(state, encoding="utf-8")
        tests = project / "tests"
        tests.mkdir()
        (tests / "test_baseline.py").write_text(
            "import unittest\n\n"
            "class TestBaseline(unittest.TestCase):\n"
            "    def test_healthy(self):\n"
            "        self.assertTrue(True)\n",
            encoding="utf-8",
        )
        return project

    def test_same_reproducer_confirms_vulnerable_vs_fixed_state(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vulnerable = self._target(root, "vulnerable")
            fixed = self._target(root, "fixed")
            reproducer = root / "test_property.py"
            reproducer.write_text(
                "import os\nimport unittest\nfrom pathlib import Path\n\n"
                "print(os.environ['ATLAS_PROOF_MARKER'])\n"
                "class TestProperty(unittest.TestCase):\n"
                "    def test_property(self):\n"
                "        state = Path('state.txt').read_text()\n"
                "        self.assertEqual(state, 'fixed')\n",
                encoding="utf-8",
            )
            finding = {"id": "F-PROOF", "file": "state.txt", "line": 1}
            with mock.patch.dict(
                os.environ, {ATTEST_ENV: "github-actions-ephemeral-vm"}, clear=False
            ):
                result = run_proof_verification(
                    vulnerable,
                    fixed,
                    finding,
                    ("python", "-m", "unittest", "discover", "-s", "tests"),
                    vulnerable_expected_exit=1,
                    fixed_expected_exit=0,
                    baseline_expected_exit=0,
                    security_property="the state transition must not accept the vulnerable state",
                    reproducer=reproducer,
                    timeout_seconds=30,
                )
            self.assertTrue(result.confirmed)
            self.assertEqual("confirmed", result.outcome)
            self.assertTrue(result.vulnerable_baseline_healthy)
            self.assertTrue(result.fixed_baseline_healthy)
            self.assertTrue(result.vulnerable_marker_present)
            self.assertTrue(result.fixed_marker_present)
            self.assertEqual("reproduced", result.vulnerable.outcome)
            self.assertEqual("reproduced", result.fixed.outcome)
            self.assertEqual(result.fixed_target_hash, result.fixed_target_hash)

    def test_identical_source_states_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vulnerable = self._target(root, "vulnerable")
            reproducer = root / "test_property.py"
            reproducer.write_text(
                "import unittest\n"
                "class TestProperty(unittest.TestCase):\n"
                "    def test_property(self):\n"
                "        self.assertTrue(False)\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ, {ATTEST_ENV: "github-actions-ephemeral-vm"}, clear=False
            ):
                with self.assertRaises(ValueError):
                    run_proof_verification(
                        vulnerable,
                        vulnerable,
                        {"id": "F-SAME"},
                        ("python", "-m", "unittest", "discover", "-s", "tests"),
                        vulnerable_expected_exit=1,
                        fixed_expected_exit=0,
                        security_property="the fixed source must differ",
                        reproducer=reproducer,
                        timeout_seconds=30,
                    )

    def test_missing_engagement_marker_is_not_confirmed(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            vulnerable = self._target(root, "vulnerable")
            fixed = self._target(root, "fixed")
            reproducer = root / "test_property.py"
            reproducer.write_text(
                "import unittest\nfrom pathlib import Path\n\n"
                "class TestProperty(unittest.TestCase):\n"
                "    def test_property(self):\n"
                "        self.assertEqual(Path('state.txt').read_text(), 'fixed')\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ, {ATTEST_ENV: "github-actions-ephemeral-vm"}, clear=False
            ):
                result = run_proof_verification(
                    vulnerable,
                    fixed,
                    {"id": "F-NOMARK"},
                    ("python", "-m", "unittest", "discover", "-s", "tests"),
                    vulnerable_expected_exit=1,
                    fixed_expected_exit=0,
                    security_property="the property must be established by the target test",
                    reproducer=reproducer,
                    timeout_seconds=30,
                )
            self.assertEqual("not-confirmed", result.outcome)
            self.assertFalse(result.vulnerable_marker_present)
            self.assertFalse(result.fixed_marker_present)


if __name__ == "__main__":
    unittest.main()
