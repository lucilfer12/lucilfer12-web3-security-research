import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from w3sec.isolation import ATTEST_ENV, TRUST_ENV, VerificationRefused, decide, require_isolation
from w3sec.run_classifier import classify_run, tool_and_subcommand
from w3sec.verification import run_verification

CARGO_COMPILE_ERR = (
    "   Compiling t v0.1.0\n"
    "error[E0425]: cannot find value `x` in this scope\n"
    "error: could not compile `t` (test \"atlas_repro\") due to 1 previous error\n"
)
CARGO_FAIL = (
    "running 1 test\ntest repro_property ... FAILED\n\nfailures:\n\n"
    "---- repro_property stdout ----\n"
    "thread 'repro_property' panicked at tests/atlas_repro.rs:5:5:\nassertion failed\n\n"
    "failures:\n    repro_property\n\n"
    "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n"
    "error: test failed, to rerun pass `--test atlas_repro`\n"
)
CARGO_PASS = "running 2 tests\ntest a ... ok\ntest b ... ok\n\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured\n"
CARGO_EMPTY = "running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured\n"
PYTHON_PASS = "....\n----------------------------------------------------------------------\nRan 4 tests in 0.002s\n\nOK\n"
PYTHON_FAIL = ".F\n======================================================================\nFAIL: test_bad (test_repro.TestBad.test_bad)\n----------------------------------------------------------------------\nTraceback\n\n----------------------------------------------------------------------\nRan 2 tests in 0.002s\n\nFAILED (failures=1)\n"
PYTEST_PASS = "========================= 3 passed in 0.02s =========================\n"
PYTEST_FAIL = "FAILED tests/test_repro.py::test_bad - AssertionError: False\n========================= 1 failed, 2 passed in 0.03s =========================\n"
FORGE_COMPILE_ERR = "Error: Compiler run failed:\nerror[2314]: Expected ';' but got identifier\n"
FORGE_FAIL = (
    "Ran 1 test for test/Repro.t.sol:ReproTest\n"
    "[FAIL: assertion failed] test_property() (gas: 123)\n"
    "Suite result: FAILED. 0 passed; 1 failed; 0 skipped; finished in 1ms\n"
)
FORGE_PASS = (
    "Ran 1 test for test/Repro.t.sol:ReproTest\n[PASS] test_property() (gas: 123)\n"
    "Suite result: ok. 1 passed; 0 failed; 0 skipped; finished in 1ms\n"
)


def _run(returncode, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr,
                           timed_out=False, output_limited=False)


class IsolationPolicy(unittest.TestCase):
    def test_refused_by_default(self):
        self.assertFalse(decide(False, {}).allowed)
        with self.assertRaises(VerificationRefused):
            require_isolation(False, {})

    def test_operator_trust_flag_and_env(self):
        self.assertEqual("operator-trusted", decide(True, {}).mode)
        self.assertEqual("operator-trusted", decide(False, {TRUST_ENV: "1"}).mode)
        self.assertFalse(decide(False, {TRUST_ENV: "0"}).allowed)

    def test_only_known_attestations_count(self):
        self.assertEqual("attested:github-actions-ephemeral-vm",
                         decide(False, {ATTEST_ENV: "github-actions-ephemeral-vm"}).mode)
        self.assertFalse(decide(False, {ATTEST_ENV: "trust-me"}).allowed)


class Classifier(unittest.TestCase):
    def test_tool_detection(self):
        self.assertEqual(("cargo", "test"), tool_and_subcommand(("cargo", "test", "--offline")))
        self.assertEqual(("forge", "test"), tool_and_subcommand(("C:\\Tools\\forge.exe", "test")))
        self.assertEqual(("python", "test"), tool_and_subcommand(("python", "-m", "unittest")))
        self.assertEqual(("pytest", "test"), tool_and_subcommand(("pytest", "-q")))

    def test_cargo(self):
        self.assertEqual("build-error", classify_run("cargo", CARGO_COMPILE_ERR, "").kind)
        failed = classify_run("cargo", CARGO_FAIL, "")
        self.assertEqual(("tests-failed", ("repro_property",)), (failed.kind, failed.failing_tests))
        self.assertEqual("tests-passed", classify_run("cargo", CARGO_PASS, "").kind)
        self.assertEqual("no-tests-ran", classify_run("cargo", CARGO_EMPTY, "").kind)
        self.assertEqual("unknown", classify_run("cargo", "", "").kind)

    def test_forge(self):
        self.assertEqual("build-error", classify_run("forge", FORGE_COMPILE_ERR, "").kind)
        failed = classify_run("forge", FORGE_FAIL, "")
        self.assertEqual(("tests-failed", ("test_property",)), (failed.kind, failed.failing_tests))
        self.assertEqual("tests-passed", classify_run("forge", FORGE_PASS, "").kind)

    def test_python_unittest_and_pytest(self):
        passed = classify_run("python", PYTHON_PASS, "")
        failed = classify_run("python", PYTHON_FAIL, "")
        self.assertEqual(("tests-passed", 4, 0), (passed.kind, passed.passed, passed.failed))
        self.assertEqual(("tests-failed", 1, 1), (failed.kind, failed.passed, failed.failed))
        pytest_passed = classify_run("pytest", PYTEST_PASS, "")
        pytest_failed = classify_run("pytest", PYTEST_FAIL, "")
        self.assertEqual(("tests-passed", 3, 0), (pytest_passed.kind, pytest_passed.passed, pytest_passed.failed))
        self.assertEqual(("tests-failed", 2, 1), (pytest_failed.kind, pytest_failed.passed, pytest_failed.failed))


class RunVerificationGate(unittest.TestCase):
    def _project(self, td):
        root = Path(td) / "proj"
        (root / "src").mkdir(parents=True)
        (root / "Cargo.toml").write_text('[package]\nname = "t"\nversion = "0.1.0"\nedition = "2021"\n', encoding="utf-8")
        (root / "src" / "lib.rs").write_text("pub fn f() {}\n", encoding="utf-8")
        return root

    def _verify(self, root, runs, **env):
        cmd = ("cargo", "test", "--offline")
        scrub = {TRUST_ENV: "", ATTEST_ENV: ""}
        scrub.update(env)
        with patch.dict(os.environ, scrub), patch("w3sec.verification.run_bounded", side_effect=runs) as fake:
            result = run_verification(
                root, {"id": "f1"}, cmd, expected_exit=101, mode="reproduction",
                security_property="allocation is bounded", timeout_seconds=5,
            )
            return result, fake

    def test_refused_without_isolation_or_trust(self):
        with tempfile.TemporaryDirectory() as td, patch.dict(os.environ, {TRUST_ENV: "", ATTEST_ENV: ""}):
            with patch("w3sec.verification.run_bounded") as fake:
                with self.assertRaises(VerificationRefused):
                    run_verification(self._project(td), {"id": "f1"}, ("cargo", "test", "--offline"),
                                     security_property="p", mode="baseline")
                fake.assert_not_called()

    def test_compile_error_is_not_a_reproduction(self):
        with tempfile.TemporaryDirectory() as td:
            result, _ = self._verify(self._project(td), [_run(0, CARGO_PASS), _run(101, CARGO_COMPILE_ERR)],
                                     **{TRUST_ENV: "1"})
        self.assertEqual("inconclusive", result.outcome)
        self.assertEqual("build-error", result.failure_class)

    def test_failing_test_is_a_reproduction(self):
        with tempfile.TemporaryDirectory() as td:
            result, _ = self._verify(self._project(td), [_run(0, CARGO_PASS), _run(101, CARGO_FAIL)],
                                     **{ATTEST_ENV: "github-actions-ephemeral-vm"})
        self.assertEqual("reproduced", result.outcome)
        self.assertEqual(("repro_property",), result.failing_tests)
        self.assertEqual(0, result.tests_passed)
        self.assertEqual(1, result.tests_failed)
        self.assertTrue(result.tests_executed)
        self.assertEqual(1, result.as_dict()["test_execution"]["executed_test_count"])
        self.assertEqual("attested:github-actions-ephemeral-vm", result.isolation)

    def test_unbuildable_baseline_is_inconclusive(self):
        with tempfile.TemporaryDirectory() as td:
            result, _ = self._verify(self._project(td), [_run(101, CARGO_COMPILE_ERR)], **{TRUST_ENV: "1"})
        self.assertEqual("inconclusive", result.outcome)


if __name__ == "__main__":
    unittest.main()
