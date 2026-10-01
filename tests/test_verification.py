import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from w3sec.verification import (
    _attach_to_report,
    default_command,
    prepare_workspace,
    run_verification,
    split_command,
    target_toolchains,
    target_source_hash,
    validate_command,
    workspace_hash,
)

class VerificationTests(unittest.TestCase):
    def test_command_policy_allows_local_test_runners(self):
        self.assertEqual(("cargo", "test", "--offline"), validate_command(("cargo", "test", "--offline")))
        self.assertEqual(("forge", "test", "--offline"), validate_command(("forge", "test", "--offline")))
        self.assertEqual(("python", "-m", "pytest", "-q"), validate_command(("python", "-m", "pytest", "-q")))

    def test_command_policy_rejects_broadcast_and_shell_commands(self):
        with self.assertRaises(ValueError):
            validate_command(("forge", "script", "Deploy.s.sol"))
        with self.assertRaises(ValueError):
            validate_command(("powershell", "-Command", "forge test"))
        with self.assertRaises(ValueError):
            validate_command(("forge", "test", "--offline", "--ffi"))
        with self.assertRaises(ValueError):
            validate_command(("forge", "test", "--offline", "--ffi=true"))

    def test_command_policy_rejects_outside_workspace_path_syntax(self):
        with self.assertRaises(ValueError):
            validate_command(("forge", "test", "--offline", "--root=C:\\Users\\pc\\outside"))

    def test_cargo_and_forge_verification_require_offline(self):
        with self.assertRaises(ValueError):
            validate_command(("cargo", "test"))
        with self.assertRaises(ValueError):
            validate_command(("forge", "test"))

    def test_standalone_source_does_not_claim_project_toolchain(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sol = root / "single.sol"
            rs = root / "single.rs"
            py = root / "single.py"
            sol.write_text("contract C {}", encoding="utf-8")
            rs.write_text("fn main() {}", encoding="utf-8")
            py.write_text("print('x')", encoding="utf-8")
            self.assertEqual([], target_toolchains(sol))
            self.assertEqual([], target_toolchains(rs))
            self.assertEqual([], target_toolchains(py))

    def test_standalone_solidity_with_reproducer_gets_foundry_harness(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "Target.sol"
            reproducer = root / "Target.t.sol"
            target.write_text("pragma solidity ^0.8.20; contract Target { uint256 public x; }", encoding="utf-8")
            reproducer.write_text(
                "pragma solidity ^0.8.20; import \"../src/Target.sol\"; contract TargetTest { "
                "function test_smoke() public { Target target = new Target(); require(target.x() == 0); } }",
                encoding="utf-8",
            )
            base, workspace = prepare_workspace(target, reproducer=reproducer)
            try:
                self.assertTrue((workspace / "foundry.toml").is_file())
                self.assertEqual("Target.sol", (workspace / "src" / "Target.sol").name)
                self.assertEqual(reproducer.name, (workspace / "test" / reproducer.name).name)
                self.assertEqual(["foundry"], target_toolchains(workspace))
                with patch("w3sec.verification.shutil.which", return_value=r"C:\Tools\forge.exe"):
                    self.assertEqual(
                        ("forge", "test", "--offline", "-vv"),
                        __import__("w3sec.verification", fromlist=["suggested_command"]).suggested_command(
                            target, reproducer
                        ),
                    )
            finally:
                import shutil
                shutil.rmtree(base, ignore_errors=True)

    def test_target_source_hash_matches_intake_for_directory_and_archive(self):
        import zipfile
        from w3sec.intake import build_intake
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "project"
            (root / "src").mkdir(parents=True)
            (root / "src" / "C.sol").write_text("contract C {}", encoding="utf-8")
            (root / "README.md").write_text("fixture", encoding="utf-8")
            intake = build_intake(root)
            self.assertEqual(intake["target"]["source_hash"], target_source_hash(root))
            archive = Path(td) / "project.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                for path in root.rglob("*"):
                    if path.is_file():
                        zf.write(path, path.relative_to(root).as_posix())
            self.assertEqual(intake["target"]["source_hash"], target_source_hash(archive))

    def test_workspace_hash_ignores_generated_build_outputs(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "project"
            (root / "src").mkdir(parents=True)
            (root / "src" / "C.sol").write_text("contract C {}", encoding="utf-8")
            before = workspace_hash(root)
            (root / "out").mkdir()
            (root / "out" / "C.json").write_text("generated", encoding="utf-8")
            (root / "target").mkdir()
            (root / "target" / "debug.bin").write_bytes(b"generated")
            self.assertEqual(before, workspace_hash(root))
            (root / "src" / "C.sol").write_text("contract C { uint x; }", encoding="utf-8")
            self.assertNotEqual(before, workspace_hash(root))

    def test_standalone_rust_with_reproducer_gets_cargo_harness(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "Target.rs"
            reproducer = root / "Target_repro.rs"
            target.write_text("pub fn value() -> u64 { 7 }", encoding="utf-8")
            reproducer.write_text(
                "use atlas_standalone_target::value;\n"
                "#[test] fn test_value() { assert_eq!(value(), 7); }\n",
                encoding="utf-8",
            )
            base, workspace = prepare_workspace(target, reproducer=reproducer)
            try:
                self.assertTrue((workspace / "Cargo.toml").is_file())
                self.assertTrue((workspace / "src" / "lib.rs").is_file())
                self.assertTrue((workspace / "tests" / reproducer.name).is_file())
                import tomllib
                with (workspace / "Cargo.toml").open("rb") as cargo_file:
                    manifest = tomllib.load(cargo_file)
                self.assertEqual(
                    "atlas_standalone_target",
                    manifest["package"]["name"],
                )
                with patch("w3sec.verification.shutil.which", return_value=r"C:\Tools\cargo.exe"):
                    self.assertEqual(
                        ("cargo", "test", "--workspace", "--offline"),
                        __import__("w3sec.verification", fromlist=["suggested_command"]).suggested_command(
                            target, reproducer
                        ),
                    )
            finally:
                import shutil
                shutil.rmtree(base, ignore_errors=True)

    def test_cargo_reproducer_uses_native_tests_directory(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "project"
            root.mkdir()
            (root / "Cargo.toml").write_text(
                "[package]\nname='demo'\nversion='0.1.0'\nedition='2021'\n",
                encoding="utf-8",
            )
            reproducer = Path(td) / "repro.rs"
            reproducer.write_text("#[test] fn repro() {}", encoding="utf-8")
            (root / "src").mkdir()
            (root / "src" / "lib.rs").write_text("", encoding="utf-8")
            base, workspace = prepare_workspace(root, reproducer=reproducer)
            try:
                self.assertTrue((workspace / "tests" / "repro.rs").is_file())
                self.assertFalse((workspace / "test" / "repro.rs").exists())
            finally:
                import shutil
                shutil.rmtree(base, ignore_errors=True)

    def test_workspace_is_an_isolated_copy(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "project"
            source.mkdir()
            (source / "foundry.toml").write_text("[profile.default]\nsrc='src'\n", encoding="utf-8")
            (source / "src").mkdir()
            (source / "src" / "C.sol").write_text("contract C {}", encoding="utf-8")
            base, workspace = prepare_workspace(source)
            try:
                self.assertNotEqual(source.resolve(), workspace.resolve())
                self.assertEqual(["foundry"], [
                    "foundry" if (workspace / "foundry.toml").exists() else "missing"
                ])
                before = workspace_hash(workspace)
                (workspace / "src" / "C.sol").write_text("contract C { uint x; }", encoding="utf-8")
                self.assertNotEqual(before, workspace_hash(workspace))
                self.assertEqual("contract C {}", (source / "src" / "C.sol").read_text(encoding="utf-8"))
            finally:
                import shutil
                shutil.rmtree(base, ignore_errors=True)
    def test_reproduced_without_verified_binding_does_not_advance_gate(self):
        from w3sec.finding_gate import evaluate_finding
        result = evaluate_finding({
            "file": "src/C.sol",
            "line": 10,
            "source_hash": "a" * 64,
            "verifications": [{
                "outcome": "reproduced",
                "security_property": "property P fails",
                "command": ["forge", "test", "--offline"],
            }],
        })
        self.assertFalse(result.gates["reproduction"])
        self.assertEqual("candidate", result.status)

    def test_multiple_reproductions_do_not_infer_independence(self):
        from w3sec.finding_gate import evaluate_finding
        finding = {
            "file": "src/C.sol",
            "line": 10,
            "source_hash": "a" * 64,
            "verifications": [
                {
                    "outcome": "reproduced",
                    "security_property": "property P fails",
                    "command": ["forge", "test", "--offline", "-vv"],
                    "binding": {
                        "workspace_unchanged": True,
                        "target_input_unchanged": True,
                        "target_input_hash_present": True,
                        "source_hash_match": True,
                    },
                },
                {
                    "outcome": "reproduced",
                    "security_property": "property P fails",
                    "command": ["cargo", "test", "--offline"],
                    "binding": {
                        "workspace_unchanged": True,
                        "target_input_unchanged": True,
                        "target_input_hash_present": True,
                        "source_hash_match": True,
                    },
                },
            ],
        }
        result = evaluate_finding(finding)
        self.assertTrue(result.gates["reproduction"])
        self.assertTrue(result.gates["security_property"])
        self.assertFalse(result.gates["independent_verification"])
        self.assertEqual("reproduced", result.status)

    def test_attached_reproduction_updates_finding_gate(self):
        with tempfile.TemporaryDirectory() as td:
            report = Path(td) / "report.json"
            payload = {
                "findings": [{
                    "id": "atlas-review-0001",
                    "file": "src/C.sol",
                    "line": 10,
                    "source_hash": "abc123",
                    "status": "candidate",
                }]
            }
            report.write_text(json.dumps(payload), encoding="utf-8")
            verification = {
                "finding_id": "atlas-review-0001",
                "outcome": "reproduced",
                "mode": "reproduction",
                "security_property": "the invariant remains true under adversarial input",
                "command": ["forge", "test", "--offline"],
                "binding": {
                    "workspace_unchanged": True,
                    "target_input_unchanged": True,
                    "target_input_hash_present": True,
                    "source_hash_match": True,
                },
            }
            _attach_to_report(report, verification)
            saved = json.loads(report.read_text(encoding="utf-8"))
            finding = saved["findings"][0]
            self.assertEqual("reproduced", finding["status"])
            self.assertTrue(finding["verification"]["gates"]["reproduction"])
            self.assertIn(verification, finding["verifications"])

    def test_reproduction_outcome_requires_explicit_security_property(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "project"
            project.mkdir()
            (project / "pyproject.toml").write_text("[project]\nname='verify-fixture'\n", encoding="utf-8")
            (project / "test_ok.py").write_text(
                "import unittest\n\n"
                "class TestOK(unittest.TestCase):\n"
                "    def test_ok(self):\n"
                "        self.assertTrue(True)\n",
                encoding="utf-8",
            )
            finding = {"id": "finding-1", "file": "test_ok.py", "line": 1}
            result = run_verification(
                project,
                finding,
                split_command("python -m unittest discover -s ."),
                expected_exit=0,
                mode="baseline",
                security_property="test harness executes deterministically",
                timeout_seconds=30,
            )
            self.assertEqual("execution-pass", result.outcome)
            self.assertFalse(result.reproduced)
            self.assertIn("isolated-copy", result.as_dict()["policy"])
    def test_reproduction_outcome_is_distinct_from_ordinary_execution_pass(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            (project / "test_fail.py").write_text(
                "import unittest\n\n"
                "class TestFail(unittest.TestCase):\n"
                "    def test_failure(self):\n"
                "        self.assertTrue(False)\n",
                encoding="utf-8",
            )
            result = run_verification(
                project,
                {"id": "finding-repro"},
                split_command("python -m unittest discover -s ."),
                expected_exit=1,
                mode="reproduction",
                security_property="the security invariant must hold under the reproduced input",
                timeout_seconds=30,
            )
            self.assertEqual("reproduced", result.outcome)
            self.assertTrue(result.reproduced)
            self.assertEqual(64, len(result.target_hash))
            self.assertEqual(64, len(result.workspace_hash_after))
            self.assertEqual(64, len(result.target_input_hash))
            self.assertEqual(result.target_input_hash, result.target_input_hash_after)
            self.assertFalse(Path(result.workspace).exists())
            binding = result.as_dict()["binding"]
            self.assertIn("workspace_hash_before_execution", binding)
            self.assertIn("workspace_hash_after_execution", binding)

    def test_cli_verify_finding_persists_reproduction_evidence(self):
        import contextlib
        import io
        import json
        import sys
        from unittest.mock import patch
        from w3sec.cli import main

        with tempfile.TemporaryDirectory() as td:
            from w3sec.intake import build_intake
            root = Path(td) / "project"
            root.mkdir()
            (root / "test_fail.py").write_text(
                "import unittest\n\n"
                "class TestFail(unittest.TestCase):\n"
                "    def test_failure(self):\n"
                "        self.assertTrue(False)\n",
                encoding="utf-8",
            )
            report_path = Path(td) / "audit.json"
            source_hash = build_intake(root)["target"]["source_hash"]
            report_path.write_text(json.dumps({
                "target": {"path": str(root)},
                "findings": [{
                    "id": "F-CLI",
                    "file": "test_fail.py",
                    "line": 1,
                    "source_hash": source_hash,
                    "signal": "test_failure",
                }],
            }), encoding="utf-8-sig")
            output = io.StringIO()
            argv = [
                "w3sec", "verify-finding", str(report_path), "F-CLI",
                "--command", "python -m unittest discover -s .",
                "--expected-exit", "1",
                "--mode", "reproduction",
                "--security-property", "security invariant must fail under the attack reproducer",
                "--os-root", str(root),
                "--json",
            ]
            with patch.object(sys, "argv", argv), contextlib.redirect_stdout(output):
                rc = main()
            self.assertEqual(0, rc, output.getvalue())
            self.assertIn('"outcome": "reproduced"', output.getvalue())
            updated = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual("reproduced", updated["findings"][0]["verification"]["derived_status"])
            self.assertTrue(updated["findings"][0]["verification"]["gates"]["reproduction"])

    def test_verification_blocks_wrong_input_bytes_from_a_pinned_finding(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td) / "project"
            project.mkdir()
            (project / "pyproject.toml").write_text(
                "[project]\nname='verify-fixture'\n",
                encoding="utf-8",
            )
            target = project / "target.py"
            target.write_text("print('original')\n", encoding="utf-8")
            finding = {
                "id": "binding-test",
                "file": "target.py",
                "line": 1,
                "target_input_sha256": "0" * 64,
            }
            with self.assertRaises(ValueError):
                run_verification(
                    project,
                    finding,
                    ("python", "-m", "unittest"),
                    security_property="input binding must remain exact",
                )

    def test_missing_property_invalid_mode_and_escape_are_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            project = Path(td)
            with self.assertRaises(ValueError):
                run_verification(
                    project,
                    {"id": "f"},
                    ("python", "-m", "unittest"),
                    security_property="",
                )
            with self.assertRaises(ValueError):
                run_verification(
                    project,
                    {"id": "f"},
                    ("python", "-m", "unittest"),
                    security_property="x",
                    mode="invalid",
                )
            with self.assertRaises(ValueError):
                validate_command(("cargo", "test", "--manifest-path", "..\\Cargo.toml"))

if __name__ == "__main__":
    unittest.main()
