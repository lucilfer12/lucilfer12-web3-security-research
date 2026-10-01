import tempfile
import unittest
from pathlib import Path

from w3sec.contract_audit import _assert_production_only, build_contract_audit

UNSAFE = "pub fn f(input: &[u8]) { unsafe { core::ptr::read(input.as_ptr()) }; }\n"


class ScopeContractTests(unittest.TestCase):
    def test_findings_are_production_only_and_supporting_is_separate(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text(
                '[package]\nname = "neard"\nversion = "0.1.0"\nedition = "2021"\n', encoding="utf-8")
            (root / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
            (root / "src" / "host.rs").write_text(UNSAFE, encoding="utf-8")
            (root / "src" / "tests.rs").write_text(UNSAFE, encoding="utf-8")
            for d, name in (("benchmarks", "bench.rs"), ("tests", "it.rs"), ("fuzz", "fz.rs")):
                (root / d).mkdir()
                (root / d / name).write_text(UNSAFE, encoding="utf-8")
            report = build_contract_audit(root, root / "research")
            paths = [x["file"] for x in report["findings"]]
            self.assertTrue(paths, "expected at least one production finding")
            for bad in ("src/tests.rs", "benchmarks/bench.rs", "tests/it.rs", "fuzz/fz.rs"):
                self.assertNotIn(bad, paths)
            self.assertTrue(all(x["scope"] == "production" for x in report["findings"]))
            self.assertEqual(len(report["findings"]), report["summary"]["finding_count"])
            self.assertEqual(len(report["supporting_evidence"]),
                             report["summary"]["supporting_finding_count"])
            self.assertEqual(
                report["summary"]["status_counts"].get("candidate", 0),
                report["summary"]["finding_count"],
            )
            self.assertEqual(
                report["summary"]["evidence_grade_counts"].get("E", 0),
                report["summary"]["finding_count"],
            )
            self.assertTrue(any(x["file"] == "benchmarks/bench.rs" for x in report["supporting_evidence"]))
            semantic_support = [
                x for x in report["supporting_evidence"]
                if x.get("evidence_type") == "taint-and-control-flow-analysis"
            ]
            if semantic_support:
                self.assertTrue(all("confidence" in x for x in semantic_support))
                self.assertTrue(all("taint" in x for x in semantic_support))

    def test_guard_rejects_a_leak(self):
        with self.assertRaises(AssertionError):
            _assert_production_only([{"scope": "production", "file": "benchmarks/x/main.rs", "line": 1}])
        with self.assertRaises(AssertionError):
            _assert_production_only([{"scope": "supporting", "file": "src/lib.rs", "line": 1}])
        _assert_production_only([{"scope": "production", "file": "src/lib.rs", "line": 1}])


if __name__ == "__main__":
    unittest.main()
