import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from w3sec.contract_audit import build_contract_audit, write_contract_audit
from w3sec.graph import ResearchGraph
from w3sec.intake import OperationCancelled, build_intake, write_intake_report
from w3sec.scanner import _production_path


class IntakeTests(unittest.TestCase):
    def test_single_solidity_file_is_structurally_indexed(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "Vault.sol"
            target.write_text(
                "pragma solidity ^0.8.20;\n"
                "import \"./IERC20.sol\";\n"
                "contract Vault {\n"
                " function sweep(address to) external onlyOwner {\n"
                "   (bool ok,) = to.call{value: 1}(\"\");\n"
                "   require(ok);\n"
                " }\n"
                "}\n",
                encoding="utf-8",
            )
            value = build_intake(target)
            self.assertEqual("file", value["target"]["kind"])
            self.assertEqual(str(target.resolve()), value["target"]["path"])
            self.assertEqual(["Vault.sol"], [item["path"] for item in value["files"]])
            self.assertEqual(1, value["summary"]["source_file_count"])
            self.assertEqual(1, value["summary"]["contract_count"])
            self.assertEqual(1, value["summary"]["function_count"])
            self.assertIn("low_level_call", value["summary"]["security_signal_kinds"])
            self.assertEqual(["./IERC20.sol"], value["files"][0]["imports"])

    def test_rust_signals_are_language_specific_and_comment_safe(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "module.rs"
            target.write_text(
                "// unsafe call assembly unchecked low_level_call\n"
                "/// docs mention unsafe and .call()\n"
                "pub fn parse(input: &[u8]) {\n"
                "    let _ = input.len();\n"
                "    unsafe { core::ptr::read(input.as_ptr()) };\n"
                "    let _ = input.len().unwrap_or(0);\n"
                "}\n",
                encoding="utf-8",
            )
            value = build_intake(target)
            signals = {item["id"] for item in value["files"][0]["signals"]}
            self.assertIn("rust_unsafe_block", signals)
            self.assertNotIn("low_level_call", signals)
            self.assertNotIn("assembly", signals)
            self.assertNotIn("unchecked", signals)
            self.assertEqual(0, value["summary"]["contract_count"])
            self.assertEqual(1, value["summary"]["source_unit_count"])

    def test_rust_production_path_excludes_test_aggregator_files(self):
        self.assertFalse(_production_path("chain/chain/src/runtime/tests.rs"))
        self.assertFalse(_production_path("core/async/src/multithread/test.rs"))
        self.assertFalse(_production_path("chain/chain/src/runtime/test_helpers.rs"))
        self.assertFalse(_production_path("chain/chain/src/runtime/foo_test.rs"))
        self.assertFalse(_production_path("chain/chain/src/runtime/mod_tests.rs"))
        self.assertFalse(_production_path("chain/network/build.rs"))
        self.assertFalse(_production_path("chain/network/src/network_protocol/testonly.rs"))
        self.assertFalse(_production_path("runtime/near-test-contracts/estimator-contract/src/lib.rs"))
        self.assertFalse(_production_path("test-loop-tests/src/utils/node.rs"))
        self.assertFalse(_production_path("benchmarks/synth-bm/src/account.rs"))
        self.assertTrue(_production_path("chain/chain/src/runtime/host.rs"))

    def test_contract_audit_retains_rust_supporting_evidence_end_to_end(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "src" / "runtime").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                "[package]\nname = \"neard\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                encoding="utf-8",
            )
            (root / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
            (root / "src" / "runtime" / "tests.rs").write_text(
                "pub fn should_not_scan(input: &[u8]) { unsafe { core::ptr::read(input.as_ptr()) }; }\n",
                encoding="utf-8",
            )
            (root / "fuzz").mkdir()
            (root / "fuzz" / "fuzz_targets.rs").write_text(
                "pub fn fuzz_target(input: &[u8]) { input.get(0).unwrap(); }\n",
                encoding="utf-8",
            )
            (root / "benchmarks").mkdir()
            (root / "benchmarks" / "bench.rs").write_text(
                "pub fn bench_target(input: &[u8]) { unsafe { core::ptr::read(input.as_ptr()) }; }\n",
                encoding="utf-8",
            )
            (root / "src" / "runtime" / "host.rs").write_text(
                "pub fn host(input: &[u8]) { unsafe { core::ptr::read(input.as_ptr()) }; }\n",
                encoding="utf-8",
            )
            (root / "src" / "runtime" / "safe_boundary.rs").write_text(
                "pub fn validate(request: &Request) { let fixed = NonZeroUsize::new(100).unwrap(); let guard = mutex.lock().unwrap(); let _ = (fixed, guard, request); }\n",
                encoding="utf-8",
            )
            report = build_contract_audit(root, root / "research")
            engine_files = [x.get("file") for x in report["engine_scan"]["engine_findings"]]
            self.assertIn("src/runtime/host.rs", engine_files)
            self.assertIn("src/runtime/tests.rs", engine_files)
            self.assertIn("fuzz/fuzz_targets.rs", engine_files)
            self.assertIn("benchmarks/bench.rs", engine_files)
            supporting = [x for x in report["findings"] if x.get("scope") == "supporting"]
            self.assertTrue(supporting)
            self.assertTrue(all(x.get("scope") == "supporting" for x in supporting))
            self.assertFalse(any(
                x.get("signal") == "panic_on_input" and x.get("file") == "src/runtime/safe_boundary.rs"
                for x in report["findings"]
            ))
            assert any(
                x.get("signal") == "panic_on_input" and x.get("file") == "fuzz/fuzz_targets.rs"
                for x in report["findings"]
            )

    def test_nearcore_total_supply_recall_detector(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "chain" / "chain" / "src").mkdir(parents=True)
            (root / "Cargo.toml").write_text(
                "[package]\nname = \"neard\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
                encoding="utf-8",
            )
            (root / "src" / "main.rs").parent.mkdir(parents=True, exist_ok=True)
            (root / "src" / "main.rs").write_text("fn main() {}\n", encoding="utf-8")
            corpus_root = Path(__file__).resolve().parents[1] / "corpus" / "recall" / "nearcore"
            pre_fix = (corpus_root / "total_supply_8790_pre_fix_chain.rs").read_text(encoding="utf-8")
            (root / "chain" / "chain" / "src" / "chain.rs").write_text(pre_fix, encoding="utf-8")
            report = build_contract_audit(root, root / "research")
            hits = [x for x in report["findings"] if x.get("signal") == "consensus_invariant_gap"]
            self.assertEqual(1, len(hits))
            self.assertEqual("high", hits[0]["severity_hint"])
            self.assertEqual("medium", hits[0]["priority"])
            self.assertEqual("high", hits[0]["confidence"])
            self.assertEqual("consensus-validation", hits[0]["reachability"])
            self.assertGreaterEqual(hits[0]["triage_score"], 60)

            fixed = root / "chain" / "chain" / "src" / "chain.rs"
            fixed.write_text(
                (corpus_root / "total_supply_8790_fixed_chain.rs").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            fixed_report = build_contract_audit(root, root / "research-fixed")
            self.assertFalse(any(x.get("signal") == "consensus_invariant_gap" for x in fixed_report["findings"]))

    def test_zip_bundle_supports_multiple_contract_languages(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            bundle_root = root / "bundle"
            (bundle_root / "contracts").mkdir(parents=True)
            samples = {
                "A.sol": "pragma solidity ^0.8.20; contract A { function ping() external {} }",
                "B.vy": "def ping():\n    pass\n",
                "C.move": "module 0x1::c { public fun ping() {} }",
                "D.rs": "pub fn ping() {}\n",
                "E.cairo": "fn ping() {}\n",
            }
            for name, content in samples.items():
                (bundle_root / "contracts" / name).write_text(content, encoding="utf-8")
            archive = root / "protocol.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                for path in (bundle_root / "contracts").glob("*"):
                    zf.write(path, arcname=f"contracts/{path.name}")
            value = build_intake(archive)
            self.assertEqual("archive", value["target"]["kind"])
            self.assertEqual("zip", value["target"]["archive_format"])
            self.assertEqual(5, value["summary"]["source_file_count"])
            self.assertEqual({"Solidity", "Vyper", "Move", "Rust (Solana/CosmWasm/ink!/generic)", "Cairo"}, set(value["summary"]["languages"]))
            self.assertEqual(4, value["summary"]["contract_count"])
            self.assertEqual(5, value["summary"]["source_unit_count"])

    def test_archive_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "evil.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../outside.sol", "contract Outside {}")
            with self.assertRaises(ValueError):
                build_intake(archive)

    def test_contract_audit_writes_findings_and_graph_lineage(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            research = root / "research"
            (research / "corpus" / "knowledge").mkdir(parents=True)
            target = root / "Risky.sol"
            target.write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Risky {\n"
                " function run(address target) external {\n"
                "   target.call{value: 1}(\"\");\n"
                " }\n"
                "}\n",
                encoding="utf-8",
            )
            report = build_contract_audit(target, research)
            write_contract_audit(research, report)
            self.assertGreaterEqual(report["summary"]["finding_count"], 1)
            self.assertTrue(any(x["signal"] == "low_level_call" for x in report["findings"]))
            graph = ResearchGraph.from_repo(research)
            self.assertTrue(any(key.startswith("contract-audit:") for key in graph.nodes))
            self.assertTrue(any(key.startswith("audit-finding:") for key in graph.nodes))

    def test_utf8_bom_does_not_enter_findings_or_reports(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "Bom.sol"
            source.write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Bom { function f() public { require(tx.origin == msg.sender); } }\n",
                encoding="utf-8-sig",
            )
            archive = root / "bom.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.write(source, arcname="Bom.sol")
            report = build_contract_audit(archive, root / "research")
            encoded = json.dumps(report, ensure_ascii=False)
            self.assertNotIn("\ufeff", encoded)
            self.assertEqual("tx_origin", report["findings"][0]["signal"])
            self.assertEqual("tx_origin", report["engine_scan"]["engine_findings"][0]["signal"])

    def test_engine_rules_produce_target_derived_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "Risky.sol"
            source.write_text(
                "pragma solidity ^0.8.20;\n"
                "contract Risky {\n"
                " function f() public { require(tx.origin == msg.sender); }\n"
                "}\n",
                encoding="utf-8",
            )
            report = build_contract_audit(source, root / "research")
            engine_findings = report["engine_scan"]["engine_findings"]
            self.assertTrue(any(
                x.get("engine") == "atlas-rules"
                and x.get("signal") == "tx_origin"
                and x.get("file") == "Risky.sol"
                for x in engine_findings
            ))
            self.assertEqual(1, report["summary"]["engine_finding_count"])
            self.assertEqual(str(source.resolve()), report["target"]["path"])
            self.assertEqual(["Risky.sol"], [item["path"] for item in report["intake"]["files"]])
            self.assertTrue(any(x.get("file") == "Risky.sol" for x in report["findings"]))


    def test_written_intake_is_visible_to_graph(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "reports" / "intake").mkdir(parents=True)
            target = root / "A.sol"
            target.write_text("contract A {}", encoding="utf-8")
            report = write_intake_report(root, build_intake(target))
            self.assertTrue(report.exists())
            graph = ResearchGraph.from_repo(root)
            self.assertTrue(any(key.startswith("intake:") for key in graph.nodes))
            self.assertTrue(any(edge.relation == "contains-contract" for edge in graph.edges))

    def test_intake_can_be_cancelled_before_work(self):
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "A.sol"
            target.write_text("contract A {}", encoding="utf-8")
            with self.assertRaises(OperationCancelled):
                build_intake(target, cancel=lambda: True)

    def test_contract_audit_can_be_cancelled_before_work(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "A.sol"
            target.write_text("contract A {}", encoding="utf-8")
            with self.assertRaises(OperationCancelled):
                build_contract_audit(target, root / "research", cancel=lambda: True)

    def test_intake_registration_is_hash_chained(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            target = root / "A.sol"
            target.write_text("contract A {}", encoding="utf-8")
            report = build_intake(target)
            write_intake_report(root, report)
            write_intake_report(root, report)
            events = (root / "ledger" / "events.jsonl").read_text(encoding="utf-8").splitlines()
            self.assertEqual(1, len(events))
            event = json.loads(events[0])
            self.assertEqual("intake-registered", event["event_type"])
            self.assertEqual("intake:" + report["id"], "intake:" + event["subject"]["id"])
            self.assertEqual([], __import__("w3sec.ledger", fromlist=["verify_chain"]).verify_chain(root / "ledger" / "events.jsonl"))

    def test_zip_audit_reports_live_progress_and_real_target_counts(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            source = root / "OneLine.sol"
            source.write_text("pragma solidity ^0.8.20;\n", encoding="utf-8")
            archive = root / "one-line.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.write(source, arcname="OneLine.sol")
            progress = []
            research = root / "research"
            report = build_contract_audit(archive, research, lambda p, label: progress.append((p, label)))
            percentages = [p for p, _ in progress]
            self.assertGreater(len(percentages), 6)
            self.assertEqual(100, percentages[-1])
            self.assertTrue(any("Discovered 1 files" in label for _, label in progress))
            self.assertEqual(1, report["summary"]["file_count"])
            self.assertEqual(1, report["summary"]["source_file_count"])
            self.assertEqual(0, report["summary"]["contract_count"])
            self.assertEqual(0, report["summary"]["finding_count"])
            self.assertIn("engine_scan", report)
            self.assertIn("structural", report["engine_scan"])
            self.assertEqual(1, report["engine_scan"]["structural"]["source_file_count"])


if __name__ == "__main__":
    unittest.main()
