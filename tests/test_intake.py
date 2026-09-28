import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from w3sec.contract_audit import build_contract_audit
from w3sec.graph import ResearchGraph
from w3sec.intake import build_intake, write_intake_report


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
            self.assertEqual(1, value["summary"]["source_file_count"])
            self.assertEqual(1, value["summary"]["contract_count"])
            self.assertEqual(1, value["summary"]["function_count"])
            self.assertIn("low_level_call", value["summary"]["security_signal_kinds"])
            self.assertEqual(["./IERC20.sol"], value["files"][0]["imports"])

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
            self.assertGreaterEqual(value["summary"]["contract_count"], 5)

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
            self.assertGreaterEqual(report["summary"]["finding_count"], 1)
            self.assertTrue(any(x["signal"] == "low_level_call" for x in report["findings"]))
            graph = ResearchGraph.from_repo(research)
            self.assertTrue(any(key.startswith("contract-audit:") for key in graph.nodes))
            self.assertTrue(any(key.startswith("audit-finding:") for key in graph.nodes))

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
