import json
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
