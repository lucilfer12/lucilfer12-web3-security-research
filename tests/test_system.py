import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from w3sec.graph import ResearchGraph
from w3sec.inventory import build_inventory
from w3sec.ledger import append_event, verify_chain
from w3sec.model import NodeRef, ResearchStage, stage_gaps
from w3sec.query import CaseQuery, query_cases
from w3sec.validator import validate_repo


ROOT = Path(__file__).resolve().parents[1]


class SystemTests(unittest.TestCase):
    def test_stage_gap_order(self):
        gaps = stage_gaps([ResearchStage.OBSERVED, ResearchStage.REPRODUCED])
        self.assertEqual(
            [ResearchStage.MODELED, ResearchStage.FORMALIZED],
            gaps,
        )
    def test_inventory_and_query(self):
        inventory = build_inventory(ROOT)
        self.assertEqual(4, inventory["case_count"])
        self.assertGreaterEqual(inventory["knowledge_registry_counts"]["invariants"], 5)
        matches = query_cases(ROOT, CaseQuery(category="replay-protection"))
        self.assertEqual(["near-neap-658"], [record["id"] for _, record in matches])

    def test_graph_lineage(self):
        graph = ResearchGraph.from_repo(ROOT)
        start = NodeRef("case", "near-neap-658")
        nodes = {node.key for node in graph.walk(start, depth=3)}
        self.assertIn("invariant:invariant.replay.nonce-monotonicity", nodes)
        self.assertIn("pattern:pattern.replay-state-reset", nodes)

    def test_validator(self):
        self.assertEqual([], validate_repo(ROOT))
    def test_ledger_hash_chain(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "events.jsonl"
            append_event(path, event_type="observation",
                         subject=NodeRef("case", "demo-case"),
                         timestamp="2026-01-01T00:00:00Z", actor="test")
            append_event(path, event_type="model",
                         subject=NodeRef("case", "demo-case"),
                         timestamp="2026-01-01T00:01:00Z", actor="test",
                         stage=ResearchStage.MODELED, payload={"key": "value"})
            self.assertEqual([], verify_chain(path))
            lines = path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(2, len(lines))
            self.assertEqual("demo-case", json.loads(lines[-1])["subject"]["id"])

if __name__ == "__main__":
    unittest.main()
