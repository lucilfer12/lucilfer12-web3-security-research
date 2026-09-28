from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from w3sec.differential import compare_revisions
from w3sec.engine_orchestrator import EngineOrchestrator, EngineSpec
from w3sec.evidence_fabric import build_evidence_fabric, validate_evidence_chain
from w3sec.negative_knowledge import (
    find_matching_negative_results,
    record_negative_result,
)
from w3sec.proof_bundle import build_proof_bundle, verify_proof_bundle
from w3sec.research_run import ResearchRun


class ResearchLayersTests(unittest.TestCase):
    def test_research_run_persists_checkpoint_and_resumes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run = ResearchRun.start(root, run_id="0123456789abcdef01234567")
            run.begin_stage("validate_repository")
            run.checkpoint("validate_repository", {"errors": []})
            loaded = ResearchRun.load(root, run.run_id)
            self.assertEqual("validate_repository", loaded.state["last_completed_stage"])
            self.assertEqual({"errors": []}, loaded.result("validate_repository"))
            loaded.resume()
            loaded.begin_stage("verify_ledger")
            loaded.checkpoint("verify_ledger", {"errors": []})
            self.assertTrue(loaded.is_completed("verify_ledger"))
            event_lines = (root / "runs" / run.run_id / "events.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            self.assertGreaterEqual(len(event_lines), 5)
            for index, line in enumerate(event_lines, 1):
                event = json.loads(line)
                self.assertEqual(index, event["sequence"])
                if index > 1:
                    self.assertIsNotNone(event["previous_hash"])
                self.assertEqual(64, len(event["event_hash"]))

    def test_evidence_fabric_rejects_shortcuts(self):
        chain = validate_evidence_chain({
            "target": {"sha256": "x"},
            "validated_finding": {"id": "f-1"},
        })
        self.assertFalse(chain["allowed_validated"])
        self.assertEqual("target", chain["highest_proven_stage"])
        self.assertTrue(chain["gaps"])
        fabric = build_evidence_fabric([
            {"id": "f-1", "target": {"sha256": "x"}, "signal": {"id": "tx-origin"}},
        ])
        self.assertEqual(1, fabric["finding_count"])
        self.assertEqual(0, fabric["validated_count"])
        self.assertEqual(1, fabric["research_debt_count"])

    def test_engine_orchestrator_records_unavailable_engine(self):
        spec = EngineSpec(
            name="missing-test-engine",
            capability="test-capability",
            scope="workspace",
            timeout_seconds=1.0,
            command=("atlas-command-that-does-not-exist",),
            version_command=("atlas-command-that-does-not-exist", "--version"),
        )
        with tempfile.TemporaryDirectory() as tmp:
            result = EngineOrchestrator({spec.name: spec}).run(spec.name, Path(tmp))
        self.assertFalse(result.available)
        self.assertFalse(result.executed)
        self.assertEqual("unavailable", result.status)
        self.assertEqual("executable-not-found", result.failure_reason)

    def test_negative_knowledge_is_queryable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            record_negative_result(
                root,
                hypothesis="withdraw can drain locked balance",
                attempt="symbolic exploration",
                environment={"compiler": "solc-0.8.20"},
                tool="halmos",
                input_space={"withdraw_amount": "[1,100]"},
                explored_states=37,
                observed_behavior={"reverted": 37},
                proof_failure_reason="No satisfiable exploit trace",
                confidence="bounded-search",
            )
            matches = find_matching_negative_results(
                root,
                hypothesis="withdraw can drain locked balance",
                tool="halmos",
                input_space={"withdraw_amount": "[1,100]"},
            )
        self.assertEqual(1, len(matches))
        self.assertEqual(37, matches[0]["explored_states"])

    def test_differential_compares_source_structure_and_findings(self):
        before = {
            "id": "before",
            "target": {"source_hash": "aaa"},
            "files": [{"path": "A.sol", "sha256": "111"}],
            "contracts": [{"file": "A.sol", "name": "A", "functions": []}],
            "findings": [{"rule_id": "tx-origin", "engine": "atlas-rules", "status": "review-required"}],
        }
        after = {
            "id": "after",
            "target": {"source_hash": "bbb"},
            "files": [{"path": "A.sol", "sha256": "222"}, {"path": "B.sol", "sha256": "333"}],
            "contracts": [{"file": "A.sol", "name": "A", "functions": []}],
            "findings": [{"rule_id": "delegatecall", "engine": "atlas-rules", "status": "review-required"}],
        }
        result = compare_revisions(before, after)
        self.assertEqual(["B.sol"], result["source"]["introduced"])
        self.assertEqual(["A.sol"], result["source"]["changed"])
        self.assertTrue(result["findings"]["introduced"])
        self.assertTrue(result["findings"]["removed"])
        self.assertEqual("aaa", result["before_revision"])
        self.assertEqual("bbb", result["after_revision"])

    def test_proof_bundle_round_trip_and_tamper_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            artifact = root / "trace.json"
            artifact.write_text('{"step":1}\n', encoding="utf-8")
            finding = {
                "id": "finding-1",
                "claim": {"summary": "reproduced state divergence"},
                "verification": {"independent": True},
                "regression": {"tested": True},
                "artifacts": ["trace.json"],
                "toolchain": {"python": "3.12"},
            }
            bundle = root / "finding.bundle.zip"
            build_proof_bundle(root, finding, bundle)
            valid = verify_proof_bundle(bundle)
            self.assertTrue(valid["valid"])
            self.assertEqual([], valid["mismatches"])
            with __import__("zipfile").ZipFile(bundle, "a") as archive:
                archive.writestr("claim.json", b'{"tampered":true}\n')
            invalid = verify_proof_bundle(bundle)
        self.assertFalse(invalid["valid"])
        self.assertIn("claim.json", invalid["mismatches"])


if __name__ == "__main__":
    unittest.main()
