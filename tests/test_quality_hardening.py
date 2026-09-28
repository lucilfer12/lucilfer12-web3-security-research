import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from w3sec.finding_gate import attach_gate, evaluate_finding
from w3sec.records import RecordLoadError, load_yaml_mapping
from w3sec.runtime import run_bounded
from w3sec.state_space import Transition, explore


class QualityHardeningTests(unittest.TestCase):
    def test_strict_yaml_rejects_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "dup.yaml"
            path.write_text("version: 1\nversion: 2\n", encoding="utf-8")
            with self.assertRaises(RecordLoadError):
                load_yaml_mapping(path)

    def test_state_space_respects_node_budget(self):
        result = explore(
            0,
            [Transition("inc", lambda state: state + 1)],
            lambda state: state < 100,
            max_depth=10,
            max_nodes=3,
        )
        self.assertEqual("exhausted_nodes", result.outcome)
        self.assertEqual(3, result.visited_states)

    def test_state_space_reports_engine_failure(self):
        result = explore(
            0,
            [Transition("boom", lambda state: 1 / 0)],
            lambda state: True,
            max_depth=1,
            max_nodes=10,
        )
        self.assertEqual("engine_failure", result.outcome)
        self.assertIn("transition 'boom' failed", result.error or "")

    def test_finding_status_is_evidence_derived(self):
        candidate = attach_gate({
            "id": "F-1",
            "signal": "tx_origin",
            "file": "Vault.sol",
            "line": 12,
            "source_hash": "a" * 64,
        })
        self.assertEqual("candidate", candidate["status"])
        self.assertFalse(candidate["verification"]["gates"]["reproduction"])

        validated = evaluate_finding({
            "file": "Vault.sol",
            "line": 12,
            "commit": "abc123",
            "security_property": "authorization integrity",
            "verification": {
                "reproduction": True,
                "impact": True,
                "independent_verification": True,
                "regression": True,
            },
        })
        self.assertEqual("validated-regressed", validated.status)

    def test_runtime_caps_output(self):
        code = "print('X' * 10000, flush=True)"
        result = run_bounded([sys.executable, "-c", code], max_output_bytes=1024, timeout=5)
        self.assertTrue(result.output_limited)
        self.assertLessEqual(len(result.stdout.encode('utf-8')), 1024)


    def test_state_key_rejects_non_deterministic_object(self):
        class Opaque:
            pass
        with self.assertRaises(TypeError):
            from w3sec.state_space import default_state_key
            default_state_key(Opaque())

    def test_state_space_exhausts_depth_explicitly(self):
        result = explore(
            0,
            [Transition("inc", lambda state: state + 1)],
            lambda state: True,
            max_depth=2,
            max_nodes=100,
        )
        self.assertEqual("exhausted_depth", result.outcome)

    def test_zip_case_collision_is_rejected(self):
        import zipfile
        from w3sec.intake import _safe_extract_archive

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            archive = root / "collision.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("Contract.sol", "contract C {}")
                zf.writestr("contract.sol", "contract D {}")
            with self.assertRaises(ValueError):
                _safe_extract_archive(archive, root / "out")

    def test_ledger_rejects_naive_timestamp(self):
        from w3sec.ledger import append_event
        from w3sec.model import NodeRef
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                append_event(
                    Path(td) / "events.jsonl",
                    event_type="test",
                    subject=NodeRef("case", "c1"),
                    timestamp="2026-09-28T08:00:00",
                    actor="tester",
                )

    def test_intake_manifest_is_deterministic_for_same_content(self):
        from w3sec.intake import build_intake
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "Vault.sol"
            path.write_text("pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8")
            first = build_intake(path)
            second = build_intake(path)
            self.assertEqual(first["target"]["source_hash"], second["target"]["source_hash"])
            self.assertEqual(first["target"]["manifest_sha256"], second["target"]["manifest_sha256"])
            self.assertEqual(first["target"]["content_address"], f"sha256:{first['target']['source_hash']}")

    def test_evidence_graph_keeps_unproved_findings_as_debt(self):
        import json
        from w3sec.evidence import build_evidence_graph
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            report_dir = root / "reports" / "contract-audits"
            report_dir.mkdir(parents=True)
            (report_dir / "audit.json").write_text(json.dumps({
                "id": "audit-1",
                "findings": [{
                    "id": "F-1",
                    "file": "Vault.sol",
                    "line": 10,
                    "source_hash": "a" * 64,
                    "security_property": "authorization integrity",
                }],
            }), encoding="utf-8")
            graph = build_evidence_graph(root)
            self.assertEqual(1, graph["summary"]["finding_count"])
            self.assertEqual(0, graph["summary"]["validated_count"])
            self.assertEqual(3, graph["summary"]["research_debt_count"])
            self.assertTrue(graph["graph_sha256"])

    def test_quality_report_is_structurally_healthy(self):
        from w3sec.quality import build_quality_report
        report = build_quality_report(ROOT)
        self.assertTrue(report["ok"])
        self.assertIn("candidate-is-not-validated", report["constitution"])


if __name__ == "__main__":
    unittest.main()
