import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from w3sec.federation import build_candidate_network, build_federation_snapshot, normalized_candidate_records
from w3sec.history import build_domain_evolution, build_temporal_timeline
from w3sec.promotion import build_promotion_engine
from w3sec.research_intelligence import build_longitudinal_report
from w3sec.versions import VersionContext, build_version_diff_report, diff_versions


class LongitudinalTests(unittest.TestCase):
    def test_federation_is_populated_but_secondary(self):
        snapshot = build_federation_snapshot(ROOT)
        self.assertEqual("ok", snapshot["federation_health"])
        self.assertGreaterEqual(snapshot["candidate_record_count"], 250)
        self.assertIn("candidate_policy", snapshot)
        self.assertEqual(snapshot["candidate_record_count"], len(normalized_candidate_records(ROOT)))

    def test_candidate_network_tracks_recurrence(self):
        network = build_candidate_network(ROOT)
        self.assertGreaterEqual(network["candidate_count"], 250)
        self.assertTrue(network["theme_recurrence"])
        self.assertTrue(network["policy"].startswith("Candidate network"))

    def test_promotion_engine_holds_current_patterns(self):
        engine = build_promotion_engine(ROOT)
        self.assertEqual(4, len(engine["decisions"]))
        self.assertEqual(0, engine["promotable_count"])
        for decision in engine["decisions"]:
            self.assertEqual("hold", decision["decision"])
            self.assertIn("cross_case", decision["missing_requirements"])

    def test_version_diff_requires_explicit_pair(self):
        report = build_version_diff_report(ROOT)
        self.assertEqual(3, report["context_count"])
        self.assertEqual(0, report["diff_count"])
        self.assertEqual(3, len(report["unresolved"]))

    def test_version_diff_detects_security_model_change(self):
        before = VersionContext("v1", "p", "1", "resolved", ("c1",), {"replay_rules": ["monotonic"]})
        after = VersionContext("v2", "p", "2", "resolved", ("c2",), {"replay_rules": ["monotonic", "rotation-closes"]})
        result = diff_versions(before, after)
        self.assertTrue(result["security_model_changed"])
        self.assertEqual("replay_rules", result["changes"][0]["field"])

    def test_git_history_is_temporal_provenance(self):
        timeline = build_temporal_timeline(ROOT)
        self.assertGreaterEqual(timeline["sources"]["git_commit_count"], 8)
        self.assertGreaterEqual(timeline["sources"]["ledger_event_count"], 13)
        self.assertTrue(any(item["event_type"] == "repository_commit" for item in timeline["timeline"]))

    def test_domain_evolution(self):
        report = build_domain_evolution(ROOT)
        self.assertGreaterEqual(report["commit_count"], 8)
        self.assertIn("knowledge", report["domain_change_counts"])
        self.assertIn("tooling", report["domain_change_counts"])

    def test_longitudinal_report_integrates_all_engines(self):
        report = build_longitudinal_report(ROOT)
        self.assertIn("cross_case", report)
        self.assertIn("cross_protocol", report)
        self.assertIn("promotion", report)
        self.assertIn("versions", report)
        self.assertIn("temporal", report)
        self.assertIn("research_debt", report)


if __name__ == "__main__":
    unittest.main()
