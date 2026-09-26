import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from w3sec.audit import audit_repo
from w3sec.coverage import build_coverage


ROOT = Path(__file__).resolve().parents[1]


class AuditCoverageTests(unittest.TestCase):
    def test_audit_is_green(self):
        report = audit_repo(ROOT)
        self.assertTrue(report["ok"])
        self.assertGreaterEqual(report["graph"]["node_count"], 30)
        self.assertGreaterEqual(report["graph"]["edge_count"], 20)

    def test_coverage_tracks_regression_debt(self):
        report = build_coverage(ROOT)
        self.assertEqual(4, report["case_count"])
        self.assertEqual(4, report["evidence_count"])
        self.assertEqual(4, report["hypothesis_count"])
        self.assertEqual(4, report["regression_plan_count"])
        self.assertEqual([], report["cases_without_evidence"])
        self.assertEqual([], report["cases_without_hypotheses"])
        self.assertEqual([], report["cases_without_regression_plan"])


if __name__ == "__main__":
    unittest.main()
