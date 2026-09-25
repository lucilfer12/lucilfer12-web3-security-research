import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from w3sec.validator import validate_repo
class RepositoryValidationTests(unittest.TestCase):
    def test_repository_records_validate(self):
        self.assertEqual([], validate_repo(ROOT))
if __name__ == "__main__":
    unittest.main()