import unittest
from pathlib import Path
import auditor

BASE = Path(__file__).parent / "fixtures"

class AuditorTests(unittest.TestCase):
    def test_safe_file(self):
        report = auditor.build_report([BASE / "benign.md"], ["*.md"], [], 256)
        self.assertEqual(report["grade"], "SAFE")
        self.assertEqual(report["findings_total"], 0)

    def test_danger_file(self):
        report = auditor.build_report([BASE / "danger.sh"], ["*.sh"], [], 256)
        self.assertEqual(report["grade"], "DANGER")
        self.assertGreaterEqual(report["severity"]["danger"], 1)

    def test_warning_file(self):
        report = auditor.build_report([BASE / "warn.md"], ["*.md"], [], 256)
        self.assertIn(report["grade"], ["WARNING", "DANGER"])
        self.assertGreaterEqual(report["findings_total"], 1)

    def test_exclude_works(self):
        report = auditor.build_report([BASE], ["*.md", "*.sh"], ["danger.sh"], 256)
        files = {Path(f["file"]).name for f in report["findings"]}
        self.assertNotIn("danger.sh", files)

if __name__ == "__main__":
    unittest.main()
