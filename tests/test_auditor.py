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


class RiskScoringTests(unittest.TestCase):
    def test_risk_score_fields_exist(self):
        report = auditor.build_report([BASE / "danger.sh"], ["*.sh"], [], 256)
        self.assertIn("risk_metrics", report)
        self.assertIn("average_risk", report["risk_metrics"])
        self.assertIn("max_risk", report["risk_metrics"])
        self.assertIn("high_risk_count", report["risk_metrics"])

    def test_finding_has_risk_score(self):
        report = auditor.build_report([BASE / "danger.sh"], ["*.sh"], [], 256)
        for finding in report["findings"]:
            self.assertIn("risk_score", finding)
            self.assertIsInstance(finding["risk_score"], int)
            self.assertGreaterEqual(finding["risk_score"], 0)
            self.assertLessEqual(finding["risk_score"], 100)

    def test_high_risk_threshold_present(self):
        report = auditor.build_report([BASE / "danger.sh"], ["*.sh"], [], 256)
        self.assertIn("high_risk_threshold", report)
        self.assertEqual(report["high_risk_threshold"], 70)

    def test_risk_metrics_calculation(self):
        report = auditor.build_report([BASE], ["*.md", "*.sh"], [], 256)
        risk_metrics = report["risk_metrics"]
        findings = report["findings"]

        if findings:
            self.assertGreaterEqual(risk_metrics["max_risk"], 0)
            self.assertLessEqual(risk_metrics["max_risk"], 100)
            self.assertGreaterEqual(risk_metrics["average_risk"], 0)
            self.assertLessEqual(risk_metrics["average_risk"], 100)
            self.assertLessEqual(risk_metrics["high_risk_count"], len(findings))

    def test_dangerous_finding_has_high_risk_score(self):
        report = auditor.build_report([BASE / "danger.sh"], ["*.sh"], [], 256)
        high_risk_findings = [f for f in report["findings"] if f["risk_score"] >= 70]
        self.assertGreater(len(high_risk_findings), 0)


class FixSuggestionTests(unittest.TestCase):
    def test_fix_suggestion_field_exists(self):
        report = auditor.build_report([BASE / "danger.sh"], ["*.sh"], [], 256)
        for finding in report["findings"]:
            self.assertIn("fix_suggestion", finding)

    def test_destructive_command_has_fix(self):
        report = auditor.build_report([BASE / "danger.sh"], ["*.sh"], [], 256)
        destructive_findings = [
            f
            for f in report["findings"]
            if f["category"] == "destructive-command" and f["actionable"]
        ]
        for finding in destructive_findings:
            self.assertIsNotNone(finding["fix_suggestion"])
            self.assertGreater(len(finding["fix_suggestion"]), 0)


class EstimatedTimeSavedTests(unittest.TestCase):
    def test_estimated_review_minutes_saved_field(self):
        report = auditor.build_report([BASE], ["*.md", "*.sh"], [], 256)
        self.assertIn("estimated_review_minutes_saved", report)
        self.assertIsInstance(report["estimated_review_minutes_saved"], int)
        self.assertGreaterEqual(report["estimated_review_minutes_saved"], 0)

    def test_time_saved_calculation(self):
        report = auditor.build_report([BASE / "danger.sh"], ["*.sh"], [], 256)
        actionable_count = report["severity"]["actionable"]
        if actionable_count > 0:
            self.assertGreater(report["estimated_review_minutes_saved"], 0)


class BaselineComparisonTests(unittest.TestCase):
    def test_baseline_comparison_not_included_by_default(self):
        report = auditor.build_report([BASE], ["*.md", "*.sh"], [], 256)
        self.assertNotIn("baseline_comparison", report)

    def test_baseline_comparison_fields_when_provided(self):
        baseline_report = auditor.build_report([BASE / "benign.md"], ["*.md"], [], 256)
        current_report = auditor.build_report(
            [BASE], ["*.md", "*.sh"], [], 256, baseline_report=baseline_report
        )
        self.assertIn("baseline_comparison", current_report)
        delta = current_report["baseline_comparison"]
        self.assertIn("actionable_delta", delta)
        self.assertIn("high_risk_delta", delta)
        self.assertIn("max_risk_delta", delta)
        self.assertIn("average_risk_delta", delta)
        self.assertIn("findings_delta", delta)

    def test_baseline_delta_calculation(self):
        baseline = auditor.build_report([BASE / "benign.md"], ["*.md"], [], 256)
        current = auditor.build_report(
            [BASE], ["*.md", "*.sh"], [], 256, baseline_report=baseline
        )
        delta = current["baseline_comparison"]
        self.assertGreater(delta["findings_delta"], 0)


class GradeLogicTests(unittest.TestCase):
    def test_safe_grade(self):
        report = auditor.build_report([BASE / "benign.md"], ["*.md"], [], 256)
        self.assertEqual(report["grade"], "SAFE")

    def test_danger_grade_for_high_risk(self):
        report = auditor.build_report([BASE / "danger.sh"], ["*.sh"], [], 256)
        self.assertEqual(report["grade"], "DANGER")


if __name__ == "__main__":
    unittest.main()
