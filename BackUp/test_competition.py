import json
import tempfile
import unittest
from pathlib import Path

from shipcheck import (
    Finding,
    ScanMetrics,
    build_report,
    calculate_score,
    filter_findings,
    format_sarif_report,
)


class CompetitionFeatureTests(unittest.TestCase):
    def test_security_rule_has_stable_id_and_category(self) -> None:
        finding = Finding(
            "HIGH",
            "app.py:4 uses eval(), which executes dynamically supplied code.",
            "Avoid dynamic code execution.",
            rule_id="SC001",
        )
        self.assertEqual(finding.rule_id, "SC001")
        self.assertEqual(finding.category, "security")
        self.assertEqual(finding.file, "app.py")
        self.assertEqual(finding.line, 4)

    def test_score_is_deterministic(self) -> None:
        findings = [
            Finding("HIGH", "app.py:1 issue", "fix", rule_id="SC001"),
            Finding("MEDIUM", "requirements.txt issue", "fix", rule_id="SC203"),
        ]
        self.assertEqual(calculate_score(findings), calculate_score(findings))

    def test_clean_score_is_ready(self) -> None:
        score = calculate_score([])
        self.assertEqual(score["overall"], 100)
        self.assertEqual(score["verdict"], "READY TO SHIP")

    def test_high_security_finding_reduces_security_score(self) -> None:
        score = calculate_score([
            Finding("HIGH", "app.py:1 issue", "fix", rule_id="SC001"),
        ])
        self.assertLess(score["categories"]["security"], 100)
        self.assertLess(score["overall"], 100)

    def test_json_schema_contains_score_and_rule_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            metrics = ScanMetrics(1, 10, 0, 1, 1, 0, 0)
            findings = [
                Finding("HIGH", "app.py:2 issue", "fix", rule_id="SC001")
            ]
            report = build_report(root, findings, metrics, 0.01)
            self.assertEqual(report["version"], "1")
            self.assertIn("score", report)
            self.assertEqual(report["findings"][0]["id"], "SC001")
            self.assertEqual(report["findings"][0]["category"], "security")
            self.assertEqual(report["findings"][0]["file"], "app.py")
            self.assertEqual(report["findings"][0]["line"], 2)

    def test_sarif_is_valid_json_with_results(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output = format_sarif_report(
                root,
                [Finding("HIGH", "app.py:3 issue", "fix", rule_id="SC001")],
            )
            data = json.loads(output)
            self.assertEqual(data["version"], "2.1.0")
            self.assertEqual(data["runs"][0]["tool"]["driver"]["name"], "ShipCheck")
            self.assertEqual(data["runs"][0]["results"][0]["ruleId"], "SC001")

    def test_severity_filter_keeps_matching_findings(self) -> None:
        findings = [
            Finding("LOW", "a", "fix", rule_id="SC009"),
            Finding("MEDIUM", "b", "fix", rule_id="SC203"),
            Finding("HIGH", "c", "fix", rule_id="SC001"),
        ]
        filtered = filter_findings(findings, severity="high")
        self.assertEqual([f.rule_id for f in filtered], ["SC001"])

    def test_multiple_severity_filter(self) -> None:
        findings = [
            Finding("LOW", "a", "fix", rule_id="SC009"),
            Finding("MEDIUM", "b", "fix", rule_id="SC203"),
            Finding("HIGH", "c", "fix", rule_id="SC001"),
        ]
        filtered = filter_findings(findings, severity="medium")
        self.assertEqual([f.rule_id for f in filtered], ["SC203", "SC001"])


if __name__ == "__main__":
    unittest.main()
