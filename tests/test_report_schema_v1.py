import unittest

from cve_poc_llm_reports.report_schema_v1 import build_report_v1, validate_report_v1


class TestReportSchemaV1(unittest.TestCase):
    def test_build_sets_default_severity_unknown(self) -> None:
        report = build_report_v1(
            cve_id="CVE-2025-0001",
            year=2025,
            template_path="nuclei-templates/http/cves/2025/CVE-2025-0001.yaml",
            signals={
                "exploit_vs_detect": "unknown",
                "auth_requirement": "unknown",
                "oast_required": False,
                "version_constraints": [],
                "feature_gates": [],
            },
        )
        self.assertEqual(report["signals"]["severity"], "unknown")

    def test_validate_accepts_minimal_valid_report(self) -> None:
        report = build_report_v1(
            cve_id="CVE-2025-0001",
            year=2025,
            template_path="nuclei-templates/http/cves/2025/CVE-2025-0001.yaml",
            signals={
                "severity": "high",
                "exploit_vs_detect": "detect",
                "auth_requirement": "none",
                "oast_required": False,
                "version_constraints": ["<=1.0.0"],
                "feature_gates": [],
            },
        )
        validate_report_v1(report)

    def test_validate_rejects_bad_enum(self) -> None:
        report = build_report_v1(
            cve_id="CVE-2025-0001",
            year=2025,
            template_path="nuclei-templates/http/cves/2025/CVE-2025-0001.yaml",
            signals={
                "severity": "high",
                "exploit_vs_detect": "nope",
                "auth_requirement": "none",
                "oast_required": False,
                "version_constraints": [],
                "feature_gates": [],
            },
        )
        with self.assertRaisesRegex(ValueError, "signals.exploit_vs_detect"):
            validate_report_v1(report)

    def test_validate_rejects_missing_required_field(self) -> None:
        report = {
            "schema_version": "v1",
            "cve": {"id": "CVE-2025-0001", "year": 2025},
            "template": {"path": "nuclei-templates/http/cves/2025/CVE-2025-0001.yaml"},
            "signals": {"severity": "high"},
        }
        with self.assertRaisesRegex(ValueError, "signals.exploit_vs_detect"):
            validate_report_v1(report)


if __name__ == "__main__":
    unittest.main()

