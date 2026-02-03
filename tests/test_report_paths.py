import unittest
from pathlib import Path

from cve_poc_llm_reports.report_paths import build_report_path


class TestBuildReportPath(unittest.TestCase):
    def test_build_report_path_normalizes_year_from_id(self) -> None:
        report_path = build_report_path(
            reports_dir=Path("reports"),
            file_path="http/cves/2018/CVE-2019-10647.yaml",
            year=2019,
            cve_id="CVE-2019-10647",
        )
        self.assertEqual(report_path.as_posix(), "reports/http/cves/2019/CVE-2019-10647.json")

    def test_build_report_path_rejects_missing_prefix(self) -> None:
        with self.assertRaisesRegex(ValueError, "must contain"):
            build_report_path(
                reports_dir=Path("reports"),
                file_path="cves/2024/CVE-2024-0001.yaml",
                year=2024,
                cve_id="CVE-2024-0001",
            )

    def test_build_report_path_rejects_unsafe_prefix(self) -> None:
        with self.assertRaisesRegex(ValueError, "must not contain"):
            build_report_path(
                reports_dir=Path("reports"),
                file_path="../escape/cves/2024/CVE-2024-0001.yaml",
                year=2024,
                cve_id="CVE-2024-0001",
            )


if __name__ == "__main__":
    unittest.main()

