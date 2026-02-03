import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from cve_poc_llm_reports.cves_jsonl import CveEntry
from cve_poc_llm_reports.openai_json import ChatJsonResult
from cve_poc_llm_reports.report_generation import ModelConfig, generate_report_v1_for_entry
from cve_poc_llm_reports.report_schema_v1 import validate_report_v1


class TestReportGeneration(unittest.TestCase):
    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_json")
    def test_generate_report_v1_for_entry(self, post_mock: MagicMock) -> None:
        post_mock.return_value = ChatJsonResult(
            data={
                "severity": "high",
                "exploit_vs_detect": "detect",
                "auth_requirement": "none",
                "oast_required": False,
                "version_constraints": [],
                "feature_gates": [],
            },
            raw_response={"id": "cmpl-1"},
        )

        with TemporaryDirectory() as temp_dir:
            templates_dir = Path(temp_dir) / "nuclei-templates"
            templates_dir.mkdir(parents=True)
            template_path = templates_dir / "http/cves/2025/CVE-2025-0001.yaml"
            template_path.parent.mkdir(parents=True)
            template_path.write_text("id: test\ninfo:\n  severity: high\n", encoding="utf-8")

            entry = CveEntry(
                id="CVE-2025-0001",
                year=2025,
                file_path="http/cves/2025/CVE-2025-0001.yaml",
                template_path=template_path.resolve(),
                line_number=1,
            )
            report = generate_report_v1_for_entry(
                entry,
                templates_dir=templates_dir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            validate_report_v1(report)
            self.assertEqual(report["cve"]["id"], "CVE-2025-0001")
            self.assertEqual(report["template"]["path"], "nuclei-templates/http/cves/2025/CVE-2025-0001.yaml")


if __name__ == "__main__":
    unittest.main()

