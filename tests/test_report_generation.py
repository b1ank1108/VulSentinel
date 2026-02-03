import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from cve_poc_llm_reports.cves_jsonl import CveEntry
from cve_poc_llm_reports.openai_text import ChatTextResult
from cve_poc_llm_reports.report_generation import ModelConfig, generate_report_markdown_for_entry


class TestReportGeneration(unittest.TestCase):
    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_text")
    def test_generate_report_markdown_for_entry(self, post_mock: MagicMock) -> None:
        post_mock.return_value = ChatTextResult(
            content="## Signals\n- severity: high\n- auth_requirement: none\n",
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
            report = generate_report_markdown_for_entry(
                entry,
                templates_dir=templates_dir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            self.assertIn("# CVE-2025-0001", report)
            self.assertIn("template_path: `nuclei-templates/http/cves/2025/CVE-2025-0001.yaml`", report)
            self.assertIn("## Signals", report)


if __name__ == "__main__":
    unittest.main()
