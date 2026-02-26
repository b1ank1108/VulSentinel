import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from cve_poc_llm_reports.cves_jsonl import CveEntry
from cve_poc_llm_reports.openai_text import ChatTextResult
from cve_poc_llm_reports.report_generation import (
    ModelConfig,
    _extract_poc_classification,
    _extract_signals_from_markdown,
    generate_report_markdown_for_entry,
)


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
            self.assertTrue(report.startswith("---\n"))
            self.assertIn("cve_id: CVE-2025-0001", report)
            self.assertIn("template_path: nuclei-templates/http/cves/2025/CVE-2025-0001.yaml", report)
            self.assertIn("severity: high", report)
            self.assertIn("# CVE-2025-0001", report)
            self.assertIn("## Signals", report)
            self.assertNotIn("- template_path:", report)

    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_text")
    def test_frontmatter_fallback_on_unparseable_signals(self, post_mock: MagicMock) -> None:
        post_mock.return_value = ChatTextResult(
            content="## Vulnerability\nSome vulnerability description.\n",
            raw_response={"id": "cmpl-2"},
        )

        with TemporaryDirectory() as temp_dir:
            templates_dir = Path(temp_dir) / "nuclei-templates"
            templates_dir.mkdir(parents=True)
            template_path = templates_dir / "http/cves/2025/CVE-2025-0002.yaml"
            template_path.parent.mkdir(parents=True)
            template_path.write_text("id: test\n", encoding="utf-8")

            entry = CveEntry(
                id="CVE-2025-0002",
                year=2025,
                file_path="http/cves/2025/CVE-2025-0002.yaml",
                template_path=template_path.resolve(),
                line_number=1,
            )
            report = generate_report_markdown_for_entry(
                entry,
                templates_dir=templates_dir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            self.assertTrue(report.startswith("---\n"))
            self.assertIn("cve_id: CVE-2025-0002", report)
            self.assertNotIn("severity:", report.split("---")[1].split("---")[0]
                             if report.count("---") >= 2 else "")


    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_text")
    def test_poc_classification_in_frontmatter(self, post_mock: MagicMock) -> None:
        def _make_entry(temp_dir: str, cve_id: str, year: int, body: str):
            templates_dir = Path(temp_dir) / "nuclei-templates"
            templates_dir.mkdir(parents=True, exist_ok=True)
            rel = f"http/cves/{year}/{cve_id}.yaml"
            tpath = templates_dir / rel
            tpath.parent.mkdir(parents=True, exist_ok=True)
            tpath.write_text("id: test\n", encoding="utf-8")
            entry = CveEntry(id=cve_id, year=year, file_path=rel, template_path=tpath.resolve(), line_number=1)
            return entry, templates_dir

        with TemporaryDirectory() as tmp:
            # detect-only
            post_mock.return_value = ChatTextResult(
                content="## PoC / Detection\nClassification: detect-only\nSome details.\n",
                raw_response={},
            )
            entry, tdir = _make_entry(tmp, "CVE-2025-0010", 2025, "")
            report = generate_report_markdown_for_entry(
                entry,
                templates_dir=tdir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            fm = report.split("---")[1]
            self.assertIn("poc_classification: detect-only", fm)

        with TemporaryDirectory() as tmp:
            # exploit
            post_mock.return_value = ChatTextResult(
                content="## PoC / Detection\nClassification: exploit\nSome details.\n",
                raw_response={},
            )
            entry, tdir = _make_entry(tmp, "CVE-2025-0011", 2025, "")
            report = generate_report_markdown_for_entry(
                entry,
                templates_dir=tdir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            fm = report.split("---")[1]
            self.assertIn("poc_classification: exploit", fm)

        with TemporaryDirectory() as tmp:
            # no Classification line -> not in frontmatter
            post_mock.return_value = ChatTextResult(
                content="## PoC / Detection\nNo classification here.\n",
                raw_response={},
            )
            entry, tdir = _make_entry(tmp, "CVE-2025-0012", 2025, "")
            report = generate_report_markdown_for_entry(
                entry,
                templates_dir=tdir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            fm = report.split("---")[1]
            self.assertNotIn("poc_classification", fm)

    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_text")
    def test_poc_classification_intrusive(self, post_mock: MagicMock) -> None:
        with TemporaryDirectory() as tmp:
            templates_dir = Path(tmp) / "nuclei-templates"
            templates_dir.mkdir(parents=True)
            tpath = templates_dir / "http/cves/2025/CVE-2025-0013.yaml"
            tpath.parent.mkdir(parents=True)
            tpath.write_text("id: test\n", encoding="utf-8")
            entry = CveEntry(
                id="CVE-2025-0013",
                year=2025,
                file_path="http/cves/2025/CVE-2025-0013.yaml",
                template_path=tpath.resolve(),
                line_number=1,
            )
            post_mock.return_value = ChatTextResult(
                content="## PoC / Detection\nClassification: intrusive\nDestructive action.\n",
                raw_response={},
            )
            report = generate_report_markdown_for_entry(
                entry,
                templates_dir=templates_dir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            fm = report.split("---")[1]
            self.assertIn("poc_classification: intrusive", fm)


class TestExtractPocClassification(unittest.TestCase):
    def test_detect_only(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: detect-only\n"), "detect-only")

    def test_exploit(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: exploit"), "exploit")

    def test_active_detect(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: active-detect"), "active-detect")

    def test_intrusive(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: intrusive"), "intrusive")

    def test_case_insensitive(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: Detect-Only"), "detect-only")

    def test_missing(self) -> None:
        self.assertIsNone(_extract_poc_classification("No classification here."))

    def test_invalid_value(self) -> None:
        self.assertIsNone(_extract_poc_classification("Classification: unknown-value"))



    def test_bare_keys(self) -> None:
        body = "## Signals\n- severity: high\n- auth_requirement: none\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {"severity": "high", "auth_requirement": "none"})

    def test_bold_keys(self) -> None:
        body = "## Signals\n- **severity**: critical\n- **oast_required**: true\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {"severity": "critical", "oast_required": "true"})

    def test_mixed_keys(self) -> None:
        body = (
            "## Signals\n"
            "- severity: high\n"
            "- **auth_requirement**: none\n"
            "- oast_required: false\n"
        )
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {
            "severity": "high",
            "auth_requirement": "none",
            "oast_required": "false",
        })

    def test_missing_section(self) -> None:
        body = "## Vulnerability\nSome text.\n## References\n- https://example.com\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {})

    def test_unknown_keys_filtered(self) -> None:
        body = "## Signals\n- severity: high\n- random_key: foo\n- auth_requirement: none\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {"severity": "high", "auth_requirement": "none"})

    def test_all_five_keys(self) -> None:
        body = (
            "## Signals\n"
            "- severity: critical\n"
            "- auth_requirement: none\n"
            "- oast_required: false\n"
            "- version_constraints: >=1.0.0, <2.0.0\n"
            "- feature_gates: []\n"
            "\n## Vulnerability\n"
        )
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {
            "severity": "critical",
            "auth_requirement": "none",
            "oast_required": "false",
            "version_constraints": ">=1.0.0, <2.0.0",
            "feature_gates": "[]",
        })

    def test_signals_at_end_of_body(self) -> None:
        body = "## Signals\n- severity: low\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {"severity": "low"})

    def test_bold_section_header(self) -> None:
        body = "**Signals**\n- severity: critical\n- auth_requirement: none\n\n**Vulnerability**\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {"severity": "critical", "auth_requirement": "none"})

    def test_bold_hash_section_header(self) -> None:
        body = "**## Signals**\n- severity: high\n- oast_required: false\n\n**## Vulnerability**\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {"severity": "high", "oast_required": "false"})

    def test_bold_section_with_trailing_spaces(self) -> None:
        body = "**Signals**  \n- severity: high\n- auth_requirement: none\n\n**PoC / Detection**\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {"severity": "high", "auth_requirement": "none"})


if __name__ == "__main__":
    unittest.main()
