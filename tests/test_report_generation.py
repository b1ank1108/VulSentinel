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


_SIGNALS_BLOCK = (
    "```signals\n"
    "- affected_product: TestProduct\n"
    "- severity: high\n"
    "- authentication: none\n"
    "- external_callback: false\n"
    "- affected_versions: unknown\n"
    "- preconditions: []\n"
    "```\n"
)


def _make_entry(temp_dir: str, cve_id: str, year: int):
    templates_dir = Path(temp_dir) / "nuclei-templates"
    templates_dir.mkdir(parents=True, exist_ok=True)
    rel = f"http/cves/{year}/{cve_id}.yaml"
    tpath = templates_dir / rel
    tpath.parent.mkdir(parents=True, exist_ok=True)
    tpath.write_text("id: test\ninfo:\n  severity: high\n", encoding="utf-8")
    entry = CveEntry(id=cve_id, year=year, file_path=rel, template_path=tpath.resolve(), line_number=1)
    return entry, templates_dir


class TestReportGeneration(unittest.TestCase):
    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_text")
    def test_generate_report_markdown_for_entry(self, post_mock: MagicMock) -> None:
        post_mock.return_value = ChatTextResult(
            content=_SIGNALS_BLOCK + "\n## Vulnerability\nDesc.\n",
            raw_response={"id": "cmpl-1"},
        )

        with TemporaryDirectory() as tmp:
            entry, tdir = _make_entry(tmp, "CVE-2025-0001", 2025)
            report = generate_report_markdown_for_entry(
                entry, templates_dir=tdir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            self.assertTrue(report.startswith("---\n"))
            self.assertIn("cve_id: CVE-2025-0001", report)
            self.assertIn("severity: high", report)
            self.assertIn("affected_product: TestProduct", report)
            self.assertIn("# CVE-2025-0001", report)
            # signals block must be stripped from body
            self.assertNotIn("```signals", report)

    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_text")
    def test_frontmatter_fallback_on_unparseable_signals(self, post_mock: MagicMock) -> None:
        post_mock.return_value = ChatTextResult(
            content="## Vulnerability\nSome vulnerability description.\n",
            raw_response={"id": "cmpl-2"},
        )

        with TemporaryDirectory() as tmp:
            entry, tdir = _make_entry(tmp, "CVE-2025-0002", 2025)
            report = generate_report_markdown_for_entry(
                entry, templates_dir=tdir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            self.assertTrue(report.startswith("---\n"))
            self.assertIn("cve_id: CVE-2025-0002", report)
            fm = report.split("---")[1]
            self.assertNotIn("severity:", fm)

    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_text")
    def test_poc_classification_in_frontmatter(self, post_mock: MagicMock) -> None:
        with TemporaryDirectory() as tmp:
            # info-leak
            post_mock.return_value = ChatTextResult(
                content=_SIGNALS_BLOCK + "\n## PoC / Detection\nClassification: info-leak\nDetails.\n",
                raw_response={},
            )
            entry, tdir = _make_entry(tmp, "CVE-2025-0010", 2025)
            report = generate_report_markdown_for_entry(
                entry, templates_dir=tdir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            fm = report.split("---")[1]
            self.assertIn("poc_classification: info-leak", fm)

        with TemporaryDirectory() as tmp:
            # rce
            post_mock.return_value = ChatTextResult(
                content=_SIGNALS_BLOCK + "\n## PoC / Detection\nClassification: rce\nDetails.\n",
                raw_response={},
            )
            entry, tdir = _make_entry(tmp, "CVE-2025-0011", 2025)
            report = generate_report_markdown_for_entry(
                entry, templates_dir=tdir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            fm = report.split("---")[1]
            self.assertIn("poc_classification: rce", fm)

        with TemporaryDirectory() as tmp:
            # no Classification line
            post_mock.return_value = ChatTextResult(
                content="## PoC / Detection\nNo classification here.\n",
                raw_response={},
            )
            entry, tdir = _make_entry(tmp, "CVE-2025-0012", 2025)
            report = generate_report_markdown_for_entry(
                entry, templates_dir=tdir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            fm = report.split("---")[1]
            self.assertNotIn("poc_classification", fm)

    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_text")
    def test_poc_classification_state_change(self, post_mock: MagicMock) -> None:
        with TemporaryDirectory() as tmp:
            entry, tdir = _make_entry(tmp, "CVE-2025-0013", 2025)
            post_mock.return_value = ChatTextResult(
                content="## PoC / Detection\nClassification: state-change\nModifies config.\n",
                raw_response={},
            )
            report = generate_report_markdown_for_entry(
                entry, templates_dir=tdir,
                model=ModelConfig(base_url="http://example.invalid", api_key="k", model="m"),
            )
            fm = report.split("---")[1]
            self.assertIn("poc_classification: state-change", fm)


class TestExtractPocClassification(unittest.TestCase):
    def test_detect_only(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: detect-only\n"), "detect-only")

    def test_info_leak(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: info-leak"), "info-leak")

    def test_auth_bypass(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: auth-bypass"), "auth-bypass")

    def test_rce(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: rce"), "rce")

    def test_state_change(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: state-change"), "state-change")

    def test_dos(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: dos"), "dos")

    def test_case_insensitive(self) -> None:
        self.assertEqual(_extract_poc_classification("Classification: Detect-Only"), "detect-only")

    def test_missing(self) -> None:
        self.assertIsNone(_extract_poc_classification("No classification here."))

    def test_invalid_value(self) -> None:
        self.assertIsNone(_extract_poc_classification("Classification: unknown-value"))


class TestExtractSignals(unittest.TestCase):
    def test_signals_block(self) -> None:
        body = (
            "```signals\n"
            "- severity: high\n"
            "- authentication: none\n"
            "```\n"
        )
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {"severity": "high", "authentication": "none"})

    def test_all_six_keys(self) -> None:
        body = (
            "```signals\n"
            "- affected_product: n8n\n"
            "- severity: critical\n"
            "- authentication: none\n"
            "- external_callback: false\n"
            "- affected_versions: >=1.0.0, <2.0.0\n"
            "- preconditions: []\n"
            "```\n"
            "\n## Vulnerability\n"
        )
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {
            "affected_product": "n8n",
            "severity": "critical",
            "authentication": "none",
            "external_callback": "false",
            "affected_versions": ">=1.0.0, <2.0.0",
            "preconditions": "[]",
        })

    def test_missing_block(self) -> None:
        body = "## Vulnerability\nSome text.\n## References\n- https://example.com\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {})

    def test_unknown_keys_filtered(self) -> None:
        body = "```signals\n- severity: high\n- random_key: foo\n- authentication: none\n```\n"
        result = _extract_signals_from_markdown(body)
        self.assertEqual(result, {"severity": "high", "authentication": "none"})

    def test_signals_block_stripped_from_body(self) -> None:
        from cve_poc_llm_reports.report_generation import _strip_signals_block
        body = "```signals\n- severity: low\n```\n\n## Vulnerability\nDesc.\n"
        stripped = _strip_signals_block(body)
        self.assertNotIn("```signals", stripped)
        self.assertIn("## Vulnerability", stripped)


if __name__ == "__main__":
    unittest.main()
