import contextlib
import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from cve_poc_llm_reports.cli import main as cli_main


class TestRunContinuesOnFailure(unittest.TestCase):
    @patch("cve_poc_llm_reports.report_generation.generate_report_markdown_for_entry")
    def test_single_failure_does_not_abort(self, gen_mock: MagicMock) -> None:
        def side_effect(entry, *args, **kwargs):  # noqa: ANN001,ANN002,ANN003
            if entry.id == "CVE-2025-0001":
                raise RuntimeError("boom")
            return f"---\ncve_id: {entry.id}\n---\n# {entry.id}\n\nok\n"

        gen_mock.side_effect = side_effect

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            templates_dir = root / "templates"
            reports_dir = root / "reports"
            templates_dir.mkdir(parents=True)
            reports_dir.mkdir(parents=True)
            (templates_dir / "cves.json").write_text(
                "\n".join(
                    [
                        '{"ID":"CVE-2025-0001","file_path":"http/cves/2025/CVE-2025-0001.yaml"}',
                        '{"ID":"CVE-2025-0002","file_path":"http/cves/2025/CVE-2025-0002.yaml"}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            old_env = os.environ.copy()
            try:
                os.environ["OPENAI_BASE_URL"] = "http://example.invalid/v1"
                os.environ["OPENAI_API_KEY"] = "dummy"
                os.environ["OPENAI_MODEL"] = "dummy"

                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    rc = cli_main(
                        [
                            "--templates-dir",
                            str(templates_dir),
                            "--reports-dir",
                            str(reports_dir),
                        ],
                        prog="cve_poc_llm_reports_cli",
                        include_openai_overrides=False,
                        repo_root=root,
                    )
                self.assertEqual(rc, 1)

                out = stderr.getvalue()
                self.assertIn("event=fail", out)
                self.assertIn("event=success", out)
                self.assertIn("event=summary", out)
                self.assertIn("processed=2", out)
                self.assertIn("failed=1", out)
                self.assertIn("succeeded=1", out)
            finally:
                os.environ.clear()
                os.environ.update(old_env)

    @patch("cve_poc_llm_reports.report_generation.generate_report_markdown_for_entry")
    def test_all_succeed_returns_zero(self, gen_mock: MagicMock) -> None:
        gen_mock.return_value = "---\ncve_id: X\n---\n# X\n\nok\n"

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            templates_dir = root / "templates"
            reports_dir = root / "reports"
            templates_dir.mkdir(parents=True)
            reports_dir.mkdir(parents=True)
            (templates_dir / "cves.json").write_text(
                '{"ID":"CVE-2025-0001","file_path":"http/cves/2025/CVE-2025-0001.yaml"}\n',
                encoding="utf-8",
            )

            old_env = os.environ.copy()
            try:
                os.environ["OPENAI_BASE_URL"] = "http://example.invalid/v1"
                os.environ["OPENAI_API_KEY"] = "dummy"
                os.environ["OPENAI_MODEL"] = "dummy"

                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    rc = cli_main(
                        [
                            "--templates-dir",
                            str(templates_dir),
                            "--reports-dir",
                            str(reports_dir),
                        ],
                        prog="cve_poc_llm_reports_cli",
                        include_openai_overrides=False,
                        repo_root=root,
                    )
                self.assertEqual(rc, 0)
            finally:
                os.environ.clear()
                os.environ.update(old_env)

    @patch("cve_poc_llm_reports.report_generation.generate_report_markdown_for_entry")
    def test_all_skipped_returns_zero(self, gen_mock: MagicMock) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            templates_dir = root / "templates"
            reports_dir = root / "reports"
            templates_dir.mkdir(parents=True)
            reports_dir.mkdir(parents=True)
            (templates_dir / "cves.json").write_text(
                '{"ID":"CVE-2025-0001","file_path":"http/cves/2025/CVE-2025-0001.yaml"}\n',
                encoding="utf-8",
            )

            report_path = reports_dir / "http" / "cves" / "2025" / "CVE-2025-0001.md"
            report_path.parent.mkdir(parents=True)
            report_path.write_text("existing report\n", encoding="utf-8")

            old_env = os.environ.copy()
            try:
                os.environ["OPENAI_BASE_URL"] = "http://example.invalid/v1"
                os.environ["OPENAI_API_KEY"] = "dummy"
                os.environ["OPENAI_MODEL"] = "dummy"

                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    rc = cli_main(
                        [
                            "--templates-dir",
                            str(templates_dir),
                            "--reports-dir",
                            str(reports_dir),
                        ],
                        prog="cve_poc_llm_reports_cli",
                        include_openai_overrides=False,
                        repo_root=root,
                    )
                self.assertEqual(rc, 0)
                gen_mock.assert_not_called()
            finally:
                os.environ.clear()
                os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()
