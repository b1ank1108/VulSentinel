import contextlib
import importlib.util
import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from cve_poc_llm_reports.openai_text import ChatTextResult


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "cve_poc_llm_reports.py"
_SPEC = importlib.util.spec_from_file_location("cve_poc_llm_reports_script_jsonl_cont", _SCRIPT_PATH)
assert _SPEC and _SPEC.loader
_SCRIPT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SCRIPT)


class TestJsonlErrorContinuation(unittest.TestCase):
    @patch("cve_poc_llm_reports.report_generation.post_chat_completions_text")
    def test_invalid_jsonl_line_does_not_abort(self, post_mock: MagicMock) -> None:
        post_mock.return_value = ChatTextResult(
            content="## Signals\n- severity: high\n- auth_requirement: none\n",
            raw_response={"id": "cmpl-1"},
        )

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
                        "not-json",
                        '{"ID":"CVE-2025-0002","file_path":"http/cves/2025/CVE-2025-0002.yaml"}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            tpl2 = templates_dir / "http/cves/2025/CVE-2025-0002.yaml"
            tpl2.parent.mkdir(parents=True)
            tpl2.write_text("id: test\ninfo:\n  severity: high\n", encoding="utf-8")

            old_env = os.environ.copy()
            try:
                os.environ["OPENAI_BASE_URL"] = "http://example.invalid"
                os.environ["OPENAI_API_KEY"] = "dummy"
                os.environ["OPENAI_MODEL"] = "dummy"

                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    rc = _SCRIPT.main(
                        [
                            "--templates-dir",
                            str(templates_dir),
                            "--reports-dir",
                            str(reports_dir),
                        ]
                    )
                self.assertEqual(rc, 0)

                out = stderr.getvalue()
                self.assertIn("jsonl_parse_failed", out)
                self.assertIn("event=success", out)
            finally:
                os.environ.clear()
                os.environ.update(old_env)

            report_path = reports_dir / "http/cves/2025/CVE-2025-0002.md"
            self.assertTrue(report_path.exists())
            self.assertIn("CVE-2025-0002", report_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
