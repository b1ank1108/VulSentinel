import contextlib
import importlib.util
import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "cve_poc_llm_reports.py"
_SPEC = importlib.util.spec_from_file_location("cve_poc_llm_reports_script_report_exists", _SCRIPT_PATH)
assert _SPEC and _SPEC.loader
_SCRIPT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SCRIPT)


class TestReportExistsSkip(unittest.TestCase):
    def test_skips_existing_report_without_processing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            templates_dir = root / "templates"
            reports_dir = root / "reports"
            templates_dir.mkdir(parents=True)
            reports_dir.mkdir(parents=True)

            (templates_dir / "cves.json").write_text(
                '{"ID":"CVE-2025-0002","file_path":"http/cves/2025/CVE-2025-0002.yaml"}\n',
                encoding="utf-8",
            )

            existing_report = reports_dir / "http/cves/2025/CVE-2025-0002.json"
            existing_report.parent.mkdir(parents=True)
            existing_report.write_text("{}", encoding="utf-8")

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
                self.assertIn("event=skip", out)
                self.assertIn("reason=\"report_exists\"", out)
                self.assertIn(str(existing_report), out)
            finally:
                os.environ.clear()
                os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()

