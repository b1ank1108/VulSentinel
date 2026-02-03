import contextlib
import importlib.util
import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory


_SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "cve_poc_llm_reports.py"
_SPEC = importlib.util.spec_from_file_location("cve_poc_llm_reports_script", _SCRIPT_PATH)
assert _SPEC and _SPEC.loader
_SCRIPT = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SCRIPT)


class TestFromYearArgparse(unittest.TestCase):
    def test_parse_from_year_validation(self) -> None:
        self.assertEqual(_SCRIPT._parse_from_year("0"), 0)
        self.assertEqual(_SCRIPT._parse_from_year("2025"), 2025)

        with self.assertRaisesRegex(Exception, ">= 0"):
            _SCRIPT._parse_from_year("-1")

        with self.assertRaisesRegex(Exception, "must be <= "):
            _SCRIPT._parse_from_year(str(_SCRIPT.date.today().year + 2))

        with self.assertRaisesRegex(Exception, "must be an integer"):
            _SCRIPT._parse_from_year("nope")


class TestFromYearFiltering(unittest.TestCase):
    def test_skip_log_includes_from_year_and_year(self) -> None:
        with TemporaryDirectory() as temp_dir:
            templates_dir = Path(temp_dir)
            (templates_dir / "cves.json").write_text(
                '\n'.join(
                    [
                        '{"ID":"CVE-2024-0001","file_path":"http/cves/2024/CVE-2024-0001.yaml"}',
                        '{"ID":"CVE-2025-0002","file_path":"http/cves/2025/CVE-2025-0002.yaml"}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            old_env = os.environ.copy()
            try:
                os.environ["OPENAI_BASE_URL"] = "http://example.invalid"
                os.environ["OPENAI_API_KEY"] = "dummy"
                os.environ["OPENAI_MODEL"] = "dummy"

                stderr = io.StringIO()
                with contextlib.redirect_stderr(stderr):
                    rc = _SCRIPT.main(
                        [
                            "--from-year",
                            "2025",
                            "--templates-dir",
                            str(templates_dir),
                            "--reports-dir",
                            str(templates_dir / "reports"),
                        ]
                    )
                self.assertEqual(rc, 0)

                out = stderr.getvalue()
                self.assertIn("event=skip", out)
                self.assertIn("reason=\"from_year\"", out)
                self.assertIn("from_year=2025", out)
                self.assertIn("year=2024", out)
            finally:
                os.environ.clear()
                os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()

