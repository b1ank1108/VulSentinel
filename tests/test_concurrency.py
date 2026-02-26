import contextlib
import io
import os
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from cve_poc_llm_reports.cli import main as cli_main


class TestConcurrency(unittest.TestCase):
    @patch("cve_poc_llm_reports.cli._process_one")
    def test_concurrent_processing_faster_than_sequential(self, proc_mock: MagicMock) -> None:
        def slow_generate(entry, templates_dir, model, client):  # noqa: ANN001
            time.sleep(0.1)
            return f"---\ncve_id: {entry.id}\n---\n# {entry.id}\n\nok\n"

        proc_mock.side_effect = slow_generate

        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            templates_dir = root / "templates"
            reports_dir = root / "reports"
            templates_dir.mkdir(parents=True)
            reports_dir.mkdir(parents=True)

            lines = []
            for i in range(1, 9):
                cve_id = f"CVE-2025-{i:04d}"
                lines.append(f'{{"ID":"{cve_id}","file_path":"http/cves/2025/{cve_id}.yaml"}}')
            (templates_dir / "cves.json").write_text("\n".join(lines) + "\n", encoding="utf-8")

            old_env = os.environ.copy()
            try:
                os.environ["OPENAI_BASE_URL"] = "http://example.invalid/v1"
                os.environ["OPENAI_API_KEY"] = "dummy"
                os.environ["OPENAI_MODEL"] = "dummy"
                os.environ["VULSENTINEL_CONCURRENCY"] = "4"

                stderr = io.StringIO()
                start = time.monotonic()
                with contextlib.redirect_stderr(stderr):
                    rc = cli_main(
                        [
                            "--templates-dir",
                            str(templates_dir),
                            "--reports-dir",
                            str(reports_dir),
                        ],
                        prog="test",
                        include_openai_overrides=False,
                        repo_root=root,
                    )
                elapsed = time.monotonic() - start

                self.assertEqual(rc, 0)
                self.assertLess(elapsed, 0.5)

                out = stderr.getvalue()
                self.assertIn("succeeded=8", out)

                for i in range(1, 9):
                    cve_id = f"CVE-2025-{i:04d}"
                    report_path = reports_dir / "http" / "cves" / "2025" / f"{cve_id}.md"
                    self.assertTrue(report_path.exists(), f"Missing report for {cve_id}")

                index_path = reports_dir / "cves.jsonl"
                self.assertTrue(index_path.exists())
                index_lines = index_path.read_text(encoding="utf-8").strip().splitlines()
                self.assertEqual(len(index_lines), 8)
            finally:
                os.environ.clear()
                os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()
