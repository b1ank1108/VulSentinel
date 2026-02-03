import contextlib
import io
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cve_poc_llm_reports.cli import main as cli_main


class TestDotenvPrecedence(unittest.TestCase):
    def test_os_env_overrides_dotenv(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            (root / ".env").write_text(
                "\n".join(
                    [
                        "OPENAI_BASE_URL=http://dotenv.example/v1",
                        "OPENAI_API_KEY=dotenv-secret",
                        "OPENAI_MODEL=dotenv-model",
                        "",
                    ]
                ),
                encoding="utf-8",
            )

            templates_dir = root / "templates"
            reports_dir = root / "reports"
            templates_dir.mkdir(parents=True)
            reports_dir.mkdir(parents=True)
            (templates_dir / "cves.json").write_text("", encoding="utf-8")

            old_env = os.environ.copy()
            try:
                os.environ["OPENAI_BASE_URL"] = "http://os.example/v1"
                os.environ["OPENAI_API_KEY"] = "os-secret"
                os.environ["OPENAI_MODEL"] = "os-model"

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

                out = stderr.getvalue()
                self.assertIn('base_url="http://os.example/v1"', out)
                self.assertIn('model="os-model"', out)
                self.assertNotIn("dotenv.example", out)
                self.assertNotIn("dotenv-model", out)
            finally:
                os.environ.clear()
                os.environ.update(old_env)


if __name__ == "__main__":
    unittest.main()

