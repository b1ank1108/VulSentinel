import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cve_poc_llm_reports.cves_jsonl import CvesJsonlLineError, iter_cves_jsonl


class TestIterCvesJsonl(unittest.TestCase):
    def test_iter_yields_entries(self) -> None:
        with TemporaryDirectory() as temp_dir:
            templates_dir = Path(temp_dir)
            (templates_dir / "http/cves/2024").mkdir(parents=True)

            (templates_dir / "cves.json").write_text(
                '\n'.join(
                    [
                        '{"ID":"CVE-2024-0001","file_path":"http/cves/2024/CVE-2024-0001.yaml"}',
                        '{"ID":"CVE-2025-9999","file_path":"http/cves/2024/CVE-2025-9999.yaml"}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            items = list(iter_cves_jsonl(templates_dir=templates_dir))
            self.assertEqual([i.id for i in items], ["CVE-2024-0001", "CVE-2025-9999"])
            self.assertEqual([i.year for i in items], [2024, 2025])
            self.assertTrue(items[0].template_path.is_absolute())
            self.assertEqual(items[0].line_number, 1)

    def test_iter_reports_errors_and_continues(self) -> None:
        with TemporaryDirectory() as temp_dir:
            templates_dir = Path(temp_dir)
            (templates_dir / "http/cves/2024").mkdir(parents=True)

            (templates_dir / "cves.json").write_text(
                '\n'.join(
                    [
                        '{"ID":"CVE-2024-0001","file_path":"http/cves/2024/CVE-2024-0001.yaml"}',
                        '{"ID":"CVE-2024-0002","file_path":"../escape.yaml"}',
                        '{"ID":"CVE-2024-0003","file_path":"http/cves/2024/CVE-2024-0003.yaml"}',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )

            errors = []

            def on_error(err: CvesJsonlLineError) -> None:
                errors.append(err)

            items = list(iter_cves_jsonl(templates_dir=templates_dir, on_error=on_error))
            self.assertEqual([i.id for i in items], ["CVE-2024-0001", "CVE-2024-0003"])
            self.assertEqual(len(errors), 1)
            self.assertEqual(errors[0].line_number, 2)
            self.assertIn("escapes templates_dir", errors[0].message)

    def test_iter_raises_with_line_number_and_excerpt(self) -> None:
        with TemporaryDirectory() as temp_dir:
            templates_dir = Path(temp_dir)
            (templates_dir / "cves.json").write_text("not-json\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, r":1: .*excerpt="):
                next(iter_cves_jsonl(templates_dir=templates_dir))


if __name__ == "__main__":
    unittest.main()

