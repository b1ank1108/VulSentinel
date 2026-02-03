import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cve_poc_llm_reports.index_jsonl import append_report_index_entry


class TestIndexJsonl(unittest.TestCase):
    def test_append_report_index_entry_appends_jsonl(self) -> None:
        with TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            index_path = root / "reports/cves.jsonl"
            append_report_index_entry(
                index_path=index_path,
                cve_id="CVE-2025-0001",
                report_path="reports/http/cves/2025/CVE-2025-0001.md",
            )
            append_report_index_entry(
                index_path=index_path,
                cve_id="CVE-2025-0002",
                report_path="reports/http/cves/2025/CVE-2025-0002.md",
            )

            lines = index_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            self.assertEqual(json.loads(lines[0])["ID"], "CVE-2025-0001")
            self.assertEqual(json.loads(lines[1])["ID"], "CVE-2025-0002")


if __name__ == "__main__":
    unittest.main()
