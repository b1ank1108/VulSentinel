import unittest

from cve_poc_llm_reports.prompt_v1 import build_signals_prompt_messages


class TestPromptV1(unittest.TestCase):
    def test_prompt_includes_id_path_and_yaml(self) -> None:
        msgs = build_signals_prompt_messages(
            cve_id="CVE-2025-0001",
            template_path="nuclei-templates/http/cves/2025/CVE-2025-0001.yaml",
            template_yaml="id: test\ninfo:\n  severity: high\n",
            max_yaml_chars=10_000,
        )
        self.assertEqual(msgs[0]["role"], "system")
        self.assertEqual(msgs[1]["role"], "user")
        content = msgs[1]["content"]
        self.assertIn("CVE-2025-0001", content)
        self.assertIn("nuclei-templates/http/cves/2025/CVE-2025-0001.yaml", content)
        self.assertIn("id: test", content)
        self.assertIn("Return ONLY a single JSON object", content)

    def test_prompt_truncates_long_yaml(self) -> None:
        long_yaml = "a" * 2000
        msgs = build_signals_prompt_messages(
            cve_id="CVE-2025-0001",
            template_path="nuclei-templates/http/cves/2025/CVE-2025-0001.yaml",
            template_yaml=long_yaml,
            max_yaml_chars=200,
        )
        content = msgs[1]["content"]
        self.assertIn("yaml_truncated: true", content)
        self.assertIn("...(truncated)...", content)


if __name__ == "__main__":
    unittest.main()

