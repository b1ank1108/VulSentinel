import unittest
from unittest.mock import MagicMock, patch

from cve_poc_llm_reports.openai_chat import build_chat_completions_url, post_chat_completions


class TestOpenAIChat(unittest.TestCase):
    def test_build_chat_completions_url_normalizes_slash(self) -> None:
        self.assertEqual(
            build_chat_completions_url("http://example.invalid/v1/"),
            "http://example.invalid/v1/chat/completions",
        )
        self.assertEqual(
            build_chat_completions_url("http://example.invalid/v1"),
            "http://example.invalid/v1/chat/completions",
        )

    @patch("cve_poc_llm_reports.openai_chat.OpenAI")
    def test_post_chat_completions_calls_sdk(self, openai_client_cls: MagicMock) -> None:
        completion = MagicMock()
        completion.model_dump.return_value = {
            "id": "cmpl-1",
            "choices": [{"message": {"content": "ok"}}],
        }
        client = MagicMock()
        client.chat.completions.create.return_value = completion
        openai_client_cls.return_value = client

        messages = [{"role": "user", "content": "hello"}]
        out = post_chat_completions(
            base_url="http://example.invalid/v1/",
            api_key="secret",
            model="gpt-test",
            messages=messages,
            timeout_seconds=5,
        )
        self.assertEqual(out["id"], "cmpl-1")

        openai_client_cls.assert_called_once_with(
            api_key="secret",
            base_url="http://example.invalid/v1/",
            timeout=5.0,
        )
        client.chat.completions.create.assert_called_once_with(
            model="gpt-test",
            messages=messages,
            extra_body=None,
        )


if __name__ == "__main__":
    unittest.main()
