import json
import unittest
from unittest.mock import MagicMock, patch

from cve_poc_llm_reports.openai_chat import build_chat_completions_url, post_chat_completions


class TestOpenAIChat(unittest.TestCase):
    def test_build_chat_completions_url_normalizes_slash(self) -> None:
        self.assertEqual(
            build_chat_completions_url("http://example.invalid/"),
            "http://example.invalid/v1/chat/completions",
        )
        self.assertEqual(
            build_chat_completions_url("http://example.invalid"),
            "http://example.invalid/v1/chat/completions",
        )

    @patch("cve_poc_llm_reports.openai_chat.urlopen")
    def test_post_chat_completions_builds_request(self, urlopen_mock: MagicMock) -> None:
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"id":"cmpl-1","choices":[{"message":{"content":"ok"}}]}'
        urlopen_mock.return_value = response

        out = post_chat_completions(
            base_url="http://example.invalid/",
            api_key="secret",
            model="gpt-test",
            messages=[{"role": "user", "content": "hello"}],
            timeout_seconds=5,
        )
        self.assertEqual(out["id"], "cmpl-1")

        (req,), kwargs = urlopen_mock.call_args
        self.assertEqual(req.full_url, "http://example.invalid/v1/chat/completions")
        self.assertEqual(kwargs, {"timeout": 5})

        headers = dict(req.header_items())
        self.assertEqual(headers["Content-type"], "application/json")
        self.assertEqual(headers["Authorization"], "Bearer secret")

        body = json.loads(req.data.decode("utf-8"))
        self.assertEqual(body["model"], "gpt-test")
        self.assertEqual(body["messages"][0]["content"], "hello")


if __name__ == "__main__":
    unittest.main()

