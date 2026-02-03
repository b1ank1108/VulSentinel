import unittest
from urllib.error import HTTPError
from unittest.mock import MagicMock, call, patch

from cve_poc_llm_reports.openai_json import ChatJsonError, post_chat_completions_json


class TestOpenAIJson(unittest.TestCase):
    @patch("cve_poc_llm_reports.openai_json.post_chat_completions_with_retry")
    def test_prefers_response_format_when_supported(self, post_mock: MagicMock) -> None:
        post_mock.return_value = {
            "choices": [{"message": {"content": "{\"ok\":true}"}}],
        }

        result = post_chat_completions_json(
            base_url="http://example.invalid",
            api_key="k",
            model="m",
            messages=[{"role": "user", "content": "hi"}],
            timeout_seconds=3,
        )
        self.assertEqual(result.data, {"ok": True})

        post_mock.assert_called_once()
        _, kwargs = post_mock.call_args
        self.assertEqual(kwargs["extra_body"], {"response_format": {"type": "json_object"}})

    @patch("cve_poc_llm_reports.openai_json.post_chat_completions_with_retry")
    def test_fallback_when_response_format_rejected(self, post_mock: MagicMock) -> None:
        post_mock.side_effect = [
            HTTPError("url", 400, "bad request", {}, None),
            {"choices": [{"message": {"content": "{\"ok\":true}"}}]},
        ]

        result = post_chat_completions_json(
            base_url="http://example.invalid",
            api_key="k",
            model="m",
            messages=[{"role": "user", "content": "hi"}],
            timeout_seconds=3,
        )
        self.assertEqual(result.data, {"ok": True})

        self.assertEqual(post_mock.call_count, 2)
        self.assertEqual(
            post_mock.mock_calls[0],
            call(
                base_url="http://example.invalid",
                api_key="k",
                model="m",
                messages=[
                    {"role": "system", "content": "Return a valid json object."},
                    {"role": "user", "content": "hi"},
                ],
                timeout_seconds=3,
                extra_body={"response_format": {"type": "json_object"}},
                max_attempts=3,
            ),
        )
        fallback_kwargs = post_mock.call_args_list[1][1]
        self.assertIsNone(fallback_kwargs["extra_body"])
        self.assertEqual(fallback_kwargs["messages"][0]["role"], "system")

    @patch("cve_poc_llm_reports.openai_json.post_chat_completions_with_retry")
    def test_raises_when_both_attempts_fail(self, post_mock: MagicMock) -> None:
        post_mock.side_effect = [
            HTTPError("url", 400, "bad request", {}, None),
            {"choices": [{"message": {"content": "not-json"}}]},
        ]

        with self.assertRaises(ChatJsonError):
            post_chat_completions_json(
                base_url="http://example.invalid",
                api_key="k",
                model="m",
                messages=[{"role": "user", "content": "hi"}],
                timeout_seconds=3,
            )


if __name__ == "__main__":
    unittest.main()
