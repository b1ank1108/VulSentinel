import unittest
from unittest.mock import MagicMock, call, patch

import httpx
from openai import BadRequestError

from cve_poc_llm_reports.openai_json import ChatJsonError, post_chat_completions_json


class TestOpenAIJson(unittest.TestCase):
    def _bad_request(self, *, message: str, body: object) -> BadRequestError:
        request = httpx.Request("POST", "http://example.invalid/v1/chat/completions")
        response = httpx.Response(status_code=400, request=request)
        return BadRequestError(message, response=response, body=body)

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
            self._bad_request(
                message="response_format rejected",
                body={"error": {"message": "response_format rejected"}},
            ),
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
            self._bad_request(
                message="response_format rejected",
                body={"error": {"message": "response_format rejected"}},
            ),
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

    @patch("cve_poc_llm_reports.openai_json.post_chat_completions_with_retry")
    def test_does_not_fallback_on_other_400(self, post_mock: MagicMock) -> None:
        post_mock.side_effect = [
            self._bad_request(
                message="invalid request",
                body={"error": {"message": "model not found"}},
            ),
        ]

        with self.assertRaises(ChatJsonError):
            post_chat_completions_json(
                base_url="http://example.invalid",
                api_key="k",
                model="m",
                messages=[{"role": "user", "content": "hi"}],
                timeout_seconds=3,
            )

        self.assertEqual(post_mock.call_count, 1)


if __name__ == "__main__":
    unittest.main()
