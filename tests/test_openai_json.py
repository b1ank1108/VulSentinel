import unittest
from unittest.mock import MagicMock, patch

import httpx
from openai import BadRequestError

from cve_poc_llm_reports.openai_json import ChatJsonError, post_chat_completions_json


class TestOpenAIJson(unittest.TestCase):
    def _bad_request(self, *, message: str, body: object) -> BadRequestError:
        request = httpx.Request("POST", "http://example.invalid/v1/chat/completions")
        response = httpx.Response(status_code=400, request=request)
        return BadRequestError(message, response=response, body=body)

    @patch("cve_poc_llm_reports.openai_chat.OpenAI")
    def test_prefers_response_format_when_supported(self, openai_client_cls: MagicMock) -> None:
        completion = MagicMock()
        completion.model_dump.return_value = {"choices": [{"message": {"content": "{\"ok\":true}"}}]}

        client = MagicMock()
        client.chat.completions.create.return_value = completion
        openai_client_cls.return_value = client

        result = post_chat_completions_json(
            base_url="http://example.invalid/v1",
            api_key="k",
            model="m",
            messages=[{"role": "user", "content": "hi"}],
            timeout_seconds=3,
        )
        self.assertEqual(result.data, {"ok": True})

        openai_client_cls.assert_called_once_with(
            api_key="k",
            base_url="http://example.invalid/v1",
            timeout=3.0,
        )
        client.chat.completions.create.assert_called_once()
        _, kwargs = client.chat.completions.create.call_args
        self.assertEqual(kwargs["model"], "m")
        self.assertEqual(kwargs["extra_body"], {"response_format": {"type": "json_object"}})
        self.assertTrue(any("json" in str(m.get("content", "")).lower() for m in kwargs["messages"]))

    @patch("cve_poc_llm_reports.openai_chat.OpenAI")
    def test_fallback_when_response_format_rejected(self, openai_client_cls: MagicMock) -> None:
        completion = MagicMock()
        completion.model_dump.return_value = {"choices": [{"message": {"content": "{\"ok\":true}"}}]}

        client = MagicMock()
        client.chat.completions.create.side_effect = [
            self._bad_request(
                message="response_format rejected",
                body={"error": {"message": "response_format rejected"}},
            ),
            completion,
        ]
        openai_client_cls.return_value = client

        result = post_chat_completions_json(
            base_url="http://example.invalid/v1",
            api_key="k",
            model="m",
            messages=[{"role": "user", "content": "hi"}],
            timeout_seconds=3,
        )
        self.assertEqual(result.data, {"ok": True})

        self.assertEqual(openai_client_cls.call_count, 2)
        self.assertEqual(client.chat.completions.create.call_count, 2)

        first_kwargs = client.chat.completions.create.call_args_list[0][1]
        self.assertEqual(first_kwargs["extra_body"], {"response_format": {"type": "json_object"}})
        self.assertTrue(any("json" in str(m.get("content", "")).lower() for m in first_kwargs["messages"]))

        second_kwargs = client.chat.completions.create.call_args_list[1][1]
        self.assertIsNone(second_kwargs["extra_body"])
        self.assertEqual(second_kwargs["messages"][0]["role"], "system")
        self.assertIn("json", str(second_kwargs["messages"][0].get("content", "")).lower())

    @patch("cve_poc_llm_reports.openai_chat.OpenAI")
    def test_raises_when_both_attempts_fail(self, openai_client_cls: MagicMock) -> None:
        completion = MagicMock()
        completion.model_dump.return_value = {"choices": [{"message": {"content": "not-json"}}]}

        client = MagicMock()
        client.chat.completions.create.side_effect = [
            self._bad_request(
                message="response_format rejected",
                body={"error": {"message": "response_format rejected"}},
            ),
            completion,
        ]
        openai_client_cls.return_value = client

        with self.assertRaises(ChatJsonError) as ctx:
            post_chat_completions_json(
                base_url="http://example.invalid/v1",
                api_key="k",
                model="m",
                messages=[{"role": "user", "content": "hi"}],
                timeout_seconds=3,
            )
        self.assertIn("content_excerpt", str(ctx.exception))
        self.assertIn("not-json", str(ctx.exception))

        self.assertEqual(openai_client_cls.call_count, 2)
        self.assertEqual(client.chat.completions.create.call_count, 2)

    @patch("cve_poc_llm_reports.openai_chat.OpenAI")
    def test_does_not_fallback_on_other_400(self, openai_client_cls: MagicMock) -> None:
        client = MagicMock()
        client.chat.completions.create.side_effect = [
            self._bad_request(
                message="invalid request",
                body={"error": {"message": "model not found"}},
            ),
        ]
        openai_client_cls.return_value = client

        with self.assertRaises(ChatJsonError):
            post_chat_completions_json(
                base_url="http://example.invalid/v1",
                api_key="k",
                model="m",
                messages=[{"role": "user", "content": "hi"}],
                timeout_seconds=3,
            )

        self.assertEqual(openai_client_cls.call_count, 1)
        self.assertEqual(client.chat.completions.create.call_count, 1)


if __name__ == "__main__":
    unittest.main()
