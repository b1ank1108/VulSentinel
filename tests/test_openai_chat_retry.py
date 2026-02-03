import unittest
from urllib.error import HTTPError
from unittest.mock import MagicMock, patch

from cve_poc_llm_reports.openai_chat import ChatRequestError, post_chat_completions_with_retry


class TestOpenAIChatRetry(unittest.TestCase):
    @patch("cve_poc_llm_reports.openai_chat.post_chat_completions")
    def test_retries_on_retryable_http_status(self, post_mock: MagicMock) -> None:
        post_mock.side_effect = [
            HTTPError("url", 500, "server error", {}, None),
            {"ok": True},
        ]

        delays = []

        out = post_chat_completions_with_retry(
            base_url="http://example.invalid",
            api_key="k",
            model="m",
            messages=[{"role": "user", "content": "hi"}],
            timeout_seconds=1,
            max_attempts=3,
            base_backoff_seconds=0.5,
            jitter_seconds=0.0,
            sleep=delays.append,
        )
        self.assertEqual(out, {"ok": True})
        self.assertEqual(post_mock.call_count, 2)
        self.assertEqual(delays, [0.5])

    @patch("cve_poc_llm_reports.openai_chat.post_chat_completions")
    def test_does_not_retry_on_400(self, post_mock: MagicMock) -> None:
        post_mock.side_effect = [HTTPError("url", 400, "bad request", {}, None)]

        with self.assertRaises(HTTPError):
            post_chat_completions_with_retry(
                base_url="http://example.invalid",
                api_key="k",
                model="m",
                messages=[{"role": "user", "content": "hi"}],
                timeout_seconds=1,
                max_attempts=3,
                jitter_seconds=0.0,
                sleep=lambda _: None,
            )

        self.assertEqual(post_mock.call_count, 1)

    @patch("cve_poc_llm_reports.openai_chat.post_chat_completions")
    def test_raises_structured_error_after_max_attempts(self, post_mock: MagicMock) -> None:
        post_mock.side_effect = [
            HTTPError("url", 503, "unavailable", {}, None),
            HTTPError("url", 503, "unavailable", {}, None),
        ]

        with self.assertRaises(ChatRequestError) as ctx:
            post_chat_completions_with_retry(
                base_url="http://example.invalid",
                api_key="k",
                model="m",
                messages=[{"role": "user", "content": "hi"}],
                timeout_seconds=1,
                max_attempts=2,
                base_backoff_seconds=0.0,
                jitter_seconds=0.0,
                sleep=lambda _: None,
            )

        err = ctx.exception
        self.assertEqual(len(err.attempts), 2)
        self.assertEqual(err.attempts[-1].status_code, 503)


if __name__ == "__main__":
    unittest.main()

