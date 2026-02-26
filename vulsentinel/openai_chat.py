from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.error import HTTPError, URLError

from openai import APIStatusError, OpenAI

_DEFAULT_TIMEOUT_SECONDS = 30
_MAX_ERROR_EXCERPT_CHARS = 200
_RETRYABLE_HTTP_STATUS = {408, 429, 500, 502, 503, 504}


@dataclass(frozen=True)
class ChatRequestAttemptError:
    attempt: int
    error_type: str
    message: str
    status_code: Optional[int] = None
    response_excerpt: Optional[str] = None


class ChatRequestError(RuntimeError):
    def __init__(self, attempts: Sequence[ChatRequestAttemptError]):
        self.attempts = list(attempts)
        last = self.attempts[-1] if self.attempts else None
        super().__init__(last.message if last else "chat request failed")


def build_chat_completions_url(base_url: str) -> str:
    return base_url.rstrip("/") + "/chat/completions"


def post_chat_completions(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: Sequence[Mapping[str, Any]],
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    extra_body: Optional[Mapping[str, Any]] = None,
    client: Optional[OpenAI] = None,
) -> Mapping[str, Any]:
    if client is None:
        client = OpenAI(api_key=api_key, base_url=base_url, timeout=float(timeout_seconds))
    completion = client.chat.completions.create(
        model=model,
        messages=messages,
        extra_body=dict(extra_body) if extra_body else None,
    )
    return completion.model_dump()


def post_chat_completions_with_retry(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: Sequence[Mapping[str, Any]],
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    extra_body: Optional[Mapping[str, Any]] = None,
    max_attempts: int = 3,
    base_backoff_seconds: float = 0.5,
    max_backoff_seconds: float = 4.0,
    jitter_seconds: float = 0.1,
    sleep: Callable[[float], None] = time.sleep,
    client: Optional[OpenAI] = None,
) -> Mapping[str, Any]:
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")

    attempts: list[ChatRequestAttemptError] = []
    for attempt in range(1, max_attempts + 1):
        try:
            return post_chat_completions(
                base_url=base_url,
                api_key=api_key,
                model=model,
                messages=messages,
                timeout_seconds=timeout_seconds,
                extra_body=extra_body,
                client=client,
            )
        except APIStatusError as e:
            if e.status_code not in _RETRYABLE_HTTP_STATUS:
                raise
            excerpt = None
            if e.body is not None:
                excerpt = str(e.body)[:_MAX_ERROR_EXCERPT_CHARS]
            attempts.append(
                ChatRequestAttemptError(
                    attempt=attempt,
                    error_type="api_status",
                    status_code=e.status_code,
                    message=f"HTTP {e.status_code}",
                    response_excerpt=excerpt,
                )
            )
            last_exc = e
        except HTTPError as e:
            if e.code not in _RETRYABLE_HTTP_STATUS:
                raise
            attempts.append(_summarize_http_error(attempt, e))
            last_exc: Exception = e
        except URLError as e:
            attempts.append(ChatRequestAttemptError(attempt=attempt, error_type="url_error", message=str(e)))
            last_exc = e
        except TimeoutError as e:
            attempts.append(ChatRequestAttemptError(attempt=attempt, error_type="timeout", message=str(e)))
            last_exc = e
        except Exception as e:  # noqa: BLE001
            attempts.append(ChatRequestAttemptError(attempt=attempt, error_type="error", message=str(e)))
            last_exc = e

        if attempt >= max_attempts:
            raise ChatRequestError(attempts) from last_exc

        backoff = min(max_backoff_seconds, base_backoff_seconds * (2 ** (attempt - 1)))
        delay = max(0.0, backoff + random.uniform(0.0, jitter_seconds))
        sleep(delay)

    raise ChatRequestError(attempts)


def _summarize_http_error(attempt: int, error: HTTPError) -> ChatRequestAttemptError:
    excerpt = None
    try:
        raw = error.read(_MAX_ERROR_EXCERPT_CHARS)
        excerpt = raw.decode("utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        excerpt = None
    return ChatRequestAttemptError(
        attempt=attempt,
        error_type="http_error",
        status_code=error.code,
        message=f"HTTP {error.code}: {error.reason}",
        response_excerpt=excerpt,
    )


@dataclass(frozen=True)
class ChatTextResult:
    content: str
    raw_response: Mapping[str, Any]


def post_chat_completions_text(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: Sequence[Mapping[str, Any]],
    timeout_seconds: int,
    max_attempts: int = 3,
    client: Optional[object] = None,
) -> ChatTextResult:
    response = post_chat_completions_with_retry(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=messages,
        timeout_seconds=timeout_seconds,
        extra_body=None,
        max_attempts=max_attempts,
        client=client,
    )
    return _parse_chat_text_response(response)


def _parse_chat_text_response(response: Mapping[str, Any]) -> ChatTextResult:
    content = _extract_first_choice_content(response)
    if content.strip() == "":
        raise ValueError("assistant content must be non-empty")
    return ChatTextResult(content=content, raw_response=response)


def _extract_first_choice_content(response: Mapping[str, Any]) -> str:
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("missing choices[0] in chat response")
    choice0 = choices[0]
    if not isinstance(choice0, Mapping):
        raise ValueError("invalid choices[0] type")
    message = choice0.get("message")
    if not isinstance(message, Mapping):
        raise ValueError("missing choices[0].message in chat response")
    content = message.get("content")
    if content is None:
        raise ValueError("missing choices[0].message.content in chat response")
    if not isinstance(content, str):
        raise ValueError("choices[0].message.content must be a string")
    return content
