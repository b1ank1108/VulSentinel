from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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
    return base_url.rstrip("/") + "/v1/chat/completions"


def post_chat_completions(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: Sequence[Mapping[str, Any]],
    timeout_seconds: int = _DEFAULT_TIMEOUT_SECONDS,
    extra_body: Optional[Mapping[str, Any]] = None,
) -> Mapping[str, Any]:
    url = build_chat_completions_url(base_url)
    body: dict[str, Any] = {"model": model, "messages": list(messages)}
    if extra_body:
        body.update(extra_body)

    data = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = Request(
        url=url,
        method="POST",
        data=data,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
    )
    with urlopen(request, timeout=timeout_seconds) as response:
        raw = response.read()
    return json.loads(raw)


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
            )
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
