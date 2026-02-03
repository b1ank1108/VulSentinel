from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from cve_poc_llm_reports.openai_chat import post_chat_completions_with_retry


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
) -> ChatTextResult:
    response = post_chat_completions_with_retry(
        base_url=base_url,
        api_key=api_key,
        model=model,
        messages=messages,
        timeout_seconds=timeout_seconds,
        extra_body=None,
        max_attempts=max_attempts,
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
