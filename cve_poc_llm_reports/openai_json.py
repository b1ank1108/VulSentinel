from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence
from openai import APIStatusError

from cve_poc_llm_reports.openai_chat import post_chat_completions_with_retry


@dataclass(frozen=True)
class ChatJsonResult:
    data: Any
    raw_response: Mapping[str, Any]


class ChatJsonError(RuntimeError):
    def __init__(self, message: str, *, causes: Sequence[BaseException]):
        super().__init__(message)
        self.causes = list(causes)


def post_chat_completions_json(
    *,
    base_url: str,
    api_key: str,
    model: str,
    messages: Sequence[Mapping[str, Any]],
    timeout_seconds: int,
    response_format_preferred: bool = True,
    max_attempts: int = 3,
) -> ChatJsonResult:
    errors: list[str] = []
    causes: list[BaseException] = []
    messages_with_json = _ensure_json_keyword(messages)

    should_fallback = not response_format_preferred
    if response_format_preferred:
        try:
            response = post_chat_completions_with_retry(
                base_url=base_url,
                api_key=api_key,
                model=model,
                messages=messages_with_json,
                timeout_seconds=timeout_seconds,
                extra_body={"response_format": {"type": "json_object"}},
                max_attempts=max_attempts,
            )
            return _parse_chat_json_response(response)
        except Exception as e:  # noqa: BLE001
            causes.append(e)
            if _is_response_format_rejected_400(e):
                errors.append("response_format rejected: HTTP 400")
                should_fallback = True
            else:
                errors.append(f"response_format failed: {e}")
                raise ChatJsonError("; ".join(errors), causes=causes) from e

    if should_fallback:
        try:
            response = post_chat_completions_with_retry(
                base_url=base_url,
                api_key=api_key,
                model=model,
                messages=_with_force_json_system_prompt(messages_with_json),
                timeout_seconds=timeout_seconds,
                extra_body=None,
                max_attempts=max_attempts,
            )
            return _parse_chat_json_response(response)
        except Exception as e:  # noqa: BLE001
            errors.append(f"fallback parse failed: {e}")
            causes.append(e)

    raise ChatJsonError("; ".join(errors), causes=causes)


def _with_force_json_system_prompt(messages: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    prefix = {
        "role": "system",
        "content": "Return ONLY a valid json object. No markdown, no extra text.",
    }
    return [prefix, *messages]


def _ensure_json_keyword(messages: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    for message in messages:
        content = message.get("content")
        if isinstance(content, str) and "json" in content.lower():
            return list(messages)
    return [
        {
            "role": "system",
            "content": "Return a valid json object.",
        },
        *messages,
    ]


def _is_response_format_rejected_400(error: BaseException) -> bool:
    if not isinstance(error, APIStatusError) or error.status_code != 400:
        return False

    message = ""
    if getattr(error, "message", None):
        message += str(error.message)
    if getattr(error, "body", None) is not None:
        message += " " + str(error.body)
    low = message.lower()
    return ("response_format" in low) or ("response format" in low)


def _parse_chat_json_response(response: Mapping[str, Any]) -> ChatJsonResult:
    content = _extract_first_choice_content(response)
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        raise ValueError(f"assistant content is not valid JSON: {e}") from e
    return ChatJsonResult(data=data, raw_response=response)


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
    return content.strip()
