from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from openai import OpenAI


def _stream_chat_content(
    *,
    client: OpenAI,
    model: str,
    messages: Sequence[Mapping[str, Any]],
) -> str:
    stream = client.chat.completions.create(
        model=model,
        messages=messages,
        stream=True,
    )
    chunks: list[str] = []
    for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content:
            chunks.append(chunk.choices[0].delta.content)
    return "".join(chunks)


@dataclass(frozen=True)
class ChatTextResult:
    content: str


def post_chat_completions_text(
    *,
    model: str,
    messages: Sequence[Mapping[str, Any]],
    client: OpenAI,
) -> ChatTextResult:
    content = _stream_chat_content(client=client, model=model, messages=messages)
    if content.strip() == "":
        raise ValueError("assistant content must be non-empty")
    return ChatTextResult(content=content)
