from __future__ import annotations

import json
from typing import Any, Mapping, Optional, Sequence
from urllib.request import Request, urlopen

_DEFAULT_TIMEOUT_SECONDS = 30


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

