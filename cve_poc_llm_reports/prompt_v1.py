from __future__ import annotations

from typing import Any, Mapping

_SIGNALS_KEYS = (
    "severity",
    "exploit_vs_detect",
    "auth_requirement",
    "oast_required",
    "version_constraints",
    "feature_gates",
)


def build_signals_prompt_messages(
    *,
    cve_id: str,
    template_path: str,
    template_yaml: str,
    max_yaml_chars: int = 12_000,
    max_summary_lines: int = 40,
) -> list[Mapping[str, Any]]:
    excerpt, truncated = _truncate_middle(template_yaml, max_chars=max_yaml_chars)
    summary = _extract_yaml_summary(template_yaml, max_lines=max_summary_lines) if truncated else ""

    user_parts = [
        "Input:",
        f"- ID: {cve_id}",
        f"- template_path: {template_path}",
        f"- yaml_truncated: {str(truncated).lower()}",
        "",
        "Task:",
        "From the nuclei template YAML, infer result-only signals. If uncertain, use the 'unknown' enum values and empty arrays.",
        "",
        "Output:",
        "Return ONLY a single JSON object with exactly these keys:",
        f"- {', '.join(_SIGNALS_KEYS)}",
        "",
        "Enums:",
        "- exploit_vs_detect: exploit | detect | mixed | unknown",
        "- auth_requirement: none | optional | required | unknown",
        "",
        "Notes:",
        "- Do NOT output markdown or explanations.",
        "- Do NOT include evidence/line numbers. Only results.",
        "",
    ]
    if summary:
        user_parts.extend(
            [
                "YAML summary (best-effort, may be incomplete):",
                "```",
                summary,
                "```",
                "",
            ]
        )
    user_parts.extend(
        [
            "Template YAML:",
            "```",
            excerpt,
            "```",
        ]
    )

    return [
        {
            "role": "system",
            "content": "You are a security analyst. Follow the user's instructions strictly.",
        },
        {"role": "user", "content": "\n".join(user_parts)},
    ]


def _truncate_middle(text: str, *, max_chars: int) -> tuple[str, bool]:
    if max_chars <= 0:
        return ("", True)
    if len(text) <= max_chars:
        return (text, False)
    head = int(max_chars * 0.7)
    tail = max_chars - head
    return (text[:head] + "\n...(truncated)...\n" + text[-tail:], True)


def _extract_yaml_summary(text: str, *, max_lines: int) -> str:
    lines = text.splitlines()
    keep = []
    needles = (
        "id:",
        "name:",
        "severity:",
        "tags:",
        "description:",
        "reference",
        "cve-id",
        "classification",
        "metadata",
        "http:",
        "requests:",
        "flow:",
        "matchers:",
        "extractors:",
        "payloads:",
        "variables:",
        "interactsh",
        "oast",
        "version",
    )
    for line in lines:
        low = line.strip().lower()
        if any(n in low for n in needles):
            keep.append(line.rstrip())
        if len(keep) >= max_lines:
            break
    return "\n".join(keep)
