from __future__ import annotations

from typing import Any, Mapping

_REQUIRED_SIGNAL_KEYS = (
    "severity",
    "auth_requirement",
    "oast_required",
    "version_constraints",
    "feature_gates",
)


def build_report_markdown_prompt_messages(
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
        "Write an information-dense Markdown report for downstream risk assessment based ONLY on the nuclei template YAML.",
        "If uncertain, write 'unknown' instead of guessing.",
        "",
        "Output:",
        "- Return ONLY Markdown (no JSON).",
        "- Do NOT include a top-level title (the caller will add '# <CVE-ID>').",
        "",
        "Required sections:",
        "",
        "FORMATTING RULE: Use standard Markdown `##` headings for ALL section titles. Do NOT use bold (`**`) for section headings.",
        "",
        "## Signals",
        f"- Include exactly these keys: {', '.join(_REQUIRED_SIGNAL_KEYS)}",
        "- Format each signal as a plain '- key: value' line (no bold, no extra formatting).",
        "- severity: copy from info.severity",
        "- auth_requirement: whether the TEMPLATE ITSELF sends auth credentials (Authorization header, cookies, login step). "
        "Values: none / required / optional. This reflects the template's behavior, NOT the real-world vulnerability's auth requirement.",
        "- oast_required: true ONLY if the template uses {{interactsh-url}}, oob, or DNS/HTTP callback mechanisms. "
        "If no such mechanism is present, set to false. Never use 'unknown' for this field.",
        "- version_constraints: ONLY report ranges that the template ENFORCES via compare_versions() or equivalent DSL in its matchers. "
        "If the template has no version-checking logic in matchers, write 'unknown' even if info.description mentions version ranges.",
        "- feature_gates: conditions beyond version that must be true for exploitation. "
        "Examples: specific features enabled ('Git node enabled'), configurations ('guest ticket creation allowed'), deployment modes ('self-hosted'). "
        "Extract from info.description and template request patterns. Use [] only if truly no preconditions.",
        "",
        "## Vulnerability",
        "",
        "## PoC / Detection",
        "Classify the template into exactly ONE of these categories based on what it ACTUALLY DOES (not what the vulnerability could do):",
        "- detect-only: template only fingerprints/version-checks, sends no payload, creates no server-side state.",
        "- active-detect: template sends a probe that triggers the vuln condition but does not exfiltrate data or create persistent state (e.g. reflected XSS check).",
        "- exploit: template actively exploits the vuln: reads unauthorized data (SSRF/LFI), creates sessions (auth bypass), modifies state (password reset), or executes code.",
        "- intrusive: template has destructive side effects (password changes, data writes, account creation). Check for 'intrusive' in tags.",
        "Use the tags field as strong hints: 'passive' -> likely detect-only, 'intrusive' -> intrusive, 'auth-bypass' -> likely exploit or intrusive.",
        "State the classification clearly at the start of this section: 'Classification: <category>'.",
        "",
        "## References",
        "Include ONLY URLs listed in the template's info.reference field. Do NOT add, infer, or fabricate any other URLs.",
        "",
        "Consistency check: before finalizing, verify that if the PoC section describes state modification, auth bypass, data exfiltration, "
        "or destructive actions, the Vulnerability section does NOT call the template 'detect-only'.",
        "",
        "Do NOT include the full YAML in the output.",
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
