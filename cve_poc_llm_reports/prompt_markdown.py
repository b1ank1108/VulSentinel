from __future__ import annotations

from typing import Any, Mapping

_REQUIRED_SIGNAL_KEYS = (
    "affected_product",
    "severity",
    "authentication",
    "external_callback",
    "affected_versions",
    "preconditions",
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
        "Signal keys:",
        f"- Include exactly these keys: {', '.join(_REQUIRED_SIGNAL_KEYS)}",
        "- affected_product: the name of the affected software product or component. "
        "Extract from info.name, stripping any prefix like 'CVE-YYYY-NNNNN -'. "
        "Examples: 'n8n', 'Mailpit', 'SmarterMail', 'WordPress modular-connector plugin'.",
        "- severity: copy from info.severity",
        "- authentication: whether the vulnerability requires authentication to exploit. "
        "Values: none / required / optional. Determine from the template's request patterns: "
        "does it send credentials (Authorization header, cookies, login step)? If yes, the vuln likely requires auth.",
        "- external_callback: whether exploiting this vulnerability requires the attacker to receive "
        "out-of-band callbacks (e.g. DNS/HTTP requests to an attacker-controlled server). "
        "true if the template uses interactsh-url, OOB, or DNS/HTTP callback mechanisms; false otherwise.",
        "- affected_versions: version range affected by this vulnerability. "
        "ONLY report ranges that the template ENFORCES via compare_versions() or equivalent DSL in its matchers. "
        "If the template has no version-checking logic in matchers, write 'unknown' even if info.description mentions version ranges.",
        "- preconditions: conditions beyond version that must be true for exploitation. "
        "Examples: specific features enabled ('Git node enabled'), configurations ('guest ticket creation allowed'), deployment modes ('self-hosted'). "
        "Extract from info.description and template request patterns. Use [] only if truly no preconditions.",
        "",
        "Output the signal values at the very start of your response in this exact format (one per line, no section heading):",
        "```signals",
        "- affected_product: <value>",
        "- severity: <value>",
        "- authentication: <value>",
        "- external_callback: <value>",
        "- affected_versions: <value>",
        "- preconditions: <value>",
        "```",
        "",
        "After the signals block, write the report sections (no ## Signals section):",
        "",
        "FORMATTING RULE: Use standard Markdown `##` headings for ALL section titles. Do NOT use bold (`**`) for section headings.",
        "",
        "## Vulnerability",
        "",
        "## PoC / Detection",
        "Classify the VULNERABILITY's exploitability into exactly ONE of these categories:",
        "- info-leak: vulnerability allows reading unauthorized data (SSRF, LFI, path traversal, information disclosure).",
        "- auth-bypass: vulnerability allows bypassing authentication or escalating privileges.",
        "- rce: vulnerability allows remote code execution or arbitrary command injection.",
        "- state-change: vulnerability allows unauthorized modification of data, configuration, or accounts (password reset, data write, account creation).",
        "- dos: vulnerability allows denial of service.",
        "- detect-only: vulnerability's impact cannot be determined from the template; template only fingerprints or version-checks.",
        "Determine the classification from the vulnerability description, CVE metadata, and what the template's request patterns reveal about the underlying flaw "
        "— NOT from what the template itself does (templates often use harmless probes to verify exploitable conditions).",
        "State the classification clearly at the start of this section: 'Classification: <category>'.",
        "Then describe what the template actually does to detect/verify the vulnerability.",
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
