from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from cve_poc_llm_reports.cves_jsonl import CveEntry
from cve_poc_llm_reports.openai_text import post_chat_completions_text
from cve_poc_llm_reports.prompt_markdown import (
    _REQUIRED_SIGNAL_KEYS,
    build_report_markdown_prompt_messages,
)

from typing import Optional


_logger = logging.getLogger(__name__)

_SIGNAL_KEY_RE = re.compile(r"^-\s+\*{0,2}(\w+)\*{0,2}\s*:\s*(.+)$", re.MULTILINE)


@dataclass(frozen=True)
class ModelConfig:
    base_url: str
    api_key: str
    model: str
    timeout_seconds: int = 30
    max_attempts: int = 3


@dataclass(frozen=True)
class PromptConfig:
    max_yaml_chars: int = 12_000
    max_summary_lines: int = 40


_POC_CLASSIFICATION_RE = re.compile(
    r"Classification:\s*(detect-only|active-detect|exploit|intrusive)",
    re.IGNORECASE,
)


def _extract_poc_classification(body: str) -> str | None:
    m = _POC_CLASSIFICATION_RE.search(body)
    return m.group(1).lower() if m else None


def _extract_signals_from_markdown(body: str) -> dict[str, str]:
    # Match "## Signals", "**Signals**", "**## Signals**", etc.
    signals_match = re.search(
        r"(?:^|\n)\s*\*{0,2}\s*(?:##+\s*)?\s*Signals\s*\*{0,2}\s*\n(.*?)(?=\n(?:##\s|\*{2,}\s*(?:#|Vulnerability|PoC))|\Z)",
        body,
        re.DOTALL,
    )
    if not signals_match:
        return {}

    section = signals_match.group(1)
    found: dict[str, str] = {}
    for m in _SIGNAL_KEY_RE.finditer(section):
        key = m.group(1).strip().lower()
        value = m.group(2).strip()
        if key in _REQUIRED_SIGNAL_KEYS:
            found[key] = value
    return found


def generate_report_markdown_for_entry(
    entry: CveEntry,
    *,
    templates_dir: Path,
    model: ModelConfig,
    prompt: PromptConfig = PromptConfig(),
    client: Optional[object] = None,
) -> str:
    template_rel_path = (Path(templates_dir.name) / entry.file_path).as_posix()
    template_yaml = entry.template_path.read_text(encoding="utf-8", errors="replace")

    messages = build_report_markdown_prompt_messages(
        cve_id=entry.id,
        template_path=template_rel_path,
        template_yaml=template_yaml,
        max_yaml_chars=prompt.max_yaml_chars,
        max_summary_lines=prompt.max_summary_lines,
    )
    result = post_chat_completions_text(
        base_url=model.base_url,
        api_key=model.api_key,
        model=model.model,
        messages=messages,
        timeout_seconds=model.timeout_seconds,
        max_attempts=model.max_attempts,
        client=client,
    )
    body = result.content.strip()
    if body == "":
        raise ValueError("markdown report must be non-empty")

    signals = _extract_signals_from_markdown(body)
    if not signals:
        _logger.warning(
            "signal extraction failed for %s; frontmatter will have deterministic fields only",
            entry.id,
        )

    poc_classification = _extract_poc_classification(body)

    fm_lines = [
        "---",
        f"cve_id: {entry.id}",
        f"template_path: {template_rel_path}",
    ]
    for key in _REQUIRED_SIGNAL_KEYS:
        if key in signals:
            fm_lines.append(f"{key}: {signals[key]}")
    if poc_classification is not None:
        fm_lines.append(f"poc_classification: {poc_classification}")
    fm_lines.append("---")
    frontmatter = "\n".join(fm_lines) + "\n"

    header = f"# {entry.id}\n\n"
    return frontmatter + header + body + "\n"
