from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from vulsentinel.cves_jsonl import CveEntry
from vulsentinel.openai_chat import post_chat_completions_text
from vulsentinel.prompt_markdown import (
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
    r"Classification:\s*(info-leak|auth-bypass|rce|state-change|dos|detect-only)",
    re.IGNORECASE,
)


def _extract_poc_classification(body: str) -> str | None:
    m = _POC_CLASSIFICATION_RE.search(body)
    return m.group(1).lower() if m else None


_SIGNALS_BLOCK_RE = re.compile(
    r"```signals\s*\n(.*?)```", re.DOTALL,
)


def _extract_signals_from_markdown(body: str) -> dict[str, str]:
    m = _SIGNALS_BLOCK_RE.search(body)
    if not m:
        return {}

    section = m.group(1)
    found: dict[str, str] = {}
    for line_m in _SIGNAL_KEY_RE.finditer(section):
        key = line_m.group(1).strip().lower()
        value = line_m.group(2).strip()
        if key in _REQUIRED_SIGNAL_KEYS:
            found[key] = value
    return found


def _strip_signals_block(body: str) -> str:
    body = _SIGNALS_BLOCK_RE.sub("", body).strip()
    # LLM sometimes appends a stray trailing fence
    if body.endswith("```"):
        body = body[:-3].rstrip()
    return body


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

    body = _strip_signals_block(body)

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

    return frontmatter + "\n" + body + "\n"


def build_report_path(*, reports_dir: Path, file_path: str, year: int, cve_id: str) -> Path:
    prefix = _extract_prefix(file_path)
    _validate_rel_prefix(prefix)
    _validate_cve_id_for_filename(cve_id)
    return reports_dir / prefix / "cves" / str(year) / f"{cve_id}.md"


def _extract_prefix(file_path: str) -> str:
    parts = file_path.split("/cves/", 1)
    if len(parts) != 2 or not parts[0]:
        raise ValueError("file_path must contain '<prefix>/cves/'")
    return parts[0].strip("/")


def _validate_rel_prefix(prefix: str) -> None:
    path = Path(prefix)
    if path.is_absolute():
        raise ValueError("prefix must be a relative path")
    if any(part in ("..", ".") for part in path.parts):
        raise ValueError("prefix must not contain '.' or '..'")


def _validate_cve_id_for_filename(cve_id: str) -> None:
    if "/" in cve_id or "\\" in cve_id:
        raise ValueError("cve_id must not contain path separators")
