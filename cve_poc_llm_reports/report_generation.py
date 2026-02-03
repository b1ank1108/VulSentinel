from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from cve_poc_llm_reports.cves_jsonl import CveEntry
from cve_poc_llm_reports.openai_json import post_chat_completions_json
from cve_poc_llm_reports.prompt_v1 import build_signals_prompt_messages
from cve_poc_llm_reports.report_schema_v1 import build_report_v1, validate_report_v1


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


def generate_report_v1_for_entry(
    entry: CveEntry,
    *,
    templates_dir: Path,
    model: ModelConfig,
    prompt: PromptConfig = PromptConfig(),
) -> dict[str, Any]:
    template_rel_path = (Path(templates_dir.name) / entry.file_path).as_posix()
    template_yaml = entry.template_path.read_text(encoding="utf-8", errors="replace")

    messages = build_signals_prompt_messages(
        cve_id=entry.id,
        template_path=template_rel_path,
        template_yaml=template_yaml,
        max_yaml_chars=prompt.max_yaml_chars,
        max_summary_lines=prompt.max_summary_lines,
    )
    result = post_chat_completions_json(
        base_url=model.base_url,
        api_key=model.api_key,
        model=model.model,
        messages=messages,
        timeout_seconds=model.timeout_seconds,
        max_attempts=model.max_attempts,
    )
    if not isinstance(result.data, Mapping):
        raise ValueError("model output must be a JSON object (signals)")
    signals: Mapping[str, Any] = result.data

    report = build_report_v1(
        cve_id=entry.id,
        year=entry.year,
        template_path=template_rel_path,
        signals=signals,
    )
    validate_report_v1(report)
    return report
