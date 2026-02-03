#!/usr/bin/env python3
import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Mapping
from typing import Optional, Sequence, TextIO


_ENV_BASE_URL = "OPENAI_BASE_URL"
_ENV_API_KEY = "OPENAI_API_KEY"
_ENV_MODEL = "OPENAI_MODEL"
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


@dataclass(frozen=True)
class AppConfig:
    from_year: Optional[int]
    base_url: str
    api_key: str
    model: str
    templates_dir: str
    reports_dir: str


class ConfigError(ValueError):
    pass


def _fmt_kv(**fields: object) -> str:
    parts = []
    for k in sorted(fields):
        v = fields[k]
        if v is None:
            continue
        parts.append(f"{k}={json.dumps(v, ensure_ascii=False, separators=(',', ':'))}")
    return " ".join(parts)


class EventLogger:
    def __init__(self, out: TextIO) -> None:
        self._out = out

    def log(self, event: str, **fields: object) -> None:
        msg = f"event={event}"
        kv = _fmt_kv(**fields)
        if kv:
            msg = f"{msg} {kv}"
        print(msg, file=self._out, flush=True)


@dataclass
class RunStats:
    processed: int = 0
    skipped: int = 0
    failed: int = 0
    succeeded: int = 0

    def as_fields(self) -> Mapping[str, int]:
        return {
            "processed": self.processed,
            "skipped": self.skipped,
            "failed": self.failed,
            "succeeded": self.succeeded,
        }


def log_progress(logger: EventLogger, *, processed: int, id: str, file_path: str) -> None:
    logger.log("progress", processed=processed, id=id, file_path=file_path)


def log_skip(
    logger: EventLogger,
    stats: RunStats,
    *,
    id: str,
    file_path: str,
    reason: str,
    **extra: object,
) -> None:
    stats.processed += 1
    stats.skipped += 1
    logger.log(
        "skip",
        processed=stats.processed,
        skipped=stats.skipped,
        id=id,
        file_path=file_path,
        reason=reason,
        **extra,
    )


def log_failure(logger: EventLogger, stats: RunStats, *, id: str, file_path: str, reason: str) -> None:
    stats.processed += 1
    stats.failed += 1
    logger.log(
        "fail",
        processed=stats.processed,
        failed=stats.failed,
        id=id,
        file_path=file_path,
        reason=reason,
    )


def log_success(
    logger: EventLogger, stats: RunStats, *, id: str, file_path: str, report_path: str
) -> None:
    stats.processed += 1
    stats.succeeded += 1
    logger.log(
        "success",
        processed=stats.processed,
        succeeded=stats.succeeded,
        id=id,
        file_path=file_path,
        report_path=report_path,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve_poc_llm_reports",
        description="Offline generator for CVE PoC LLM reports (reads nuclei-templates/, writes reports/).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--from-year",
        type=_parse_from_year,
        default=None,
        help="Only process CVEs whose year (from CVE ID) >= from_year.",
    )
    parser.add_argument(
        "--base-url",
        default=None,
        help=f"OpenAI-compatible base URL (env: {_ENV_BASE_URL}).",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help=f"API key for OpenAI-compatible server (env: {_ENV_API_KEY}; never logged).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=f"Chat model name to use (env: {_ENV_MODEL}).",
    )
    parser.add_argument(
        "--templates-dir",
        default="nuclei-templates",
        help="Path to nuclei templates checkout (read-only).",
    )
    parser.add_argument(
        "--reports-dir",
        default="reports",
        help="Output directory root for generated reports (write-only).",
    )
    return parser


def _parse_from_year(raw: str) -> int:
    try:
        year = int(raw)
    except ValueError as e:
        raise argparse.ArgumentTypeError("from-year must be an integer") from e

    if year < 0:
        raise argparse.ArgumentTypeError("from-year must be >= 0")

    max_year = date.today().year + 1
    if year > max_year:
        raise argparse.ArgumentTypeError(f"from-year must be <= {max_year}")
    return year


def _coalesce_nonempty(*values: Optional[str]) -> Optional[str]:
    for v in values:
        if v is None:
            continue
        if str(v).strip() == "":
            continue
        return str(v)
    return None


def _normalize_base_url(base_url: str) -> str:
    return base_url.rstrip("/")


def resolve_config(args: argparse.Namespace, env: Mapping[str, str]) -> AppConfig:
    base_url = _coalesce_nonempty(getattr(args, "base_url", None), env.get(_ENV_BASE_URL))
    api_key = _coalesce_nonempty(getattr(args, "api_key", None), env.get(_ENV_API_KEY))
    model = _coalesce_nonempty(getattr(args, "model", None), env.get(_ENV_MODEL))

    missing = []
    if base_url is None:
        missing.append(f"base_url (--base-url or env:{_ENV_BASE_URL})")
    if api_key is None:
        missing.append(f"api_key (--api-key or env:{_ENV_API_KEY})")
    if model is None:
        missing.append(f"model (--model or env:{_ENV_MODEL})")
    if missing:
        raise ConfigError("Missing required config: " + ", ".join(missing))

    normalized_base_url = _normalize_base_url(base_url)
    if normalized_base_url == "":
        raise ConfigError("Invalid base_url: empty after normalization")

    templates_dir = str(getattr(args, "templates_dir"))
    reports_dir = str(getattr(args, "reports_dir"))

    return AppConfig(
        from_year=getattr(args, "from_year"),
        base_url=normalized_base_url,
        api_key=api_key,
        model=model,
        templates_dir=templates_dir,
        reports_dir=reports_dir,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logger = EventLogger(sys.stderr)
    try:
        config = resolve_config(args, os.environ)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    logger.log(
        "start",
        from_year=config.from_year,
        base_url=config.base_url,
        model=config.model,
        templates_dir=config.templates_dir,
        reports_dir=config.reports_dir,
    )
    stats = RunStats()

    from cve_poc_llm_reports.cves_jsonl import CvesJsonlLineError, iter_cves_jsonl
    from cve_poc_llm_reports.atomic_write import atomic_write_json
    from cve_poc_llm_reports.index_jsonl import append_report_index_entry
    from cve_poc_llm_reports.report_paths import build_report_path
    from cve_poc_llm_reports.report_generation import ModelConfig, generate_report_v1_for_entry

    templates_dir = Path(config.templates_dir)
    reports_dir = Path(config.reports_dir)
    index_path = reports_dir / "cves.jsonl"
    model = ModelConfig(
        base_url=config.base_url,
        api_key=config.api_key,
        model=config.model,
        timeout_seconds=30,
        max_attempts=3,
    )
    def on_jsonl_error(err: CvesJsonlLineError) -> None:
        log_failure(
            logger,
            stats,
            id="(jsonl)",
            file_path=f"{templates_dir / 'cves.json'}:{err.line_number}",
            reason=f"jsonl_parse_failed: {err.message}; excerpt={err.raw_excerpt}",
        )

    for entry in iter_cves_jsonl(templates_dir=templates_dir, on_error=on_jsonl_error):
        if config.from_year is not None and entry.year < config.from_year:
            log_skip(
                logger,
                stats,
                id=entry.id,
                file_path=entry.file_path,
                reason="from_year",
                from_year=config.from_year,
                year=entry.year,
            )
            continue

        report_path = build_report_path(
            reports_dir=reports_dir, file_path=entry.file_path, year=entry.year, cve_id=entry.id
        )
        if report_path.exists():
            log_skip(
                logger,
                stats,
                id=entry.id,
                file_path=entry.file_path,
                reason="report_exists",
                report_path=str(report_path),
            )
            continue

        try:
            report_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            log_failure(
                logger,
                stats,
                id=entry.id,
                file_path=entry.file_path,
                reason=f"mkdir_failed: {e}",
            )
            continue

        try:
            report = generate_report_v1_for_entry(entry, templates_dir=templates_dir, model=model)
        except Exception as e:  # noqa: BLE001
            log_failure(
                logger,
                stats,
                id=entry.id,
                file_path=entry.file_path,
                reason=f"report_generation_failed: {e}",
            )
            continue

        try:
            atomic_write_json(report_path, report)
        except Exception as e:  # noqa: BLE001
            log_failure(
                logger,
                stats,
                id=entry.id,
                file_path=entry.file_path,
                reason=f"report_write_failed: {e}",
            )
            continue

        try:
            append_report_index_entry(
                index_path=index_path,
                cve_id=entry.id,
                report_path=_as_repo_relative(report_path),
            )
        except Exception as e:  # noqa: BLE001
            try:
                report_path.unlink()
            except OSError:
                pass
            log_failure(
                logger,
                stats,
                id=entry.id,
                file_path=entry.file_path,
                reason=f"index_write_failed: {e}",
            )
            continue

        log_success(
            logger,
            stats,
            id=entry.id,
            file_path=entry.file_path,
            report_path=str(report_path),
        )

    logger.log("summary", **stats.as_fields())
    return 0


def _as_repo_relative(path: Path) -> str:
    try:
        return path.resolve(strict=False).relative_to(_REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


if __name__ == "__main__":
    raise SystemExit(main())
