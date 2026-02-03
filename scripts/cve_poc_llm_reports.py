#!/usr/bin/env python3
import argparse
import os
import sys
from dataclasses import dataclass
from typing import Mapping
from typing import Optional, Sequence


_ENV_BASE_URL = "OPENAI_BASE_URL"
_ENV_API_KEY = "OPENAI_API_KEY"
_ENV_MODEL = "OPENAI_MODEL"


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cve_poc_llm_reports",
        description="Offline generator for CVE PoC LLM reports (reads nuclei-templates/, writes reports/).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--from-year",
        type=int,
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
    try:
        _config = resolve_config(args, os.environ)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
