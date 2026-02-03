#!/usr/bin/env python3
import argparse
from typing import Optional, Sequence


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
        help="OpenAI-compatible base URL (e.g. https://api.openai.com).",
    )
    parser.add_argument(
        "--api-key",
        default=None,
        help="API key for OpenAI-compatible server (never logged).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help="Chat model name to use.",
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    _args = parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
