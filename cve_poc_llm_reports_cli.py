#!/usr/bin/env python3
from cve_poc_llm_reports.cli import main


if __name__ == "__main__":
    raise SystemExit(main(prog="cve_poc_llm_reports_cli", include_openai_overrides=True))
