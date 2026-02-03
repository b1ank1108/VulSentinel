#!/usr/bin/env python3
from __future__ import annotations

import sys
from datetime import date
from pathlib import Path
from typing import Optional, Sequence

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from cve_poc_llm_reports.cli import _parse_from_year  # noqa: E402
from cve_poc_llm_reports.cli import main as _main  # noqa: E402


def main(argv: Optional[Sequence[str]] = None) -> int:
    return _main(
        argv,
        prog="cve_poc_llm_reports",
        include_openai_overrides=True,
        repo_root=_REPO_ROOT,
    )


if __name__ == "__main__":
    raise SystemExit(main())

