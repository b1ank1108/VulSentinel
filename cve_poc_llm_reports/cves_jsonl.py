from __future__ import annotations

import json
import re
from datetime import date
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Optional

_MAX_LOG_EXCERPT_CHARS = 200
_CVE_ID_RE = re.compile(r"^CVE-(\d{4})-(\d+)$", flags=re.IGNORECASE)
_MIN_CVE_YEAR = 1999
_MAX_CVE_YEAR = date.today().year + 1


@dataclass(frozen=True)
class CveEntry:
    id: str
    year: int
    file_path: str
    template_path: Path
    line_number: int


@dataclass(frozen=True)
class CvesJsonlLineError:
    line_number: int
    message: str
    raw_excerpt: str


def _make_excerpt(raw_line: str, *, limit: int = _MAX_LOG_EXCERPT_CHARS) -> str:
    line = raw_line.strip()
    if len(line) <= limit:
        return line
    return f"{line[:limit]}...(truncated)"


def parse_cve_year_from_id(cve_id: str) -> int:
    match = _CVE_ID_RE.match(cve_id.strip())
    if not match:
        raise ValueError(f"invalid CVE ID: {cve_id!r} (expected CVE-YYYY-<number>)")
    year = int(match.group(1))
    if year < _MIN_CVE_YEAR or year > _MAX_CVE_YEAR:
        raise ValueError(
            f"invalid CVE ID: {cve_id!r} (year {year} out of range {_MIN_CVE_YEAR}-{_MAX_CVE_YEAR})"
        )
    return year


def resolve_template_path(templates_dir: Path, file_path: str) -> Path:
    if not file_path:
        raise ValueError("missing file_path")
    if "\x00" in file_path:
        raise ValueError("file_path contains NUL byte")

    candidate = (templates_dir / file_path).resolve(strict=False)
    root = templates_dir.resolve(strict=False)
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("file_path escapes templates_dir") from exc
    return candidate


def iter_cves_jsonl(
    *,
    templates_dir: Path,
    cves_json_path: Optional[Path] = None,
    on_error: Optional[Callable[[CvesJsonlLineError], None]] = None,
) -> Iterator[CveEntry]:
    jsonl_path = cves_json_path or (templates_dir / "cves.json")
    with jsonl_path.open("r", encoding="utf-8", newline="") as f:
        for line_number, raw in enumerate(f, start=1):
            raw_line = raw.strip()
            if not raw_line:
                continue
            try:
                obj = json.loads(raw_line)
                cve_id = obj["ID"]
                file_path = obj["file_path"]
                year = parse_cve_year_from_id(cve_id)
                template_path = resolve_template_path(templates_dir, file_path)
            except Exception as exc:  # noqa: BLE001 - convert to structured error
                excerpt = _make_excerpt(raw_line)
                if on_error is None:
                    raise ValueError(
                        f"failed to parse {jsonl_path}:{line_number}: {exc}; excerpt={excerpt}"
                    ) from exc
                on_error(
                    CvesJsonlLineError(
                        line_number=line_number,
                        message=str(exc),
                        raw_excerpt=excerpt,
                    )
                )
                continue

            yield CveEntry(
                id=str(cve_id),
                year=year,
                file_path=str(file_path),
                template_path=template_path,
                line_number=line_number,
            )
