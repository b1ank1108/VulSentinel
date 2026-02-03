from __future__ import annotations

from pathlib import Path


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
