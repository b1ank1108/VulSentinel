from __future__ import annotations

import json
import os
from pathlib import Path


def append_report_index_entry(*, index_path: Path, cve_id: str, report_path: str) -> None:
    index_path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ID": cve_id, "report_path": report_path}, ensure_ascii=False) + "\n"
    with index_path.open("a", encoding="utf-8", newline="\n") as f:
        f.write(line)
        f.flush()
        os.fsync(f.fileno())

