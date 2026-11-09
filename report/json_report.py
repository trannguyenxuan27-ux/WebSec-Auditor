"""JSON report writer."""
from __future__ import annotations

import json
from pathlib import Path

from models import ScanResult


def save_json(result: ScanResult, path: str | Path) -> Path:
    out = Path(path)
    out.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return out
