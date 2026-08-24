from __future__ import annotations

import json
from pathlib import Path


def save_analysis_json(report: dict, reports_dir: str | Path) -> Path:
    output_path = Path(reports_dir) / "analysis.json"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return output_path


def load_analysis_json(path: str | Path) -> dict:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)

