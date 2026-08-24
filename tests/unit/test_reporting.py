from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fwagent.reporting.json_report import save_analysis_json


class ReportingTests(unittest.TestCase):
    def test_saves_analysis_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = {"schema_version": "0.1", "task": {"id": "task"}}
            path = save_analysis_json(report, Path(tmp))

            self.assertTrue(path.exists())
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["task"]["id"], "task")


if __name__ == "__main__":
    unittest.main()

