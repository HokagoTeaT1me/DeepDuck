from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.config import GhidraSettings
from fwagent.runtime.ghidra import GhidraRuntime


class GhidraRuntimeTests(unittest.TestCase):
    def test_builds_headless_export_command(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            home = base / "ghidra"
            support = home / "support"
            scripts = base / "scripts"
            support.mkdir(parents=True)
            scripts.mkdir()
            (support / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
            binary = base / "sample"
            binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
            runtime = GhidraRuntime(
                base / "workspace",
                settings=GhidraSettings(home=home, project_dir=base / "projects", script_dir=scripts),
            )

            command = runtime.build_export_command(binary, "proj", base / "out")

            self.assertEqual(command[0], str(support / "analyzeHeadless"))
            self.assertIn("-import", command)
            self.assertIn("ExportBinarySummary.java", command)
            self.assertIn("-deleteProject", command)

    def test_cache_key_is_stable_for_same_binary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            binary = base / "sample"
            binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
            runtime = GhidraRuntime(base / "workspace", settings=GhidraSettings(home=base / "missing"))

            self.assertEqual(runtime.cache_key(binary), runtime.cache_key(binary))


if __name__ == "__main__":
    unittest.main()

