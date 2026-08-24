from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.tools.filesystem import inventory_filesystem


class FilesystemTests(unittest.TestCase):
    def test_classifies_common_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bin").mkdir()
            (root / "etc").mkdir()
            (root / "www" / "cgi-bin").mkdir(parents=True)
            (root / "bin" / "app").write_bytes(b"\x7fELF" + b"\x00" * 64)
            (root / "etc" / "system.conf").write_text("password=admin\n", encoding="utf-8")
            (root / "www" / "cgi-bin" / "ping.cgi").write_text("#!/bin/sh\n", encoding="utf-8")
            (root / "www" / "index.html").write_text("<html></html>", encoding="utf-8")

            result = inventory_filesystem(root)

            self.assertEqual(result["elf_files"], 1)
            self.assertGreaterEqual(result["scripts"], 1)
            self.assertGreaterEqual(result["config_files"], 1)
            self.assertGreaterEqual(result["web_files"], 2)
            self.assertIn("/bin/app", result["categories"]["elf"])

    def test_skips_symlinks_pointing_outside_rootfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            (root / "bin").mkdir()
            (root / "bin" / "app").write_bytes(b"\x7fELF" + b"\x00" * 64)
            try:
                (root / "etc" / "fstab").symlink_to("/tmp/fstab")
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {exc}")

            result = inventory_filesystem(root)

            self.assertEqual(result["elf_files"], 1)
            self.assertEqual(result["symlinks"], 1)
            self.assertIn("/bin/app", result["categories"]["elf"])


if __name__ == "__main__":
    unittest.main()
