from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.tools.common import iter_files
from fwagent.tools.filesystem import inventory_filesystem
from fwagent.tools.secrets import scan_sensitive_files


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

    def test_iter_files_skips_windows_reparse_points(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            keep = root / "etc" / "system.conf"
            skip = root / "etc" / "badlink"
            keep.write_text("x=y\n", encoding="utf-8")
            skip.write_text("broken", encoding="utf-8")

            with unittest.mock.patch("fwagent.tools.common.is_windows_reparse_point", side_effect=lambda path: Path(path).name == "badlink"):
                files = list(iter_files(root))

            self.assertEqual(files, [keep])

    def test_passwd_reparse_does_not_abort_secret_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc").mkdir()
            passwd = root / "etc" / "passwd"
            passwd.write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")

            reparse = lambda path: Path(path).name == "passwd"
            with unittest.mock.patch("fwagent.tools.common.is_windows_reparse_point", side_effect=reparse), unittest.mock.patch("fwagent.tools.secrets.safe_exists", side_effect=lambda path: Path(path).name != "passwd"):
                findings = scan_sensitive_files(root)

            self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
