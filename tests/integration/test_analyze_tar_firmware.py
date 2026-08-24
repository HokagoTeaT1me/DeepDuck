from __future__ import annotations

import io
import tarfile
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from io import StringIO

from fwagent.cli import main
from fwagent.pipeline import analyze_firmware


def add_bytes(archive: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    archive.addfile(info, io.BytesIO(data))


def fake_mips_elf(payload: bytes = b"") -> bytes:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 1
    header[5] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (8).to_bytes(2, "little")
    return bytes(header) + payload


class AnalyzeTarFirmwareIntegrationTests(unittest.TestCase):
    def test_analyze_tar_firmware_generates_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            firmware = base / "firmware.tar"
            with tarfile.open(firmware, "w") as archive:
                add_bytes(archive, "etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n")
                add_bytes(archive, "etc/init.d/S80httpd", b"/usr/sbin/httpd -p 80\n", mode=0o755)
                add_bytes(archive, "usr/sbin/httpd", fake_mips_elf(b"HTTP/1.1\x00system\x00/bin/sh\x00"), mode=0o755)
                add_bytes(archive, "www/cgi-bin/ping.cgi", b"#!/bin/sh\n", mode=0o755)
                add_bytes(archive, "etc/config/system.conf", b"password=admin\n")

            report, report_path = analyze_firmware(firmware, workspace=base / "workspace", timeout=30)

            self.assertTrue(report_path.exists())
            self.assertEqual(report["extraction"]["extractor"], "tarfile")
            self.assertEqual(report["platform"]["architecture"], "mips")
            self.assertTrue(any(service["name"] == "httpd" for service in report["services"]))
            self.assertGreaterEqual(len(report["priority_binaries"]), 1)
            self.assertTrue(any(item["type"] == "credential_candidate" for item in report["security_candidates"]))

    def test_cli_analyze_exits_successfully(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            firmware = base / "firmware.tar"
            with tarfile.open(firmware, "w") as archive:
                add_bytes(archive, "etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n")
                add_bytes(archive, "usr/sbin/httpd", fake_mips_elf(b"HTTP/1.1\x00system\x00/bin/sh\x00"), mode=0o755)
                add_bytes(archive, "www/cgi-bin/ping.cgi", b"#!/bin/sh\n", mode=0o755)

            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["analyze", str(firmware), "--workspace", str(base / "workspace"), "--timeout", "30"])

            self.assertEqual(exit_code, 0)
            self.assertIn("DeepDuck v", stdout.getvalue())
            self.assertIn("Architecture: mips", stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
