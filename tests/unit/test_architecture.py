from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.tools.architecture import identify_architecture


def write_fake_elf(path: Path, machine: int = 8) -> None:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 1
    header[5] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = machine.to_bytes(2, "little")
    path.write_bytes(bytes(header) + b"HTTP/1.1\x00system\x00/bin/sh\x00")


class ArchitectureTests(unittest.TestCase):
    def test_identifies_mips_little_endian(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "bin" / "busybox"
            binary.parent.mkdir()
            write_fake_elf(binary)

            result = identify_architecture(root, ["/bin/busybox"])

            self.assertEqual(result["primary_architecture"], "mips")
            self.assertEqual(result["endianness"], "little")
            self.assertEqual(result["bitness"], 32)
            self.assertEqual(result["architectures"], {"mips": 1})


if __name__ == "__main__":
    unittest.main()

