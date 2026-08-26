from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.config import GhidraSettings, Round2Config
from fwagent.tools.ghidra_api import BinaryToolAPI


def write_fake_x86_elf(path: Path, payload: bytes = b"") -> None:
    header = bytearray(64)
    header[0:4] = b"\x7fELF"
    header[4] = 1
    header[5] = 1
    header[16:18] = (2).to_bytes(2, "little")
    header[18:20] = (3).to_bytes(2, "little")
    path.write_bytes(bytes(header) + payload)


class GhidraApiTests(unittest.TestCase):
    def test_fallback_analyze_returns_structured_result(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            binary = base / "sample"
            write_fake_x86_elf(binary, b"/bin/sh\x00HTTP/1.1\x00")

            config = Round2Config(ghidra=GhidraSettings(home=base / "missing-ghidra"))
            result = BinaryToolAPI(base / "workspace", config=config).analyze_binary(binary)

            self.assertTrue(result["success"])
            self.assertEqual(result["result"]["summary"]["language"], "x86:LE:32:default")
            self.assertTrue(result["result"]["metadata"]["fallback"])
            self.assertEqual(result["result"]["metadata"]["backend_used"], "static_elf_fallback")
            self.assertIn("fallback_reason", result["result"]["metadata"])
            self.assertIn("warnings", result)

    def test_no_fallback_returns_structured_failure_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            binary = base / "sample"
            write_fake_x86_elf(binary)
            api = BinaryToolAPI(base / "workspace", config=Round2Config(ghidra=GhidraSettings(home=base / "missing-ghidra")))
            api.runtime.check_environment = lambda: {"success": False, "errors": ["analyzeHeadless not found"], "warnings": []}
            api.runtime.check_container_environment = lambda: {"success": False, "errors": ["docker permission denied"], "warnings": []}

            result = api.analyze_binary(binary, force=True, allow_fallback=False)

            self.assertFalse(result["success"])
            metadata = result["result"]["metadata"]
            self.assertEqual(metadata["backend_used"], "none")
            self.assertFalse(metadata["fallback_used"])
            self.assertEqual(metadata["fallback_reason"], "GHIDRA_CONTAINER_DOCKER_PERMISSION_DENIED")


if __name__ == "__main__":
    unittest.main()
