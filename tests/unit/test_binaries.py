from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.tools.binaries import analyze_binaries, rank_binaries


class BinaryTests(unittest.TestCase):
    def test_scores_web_binary_with_dangerous_references(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / "usr" / "sbin" / "httpd"
            binary.parent.mkdir(parents=True)
            header = bytearray(64)
            header[0:4] = b"\x7fELF"
            header[4] = 1
            header[5] = 1
            header[18:20] = (8).to_bytes(2, "little")
            binary.write_bytes(bytes(header) + b"HTTP/1.1\x00system\x00/bin/sh\x00")

            binaries = analyze_binaries(root, ["/usr/sbin/httpd"])
            ranked = rank_binaries(
                binaries,
                [{"name": "httpd", "binary": "/usr/sbin/httpd", "source": "/etc/init.d/S80httpd"}],
                {"candidate_backend_binaries": ["/usr/sbin/httpd"], "cgi": []},
            )

            self.assertEqual(ranked[0]["path"], "/usr/sbin/httpd")
            self.assertGreaterEqual(ranked[0]["score"], 50)


if __name__ == "__main__":
    unittest.main()

