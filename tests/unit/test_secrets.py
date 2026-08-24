from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.tools.secrets import scan_sensitive_files


class SecretTests(unittest.TestCase):
    def test_finds_private_key_and_credential_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "etc" / "ssl").mkdir(parents=True)
            (root / "etc" / "config").mkdir(parents=True)
            (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n", encoding="utf-8")
            (root / "etc" / "ssl" / "server.key").write_text(
                "-----BEGIN PRIVATE KEY-----\nredacted\n-----END PRIVATE KEY-----\n",
                encoding="utf-8",
            )
            (root / "etc" / "config" / "system.conf").write_text("password=admin\n", encoding="utf-8")

            findings = scan_sensitive_files(root)
            types = {finding["type"] for finding in findings}

            self.assertIn("private_key", types)
            self.assertIn("credential_candidate", types)
            self.assertIn("passwd_root_user", types)


if __name__ == "__main__":
    unittest.main()

