from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.tools.services import discover_services, discover_web_surface


class ServiceTests(unittest.TestCase):
    def test_discovers_startup_service_and_web_surface(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "usr" / "sbin").mkdir(parents=True)
            (root / "etc" / "init.d").mkdir(parents=True)
            (root / "www" / "cgi-bin").mkdir(parents=True)
            (root / "usr" / "sbin" / "httpd").write_bytes(b"\x7fELF" + b"\x00" * 64)
            (root / "etc" / "init.d" / "S80httpd").write_text("/usr/sbin/httpd -p 80\n", encoding="utf-8")
            (root / "www" / "cgi-bin" / "ping.cgi").write_text("#!/bin/sh\n", encoding="utf-8")

            services = discover_services(root)["services"]
            web = discover_web_surface(root)

            self.assertTrue(any(service["name"] == "httpd" for service in services))
            self.assertIn("/www", web["roots"])
            self.assertIn("/www/cgi-bin/ping.cgi", web["cgi"])


if __name__ == "__main__":
    unittest.main()

