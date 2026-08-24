from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.backend import QemuUserServiceBackend
from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.models import DYNAMIC_EVIDENCE_TYPES
from fwagent.dynamic.service import (
    check_runtime_dependencies,
    classify_service_failure,
    parse_boot_progress,
    parse_lighttpd_config,
    prepare_service_rootfs,
    reconstruct_service_startup,
)


class Round32Tests(unittest.TestCase):
    def test_lighttpd_config_parser_extracts_runtime_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "lighttpd.conf"
            config.write_text(
                "\n".join(
                    [
                        'server.document-root = "/www"',
                        "server.port = 3000",
                        'server.username = "root"',
                        'server.groupname = "root"',
                        'server.pid-file = "/tmp/lighttpd.pid"',
                        'server.modules = ( "mod_access",',
                        '                   "mod_cgi" )',
                    ]
                ),
                encoding="utf-8",
            )

            parsed = parse_lighttpd_config(config)

            self.assertEqual(parsed["server.document-root"], "/www")
            self.assertEqual(parsed["server.port"], 3000)
            self.assertEqual(parsed["server.pid-file"], "/tmp/lighttpd.pid")
            self.assertEqual(parsed["server.modules"], ["mod_access", "mod_cgi"])

    def test_reconstruct_service_startup_from_init_script(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = _make_lighttpd_rootfs(Path(tmp))

            profile = reconstruct_service_startup(rootfs, "lighttpd")

            self.assertEqual(profile.binary, "/usr/sbin/lighttpd")
            self.assertEqual(profile.arguments, ["-D", "-f", "/etc/lighttpd/lighttpd.conf"])
            self.assertEqual(profile.startup_source, "/etc/init.d/lighttpd")
            self.assertEqual(profile.expected_ports, [3000])
            self.assertIn("/tmp", profile.writable_paths)
            self.assertGreaterEqual(profile.confidence, 0.8)

    def test_runtime_dependency_check_reports_missing_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = _make_lighttpd_rootfs(Path(tmp))
            (rootfs / "etc" / "lighttpd" / "lighttpd.conf").unlink()
            profile = reconstruct_service_startup(rootfs, "lighttpd")

            result = check_runtime_dependencies(rootfs, profile)

            self.assertFalse(result["success"])
            self.assertIn("/etc/lighttpd/lighttpd.conf", result["missing_paths"])

    def test_prepare_service_rootfs_creates_writable_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rootfs = _make_lighttpd_rootfs(root / "source")
            profile = reconstruct_service_startup(rootfs, "lighttpd")
            service_rootfs = root / "runtime" / "lighttpd"

            result = prepare_service_rootfs(rootfs, service_rootfs, profile)

            self.assertTrue(result["success"])
            self.assertTrue((service_rootfs / "tmp").exists())
            self.assertTrue((service_rootfs / "var" / "run").exists())

    def test_service_failure_classification(self) -> None:
        self.assertEqual(classify_service_failure("", "can't load library libc.so.0", 1), "missing_library")
        self.assertEqual(classify_service_failure("", "Address already in use", 1), "port_in_use")
        self.assertEqual(classify_service_failure("", "Segmentation fault", 139), "segmentation_fault")
        self.assertEqual(classify_service_failure("", "mod_fastcgi.c.1399 [ERROR]: spawning fcgi failed", 255), "fastcgi_backend_failure")

    def test_boot_progress_parser_finds_userland_nvram_stage(self) -> None:
        progress = parse_boot_progress(
            "Linux version 4.1\n"
            "VFS: Mounted root\n"
            "do_execve: /sbin/init\n"
            "do_execve[PID: 227 (sh)]: argv: nvrammanager -e -p user-config\n"
        )

        self.assertTrue(progress.kernel_started)
        self.assertTrue(progress.rootfs_mounted)
        self.assertTrue(progress.init_started)
        self.assertTrue(progress.nvram_started)
        self.assertEqual(progress.last_stage, "nvram")

    def test_service_tools_are_registered_without_forbidden_raw_access(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = root / "task"
            rootfs = _make_lighttpd_rootfs(task / "rootfs")
            (task / "reports").mkdir(parents=True)
            firmware = task / "firmware.bin"
            firmware.write_bytes(b"\x1f\x8b")
            (task / "reports" / "analysis.json").write_text(
                json.dumps({"firmware": {"path": str(firmware)}, "extraction": {"rootfs": str(rootfs)}}),
                encoding="utf-8",
            )

            api = DynamicToolAPI(root, "task", config=DynamicConfig(backend="service-qemu"), backend=QemuUserServiceBackend(task))

            self.assertIn("dynamic.reconstruct_service_startup", api.tools)
            self.assertIn("dynamic.start_service", api.tools)
            for forbidden in ("shell", "bash", "docker", "qemu-arm-static"):
                self.assertNotIn(forbidden, api.tools)

    def test_service_evidence_types_are_allowed(self) -> None:
        for evidence_type in (
            "service_start_success",
            "service_start_failure",
            "service_port_listening",
            "service_reachable",
            "runtime_dependency_missing",
        ):
            self.assertIn(evidence_type, DYNAMIC_EVIDENCE_TYPES)


def _make_lighttpd_rootfs(root: Path) -> Path:
    rootfs = root
    (rootfs / "usr" / "sbin").mkdir(parents=True)
    (rootfs / "etc" / "init.d").mkdir(parents=True)
    (rootfs / "etc" / "lighttpd").mkdir(parents=True)
    (rootfs / "www").mkdir(parents=True)
    (rootfs / "usr" / "sbin" / "lighttpd").write_bytes(b"\x7fELF")
    (rootfs / "etc" / "init.d" / "lighttpd").write_text(
        "start() {\n    service_start /usr/sbin/lighttpd -D -f /etc/lighttpd/lighttpd.conf\n}\n",
        encoding="utf-8",
    )
    (rootfs / "etc" / "lighttpd" / "lighttpd.conf").write_text(
        'server.document-root = "/www"\n'
        "server.port = 3000\n"
        'server.username = "root"\n'
        'server.groupname = "root"\n'
        'server.pid-file = "/tmp/lighttpd.pid"\n',
        encoding="utf-8",
    )
    return rootfs


if __name__ == "__main__":
    unittest.main()
