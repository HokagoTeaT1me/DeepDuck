from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.application import (
    classify_application_failure,
    parse_fastcgi_stanzas,
    parse_qemu_strace,
    reconstruct_endpoints,
    reconstruct_fastcgi_launch,
    resolve_lighttpd_config,
)
from fwagent.dynamic.backend import QemuUserServiceBackend
from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.models import DYNAMIC_EVIDENCE_TYPES


class Round33Tests(unittest.TestCase):
    def test_fastcgi_config_parsing_resolves_variables(self) -> None:
        stanzas = parse_fastcgi_stanzas(_lighttpd_config())

        self.assertEqual(stanzas[0]["route"], "/services/device_manager/")
        self.assertEqual(stanzas[0]["bin-path"], "/www/services/device_manager/device_manager.fcgi")
        self.assertEqual(stanzas[0]["socket"], "/tmp/device_manager-${PID}.socket")
        self.assertEqual(stanzas[0]["max-procs"], 1)

    def test_include_resolution_builds_effective_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = _make_application_rootfs(Path(tmp))

            result = resolve_lighttpd_config(rootfs)

            self.assertTrue(result["success"])
            self.assertIn("/etc/lighttpd/lighttpd.conf", result["sources"])
            self.assertIn("/etc/lighttpd/fastcgi.conf", result["sources"])
            self.assertEqual(result["fastcgi"][0]["bin-path"], "/www/services/device_manager/device_manager.fcgi")

    def test_launch_profile_and_dependency_graph(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = _make_application_rootfs(Path(tmp))

            profile = reconstruct_fastcgi_launch(rootfs)

            self.assertEqual(profile.binary, "/www/services/device_manager/device_manager.fcgi")
            self.assertEqual(profile.route, "/services/device_manager/")
            self.assertEqual(profile.parent_service, "lighttpd")
            self.assertTrue(any(item.type == "config_file" and item.path_or_name == "/etc/device.conf" for item in profile.dependencies))
            self.assertTrue(any(item.type == "unix_socket" and item.path_or_name == "/tmp/ubus.sock" for item in profile.dependencies))
            self.assertTrue(any(item.type == "nvram" for item in profile.dependencies))

    def test_trace_parser_extracts_missing_files_and_ipc(self) -> None:
        trace = parse_qemu_strace(
            '12 open("/etc/missing.conf",O_RDONLY) = -1 errno=2 (No such file or directory)\n'
            '12 connect(4,0x1234,16) = -1 errno=111 (Connection refused)\n'
            '12 ioctl(5,0x8913,0x4080) = -1 errno=19 (No such device)\n'
        )

        self.assertEqual(trace["event_count"], 3)
        self.assertEqual(trace["missing_files"][0]["target"], "/etc/missing.conf")
        self.assertEqual(len(trace["failed_connects"]), 1)
        self.assertEqual(len(trace["failed_ioctls"]), 1)

    def test_endpoint_reconstruction_links_fastcgi_route(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            rootfs = _make_application_rootfs(Path(tmp))
            profile = reconstruct_fastcgi_launch(rootfs)

            result = reconstruct_endpoints(rootfs, profile)

            paths = {item["path"] for item in result["endpoints"]}
            self.assertIn("/services/device_manager/", paths)
            self.assertTrue(any(link["backend"] == "/www/services/device_manager/device_manager.fcgi" for link in result["links"]))

    def test_exit_182_classification(self) -> None:
        self.assertEqual(
            classify_application_failure("mod_fastcgi: child exited with status 182; spawning fcgi failed", 255),
            "fastcgi_child_exit_182",
        )

    def test_application_tools_are_registered_without_forbidden_raw_access(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = root / "task"
            rootfs = _make_application_rootfs(task / "rootfs")
            (task / "reports").mkdir(parents=True)
            firmware = task / "firmware.bin"
            firmware.write_bytes(b"\x1f\x8b")
            (task / "reports" / "analysis.json").write_text(
                json.dumps({"firmware": {"path": str(firmware)}, "extraction": {"rootfs": str(rootfs)}}),
                encoding="utf-8",
            )

            api = DynamicToolAPI(root, "task", config=DynamicConfig(backend="service-qemu"), backend=QemuUserServiceBackend(task))

            self.assertIn("application.inspect_backend", api.tools)
            self.assertIn("application.trace_startup", api.tools)
            self.assertIn("application.probe_endpoint", api.tools)
            for forbidden in ("shell", "bash", "docker", "qemu-arm-static", "strace"):
                self.assertNotIn(forbidden, api.tools)

    def test_application_evidence_types_are_allowed(self) -> None:
        for evidence_type in (
            "backend_start_failure",
            "backend_socket_ready",
            "backend_ipc_dependency",
            "endpoint_discovered",
            "endpoint_backend_link",
            "application_endpoint_reachable",
        ):
            self.assertIn(evidence_type, DYNAMIC_EVIDENCE_TYPES)


def _make_application_rootfs(root: Path) -> Path:
    (root / "etc" / "lighttpd").mkdir(parents=True)
    (root / "www" / "services" / "device_manager").mkdir(parents=True)
    (root / "www" / "js").mkdir(parents=True)
    (root / "lib").mkdir(parents=True)
    (root / "etc" / "lighttpd" / "lighttpd.conf").write_text(
        'include "/etc/lighttpd/fastcgi.conf"\n',
        encoding="utf-8",
    )
    (root / "etc" / "lighttpd" / "fastcgi.conf").write_text(_lighttpd_config(), encoding="utf-8")
    (root / "www" / "index.html").write_text(
        '<form action="/services/device_manager/" method="POST"><input name="operation"/></form>',
        encoding="utf-8",
    )
    (root / "www" / "js" / "app.js").write_text(
        'fetch("/services/device_manager/status");',
        encoding="utf-8",
    )
    (root / "www" / "services" / "device_manager" / "device_manager.fcgi").write_bytes(
        b"\x7fELF\x00/etc/device.conf\x00/tmp/ubus.sock\x00nvram_get\x00REQUEST_METHOD\x00"
    )
    return root


def _lighttpd_config() -> str:
    return (
        'var.home = "/www/services"\n'
        'var.socket-dir = "/tmp"\n'
        'fastcgi.server = (\n'
        '  "/services/device_manager/" => ("localhost" =>\n'
        '    ( "socket" => socket-dir + "/device_manager-" + PID + ".socket",\n'
        '      "bin-path" => home + "/device_manager/device_manager.fcgi",\n'
        '      "max-procs" => 1\n'
        "    )\n"
        "  )\n"
        ")\n"
    )
