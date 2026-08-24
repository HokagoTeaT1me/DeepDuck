from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.cli import build_parser
from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.application import (
    FastCGIRuntimeSnapshot,
    classify_fastcgi_child_failure,
    compare_fastcgi_runtime_snapshots,
)
from fwagent.dynamic.backend import _lighttpd_external_fastcgi
from fwagent.dynamic.models import DYNAMIC_EVIDENCE_TYPES
from fwagent.dynamic.service import RuntimeRepair


class Round35Backend:
    name = "round35-stub"

    def get_fastcgi_runtime_context(self, backend="device_manager", *, mode="standalone", timeout_seconds=10):
        snapshot = _snapshot(mode=mode)
        return {"success": True, "backend": backend, "mode": mode, "snapshot": snapshot.to_dict()}

    def compare_fastcgi_runtime(self, backend="device_manager"):
        diff = compare_fastcgi_runtime_snapshots(_snapshot(mode="standalone"), _snapshot(mode="lighttpd"))
        return {"success": True, "backend": backend, "diff": diff.to_dict()}

    def get_fastcgi_child_failure(self, backend="device_manager", *, stability_seconds=5):
        return {
            "success": True,
            "backend": backend,
            "classification": classify_fastcgi_child_failure(
                exit_code=182,
                signal=None,
                stderr="child exited with status 182 /www/services/device_manager/device_manager.fcgi",
            ),
        }

    def validate_fastcgi_integration(self, backend="device_manager", *, endpoint="/services/device_manager/", stability_seconds=3):
        return {
            "success": True,
            "backend": backend,
            "endpoint": endpoint,
            "runtime_repair": {"id": "RR-3501", "type": "external_fastcgi_lifecycle_parity", "source_rootfs_modified": False},
            "backend_child": {"started": True, "alive_after_startup": True},
            "lighttpd": {"started": True, "alive_after_startup": True},
            "probe": {"status": 500, "body_preview": "Unknown SOAP action"},
            "application_response_reached": True,
        }


def _snapshot(mode: str) -> FastCGIRuntimeSnapshot:
    standalone = mode == "standalone"
    return FastCGIRuntimeSnapshot(
        mode=mode,
        backend="device_manager",
        executable="/www/services/device_manager/device_manager.fcgi",
        argv=["qemu-arm-static", "/www/services/device_manager/device_manager.fcgi"] if standalone else ["lighttpd", "device_manager.fcgi"],
        cwd="/www/services/device_manager" if standalone else "/",
        uid=None if standalone else 0,
        gid=None if standalone else 0,
        environment={"PATH": "/bin", "REQUEST_URI": "/services/device_manager/"} if standalone else {"PATH": "/sbin"},
        stdin={"fd": 0, "role": "FCGI_LISTENSOCK_FILENO"} if standalone else {"fd": 0, "role": "FCGI_LISTENSOCK_FILENO"},
        stdout={"fd": 1, "role": "stdout"},
        stderr={"fd": 2, "role": "stderr"},
        fastcgi_listener_fd=0,
        socket_type="AF_UNIX/SOCK_STREAM",
        socket_address="/tmp/fwagent-device_manager.socket" if standalone else "/tmp/device_manager-${PID}.socket",
        filesystem_root="/tmp/rootfs",
        writable_directories=["/tmp", "/var/run"],
        required_files=["/www/services/device_manager/device_manager.fcgi"],
        config_files=["/etc/lighttpd/lighttpd.conf"],
        parent_process={"service": "fwagent_harness" if standalone else "lighttpd"},
        process_hierarchy=["proot", "qemu-user", "device_manager.fcgi"] if standalone else ["proot", "qemu-user", "lighttpd", "device_manager.fcgi"],
    )


class Round35Tests(unittest.TestCase):
    def test_runtime_snapshot_serialization(self) -> None:
        data = _snapshot("standalone").to_dict()
        self.assertEqual(data["mode"], "standalone")
        self.assertEqual(data["fastcgi_listener_fd"], 0)
        self.assertIn("/tmp", data["writable_directories"])

    def test_runtime_diff_covers_argv_env_cwd_fd_and_socket(self) -> None:
        diff = compare_fastcgi_runtime_snapshots(_snapshot("standalone"), _snapshot("lighttpd")).to_dict()
        fields = {item["field"] for item in diff["differences"]}
        self.assertIn("argv", fields)
        self.assertIn("environment", fields)
        self.assertIn("cwd", fields)
        self.assertIn("socket", fields)
        self.assertIn("parent_process", fields)

    def test_exit_182_classification_is_not_signal(self) -> None:
        result = classify_fastcgi_child_failure(
            exit_code=182,
            signal=None,
            stderr="child exited with status 182 /www/services/device_manager/device_manager.fcgi",
        )
        self.assertEqual(result["category"], "fastcgi_child_unknown_exit")
        self.assertIn("linux_process_exit_status_182", result["confirmed"])
        self.assertIn("exact application branch producing exit 182", result["unknown"])

    def test_signal_classification_is_distinct_from_exit_code(self) -> None:
        result = classify_fastcgi_child_failure(exit_code=None, signal=15)
        self.assertEqual(result["category"], "fastcgi_child_signal_exit")
        self.assertIn("terminated_by_signal_15", result["confirmed"])

    def test_runtime_repair_serialization(self) -> None:
        repair = RuntimeRepair(
            id="RR-3501",
            type="external_fastcgi_lifecycle_parity",
            target="/etc/lighttpd/lighttpd.fwagent-fastcgi-external.conf",
            reason="preserve routing while using verified external FastCGI child lifecycle",
            source_evidence=["runtime_diff.json", "harness_result.json"],
        ).to_dict()
        self.assertEqual(repair["id"], "RR-3501")
        self.assertTrue(repair["reversible"])

    def test_external_fastcgi_repair_does_not_mutate_source_config(self) -> None:
        original = 'server.modules = ( "mod_fastcgi" )\nfastcgi.server = ( "/old" => (( "bin-path" => "/bin/app" )) )\n'
        repaired = _lighttpd_external_fastcgi(
            original,
            socket_guest="/tmp/fwagent-device_manager.socket",
            endpoint="/services/device_manager/",
        )
        self.assertIn("fwagent-device_manager.socket", repaired)
        self.assertIn("check-local", repaired)
        self.assertIn('"mod_fastcgi"', original)
        self.assertIn('"bin-path"', original)

    def test_round35_evidence_types_are_allowed(self) -> None:
        for evidence_type in (
            "fastcgi_runtime_context",
            "fastcgi_runtime_difference",
            "fastcgi_child_started",
            "fastcgi_child_exit",
            "fastcgi_request_received",
            "fastcgi_application_response",
            "fastcgi_integration_reachable",
            "fastcgi_validation_blocked",
            "fastcgi_validation_inconclusive",
        ):
            self.assertIn(evidence_type, DYNAMIC_EVIDENCE_TYPES)

    def test_round35_tools_are_registered_without_forbidden_raw_access(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            api = DynamicToolAPI(Path(tmp), "task", backend=Round35Backend())
            names = set(api.tools)
        for tool in (
            "dynamic.get_fastcgi_runtime_context",
            "dynamic.compare_fastcgi_runtime",
            "dynamic.get_fastcgi_child_failure",
            "dynamic.validate_fastcgi_integration",
        ):
            self.assertIn(tool, names)
        for forbidden in ("shell", "bash", "subprocess", "docker", "qemu-system-arm", "strace"):
            self.assertNotIn(forbidden, names)

    def test_round35_api_evidence_creation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            api = DynamicToolAPI(Path(tmp), "task", backend=Round35Backend())
            diff = api.execute("dynamic.compare_fastcgi_runtime", {"backend": "device_manager"})
            failure = api.execute("dynamic.get_fastcgi_child_failure", {"backend": "device_manager"})
            integration = api.execute("dynamic.validate_fastcgi_integration", {"backend": "device_manager"})
            evidence_types = {item.type for item in api.evidence}
        self.assertTrue(diff["success"])
        self.assertTrue(failure["success"])
        self.assertTrue(integration["success"])
        self.assertIn("fastcgi_runtime_difference", evidence_types)
        self.assertIn("fastcgi_child_exit", evidence_types)
        self.assertIn("fastcgi_integration_reachable", evidence_types)

    def test_blocked_and_inconclusive_semantics_are_available(self) -> None:
        self.assertIn("fastcgi_validation_blocked", DYNAMIC_EVIDENCE_TYPES)
        self.assertIn("fastcgi_validation_inconclusive", DYNAMIC_EVIDENCE_TYPES)

    def test_cli_wiring(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["fastcgi-diff", "task", "device_manager"])
        self.assertEqual(args.command, "fastcgi-diff")
        args = parser.parse_args(["fastcgi-child-status", "task"])
        self.assertEqual(args.command, "fastcgi-child-status")
        args = parser.parse_args(["fastcgi-integration-validate", "task", "--endpoint", "/services/device_manager/"])
        self.assertEqual(args.command, "fastcgi-integration-validate")


if __name__ == "__main__":
    unittest.main()
