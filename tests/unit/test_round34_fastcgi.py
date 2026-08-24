from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.application import (
    FastCGILaunchProfile,
    compare_runtime_contexts,
    infer_direct_context,
    infer_fastcgi_context,
    infer_startup_stages,
)
from fwagent.dynamic.fastcgi_harness import (
    default_fastcgi_params,
    encode_begin_request,
    encode_params,
    encode_stdin,
    parse_fastcgi_response,
)
from fwagent.dynamic.models import DYNAMIC_EVIDENCE_TYPES


class Round34Backend:
    name = "round34-stub"

    def get_fastcgi_launch_profile(self, backend="device_manager"):
        return {"success": True, "backend": backend, "binary": "/www/services/device_manager/device_manager.fcgi"}

    def get_direct_application_context(self, backend="device_manager", *, timeout_seconds=10):
        return {
            "success": True,
            "backend": backend,
            "context": infer_direct_context(
                ["/usr/bin/qemu-arm-static", "/www/services/device_manager/device_manager.fcgi"],
                '100 execve("/www/services/device_manager/device_manager.fcgi",{"/www/services/device_manager/device_manager.fcgi",NULL}) = 0\n'
                "100 getuid32() = 0\n"
                "100 getgid32() = 0\n",
                environment={"PATH": "/bin"},
            ).to_dict(),
        }

    def get_fastcgi_application_context(self, backend="device_manager", *, timeout_seconds=10):
        profile = FastCGILaunchProfile(
            binary="/www/services/device_manager/device_manager.fcgi",
            environment={"PATH": "/sbin", "FCGI_ROLE": "RESPONDER"},
        )
        trace = (
            '200 chdir("/www/services/device_manager") = 0\n'
            '200 execve("/www/services/device_manager/device_manager.fcgi",{"/www/services/device_manager/device_manager.fcgi",NULL}) = 0\n'
            "200 getuid32() = 0\n"
            "200 getgid32() = 0\n"
            "201 SIGCHLD {si_pid=200, si_status=182}\n"
        )
        return {"success": True, "backend": backend, "context": infer_fastcgi_context(trace, profile).to_dict()}

    def compare_application_runtime_contexts(self, backend="device_manager"):
        direct = self.get_direct_application_context(backend)["context"]
        fastcgi = self.get_fastcgi_application_context(backend)["context"]
        result = compare_runtime_contexts(
            infer_direct_context([], "", cwd=direct["cwd"], environment=direct["environment"]),
            infer_fastcgi_context(
                'chdir("/www/services/device_manager") = 0\nexecve("/www/services/device_manager/device_manager.fcgi",{}) = 0\n',
                FastCGILaunchProfile(
                    binary="/www/services/device_manager/device_manager.fcgi",
                    environment=fastcgi["environment"],
                ),
            ),
        )
        return {"success": True, "backend": backend, "diff": result}

    def get_application_startup_graph(self, backend="device_manager"):
        stages = infer_startup_stages(
            'execve("/www/services/device_manager/device_manager.fcgi",{}) = 0\nsocket(AF_UNIX, SOCK_STREAM, 0) = 3\n'
            "SIGCHLD {si_status=182}\n",
            "spawning fcgi failed",
        )
        return {"success": True, "backend": backend, "stages": [stage.to_dict() for stage in stages]}

    def start_fastcgi_harness(self, backend="device_manager", *, endpoint="/services/device_manager/", timeout_seconds=10):
        return {
            "success": True,
            "backend_started": True,
            "backend_alive": True,
            "socket_ready": True,
            "request_sent": True,
            "response_received": True,
            "response_status_hint": 404,
            "backend": backend,
            "endpoint": endpoint,
        }


class Round34FastCGITests(unittest.TestCase):
    def test_runtime_context_diff_captures_fastcgi_fd_and_cwd(self) -> None:
        direct = infer_direct_context(
            ["/usr/bin/qemu-arm-static", "/www/services/device_manager/device_manager.fcgi"],
            'execve("/www/services/device_manager/device_manager.fcgi",{}) = 0\ngetuid32() = 0\ngetgid32() = 0\n',
            cwd="/",
            environment={"PATH": "/bin"},
        )
        fastcgi = infer_fastcgi_context(
            'chdir("/www/services/device_manager") = 0\n'
            'execve("/www/services/device_manager/device_manager.fcgi",{}) = 0\n'
            "getuid32() = 0\n"
            "getgid32() = 0\n"
            "SIGCHLD {si_pid=33, si_status=182}\n",
            FastCGILaunchProfile(
                binary="/www/services/device_manager/device_manager.fcgi",
                environment={"PATH": "/sbin", "FCGI_ROLE": "RESPONDER"},
            ),
        )

        diff = compare_runtime_contexts(direct, fastcgi)

        self.assertTrue(diff["cwd_diff"]["different"])
        self.assertTrue(diff["fd_diff"]["different"])
        self.assertEqual(fastcgi.listen_socket_fd, 0)
        self.assertEqual(fastcgi.parent_pid, 33)

    def test_fastcgi_frame_helpers_roundtrip_response_status(self) -> None:
        request = encode_begin_request() + encode_params(default_fastcgi_params()) + encode_stdin()
        self.assertGreater(len(request), 24)
        response = parse_fastcgi_response(
            b"\x01\x06\x00\x01\x00\x17\x01\x00Status: 404 Not Found\n\x00"
            b"\x01\x03\x00\x01\x00\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        )
        self.assertEqual(response["status_hint"], 404)
        self.assertIn("Status: 404", response["stdout"])

    def test_startup_graph_marks_182_block_before_request_loop(self) -> None:
        stages = infer_startup_stages(
            'execve("/www/services/device_manager/device_manager.fcgi",{}) = 0\nsocket(AF_UNIX, SOCK_STREAM, 0) = 3\n'
            "SIGCHLD {si_status=182}\n",
            "spawning fcgi failed",
        )
        by_name = {stage.name: stage for stage in stages}
        self.assertTrue(by_name["runtime_init"].entered)
        self.assertFalse(by_name["socket_init"].completed)
        self.assertFalse(by_name["fastcgi_init"].completed)

    def test_round34_tool_registration_and_evidence_types(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            api = DynamicToolAPI(Path(tmp), "task", backend=Round34Backend())
            names = set(api.tools)

        for tool in (
            "application.get_direct_context",
            "application.get_fastcgi_context",
            "application.compare_runtime_contexts",
            "application.trace_backend_startup",
            "application.get_startup_graph",
            "application.build_fastcgi_harness",
            "application.start_fastcgi_harness",
            "application.send_fastcgi_request",
            "application.get_fastcgi_result",
        ):
            self.assertIn(tool, names)
        for forbidden in ("shell", "bash", "subprocess", "docker", "qemu-system-arm"):
            self.assertNotIn(forbidden, names)
        for evidence_type in (
            "fastcgi_context_difference",
            "fastcgi_fd_missing",
            "fastcgi_socket_ready",
            "fastcgi_socket_failure",
            "fastcgi_backend_alive",
            "fastcgi_request_sent",
            "fastcgi_response_received",
            "fastcgi_init_failure",
            "fastcgi_exit_code_explained",
        ):
            self.assertIn(evidence_type, DYNAMIC_EVIDENCE_TYPES)

    def test_round34_api_handlers_generate_structured_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            api = DynamicToolAPI(Path(tmp), "task", backend=Round34Backend())
            direct = api.execute("application.get_direct_context", {"backend": "device_manager"})
            fastcgi = api.execute("application.get_fastcgi_context", {"backend": "device_manager"})
            diff = api.execute("application.compare_runtime_contexts", {"backend": "device_manager"})
            graph = api.execute("application.get_startup_graph", {"backend": "device_manager"})
            harness = api.execute("application.start_fastcgi_harness", {"backend": "device_manager"})

        self.assertTrue(direct["success"])
        self.assertTrue(fastcgi["success"])
        self.assertTrue(diff["success"])
        self.assertTrue(graph["success"])
        self.assertTrue(harness["success"])


if __name__ == "__main__":
    unittest.main()
