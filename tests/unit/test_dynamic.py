from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from fwagent.dynamic.agent import DynamicValidationAgent
from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.backend import FirmAEBackend, QEMUBackend, create_backend
from fwagent.dynamic.backend import DockerQemuBackend
from fwagent.dynamic.config import DynamicConfig, DynamicNetworkSettings, DynamicValidationSettings, load_dynamic_config
from fwagent.dynamic.models import DynamicEvidence, EmulationState
from fwagent.dynamic.workspace import DynamicWorkspace


class StubBackend:
    name = "stub"

    def __init__(self):
        self.stopped = False

    def prepare(self, firmware_path):
        return {"success": True, "prepared": str(firmware_path)}

    def boot(self, firmware_path, *, timeout=300):
        return {"success": True, "duration": 0.1}

    def status(self):
        return {"success": True, "status": "running"}

    def stop(self):
        self.stopped = True
        return {"success": True, "stopped": True}

    def logs(self, limit=200):
        return ["stub log"]

    def check_environment(self):
        return {"success": True}


class StubFailingBackend(StubBackend):
    def boot(self, firmware_path, *, timeout=300):
        return {"success": False, "errors": ["timed out"], "diagnosis": "timeout", "duration": 0.2}


class FakeModel:
    def __init__(self, actions):
        self.actions = list(actions)

    def chat(self, messages, **kwargs):
        action = self.actions.pop(0) if self.actions else {"reason": "done", "stop": True}
        return {"success": True, "content": json.dumps(action)}


class DynamicTests(unittest.TestCase):
    def test_loads_dynamic_config(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dynamic.yaml"
            path.write_text(
                "\n".join(
                    [
                        "dynamic:",
                        "  backend: qemu",
                        "  boot:",
                        "    timeout_seconds: 12",
                        "dynamic_agent:",
                        "  max_steps: 7",
                    ]
                ),
                encoding="utf-8",
            )
            config = load_dynamic_config(path)

        self.assertEqual(config.backend, "qemu")
        self.assertEqual(config.boot.timeout_seconds, 12)
        self.assertEqual(config.agent.max_steps, 7)

    def test_backend_selection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsInstance(create_backend(DynamicConfig(backend="qemu"), Path(tmp)), DockerQemuBackend)
            backend = create_backend(DynamicConfig(backend="firmae"), Path(tmp))
            self.assertTrue(isinstance(backend, (DockerQemuBackend, FirmAEBackend)))

    def test_state_transitions(self) -> None:
        state = EmulationState(backend="firmae")
        state.transition("preparing")
        state.transition("booting")
        state.transition("running")
        state.transition("stopped")
        self.assertEqual(state.status, "stopped")
        with self.assertRaises(ValueError):
            state.transition("unknown")

    def test_dynamic_evidence_serialization(self) -> None:
        evidence = DynamicEvidence(
            id="DE-0001",
            type="boot_success",
            target="http://192.168.0.1:80",
            observation="HTTP service responded with status 200",
            source_tool="http_probe",
            confidence=1.0,
        )
        data = evidence.to_dict()
        self.assertEqual(data["id"], "DE-0001")
        self.assertEqual(data["type"], "boot_success")
        self.assertIn("timestamp", data)

    def test_tool_registration_is_controlled(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            api = DynamicToolAPI(Path(tmp), "task", backend=StubBackend())
            names = set(api.tools)

        self.assertIn("dynamic.boot_firmware", names)
        self.assertIn("dynamic.probe_http", names)
        for forbidden in ("shell", "bash", "subprocess", "docker", "qemu-system-arm", "firmae"):
            self.assertNotIn(forbidden, names)

    def test_http_limit_and_port_restrictions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            config = DynamicConfig(
                network=DynamicNetworkSettings(probe_timeout_seconds=1),
                validation=DynamicValidationSettings(max_http_requests=0),
            )
            api = DynamicToolAPI(Path(tmp), "task", config=config, backend=StubBackend())
            limited = api.execute("dynamic.probe_http", {"url": "http://192.168.1.1/", "method": "GET"})
            self.assertFalse(limited["success"])
            self.assertIn("max_http_requests", limited["errors"][0])

            api = DynamicToolAPI(Path(tmp), "task", backend=StubBackend())
            public = api.execute("dynamic.probe_tcp", {"host": "8.8.8.8", "port": 80})
            self.assertFalse(public["success"])
            self.assertIn("private/emulated", public["errors"][0])
            post = api.execute("dynamic.probe_http", {"url": "http://192.168.1.1/", "method": "POST"})
            self.assertFalse(post["success"])
            self.assertIn("GET/HEAD", post["errors"][0])

    def test_boot_failure_creates_evidence_and_failure_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = root / "task"
            (task / "reports").mkdir(parents=True)
            firmware = task / "firmware.bin"
            firmware.write_bytes(b"\x1f\x8b")
            (task / "reports" / "analysis.json").write_text(
                json.dumps({"firmware": {"path": str(firmware)}, "extraction": {"rootfs": None}}),
                encoding="utf-8",
            )
            api = DynamicToolAPI(root, "task", backend=StubFailingBackend())

            result = api.execute("dynamic.boot_firmware", {})

            self.assertFalse(result["success"])
            self.assertEqual(api.state.status, "failed")
            self.assertTrue(any(item.type == "validation_blocked" for item in api.evidence))

    def test_dynamic_agent_respects_step_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = root / "task"
            (task / "reports").mkdir(parents=True)
            firmware = task / "firmware.bin"
            firmware.write_bytes(b"\x1f\x8b")
            (task / "reports" / "analysis.json").write_text(
                json.dumps({"firmware": {"path": str(firmware)}, "extraction": {"rootfs": None}}),
                encoding="utf-8",
            )
            backend = StubBackend()
            config = DynamicConfig(backend="stub")
            config = DynamicConfig(
                backend="stub",
                agent=config.agent.__class__(max_steps=1),
                shutdown=config.shutdown.__class__(always_stop_after_task=False),
            )
            agent = DynamicValidationAgent(
                root,
                "task",
                config=config,
                model=FakeModel(
                    [
                        {"reason": "status", "tool": "dynamic.get_emulation_status", "arguments": {}, "stop": False},
                        {"reason": "stop", "stop": True},
                    ]
                ),
                model_info={"provider": "test", "model": "test-model"},
            )
            agent.api = DynamicToolAPI(root, "task", config=config, backend=backend)

            result = agent.run()

            self.assertEqual(result["steps"], 1)
            self.assertEqual(result["stop_reason"], "max_steps_reached")
            self.assertTrue((root / "task" / "dynamic" / "tool_trace.json").exists())


if __name__ == "__main__":
    unittest.main()
