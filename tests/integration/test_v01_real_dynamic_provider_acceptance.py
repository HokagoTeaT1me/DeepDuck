from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from fwagent.dynamic.api import DynamicToolAPI


WORKSPACE = Path("workspace")
DYNAMIC_TASK = WORKSPACE / "v0_1-final-dynamic-01"
PROVIDER_TASK = WORKSPACE / "v0_1-provider-01"


class V01RealDynamicProviderAcceptanceTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get("DEEPDUCK_RUN_REAL_DYNAMIC_TESTS") == "1", "real dynamic acceptance disabled")
    def test_real_fastcgi_runtime_observation_is_canonical(self) -> None:
        evidence_path = DYNAMIC_TASK / "dynamic" / "evidence" / "evidence.json"
        integration_path = DYNAMIC_TASK / "dynamic" / "application" / "device_manager" / "integration_validation.json"
        self.assertTrue(evidence_path.exists(), f"missing dynamic evidence: {evidence_path}")
        self.assertTrue(integration_path.exists(), f"missing integration artifact: {integration_path}")

        evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
        integration = json.loads(integration_path.read_text(encoding="utf-8"))
        real_runtime = [
            item
            for item in evidence
            if item.get("execution_mode") == "real" and item.get("runtime_observation_real")
        ]

        self.assertTrue(integration["success"])
        self.assertEqual(integration["diagnosis"], "fastcgi_integration_reachable")
        self.assertTrue(integration["application_response_reached"])
        self.assertGreaterEqual(len(real_runtime), 1)
        self.assertIn("fastcgi_application_response", {item["type"] for item in real_runtime})
        request_text = json.dumps(integration.get("request_observations", []))
        for token in ("$(", "`", "&&", "||", "/bin/sh", "cmd.exe", "powershell"):
            self.assertNotIn(token, request_text)

    @unittest.skipUnless(os.environ.get("DEEPDUCK_RUN_REAL_DYNAMIC_TESTS") == "1", "real dynamic acceptance disabled")
    def test_real_dynamic_tools_do_not_expose_raw_execution(self) -> None:
        api = DynamicToolAPI(WORKSPACE, "v0_1-final-dynamic-01")
        forbidden = {
            "shell",
            "bash",
            "cmd",
            "powershell",
            "subprocess",
            "docker",
            "qemu-system-arm",
            "arbitrary_url_fetch",
            "force_canonical_update",
            "disable_safety",
            "override_budget",
        }
        self.assertFalse(set(api.tools) & forbidden)

    @unittest.skipUnless(os.environ.get("DEEPDUCK_RUN_REAL_PROVIDER_TESTS") == "1", "real provider acceptance disabled")
    def test_real_provider_smoke_cli_ready(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "fwagent.cli", "model-smoke", "--timeout", "30", "--max-retries", "1"],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "ready")
        self.assertEqual(payload["connection"], "pass")
        self.assertEqual(payload["structured_output"], "pass")
        self.assertEqual(payload["tool_calling"]["supported"], "supported")
        self.assertNotIn("Authorization", result.stdout)

    @unittest.skipUnless(os.environ.get("DEEPDUCK_RUN_REAL_PROVIDER_TESTS") == "1", "real provider acceptance disabled")
    def test_real_provider_agent_artifact_is_provider_backed(self) -> None:
        agent_path = PROVIDER_TASK / "dynamic" / "validation" / "agent" / "agent_run.json"
        self.assertTrue(agent_path.exists(), f"missing provider agent artifact: {agent_path}")
        agent = json.loads(agent_path.read_text(encoding="utf-8"))

        self.assertTrue(agent["provider_backed"])
        self.assertGreater(agent["tool_calls"], 0)
        self.assertFalse(agent["safety_stop"])
        self.assertIsNone(agent["model_error"])
        self.assertNotIn("chain_of_thought", json.dumps(agent).lower())


if __name__ == "__main__":
    unittest.main()
