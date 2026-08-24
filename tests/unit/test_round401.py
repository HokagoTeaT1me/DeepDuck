from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from fwagent.cli import build_parser
from fwagent.dynamic.agent import DynamicValidationAgent
from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.config import DynamicConfig
from fwagent.model.config import ModelConfig, load_model_config_with_overrides
from fwagent.model.diagnostics import (
    AgentExecutionTrace,
    ModelProviderStatus,
    ProviderBackedAgentRun,
    ProviderSmokeRunner,
    ToolCallingCapability,
    classify_provider_error,
    provider_metadata,
)
from fwagent.model.provider import ModelProviderError


class FakeProvider:
    def __init__(self, responses=None, errors=None, config=None):
        self.config = config or ModelConfig("DeepSeek", "deepseek-v4-flash", "sk-secret", "https://api.example")
        self.responses = list(responses or [])
        self.errors = list(errors or [])
        self.calls = 0

    def chat(self, messages, *, max_tokens=256, temperature=0.0):
        self.calls += 1
        if self.errors:
            raise self.errors.pop(0)
        content = self.responses.pop(0) if self.responses else "FWAGENT_MODEL_OK"
        return {"success": True, "content": content, "model": self.config.model, "duration": 0.01}


class ScriptedModel(FakeProvider):
    def __init__(self, actions, *, config=None):
        super().__init__(config=config)
        self.actions = list(actions)

    def chat(self, messages, *, max_tokens=256, temperature=0.0):
        self.calls += 1
        if not self.actions:
            return {"success": True, "content": json.dumps({"stop": True, "reason": "done"}), "model": self.config.model, "duration": 0.01}
        return {"success": True, "content": json.dumps(self.actions.pop(0)), "model": self.config.model, "duration": 0.01}


class StubBackend:
    name = "service-qemu"

    def stop(self):
        return {"success": True}

    def validate_fastcgi_integration(self, backend="device_manager", **kwargs):
        observations = []
        for item in kwargs.get("safe_inputs") or []:
            observations.append(
                {
                    "input_id": item.get("input_id"),
                    "category": item.get("category"),
                    "probe": {
                        "status": 500,
                        "headers": {"Content-Type": "text/xml", "Server": "lighttpd/1.4.26"},
                        "body_preview": "Unknown SOAP action",
                        "duration": 0.01,
                    },
                    "backend_alive_after": True,
                    "lighttpd_alive_after": True,
                    "errors": [],
                }
            )
        return {"success": True, "diagnosis": "fastcgi_integration_reachable", "backend_child": {"alive_after_startup": True}, "request_observations": observations, "logs": {}}


class Round401Tests(unittest.TestCase):
    def _workspace(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        task = root / "task"
        (task / "reports").mkdir(parents=True)
        (task / "hypotheses").mkdir(parents=True)
        (task / "evidence").mkdir(parents=True)
        (task / "reports" / "analysis.json").write_text(json.dumps({"security_candidates": []}), encoding="utf-8")
        (task / "evidence" / "evidence.json").write_text(
            json.dumps([{"id": "SE-FCGI-0001", "function": "soap_handler", "description": "Unknown SOAP action"}]),
            encoding="utf-8",
        )
        (task / "hypotheses" / "hypotheses.json").write_text(
            json.dumps([
                {
                    "id": "H-FCGI-0001",
                    "title": "Specific SOAP request handling reaches device_manager.fcgi application logic",
                    "status": "supported",
                    "confidence": 0.6,
                    "evidence_ids": ["SE-FCGI-0001"],
                }
            ]),
            encoding="utf-8",
        )
        return tmp, root

    def test_provider_config_precedence(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "model.yaml"
            cfg.write_text("model:\n  provider: File\n  model: file-model\n  api_key: sk-file\n  base_url: https://file.example\n", encoding="utf-8")
            with patch.dict(os.environ, {"FWAGENT_MODEL_PROVIDER": "Env", "FWAGENT_MODEL_NAME": "env-model", "FWAGENT_MODEL_API_KEY": "sk-env", "FWAGENT_MODEL_BASE_URL": "https://env.example"}, clear=True):
                loaded = load_model_config_with_overrides(config_path=cfg, provider="CLI")
        self.assertEqual(loaded.provider, "CLI")
        self.assertEqual(loaded.model, "env-model")
        self.assertEqual(loaded.api_key, "sk-env")

    def test_missing_credentials(self):
        status = ProviderSmokeRunner(FakeProvider(config=ModelConfig("", "", "", None))).doctor()
        self.assertEqual(status.status, "missing_credentials")

    def test_invalid_credentials_classification(self):
        self.assertEqual(classify_provider_error("MODEL_AUTH_FAILED", "401"), "invalid_credentials")

    def test_approval_required_classification(self):
        self.assertEqual(classify_provider_error("MODEL_CONNECTION_ERROR", "WinError 10013 forbidden by its access permissions"), "approval_required")

    def test_rate_limit_classification(self):
        self.assertEqual(classify_provider_error("MODEL_RATE_LIMITED", "429"), "rate_limited")

    def test_timeout_classification(self):
        self.assertEqual(classify_provider_error("MODEL_CONNECTION_TIMEOUT", "timeout"), "timeout")

    def test_provider_metadata_serialization(self):
        metadata = provider_metadata(ModelConfig("DeepSeek", "deepseek-v4-flash", "sk", "https://api.example/v1"))
        self.assertEqual(metadata.endpoint_type, "openai_compatible_base")
        self.assertNotIn("sk", json.dumps(metadata.to_dict()))

    def test_secrets_redaction_in_status(self):
        status = ModelProviderStatus(status="ready", provider="P", model="M", credentials_configured=True, endpoint_configured=True)
        self.assertNotIn("api_key", json.dumps(status.to_dict()))

    def test_tool_calling_capability(self):
        provider = FakeProvider([
            '{"tool":"validation.get_status","arguments":{}}',
            '{"done":true}',
        ])
        cap = ProviderSmokeRunner(provider).tool_calling_smoke()
        self.assertEqual(cap.supported, "supported")
        self.assertTrue(cap.continuation_ok)

    def test_provider_retry_limit(self):
        provider = FakeProvider(["FWAGENT_MODEL_OK"], errors=[ModelProviderError("MODEL_CONNECTION_ERROR", "temporary")])
        result = ProviderSmokeRunner(provider, max_retries=1).completion_smoke()
        self.assertTrue(result["success"])
        self.assertEqual(provider.calls, 2)

    def test_non_retryable_errors(self):
        provider = FakeProvider(errors=[ModelProviderError("MODEL_AUTH_FAILED", "bad key")])
        result = ProviderSmokeRunner(provider, max_retries=3).completion_smoke()
        self.assertFalse(result["success"])
        self.assertEqual(provider.calls, 1)

    def test_agent_execution_trace(self):
        trace = AgentExecutionTrace(1, "now", "tool_call", "dynamic.get_hypothesis", {"hypothesis_id": "H"}, "ok", ["DE-0001"], "read")
        self.assertEqual(trace.to_dict()["tool_name"], "dynamic.get_hypothesis")

    def test_provider_backed_agent_run(self):
        run = ProviderBackedAgentRun("PAR-1", "DeepSeek", "deepseek-v4-flash", True, "H", "start")
        self.assertTrue(run.provider_backed)
        self.assertEqual(run.stop_reason, "completed")

    def test_provider_backed_flag(self):
        tmp, root = self._workspace()
        with tmp:
            actions = [
                {"reason": "read hypothesis", "tool": "dynamic.get_hypothesis", "arguments": {"hypothesis_id": "H-FCGI-0001"}, "stop": False},
                {"reason": "read context", "tool": "dynamic.get_static_dynamic_context", "arguments": {"hypothesis_id": "H-FCGI-0001"}, "stop": False},
                {"reason": "plan", "tool": "dynamic.create_validation_plan", "arguments": {"hypothesis_id": "H-FCGI-0001"}, "stop": False},
                {"reason": "run", "tool": "dynamic.run_safe_validation", "arguments": {"validation_id": "DV-0001"}, "stop": False},
                {"reason": "finalize", "tool": "dynamic.finalize_validation", "arguments": {"validation_id": "DV-0001"}, "stop": False},
            ]
            agent = DynamicValidationAgent(root, "task", config=DynamicConfig(backend="service-qemu"), model=ScriptedModel(actions), hypothesis_id="H-FCGI-0001")
            agent.api.backend = StubBackend()
            result = agent.run()
            self.assertTrue(result["agent_run"]["provider_backed"])

    def test_mock_provider_cannot_count_as_real_validation(self):
        tmp, root = self._workspace()
        with tmp:
            agent = DynamicValidationAgent(root, "task", config=DynamicConfig(backend="service-qemu"), model=ScriptedModel([]), model_info={"mock": True}, hypothesis_id="H-FCGI-0001")
            result = agent.run()
            self.assertFalse(result["agent_run"]["provider_backed"])

    def test_agent_stop_reasons(self):
        for reason in ["completed", "model_stopped", "max_steps", "max_tool_calls", "request_budget", "runtime_blocked", "provider_error", "tool_error", "safety_stop", "timeout"]:
            ProviderBackedAgentRun("PAR", None, None, False, "H", "start", stop_reason=reason)

    def test_forbidden_tool_registration(self):
        tmp, root = self._workspace()
        with tmp:
            tools = set(DynamicToolAPI(root, "task", config=DynamicConfig(backend="service-qemu"), backend=StubBackend()).tools)
            self.assertFalse(tools & {"shell", "bash", "cmd", "powershell", "docker", "subprocess", "raw_qemu", "raw_strace"})

    def test_public_target_guard_still_active(self):
        tmp, root = self._workspace()
        with tmp:
            api = DynamicToolAPI(root, "task", config=DynamicConfig(backend="service-qemu"), backend=StubBackend())
            self.assertFalse(api.execute("dynamic.probe_http", {"url": "http://8.8.8.8/"})["success"])

    def test_cli_model_doctor(self):
        self.assertIn("model-doctor", build_parser()._subparsers._group_actions[0].choices)

    def test_cli_model_smoke(self):
        self.assertIn("model-smoke", build_parser()._subparsers._group_actions[0].choices)

    def test_cli_agent_smoke(self):
        self.assertIn("agent-smoke", build_parser()._subparsers._group_actions[0].choices)


if __name__ == "__main__":
    unittest.main()
