from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from fwagent.cli import build_parser
from fwagent.dynamic.agent import DynamicValidationAgent
from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.config import DynamicConfig, DynamicValidationSettings
from fwagent.dynamic.models import DYNAMIC_EVIDENCE_TYPES, DynamicHypothesis
from fwagent.dynamic.validation import (
    BehaviorObservation,
    DynamicValidationPlan,
    SafeValidationInput,
    build_static_dynamic_context,
    compare_behavior,
    decide_verdict,
    default_safe_inputs,
    ensure_loopback_url,
    response_signature,
    validate_safe_input,
)


class StubBackend:
    name = "service-qemu"

    def __init__(self) -> None:
        self.calls = []

    def stop(self):
        return {"success": True}

    def validate_fastcgi_integration(self, backend="device_manager", **kwargs):
        self.calls.append((backend, kwargs))
        observations = []
        for item in kwargs.get("safe_inputs") or []:
            body = "Unknown SOAP action" if item.get("category") != "invalid_value" else "Different safe SOAP fault"
            observations.append(
                {
                    "input_id": item.get("input_id"),
                    "category": item.get("category"),
                    "probe": {
                        "status": 500,
                        "headers": {"Content-Type": "text/xml", "Server": "lighttpd/1.4.26"},
                        "body_preview": body,
                        "duration": 0.01,
                    },
                    "backend_alive_after": True,
                    "lighttpd_alive_after": True,
                    "errors": [],
                }
            )
        return {
            "success": True,
            "diagnosis": "fastcgi_integration_reachable",
            "backend_child": {"alive_after_startup": True},
            "request_observations": observations,
            "logs": {},
        }


class FakeModel:
    def __init__(self, actions):
        self.actions = list(actions)

    def chat(self, messages, max_tokens=800):
        if not self.actions:
            return {"success": True, "content": json.dumps({"stop": True, "reason": "done"})}
        return {"success": True, "content": json.dumps(self.actions.pop(0))}


class Round4Tests(unittest.TestCase):
    def _workspace(self):
        tmp = tempfile.TemporaryDirectory()
        root = Path(tmp.name)
        task = root / "task"
        (task / "reports").mkdir(parents=True)
        (task / "hypotheses").mkdir(parents=True)
        report = {
            "security_candidates": [
                {"id": "SE-0001", "function": "soap_handler", "description": "Unknown SOAP action string reference"}
            ],
            "priority_binaries": [{"path": "/www/services/device_manager/device_manager.fcgi"}],
            "services": [{"name": "lighttpd"}],
            "firmware": {"filename": "dummy.bin"},
        }
        (task / "reports" / "analysis.json").write_text(json.dumps(report), encoding="utf-8")
        (task / "hypotheses" / "hypotheses.json").write_text(
            json.dumps(
                [
                    {
                        "id": "H-FCGI",
                        "title": "Specific SOAP request handling reaches device_manager.fcgi application logic and different malformed action values produce distinguishable application-level behavior.",
                        "status": "supported",
                        "confidence": 0.6,
                        "evidence_ids": ["SE-0001"],
                    },
                    {
                        "id": "H-RET2TEXT",
                        "title": "Ret2text stack overflow in main can redirect execution to secure shell function",
                        "status": "supported",
                        "confidence": 0.7,
                        "evidence_ids": [],
                    },
                ]
            ),
            encoding="utf-8",
        )
        return tmp, root

    def _api(self, root, *, validation_settings=None):
        config = DynamicConfig(backend="service-qemu")
        if validation_settings is not None:
            config = replace(config, validation=validation_settings)
        return DynamicToolAPI(root, "task", config=config, backend=StubBackend())

    def test_dynamic_validation_plan(self):
        plan = DynamicValidationPlan(validation_id="DV-0001", hypothesis_id="H-1", request_budget=2)
        self.assertFalse(plan.destructive)
        self.assertEqual(plan.risk_level, "low")
        with self.assertRaises(ValueError):
            DynamicValidationPlan(validation_id="DV-0002", hypothesis_id="H-1", destructive=True)

    def test_safe_validation_input(self):
        item = SafeValidationInput(input_id="VI-1", method="POST", path="/services/device_manager/", body="x", category="boundary_small")
        self.assertGreater(item.size_bytes, 0)
        with self.assertRaises(ValueError):
            SafeValidationInput(input_id="VI-2", path="http://example.com/")

    def test_behavior_observation(self):
        sig = response_signature({"status": 500, "headers": {"Content-Type": "text/xml"}, "body_preview": "Unknown SOAP action"}, max_preview=8)
        obs = BehaviorObservation("BO-1", "DV-1", "VI-1", http_status=500, response_signature=sig.to_dict())
        self.assertEqual(obs.response_signature["known_error"], "unknown_soap_action")
        self.assertEqual(len(obs.response_signature["body_preview"]), 8)

    def test_behavior_differential(self):
        base = BehaviorObservation("BO-1", "DV-1", "VI-1", http_status=500, response_signature={"body_hash": "a"}, process_alive_after=True)
        var = BehaviorObservation("BO-2", "DV-1", "VI-2", http_status=500, response_signature={"body_hash": "b"}, process_alive_after=True)
        diff = compare_behavior(base, var)
        self.assertTrue(diff.body_changed)
        self.assertEqual(diff.relevance, "medium")

    def test_static_dynamic_bridge_fastcgi(self):
        ctx = build_static_dynamic_context(
            {"id": "H-FCGI", "title": "SOAP handler reaches device_manager FastCGI"},
            [{"id": "SE-1", "function": "soap_handler", "string": "Unknown SOAP action"}],
            {},
        )
        self.assertEqual(ctx.runtime_backend, "fastcgi-integration")
        self.assertEqual(ctx.known_endpoint, "/services/device_manager/")

    def test_static_dynamic_bridge_ret2text(self):
        ctx = build_static_dynamic_context({"id": "H-R", "title": "ret2text gets stack"}, [{"function": "main"}], {})
        self.assertEqual(ctx.runtime_backend, "process-stdin")

    def test_hypothesis_state_transition(self):
        tmp, root = self._workspace()
        with tmp:
            api = self._api(root)
            plan = api.execute("dynamic.create_validation_plan", {"hypothesis_id": "H-FCGI"})
            self.assertTrue(plan["success"])
            hyp = next(item for item in api.hypotheses if item.id == "H-FCGI")
            self.assertEqual(hyp.static_status, "supported")
            self.assertEqual(hyp.dynamic_status, "validation_planned")

    def test_supported_verdict(self):
        plan = DynamicValidationPlan("DV-1", "H-1", validation_strategy="handler_reachability")
        obs = [BehaviorObservation("BO-1", "DV-1", "VI-1", http_status=500, response_signature={"known_error": "unknown_soap_action"}, process_alive_after=True)]
        verdict = decide_verdict(plan, obs, [])
        self.assertEqual(verdict.dynamic_status, "dynamically_supported")

    def test_rejected_verdict(self):
        plan = DynamicValidationPlan("DV-1", "H-1", contradictory_observations=["handler absent"])
        obs = [BehaviorObservation("BO-1", "DV-1", "VI-1", http_status=404, response_signature={"body_hash": "x"}, process_alive_after=True)]
        verdict = decide_verdict(plan, obs, [])
        self.assertEqual(verdict.dynamic_status, "dynamically_rejected")

    def test_inconclusive_verdict(self):
        plan = DynamicValidationPlan("DV-1", "H-1", validation_strategy="service_reachability")
        obs = [BehaviorObservation("BO-1", "DV-1", "VI-1", process_alive_after=True)]
        verdict = decide_verdict(plan, obs, [])
        self.assertEqual(verdict.dynamic_status, "validation_inconclusive")

    def test_blocked_verdict(self):
        plan = DynamicValidationPlan("DV-1", "H-1")
        verdict = decide_verdict(plan, [], [], blocked=True)
        self.assertEqual(verdict.dynamic_status, "validation_blocked")

    def test_validation_safety_stop(self):
        plan = DynamicValidationPlan("DV-1", "H-1")
        obs = [BehaviorObservation("BO-1", "DV-1", "VI-1", side_effect_detected=True)]
        verdict = decide_verdict(plan, obs, [], safety_stop=True)
        self.assertEqual(verdict.stop_reason, "safety_stop")

    def test_request_budget(self):
        tmp, root = self._workspace()
        with tmp:
            api = self._api(root)
            created = api.execute("dynamic.create_validation_plan", {"hypothesis_id": "H-FCGI", "request_budget": 1})
            vid = created["result"]["plan"]["validation_id"]
            result = api.execute("dynamic.run_safe_validation", {"validation_id": vid, "inputs": [SafeValidationInput("VI-1").to_dict(), SafeValidationInput("VI-2").to_dict()]})
            self.assertFalse(result["success"])
            self.assertIn("request budget", result["errors"][0])

    def test_tool_call_budget(self):
        tmp, root = self._workspace()
        with tmp:
            settings = DynamicValidationSettings(max_tool_calls=1)
            api = self._api(root, validation_settings=settings)
            self.assertTrue(api.execute("dynamic.get_emulation_status", {})["success"])
            self.assertFalse(api.execute("dynamic.get_emulation_status", {})["success"])

    def test_timeout_setting_propagates_to_plan(self):
        tmp, root = self._workspace()
        with tmp:
            settings = DynamicValidationSettings(timeout_seconds=7)
            api = self._api(root, validation_settings=settings)
            created = api.execute("dynamic.create_validation_plan", {"hypothesis_id": "H-FCGI"})
            self.assertEqual(created["result"]["plan"]["timeout_seconds"], 7)

    def test_loopback_enforcement(self):
        self.assertTrue(ensure_loopback_url("http://127.0.0.1:3000/"))
        self.assertTrue(ensure_loopback_url("https://localhost/"))

    def test_public_ip_rejected(self):
        tmp, root = self._workspace()
        with tmp:
            api = self._api(root)
            result = api.execute("dynamic.probe_http", {"url": "http://8.8.8.8/"})
            self.assertFalse(result["success"])

    def test_arbitrary_url_rejected(self):
        tmp, root = self._workspace()
        with tmp:
            api = self._api(root)
            result = api.execute("dynamic.probe_http", {"url": "http://example.com/"})
            self.assertFalse(result["success"])

    def test_oversized_request_rejected(self):
        item = SafeValidationInput("VI-1", method="POST", path="/x", body="A" * 20, category="boundary_small")
        self.assertTrue(validate_safe_input(item, max_request_bytes=10, max_body_bytes=10))

    def test_forbidden_tools_unavailable(self):
        tmp, root = self._workspace()
        with tmp:
            tools = set(self._api(root).tools)
            forbidden = {"shell", "bash", "cmd", "powershell", "docker", "subprocess", "raw_qemu", "raw_strace"}
            self.assertFalse(tools & forbidden)

    def test_response_preview_truncation(self):
        sig = response_signature({"status": 200, "headers": {}, "body_preview": "abcdef"}, max_preview=3)
        self.assertEqual(sig.body_preview, "abc")

    def test_evidence_linkage(self):
        tmp, root = self._workspace()
        with tmp:
            api = self._api(root)
            created = api.execute("dynamic.create_validation_plan", {"hypothesis_id": "H-FCGI"})
            vid = created["result"]["plan"]["validation_id"]
            run = api.execute("dynamic.run_safe_validation", {"validation_id": vid})
            metadata = [item.metadata for item in api.evidence if item.type in {"baseline_response", "validation_request"}]
            self.assertTrue(run["success"])
            self.assertTrue(all(item.get("validation_id") == vid and item.get("hypothesis_id") == "H-FCGI" for item in metadata))

    def test_cli_wiring(self):
        commands = build_parser()._subparsers._group_actions[0].choices
        self.assertIn("validate-hypothesis", commands)
        self.assertIn("validation-status", commands)
        self.assertIn("validation-report", commands)

    def test_agent_tool_registration(self):
        tmp, root = self._workspace()
        with tmp:
            agent = DynamicValidationAgent(root, "task", config=DynamicConfig(backend="service-qemu"), hypothesis_id="H-FCGI")
            self.assertIn("dynamic.create_validation_plan", agent.api.tools)
            self.assertIn("dynamic.run_safe_validation", agent.api.tools)
            self.assertIn("dynamic.finalize_validation", agent.api.tools)

    def test_no_shell_tool(self):
        tmp, root = self._workspace()
        with tmp:
            tools = "\n".join(self._api(root).tools)
            self.assertNotIn("shell", tools)

    def test_no_arbitrary_subprocess(self):
        tmp, root = self._workspace()
        with tmp:
            tools = "\n".join(self._api(root).tools)
            self.assertNotIn("subprocess", tools)

    def test_agent_runs_round4_tool_sequence(self):
        tmp, root = self._workspace()
        with tmp:
            actions = [
                {"reason": "plan", "tool": "dynamic.create_validation_plan", "arguments": {"hypothesis_id": "H-FCGI"}, "stop": False},
                {"reason": "run", "tool": "dynamic.run_safe_validation", "arguments": {"validation_id": "DV-0001"}, "stop": False},
                {"reason": "finalize", "tool": "dynamic.finalize_validation", "arguments": {"validation_id": "DV-0001"}, "stop": False},
            ]
            agent = DynamicValidationAgent(root, "task", config=DynamicConfig(backend="service-qemu"), model=FakeModel(actions), hypothesis_id="H-FCGI")
            agent.api.backend = StubBackend()
            result = agent.run()
            self.assertEqual(result["stop_reason"], "validation_finalized")
            self.assertEqual([item["tool"] for item in result["tool_trace"]], ["dynamic.create_validation_plan", "dynamic.run_safe_validation", "dynamic.finalize_validation"])
            self.assertEqual(result["validation_verdict"]["dynamic_status"], "dynamically_supported")

    def test_round4_evidence_types_registered(self):
        for evidence_type in [
            "validation_plan_created",
            "runtime_ready",
            "baseline_response",
            "validation_request",
            "behavior_difference",
            "handler_reached",
            "application_response",
            "validation_supported",
            "validation_rejected",
            "validation_inconclusive",
            "validation_blocked",
        ]:
            self.assertIn(evidence_type, DYNAMIC_EVIDENCE_TYPES)


if __name__ == "__main__":
    unittest.main()
