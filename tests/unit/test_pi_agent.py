from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from fwagent.config import AgentSettings, GhidraSettings, Round2Config
from fwagent.investigation import PiAgent
from fwagent.model.config import ModelConfig


class StubBinaryTools:
    def __init__(self) -> None:
        self.decompile_calls = 0

    def get_binary_summary(self, binary):
        return {
            "success": True,
            "tool": "ghidra.get_binary_summary",
            "binary": str(binary),
            "result": {"summary": {"binary": str(binary), "function_count": 3, "language": "x86:LE:32"}},
        }

    def decompile_function(self, binary, function):
        self.decompile_calls += 1
        return {
            "success": True,
            "tool": "ghidra.decompile_function",
            "binary": str(binary),
            "result": {"name": function, "decompiled_code": "int main() { return 0; }"},
        }


class FakeModel:
    def __init__(self, actions: list[dict[str, Any]]):
        self.actions = list(actions)
        self.calls = 0

    def chat(self, messages, **kwargs):
        self.calls += 1
        action = self.actions.pop(0) if self.actions else {"reason": "done", "stop": True}
        return {"success": True, "content": json.dumps(action)}


class PiAgentTests(unittest.TestCase):
    def _make_agent(self, workspace, task_id, actions, *, max_steps=10, max_decompilations=5):
        task = workspace / task_id
        rootfs = task / "rootfs"
        binary = rootfs / "bin" / "app"
        binary.parent.mkdir(parents=True)
        binary.write_bytes(b"\x7fELF" + b"\x00" * 60)
        (task / "reports").mkdir(parents=True)
        (task / "reports" / "analysis.json").write_text(
            json.dumps(
                {
                    "extraction": {"rootfs": str(rootfs)},
                    "priority_binaries": [{"path": "/bin/app", "score": 50, "reasons": ["test"]}],
                    "services": [],
                    "web": {"roots": [], "cgi": []},
                    "firmware": {"filename": "app.bin"},
                    "platform": {"architecture": "x86"},
                }
            ),
            encoding="utf-8",
        )
        config = Round2Config(
            ghidra=GhidraSettings(home=Path("missing-ghidra"), minimum_priority_score=30),
            agent=AgentSettings(max_steps=max_steps, max_binary_analyses=1, max_decompilations_per_binary=max_decompilations),
        )
        agent = PiAgent(workspace, task_id, config=config, model=FakeModel(actions))
        agent.binary_tools = StubBinaryTools()
        agent.sanity_check = lambda: {
            "workspace_exists": True,
            "analysis_json_exists": True,
            "priority_binary_exists": True,
            "ghidra_tool_api_callable": True,
        }
        return agent

    def test_tools_do_not_register_forbidden_shell(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            agent = self._make_agent(Path(tmp), "task", [])

        names = set(agent.tools)
        for forbidden in ("shell", "bash", "subprocess", "docker", "terminal", "run_arbitrary_ghidra_script"):
            self.assertNotIn(forbidden, names)

    def test_agent_runs_tools_and_saves_trace_and_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            agent = self._make_agent(
                workspace,
                "task",
                [
                    {
                        "reason": "inspect binary",
                        "tool": "ghidra.get_binary_summary",
                        "arguments": {"binary": "/bin/app"},
                        "stop": False,
                    },
                    {
                        "reason": "record observation",
                        "tool": "evidence.create",
                        "arguments": {
                            "type": "dangerous_function_reference",
                            "binary": "/bin/app",
                            "description": "Binary references system()",
                            "source_tool": "ghidra",
                            "confidence": 0.8,
                        },
                        "stop": False,
                    },
                    {
                        "reason": "track hypothesis",
                        "tool": "hypothesis.create",
                        "arguments": {
                            "title": "Potential command execution path",
                            "cwe": "CWE-78",
                            "status": "investigating",
                            "confidence": 0.45,
                            "evidence_ids": ["E-0001"],
                            "missing_evidence": ["external input origin"],
                        },
                        "stop": False,
                    },
                    {"reason": "stop", "stop": True},
                ],
            )

            result = agent.run()

            self.assertTrue(result["success"])
            self.assertEqual(result["steps"], 3)
            self.assertEqual(result["evidence_count"], 2)
            self.assertEqual(result["hypothesis_count"], 1)
            self.assertEqual(result["stop_reason"], "model_stopped")
            task = workspace / "task"
            self.assertTrue((task / "agent" / "tool_trace.json").exists())
            self.assertTrue((task / "evidence" / "evidence.json").exists())
            self.assertTrue((task / "hypotheses" / "hypotheses.json").exists())
            trace = json.loads((task / "agent" / "tool_trace.json").read_text(encoding="utf-8"))
            self.assertEqual(len(trace), 3)
            self.assertEqual(trace[0]["tool"], "ghidra.get_binary_summary")
            self.assertEqual(trace[0]["step"], 1)

    def test_step_limit_is_respected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            agent = self._make_agent(
                workspace,
                "task",
                [
                    {
                        "reason": "inspect binary",
                        "tool": "ghidra.get_binary_summary",
                        "arguments": {"binary": "/bin/app"},
                        "stop": False,
                    }
                ],
                max_steps=1,
            )

            result = agent.run()

            self.assertEqual(result["steps"], 1)
            self.assertEqual(result["stop_reason"], "max_steps_reached")

    def test_decompilation_limit_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            agent = self._make_agent(
                workspace,
                "task",
                [
                    {
                        "reason": "decompile",
                        "tool": "ghidra.decompile_function",
                        "arguments": {"binary": "/bin/app", "function": "main"},
                        "stop": False,
                    },
                    {
                        "reason": "decompile again",
                        "tool": "ghidra.decompile_function",
                        "arguments": {"binary": "/bin/app", "function": "other"},
                        "stop": False,
                    },
                    {"reason": "stop", "stop": True},
                ],
                max_decompilations=1,
            )

            result = agent.run()

            self.assertEqual(agent.binary_tools.decompile_calls, 1)
            second = [item for item in agent.tool_trace if item["tool"] == "ghidra.decompile_function"][1]
            self.assertFalse(second["success"])
            self.assertIn("max_decompilations_per_binary", second["result_summary"])

    def test_dry_run_reports_ready_with_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            agent = self._make_agent(workspace, "task", [])
            config = ModelConfig(
                provider="P",
                model="M",
                api_key="sk-test",
                base_url="https://example.com",
            )

            result = agent.dry_run(model_config=config)

            self.assertTrue(result["ready"])
            self.assertEqual(len(result["tools"]), 14)
            self.assertTrue(result["model"]["api_key_present"])


if __name__ == "__main__":
    unittest.main()
