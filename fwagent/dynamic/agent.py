from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.config import DynamicConfig, DynamicAgentSettings, load_dynamic_config
from fwagent.dynamic.models import (
    VALID_DYNAMIC_HYPOTHESIS_STATUSES,
    DynamicEvidence,
    DynamicHypothesis,
)
from fwagent.dynamic.workspace import DynamicWorkspace
from fwagent.model.diagnostics import (
    AgentExecutionTrace,
    ProviderBackedAgentRun,
    classify_provider_error,
    count_validation_requests,
    extract_evidence_ids,
    now_utc,
    provider_metadata,
    summarize_tool_arguments,
)
from fwagent.model.config import CONFIGURED_MESSAGE, ModelConfig, ModelConfigError
from fwagent.model.provider import ModelProviderError


SYSTEM_PROMPT = """You are performing dynamic validation of an IoT firmware hypothesis.

The goal is runtime behavior observation, not exploitation. You must not generate
exploit payloads, fuzz inputs, brute-force credentials, or access the public
Internet.

Available tools:
{tools}

Workflow:
1. read the static hypothesis and its missing evidence
2. translate static evidence into a dynamic validation context
3. inspect the selected hypothesis and context with read-only tools
4. create a DynamicValidationPlan
4. choose a controlled runtime backend
5. run bounded SafeValidationInput requests
6. collect BehaviorObservation and BehaviorDifferential artifacts
7. finalize the validation verdict

A port being open or HTTP responding is runtime reachability evidence only. It is
NOT a validated vulnerability. validated requires static evidence plus runtime
reachability plus directly relevant behavior.

Return ONLY a JSON object:
{{"reason": "short rationale", "tool": "dynamic.tool_name", "arguments": {{...}}, "stop": false}}

Set stop to true when no useful dynamic action remains."""


class DynamicValidationAgent:
    def __init__(
        self,
        workspace_root: str | Path,
        task_id: str,
        *,
        config: DynamicConfig | None = None,
        model: Any = None,
        model_info: dict[str, str] | None = None,
        hypothesis_id: str | None = None,
        service: str | None = None,
    ):
        self.workspace = DynamicWorkspace(workspace_root, task_id)
        self.config = config or load_dynamic_config()
        self.model = model
        self.model_info = dict(model_info or {})
        self.hypothesis_id = hypothesis_id
        self.service = service
        self.api = DynamicToolAPI(workspace_root, task_id, config=self.config)
        self.tool_trace: list[dict[str, Any]] = []
        self.execution_trace: list[AgentExecutionTrace] = []
        self.steps = 0
        self.stop_reason = "completed"
        self.model_error: str | None = None
        self.report_error: str | None = None
        try:
            self.static_report = self.workspace.load_report()
        except Exception as exc:  # noqa: BLE001
            self.static_report = {}
            self.report_error = str(exc)
        self.started_at = now_utc()
        self.run_id = f"PAR-{int(time.time() * 1000)}"

    def run(self) -> dict[str, Any]:
        if self.model is None:
            raise ModelConfigError(CONFIGURED_MESSAGE)
        self._run_loop()
        if self.config.shutdown.always_stop_after_task:
            self.api._stop_firmware({})
        self._finalize_hypothesis()
        output = self._summary()
        self._save_outputs(output)
        return output

    def dry_run(self, model_config: ModelConfig | None = None) -> dict[str, Any]:
        errors = []
        if self.report_error:
            errors.append(f"analysis report unavailable: {self.report_error}")
        if not self.workspace.resolve_firmware():
            errors.append("firmware path not found")
        model_info: dict[str, Any] = {
            "provider": None,
            "model": None,
            "base_url": None,
            "api_key_present": False,
        }
        if model_config is not None:
            model_info = model_config.safe_dict()
            try:
                model_config.require_credentials()
            except ModelConfigError as exc:
                errors.append(str(exc).splitlines()[0])
        else:
            errors.append("model configuration not available")
        return {
            "ready": not errors,
            "task": self.workspace.task_id,
            "backend": self.config.backend,
            "hypothesis": self.hypothesis_id,
            "service": self.service,
            "model": model_info,
            "tools": list(self.api.tools),
            "limits": {
                "steps": self.config.agent.max_steps,
                "http_requests": self.config.agent.max_http_requests,
                "port_probes": self.config.agent.max_port_probes,
                "log_reads": self.config.agent.max_log_reads,
            },
            "errors": errors,
        }

    def _run_loop(self) -> None:
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT.format(tools=self._tool_descriptions())},
            {"role": "user", "content": self._initial_prompt()},
        ]
        malformed = 0
        while self.steps < self.config.agent.max_steps:
            try:
                response = self.model.chat(messages, max_tokens=800)
            except ModelProviderError as exc:
                self.stop_reason = "model_error"
                self.model_error = f"{classify_provider_error(exc.code, str(exc))}: {exc}"
                break
            except Exception as exc:  # noqa: BLE001
                self.stop_reason = "model_error"
                self.model_error = str(exc)
                break
            if not response.get("success"):
                self.stop_reason = "model_error"
                self.model_error = str(response.get("error") or "model request failed")
                break
            action = _parse_action(response.get("content", ""))
            if action is None:
                malformed += 1
                messages.append(
                    {
                        "role": "user",
                        "content": "Previous response was not valid JSON. Return only JSON with reason, tool, arguments, stop.",
                    }
                )
                if malformed >= 2:
                    self.stop_reason = "invalid_model_output"
                continue
            if action.get("stop"):
                self.stop_reason = "model_stopped"
                break
            tool_name = str(action.get("tool") or "")
            args = action.get("arguments") or {}
            reason = str(action.get("reason") or "")
            start = time.monotonic()
            result = self.api.execute(tool_name, args)
            duration = round(time.monotonic() - start, 3)
            self.steps += 1
            self.tool_trace.append(
                {
                    "step": self.steps,
                    "tool": tool_name,
                    "arguments": args,
                    "reason": reason[:500],
                    "success": bool(result.get("success")),
                    "result_summary": _result_summary(result),
                    "duration": duration,
                }
            )
            self.execution_trace.append(
                AgentExecutionTrace(
                    step=self.steps,
                    timestamp=now_utc(),
                    action="tool_call",
                    tool_name=tool_name,
                    tool_arguments_summary=summarize_tool_arguments(args),
                    tool_result_summary=_result_summary(result),
                    evidence_ids=extract_evidence_ids(result),
                    decision_summary=reason[:300],
                )
            )
            messages.append(
                {
                    "role": "assistant",
                    "content": json.dumps({"tool": tool_name, "arguments": args, "reason": reason}, ensure_ascii=True),
                }
            )
            messages.append({"role": "user", "content": f"Tool result:\n{_compact_json(result)}"})
            if self._stop_after_tool():
                break
        else:
            self.stop_reason = "max_steps_reached"

    def _stop_after_tool(self) -> bool:
        evidence_types = {item.type for item in self.api.evidence}
        if evidence_types & {"validation_supported", "validation_rejected", "validation_safety_stop"}:
            self.stop_reason = "validation_finalized"
            return True
        if self.tool_trace and self.tool_trace[-1]["tool"] == "dynamic.finalize_validation":
            self.stop_reason = "validation_finalized"
            return True
        if {"boot_success", "process_running", "port_open", "http_response"} <= evidence_types:
            self.stop_reason = "runtime_reachability_confirmed"
            return True
        return False

    def _finalize_hypothesis(self) -> None:
        verdict = self._latest_validation_verdict()
        if verdict is not None:
            target = str(verdict.get("hypothesis_id") or self.hypothesis_id or "")
            hypothesis = next((item for item in self.api.hypotheses if item.id == target), None)
            if hypothesis is not None:
                hypothesis.dynamic_status = str(verdict.get("dynamic_status") or "validation_inconclusive")
                hypothesis.status = hypothesis.dynamic_status
                hypothesis.confidence = float(verdict.get("dynamic_confidence") or hypothesis.confidence)
                hypothesis.evidence_ids = list(dict.fromkeys([*hypothesis.evidence_ids, *verdict.get("evidence_ids", [])]))
                hypothesis.missing_evidence = list(verdict.get("missing_observations") or hypothesis.missing_evidence)
                self.api.workspace.save_hypotheses(self.api.hypotheses)
            return
        evidence_types = {item.type for item in self.api.evidence}
        target = self.hypothesis_id
        if target:
            hypothesis = next((item for item in self.api.hypotheses if item.id == target), None)
        else:
            hypothesis = self.api.hypotheses[0] if self.api.hypotheses else None
        if hypothesis is None:
            hypothesis = DynamicHypothesis(
                id="H-0001",
                title="Dynamic runtime validation of lighttpd service reachability",
                status="candidate",
                confidence=0.4,
                missing_evidence=["runtime reachability", "service availability", "input reachability"],
                static_status="candidate",
            )
            self.api.hypotheses.append(hypothesis)
        if {"boot_success", "process_running", "port_open", "http_response"} <= evidence_types:
            hypothesis.status = "dynamically_supported"
            hypothesis.dynamic_status = "dynamically_supported"
            hypothesis.confidence = 0.7
            hypothesis.evidence_ids = [item.id for item in self.api.evidence if item.type in {"boot_success", "process_running", "port_open", "http_response"}]
            hypothesis.missing_evidence = ["vulnerability-specific runtime behavior", "dynamic confirmation of a security impact"]
            hypothesis.next_actions = []
        elif evidence_types & {"boot_failure", "validation_blocked"}:
            hypothesis.status = "validation_blocked"
            hypothesis.dynamic_status = "validation_blocked"
            hypothesis.confidence = 0.5
            hypothesis.evidence_ids = [item.id for item in self.api.evidence if item.type in {"boot_failure", "validation_blocked"}]
            hypothesis.missing_evidence = ["successful firmware boot", "runtime reachability", "service availability"]
        elif any(item.type in {"port_closed", "service_exit", "process_crash"} for item in self.api.evidence):
            hypothesis.status = "validation_inconclusive"
            hypothesis.dynamic_status = "validation_inconclusive"
            hypothesis.confidence = 0.5
            hypothesis.evidence_ids = [item.id for item in self.api.evidence]
        else:
            hypothesis.status = "candidate"
            hypothesis.dynamic_status = "not_tested"
            hypothesis.missing_evidence = ["runtime reachability", "service availability", "input reachability"]
        self.api.workspace.save_hypotheses(self.api.hypotheses)

    def _summary(self) -> dict[str, Any]:
        return {
            "success": True,
            "status": "complete",
            "task_id": self.workspace.task_id,
            "model": self.model_info,
            "hypothesis": self.hypothesis_id,
            "backend": self.config.backend,
            "service": self.service,
            "steps": self.steps,
            "tool_calls": len(self.tool_trace),
            "tool_trace": self.tool_trace,
            "stop_reason": self.stop_reason,
            "model_error": self.model_error,
            "evidence_count": len(self.api.evidence),
            "hypothesis_count": len(self.api.hypotheses),
            "evidence": [item.to_dict() for item in self.api.evidence],
            "hypotheses": [item.to_dict() for item in self.api.hypotheses],
            "emulation_state": self.api.state.to_dict(),
            "validation_verdict": self._latest_validation_verdict(),
            "agent_run": self._agent_run_record().to_dict(),
        }

    def _save_outputs(self, output: dict[str, Any]) -> None:
        self.workspace.save_tool_trace(self.tool_trace)
        path = self.workspace.dynamic_dir / "validation.json"
        path.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        self.workspace.save_validation_artifact("agent", "agent_run.json", output["agent_run"])
        self.workspace.save_validation_artifact("agent", "agent_execution_trace.json", [item.to_dict() for item in self.execution_trace])

    def _initial_prompt(self) -> str:
        report = self.static_report
        hypotheses = [item.to_dict() for item in self.api.hypotheses]
        selected = next((item for item in hypotheses if item["id"] == self.hypothesis_id), hypotheses[0] if hypotheses else None)
        state = {
            "firmware": report.get("firmware", {}),
            "platform": report.get("platform", {}),
            "services": report.get("services", [])[:10],
            "web": report.get("web", {}),
            "priority_binaries": report.get("priority_binaries", [])[:5],
            "selected_hypothesis": selected,
            "selected_service": self.service,
        }
        return (
            f"Task: {self.workspace.task_id}\n\n"
            f"Existing Round 1/2 state:\n{json.dumps(state, ensure_ascii=True, indent=2)[:20000]}"
            "\n\nFirst inspect the selected hypothesis, static-dynamic context, priority assessment, validation budget, and queue with read-only tools, then choose controlled validation tools. The deterministic scheduler owns priority scores and budget constraints; do not assume the verdict in advance."
        )

    def _tool_descriptions(self) -> str:
        return "\n".join(f"- {name}: {spec.description}" for name, spec in self.api.tools.items())

    def _agent_run_record(self) -> ProviderBackedAgentRun:
        model_config = getattr(self.model, "config", None)
        metadata = provider_metadata(model_config).to_dict() if model_config is not None else {}
        verdict = self._latest_validation_verdict()
        evidence = [item.to_dict() for item in self.api.evidence]
        runtime_backend = None
        validation_root = self.workspace.dynamic_dir / "validation"
        if validation_root.exists():
            plans = []
            for path in validation_root.glob("DV-*/plan.json"):
                try:
                    plans.append((path.stat().st_mtime, json.loads(path.read_text(encoding="utf-8"))))
                except (OSError, json.JSONDecodeError):
                    continue
            if plans:
                plans.sort(key=lambda item: item[0], reverse=True)
                runtime_backend = plans[0][1].get("runtime_backend")
        provider_backed = bool(model_config is not None and not self.model_info.get("mock"))
        stop_reason = {
            "validation_finalized": "completed",
            "max_steps_reached": "max_steps",
            "model_error": "provider_error",
            "runtime_blocked": "runtime_blocked",
        }.get(self.stop_reason, self.stop_reason if self.stop_reason in {"completed", "model_stopped", "timeout", "safety_stop"} else "completed")
        return ProviderBackedAgentRun(
            run_id=self.run_id,
            provider=getattr(model_config, "provider", None) or self.model_info.get("provider"),
            model=getattr(model_config, "model", None) or self.model_info.get("model"),
            provider_backed=provider_backed,
            hypothesis_id=self.hypothesis_id or "",
            started_at=self.started_at,
            finished_at=now_utc(),
            steps=self.steps,
            tool_calls=len(self.tool_trace),
            validation_requests=count_validation_requests(evidence),
            evidence_ids=[item["id"] for item in evidence],
            final_verdict=verdict,
            stop_reason=stop_reason,
            model_error=self.model_error,
            runtime_backend=runtime_backend,
            safety_stop=bool(verdict and verdict.get("stop_reason") == "safety_stop"),
            metadata=metadata,
            trace=[item.to_dict() for item in self.execution_trace],
        )

    def _latest_validation_verdict(self) -> dict[str, Any] | None:
        validation_root = self.workspace.dynamic_dir / "validation"
        if not validation_root.exists():
            return None
        verdicts: list[tuple[float, dict[str, Any]]] = []
        for path in validation_root.glob("DV-*/verdict.json"):
            try:
                verdicts.append((path.stat().st_mtime, json.loads(path.read_text(encoding="utf-8"))))
            except (OSError, json.JSONDecodeError):
                continue
        if not verdicts:
            return None
        verdicts.sort(key=lambda item: item[0], reverse=True)
        return verdicts[0][1]


def _parse_action(content: str) -> dict[str, Any] | None:
    text = (content or "").strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    try:
        data = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _result_summary(result: dict[str, Any]) -> str:
    if not result.get("success"):
        return "; ".join(result.get("errors", []) or ["failed"])[:500]
    data = result.get("result")
    if isinstance(data, dict) and data:
        return json.dumps(data, ensure_ascii=True)[:800]
    return str(data or "success")[:300]


def _compact_json(result: dict[str, Any]) -> str:
    return json.dumps(_compact(result), ensure_ascii=True)[:12000]


def _compact(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _compact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_compact(item) for item in value[:50]]
    if isinstance(value, str) and len(value) > 2000:
        return value[:2000] + "..."
    return value
