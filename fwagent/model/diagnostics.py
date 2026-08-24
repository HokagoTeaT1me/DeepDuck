from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from fwagent.model.config import ModelConfig, ModelConfigError
from fwagent.model.provider import ModelProvider, ModelProviderError
from fwagent.model.redaction import redact_text


MODEL_PROVIDER_STATUSES = {
    "ready",
    "missing_credentials",
    "invalid_credentials",
    "provider_rejected",
    "model_unavailable",
    "network_unavailable",
    "approval_required",
    "rate_limited",
    "configuration_error",
    "unsupported_tool_calling",
    "timeout",
    "unknown_error",
}

AGENT_STOP_REASONS = {
    "completed",
    "model_stopped",
    "max_steps",
    "max_tool_calls",
    "request_budget",
    "runtime_blocked",
    "provider_error",
    "tool_error",
    "safety_stop",
    "timeout",
}


class ChatProvider(Protocol):
    config: ModelConfig

    def chat(self, messages: list[dict[str, Any]], *, max_tokens: int = 256, temperature: float = 0.0) -> dict[str, Any]: ...


@dataclass
class ToolCallingCapability:
    supported: str = "unknown"
    tool_requested: bool = False
    tool_name: str | None = None
    continuation_ok: bool = False
    details: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModelProviderMetadata:
    provider: str | None
    model: str | None
    endpoint_type: str | None
    tool_calling_supported: str = "unknown"
    temperature: float = 0.0
    max_tokens: int = 256
    timeout: int = 30
    api_key_present: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModelProviderStatus:
    status: str
    provider: str | None = None
    model: str | None = None
    credentials_configured: bool = False
    endpoint_configured: bool = False
    connection: str = "unknown"
    structured_output: str = "unknown"
    tool_calling: ToolCallingCapability = field(default_factory=ToolCallingCapability)
    failure_category: str | None = None
    details: str = ""
    metadata: ModelProviderMetadata | None = None

    def __post_init__(self) -> None:
        if self.status not in MODEL_PROVIDER_STATUSES:
            raise ValueError(f"invalid model provider status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.metadata is not None:
            data["metadata"] = self.metadata.to_dict()
        data["tool_calling"] = self.tool_calling.to_dict()
        return data


@dataclass
class AgentExecutionTrace:
    step: int
    timestamp: str
    action: str
    tool_name: str
    tool_arguments_summary: dict[str, Any]
    tool_result_summary: str
    evidence_ids: list[str] = field(default_factory=list)
    decision_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProviderBackedAgentRun:
    run_id: str
    provider: str | None
    model: str | None
    provider_backed: bool
    hypothesis_id: str
    started_at: str
    finished_at: str | None = None
    steps: int = 0
    tool_calls: int = 0
    validation_requests: int = 0
    evidence_ids: list[str] = field(default_factory=list)
    final_verdict: dict[str, Any] | None = None
    stop_reason: str = "completed"
    model_error: str | None = None
    runtime_backend: str | None = None
    safety_stop: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    trace: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.stop_reason not in AGENT_STOP_REASONS:
            raise ValueError(f"invalid agent stop reason: {self.stop_reason}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class ProviderSmokeRunner:
    def __init__(self, provider: ChatProvider, *, timeout: int = 30, max_retries: int = 1):
        self.provider = provider
        self.timeout = timeout
        self.max_retries = max(0, int(max_retries))

    def doctor(self) -> ModelProviderStatus:
        config = self.provider.config
        metadata = provider_metadata(config, timeout=self.timeout)
        try:
            config.require_credentials()
        except ModelConfigError as exc:
            return ModelProviderStatus(
                status="missing_credentials",
                provider=config.provider or None,
                model=config.model or None,
                credentials_configured=bool(config.api_key.strip()),
                endpoint_configured=bool((config.base_url or "").strip()),
                connection="fail",
                failure_category="missing_credentials",
                details=str(exc).splitlines()[0],
                metadata=metadata,
            )
        return ModelProviderStatus(
            status="ready",
            provider=config.provider,
            model=config.model,
            credentials_configured=True,
            endpoint_configured=bool(config.base_url),
            connection="not_tested",
            metadata=metadata,
        )

    def run_all(self) -> ModelProviderStatus:
        status = self.doctor()
        if status.status != "ready":
            return status
        completion = self.completion_smoke()
        if not completion.get("success"):
            return self._failed_status(completion)
        structured = self.structured_smoke()
        if not structured.get("success"):
            failed = self._failed_status(structured)
            failed.connection = "pass"
            failed.structured_output = "fail"
            return failed
        tool = self.tool_calling_smoke()
        if tool.supported != "supported":
            status.status = "unsupported_tool_calling"
            status.failure_category = "unsupported_tool_calling"
            status.connection = "pass"
            status.structured_output = "pass"
            status.tool_calling = tool
            status.details = tool.details
            if status.metadata:
                status.metadata.tool_calling_supported = tool.supported
            return status
        status.connection = "pass"
        status.structured_output = "pass"
        status.tool_calling = tool
        status.details = "provider completion, structured output, and DeepDuck JSON tool protocol smoke passed"
        if status.metadata:
            status.metadata.tool_calling_supported = tool.supported
        return status

    def completion_smoke(self) -> dict[str, Any]:
        return self._chat_with_retry(
            [{"role": "user", "content": "Return exactly: FWAGENT_MODEL_OK"}],
            max_tokens=128,
            validator=lambda content: "FWAGENT_MODEL_OK" in content,
            phase="completion",
        )

    def structured_smoke(self) -> dict[str, Any]:
        return self._chat_with_retry(
            [
                {
                    "role": "user",
                    "content": 'Return only this JSON object with no markdown: {"status":"ok","component":"fwagent"}',
                }
            ],
            max_tokens=256,
            validator=_valid_structured_smoke,
            phase="structured_output",
        )

    def tool_calling_smoke(self) -> ToolCallingCapability:
        first = self._chat_with_retry(
            [
                {
                    "role": "system",
                    "content": "You can request exactly one safe tool by returning JSON only. Available tool: validation.get_status. Return {\"tool\":\"validation.get_status\",\"arguments\":{}} when useful.",
                },
                {"role": "user", "content": "Check DeepDuck validation status using the available tool."},
            ],
            max_tokens=384,
            validator=lambda content: _extract_json(content).get("tool") == "validation.get_status",
            phase="tool_request",
        )
        if not first.get("success"):
            return ToolCallingCapability(supported="unsupported", details=first.get("error") or "model did not request validation.get_status")
        continuation = self._chat_with_retry(
            [
                {"role": "assistant", "content": first["content"]},
                {"role": "user", "content": 'Tool result: {"status":"ready","safe":true}. Return only JSON: {"done":true}'},
            ],
            max_tokens=256,
            validator=lambda content: bool(_extract_json(content).get("done") is True),
            phase="tool_continuation",
        )
        supported = "supported" if continuation.get("success") else "unsupported"
        return ToolCallingCapability(
            supported=supported,
            tool_requested=True,
            tool_name="validation.get_status",
            continuation_ok=bool(continuation.get("success")),
            details="tool protocol smoke passed" if continuation.get("success") else continuation.get("error", "tool continuation failed"),
        )

    def _chat_with_retry(self, messages: list[dict[str, Any]], *, max_tokens: int, validator, phase: str) -> dict[str, Any]:
        attempts = 0
        while True:
            try:
                result = self.provider.chat(messages, max_tokens=max_tokens, temperature=0.0)
            except ModelProviderError as exc:
                category = classify_provider_error(exc.code, str(exc))
                if category in _NON_RETRYABLE or attempts >= self.max_retries:
                    return {"success": False, "phase": phase, "category": category, "code": exc.code, "error": str(exc), "attempts": attempts + 1}
                attempts += 1
                time.sleep(min(0.5 * attempts, 2.0))
                continue
            content = str(result.get("content") or "")
            if not validator(content):
                return {"success": False, "phase": phase, "category": "unknown_error", "error": f"unexpected model response: {content[:120]}", "attempts": attempts + 1}
            return {"success": True, "phase": phase, "content": content[:500], "model": result.get("model"), "duration": result.get("duration"), "attempts": attempts + 1}

    def _failed_status(self, result: dict[str, Any]) -> ModelProviderStatus:
        config = self.provider.config
        category = str(result.get("category") or "unknown_error")
        status = category if category in MODEL_PROVIDER_STATUSES else "unknown_error"
        return ModelProviderStatus(
            status=status,
            provider=config.provider,
            model=config.model,
            credentials_configured=bool(config.api_key.strip()),
            endpoint_configured=bool(config.base_url),
            connection="fail",
            failure_category=category,
            details=redact_text(str(result.get("error") or result), [config.api_key]),
            metadata=provider_metadata(config, timeout=self.timeout),
        )


def provider_metadata(config: ModelConfig, *, timeout: int = 30, tool_calling_supported: str = "unknown") -> ModelProviderMetadata:
    endpoint = (config.base_url or "").rstrip("/")
    if endpoint.endswith("/chat/completions"):
        endpoint_type = "chat_completions"
    elif endpoint:
        endpoint_type = "openai_compatible_base"
    else:
        endpoint_type = None
    return ModelProviderMetadata(
        provider=config.provider or None,
        model=config.model or None,
        endpoint_type=endpoint_type,
        tool_calling_supported=tool_calling_supported,
        timeout=timeout,
        api_key_present=bool(config.api_key.strip()),
    )


def classify_provider_error(code: str, message: str = "") -> str:
    text = f"{code} {message}".lower()
    if code == "MODEL_CONFIG_MISSING":
        return "missing_credentials"
    if code == "MODEL_AUTH_FAILED":
        return "invalid_credentials"
    if code == "MODEL_RATE_LIMITED":
        return "rate_limited"
    if code in {"MODEL_NOT_FOUND", "MODEL_UNAVAILABLE"}:
        return "model_unavailable"
    if code == "MODEL_CONNECTION_TIMEOUT":
        return "timeout"
    if "approval" in text or "rejected" in text or "forbidden by its access permissions" in text or "winerror 10013" in text:
        return "approval_required"
    if code == "MODEL_CONNECTION_ERROR":
        return "network_unavailable"
    if code in {"MODEL_REQUEST_INVALID", "MODEL_RESPONSE_INVALID"}:
        return "configuration_error"
    if "provider rejected" in text:
        return "provider_rejected"
    return "unknown_error"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def summarize_tool_arguments(args: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key, value in args.items():
        if key in {"body", "headers", "parameters"}:
            summary[key] = f"<{key} omitted>"
        elif isinstance(value, str) and len(value) > 120:
            summary[key] = value[:120] + "..."
        else:
            summary[key] = value
    return summary


def extract_evidence_ids(result: dict[str, Any]) -> list[str]:
    found: list[str] = []
    data = json.dumps(result, ensure_ascii=True)
    import re

    for match in re.findall(r"DE-\d{4}", data):
        if match not in found:
            found.append(match)
    return found


def count_validation_requests(evidence: list[dict[str, Any]]) -> int:
    return sum(1 for item in evidence if item.get("type") in {"baseline_response", "validation_request"})


def _extract_json(content: str) -> dict[str, Any]:
    text = (content or "").strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return {}
    try:
        value = json.loads(text[start : end + 1])
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _valid_structured_smoke(content: str) -> bool:
    data = _extract_json(content)
    return data.get("status") == "ok" and data.get("component") == "fwagent"


_NON_RETRYABLE = {
    "missing_credentials",
    "invalid_credentials",
    "approval_required",
    "model_unavailable",
    "configuration_error",
    "unsupported_tool_calling",
}
