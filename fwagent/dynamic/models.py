from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


EMULATION_STATUSES = ("not_started", "preparing", "booting", "running", "failed", "stopped")

DYNAMIC_EVIDENCE_TYPES = {
    "boot_success",
    "boot_failure",
    "validation_blocked",
    "validation_inconclusive",
    "process_running",
    "process_started",
    "port_open",
    "port_closed",
    "service_reachable",
    "http_response",
    "runtime_error",
    "runtime_log_observed",
    "process_crash",
    "service_exit",
    "log_observation",
    "request_response_difference",
    "service_start_success",
    "service_start_failure",
    "service_process_alive",
    "service_process_exit",
    "service_port_listening",
    "service_reachable",
    "service_http_response",
    "runtime_dependency_missing",
    "nvram_dependency",
    "config_dependency",
    "backend_start_success",
    "backend_start_failure",
    "backend_socket_ready",
    "backend_dependency_missing",
    "backend_nvram_dependency",
    "backend_ipc_dependency",
    "endpoint_discovered",
    "endpoint_backend_link",
    "endpoint_reachable",
    "application_endpoint_reachable",
    "fastcgi_context_difference",
    "fastcgi_fd_missing",
    "fastcgi_socket_ready",
    "fastcgi_socket_failure",
    "fastcgi_backend_alive",
    "fastcgi_request_sent",
    "fastcgi_response_received",
    "fastcgi_init_failure",
    "fastcgi_exit_code_explained",
    "fastcgi_runtime_context",
    "fastcgi_runtime_difference",
    "fastcgi_child_started",
    "fastcgi_child_exit",
    "fastcgi_request_received",
    "fastcgi_application_response",
    "fastcgi_integration_reachable",
    "fastcgi_validation_blocked",
    "fastcgi_validation_inconclusive",
    "validation_plan_created",
    "runtime_ready",
    "baseline_response",
    "validation_request",
    "behavior_difference",
    "handler_reached",
    "application_response",
    "request_received",
    "protocol_response",
    "validation_supported",
    "validation_rejected",
    "validation_safety_stop",
    "entry_point_discovered",
    "route_discovered",
    "listener_observed",
    "entry_runtime_confirmed",
    "handler_reachable",
    "hypothesis_reachable",
    "entry_validation_blocked",
    "entry_validation_inconclusive",
    "taint_source_discovered",
    "sensitive_sink_discovered",
    "taint_path_candidate",
    "taint_path_supported",
    "taint_runtime_correlated",
    "taint_validation_blocked",
    "taint_validation_inconclusive",
    "hypothesis_candidate_generated",
    "hypothesis_candidate_promoted",
    "hypothesis_candidate_rejected",
    "finding_candidate_grouped",
}

CANONICAL_RUNTIME_OBSERVATION_TYPES = {
    "process_running",
    "process_started",
    "port_open",
    "service_reachable",
    "http_response",
    "service_start_success",
    "service_process_alive",
    "service_port_listening",
    "service_http_response",
    "backend_start_success",
    "backend_socket_ready",
    "fastcgi_socket_ready",
    "fastcgi_backend_alive",
    "fastcgi_request_sent",
    "fastcgi_response_received",
    "fastcgi_child_started",
    "fastcgi_request_received",
    "fastcgi_application_response",
    "fastcgi_integration_reachable",
    "runtime_ready",
    "baseline_response",
    "validation_request",
    "handler_reached",
    "application_response",
    "request_received",
    "protocol_response",
    "listener_observed",
    "entry_runtime_confirmed",
    "handler_reachable",
    "runtime_log_observed",
    "behavior_difference",
    "request_response_difference",
}


def is_canonical_runtime_evidence(item: "DynamicEvidence | dict[str, Any]") -> bool:
    data = item.to_dict() if isinstance(item, DynamicEvidence) else item
    return bool(
        data.get("type") in CANONICAL_RUNTIME_OBSERVATION_TYPES
        and data.get("execution_mode") == "real"
        and data.get("runtime_observation_real") is True
        and data.get("provenance") == "real_runtime_observation"
        and not data.get("provider_backed")
    )

VALID_DYNAMIC_HYPOTHESIS_STATUSES = {
    "candidate",
    "investigating",
    "supported",
    "rejected",
    "inconclusive",
    "not_tested",
    "validation_planned",
    "validation_running",
    "dynamically_supported",
    "dynamically_rejected",
    "validation_blocked",
    "validation_inconclusive",
    "validated",
}


@dataclass
class EmulationState:
    backend: str
    status: str = "not_started"
    architecture: str | None = None
    boot_started_at: str | None = None
    boot_completed_at: str | None = None
    ip_addresses: list[str] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    processes: list[dict[str, Any]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    errors: list[dict[str, Any]] = field(default_factory=list)

    def transition(self, status: str) -> None:
        if status not in EMULATION_STATUSES:
            raise ValueError(f"invalid emulation status: {status}")
        self.status = status

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DynamicEvidence:
    id: str
    type: str
    observation: str
    source_tool: str
    confidence: float
    target: str | None = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)
    provenance: str = "real_runtime_observation"
    execution_mode: str = "real"
    provider_backed: bool = False
    runtime_observation_real: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DynamicHypothesis:
    id: str
    title: str
    status: str
    confidence: float
    cwe: str | None = None
    evidence_ids: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)
    static_status: str | None = None
    dynamic_status: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
