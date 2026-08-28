from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse


STATIC_STATUSES = {"candidate", "supported", "rejected", "inconclusive"}
DYNAMIC_STATUSES = {
    "not_tested",
    "validation_planned",
    "validation_running",
    "dynamically_supported",
    "dynamically_rejected",
    "validation_inconclusive",
    "validation_blocked",
}
VALIDATION_STRATEGIES = {
    "service_reachability",
    "handler_reachability",
    "input_behavior_difference",
    "error_path_validation",
    "crash_observation",
    "state_transition_validation",
    "hypothesis_contradiction",
}
SAFE_INPUT_CATEGORIES = {
    "baseline",
    "empty",
    "missing_parameter",
    "invalid_value",
    "boundary_small",
    "malformed_protocol",
    "semantic_mismatch",
}
SAFE_RISK_LEVELS = {"low", "moderate"}


@dataclass
class DynamicValidationPlan:
    validation_id: str
    hypothesis_id: str
    target_binary: str | None = None
    target_service: str | None = None
    target_function: str | None = None
    runtime_backend: str = "service-qemu"
    validation_goal: str = "Observe runtime behavior relevant to the hypothesis."
    validation_strategy: str = "handler_reachability"
    required_evidence: list[str] = field(default_factory=list)
    expected_observations: list[str] = field(default_factory=list)
    contradictory_observations: list[str] = field(default_factory=list)
    preconditions: list[str] = field(default_factory=list)
    runtime_repairs: list[dict[str, Any]] = field(default_factory=list)
    request_budget: int = 3
    step_budget: int = 12
    timeout_seconds: int = 30
    risk_level: str = "low"
    destructive: bool = False
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    relevant_evidence_ids: list[str] = field(default_factory=list)
    known_endpoint: str | None = None
    known_protocol: str | None = None
    out_of_scope: list[str] = field(default_factory=list)
    backend_reason: str | None = None
    architecture: str | None = None
    endianness: str | None = None
    emulator: str | None = None
    loader: str | None = None
    rootfs_source: str | None = None
    rootfs_semantic_fidelity: str | None = None
    container_image: str | None = None
    network_isolation: str = "loopback/private-only"
    service_binary: str | None = None
    startup_method: str | None = None
    repair_ids: list[str] = field(default_factory=list)
    runtime_budget_seconds: int | None = None

    def __post_init__(self) -> None:
        if self.validation_strategy not in VALIDATION_STRATEGIES:
            raise ValueError(f"invalid validation strategy: {self.validation_strategy}")
        if self.risk_level not in SAFE_RISK_LEVELS:
            raise ValueError(f"invalid validation risk level: {self.risk_level}")
        if self.destructive:
            raise ValueError("dynamic validation plans must be non-destructive")
        self.request_budget = max(1, int(self.request_budget))
        self.step_budget = max(1, int(self.step_budget))
        self.timeout_seconds = max(1, int(self.timeout_seconds))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SafeValidationInput:
    input_id: str
    protocol: str = "http"
    method: str = "GET"
    path: str = "/"
    headers: dict[str, str] = field(default_factory=dict)
    parameters: dict[str, str] = field(default_factory=dict)
    body: str = ""
    expected_safe_effect: str = "No persistent side effect; observe response only."
    size_bytes: int = 0
    category: str = "baseline"
    source: str = "fwagent"
    hypothesis_id: str | None = None

    def __post_init__(self) -> None:
        self.protocol = self.protocol.lower()
        self.method = self.method.upper()
        self.category = self.category.lower()
        if self.protocol not in {"http", "https", "fastcgi"}:
            raise ValueError(f"invalid validation protocol: {self.protocol}")
        if self.method not in {"GET", "HEAD", "POST"}:
            raise ValueError(f"invalid validation method: {self.method}")
        if self.category not in SAFE_INPUT_CATEGORIES:
            raise ValueError(f"invalid validation input category: {self.category}")
        if not self.path.startswith("/") or "://" in self.path:
            raise ValueError("validation input path must be a local absolute path, not a URL")
        self.headers = {str(k): str(v) for k, v in self.headers.items()}
        self.parameters = {str(k): str(v) for k, v in self.parameters.items()}
        self.body = str(self.body or "")
        self.size_bytes = self.estimated_size()

    def estimated_size(self) -> int:
        return len(self.body.encode("utf-8")) + sum(len(k) + len(v) for k, v in self.headers.items()) + sum(
            len(k) + len(v) for k, v in self.parameters.items()
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResponseSignature:
    status: int | None
    content_type: str | None
    body_hash: str
    body_preview: str
    known_error: str | None = None
    server_header: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BehaviorObservation:
    observation_id: str
    validation_id: str
    input_id: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    http_status: int | None = None
    response_signature: dict[str, Any] | None = None
    response_length: int = 0
    process_alive_before: bool | None = None
    process_alive_after: bool | None = None
    service_state: str | None = None
    runtime_error: str | None = None
    log_signature: str | None = None
    duration_ms: int = 0
    side_effect_detected: bool = False
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BehaviorDifferential:
    baseline_observation_id: str
    variant_observation_id: str
    status_changed: bool = False
    body_changed: bool = False
    response_time_changed: bool = False
    process_state_changed: bool = False
    new_error: bool = False
    new_log_event: bool = False
    side_effect: bool = False
    relevance: str = "none"
    interpretation: str = "No meaningful runtime behavior difference observed."

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class StaticDynamicContext:
    hypothesis_id: str
    target_binary: str | None = None
    candidate_service: str | None = None
    candidate_functions: list[str] = field(default_factory=list)
    candidate_strings: list[str] = field(default_factory=list)
    runtime_backend: str = "service-qemu"
    known_endpoint: str | None = None
    known_protocol: str | None = None
    relevant_evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DynamicValidationVerdict:
    validation_id: str
    hypothesis_id: str
    dynamic_status: str
    dynamic_confidence: float
    reason: str
    evidence_ids: list[str] = field(default_factory=list)
    stop_reason: str = "completed"
    supported_observations: list[str] = field(default_factory=list)
    contradictory_observations: list[str] = field(default_factory=list)
    missing_observations: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.dynamic_status not in DYNAMIC_STATUSES:
            raise ValueError(f"invalid dynamic status: {self.dynamic_status}")
        self.dynamic_confidence = max(0.0, min(1.0, float(self.dynamic_confidence)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def ensure_loopback_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    return is_loopback_or_private_host(parsed.hostname)


def is_loopback_or_private_host(host: str) -> bool:
    if host in {"localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip.is_loopback or ip.is_private)


def validate_safe_input(item: SafeValidationInput, *, max_request_bytes: int, max_body_bytes: int) -> list[str]:
    errors: list[str] = []
    if item.estimated_size() > max_request_bytes:
        errors.append("validation input exceeds max_request_bytes")
    if len(item.body.encode("utf-8")) > max_body_bytes:
        errors.append("validation input exceeds max_body_bytes")
    if item.method == "POST" and item.category == "baseline" and not item.body:
        errors.append("baseline POST validation input must include a bounded body")
    for header, value in item.headers.items():
        if len(header) > 128 or len(value) > 512:
            errors.append("validation input contains oversized header")
            break
    return errors


def response_signature(response: dict[str, Any] | None, *, max_preview: int) -> ResponseSignature:
    response = response or {}
    headers = response.get("headers") or {}
    body = str(response.get("body_preview") or "")
    preview = body[: max(0, max_preview)]
    known_error = None
    lowered = body.lower()
    if "unknown soap action" in lowered:
        known_error = "unknown_soap_action"
    elif "soap:fault" in lowered:
        known_error = "soap_fault"
    elif response.get("status") and int(response.get("status")) >= 500:
        known_error = "http_5xx"
    return ResponseSignature(
        status=response.get("status"),
        content_type=headers.get("Content-Type") or headers.get("content-type"),
        body_hash=hashlib.sha256(body.encode("utf-8", errors="replace")).hexdigest(),
        body_preview=preview,
        known_error=known_error,
        server_header=headers.get("Server") or headers.get("server"),
    )


def compare_behavior(baseline: BehaviorObservation, variant: BehaviorObservation) -> BehaviorDifferential:
    base_sig = baseline.response_signature or {}
    variant_sig = variant.response_signature or {}
    status_changed = baseline.http_status != variant.http_status
    body_changed = base_sig.get("body_hash") != variant_sig.get("body_hash")
    process_state_changed = baseline.process_alive_after != variant.process_alive_after
    new_error = not baseline.runtime_error and bool(variant.runtime_error)
    new_log_event = bool(variant.log_signature and variant.log_signature != baseline.log_signature)
    response_time_changed = abs(int(variant.duration_ms or 0) - int(baseline.duration_ms or 0)) > 1000
    side_effect = bool(baseline.side_effect_detected or variant.side_effect_detected)
    if side_effect or process_state_changed or new_error:
        relevance = "high"
        interpretation = "Variant changed process/error state; stop or inspect safety before additional validation."
    elif status_changed or body_changed or new_log_event:
        relevance = "medium"
        interpretation = "Variant produced a distinguishable application-level behavior."
    else:
        relevance = "low"
        interpretation = "Variant matched baseline behavior within configured observation limits."
    return BehaviorDifferential(
        baseline_observation_id=baseline.observation_id,
        variant_observation_id=variant.observation_id,
        status_changed=status_changed,
        body_changed=body_changed,
        response_time_changed=response_time_changed,
        process_state_changed=process_state_changed,
        new_error=new_error,
        new_log_event=new_log_event,
        side_effect=side_effect,
        relevance=relevance,
        interpretation=interpretation,
    )


def build_static_dynamic_context(hypothesis: dict[str, Any], static_evidence: list[dict[str, Any]], report: dict[str, Any]) -> StaticDynamicContext:
    title = f"{hypothesis.get('title') or hypothesis.get('claim') or ''}".lower()
    evidence_text = json.dumps(static_evidence, ensure_ascii=True).lower()
    relevant_ids = [str(item.get("id")) for item in static_evidence if item.get("id")]
    context = StaticDynamicContext(hypothesis_id=str(hypothesis.get("id") or "H-0001"), relevant_evidence_ids=relevant_ids)
    if "device_manager" in title or "soap" in title or "fastcgi" in title or "soap" in evidence_text:
        context.target_binary = "/www/services/device_manager/device_manager.fcgi"
        context.candidate_service = "lighttpd"
        context.candidate_functions = _candidate_functions(static_evidence, ["soap", "handler", "device"])
        context.candidate_strings = _candidate_strings(static_evidence, ["soap", "unknown soap action", "device_manager"])
        context.runtime_backend = "fastcgi-integration"
        context.known_endpoint = "/services/device_manager/"
        context.known_protocol = "https"
    elif "gets" in title or "ret2text" in title or "stack" in title or "gets" in evidence_text:
        context.target_binary = str(hypothesis.get("target") or "ret2text")
        context.candidate_service = None
        context.candidate_functions = _candidate_functions(static_evidence, ["main", "gets", "secure"])
        context.runtime_backend = "process-stdin"
        context.known_protocol = "stdin"
    else:
        priority = (report.get("priority_binaries") or [{}])[0] if isinstance(report.get("priority_binaries"), list) else {}
        context.target_binary = priority.get("path") or priority.get("binary")
        context.candidate_service = (report.get("services") or [{}])[0].get("name") if isinstance(report.get("services"), list) and report.get("services") else None
        context.runtime_backend = "service-qemu"
    return context


def default_safe_inputs(plan: DynamicValidationPlan, *, max_inputs: int = 3) -> list[SafeValidationInput]:
    if plan.runtime_backend == "process-stdin":
        inputs = [
            SafeValidationInput(input_id="VI-0001", protocol="fastcgi", method="POST", path="/stdin", body="A\n", category="baseline", hypothesis_id=plan.hypothesis_id),
            SafeValidationInput(input_id="VI-0002", protocol="fastcgi", method="POST", path="/stdin", body="BBBBBBBB\n", category="boundary_small", hypothesis_id=plan.hypothesis_id),
        ]
        return inputs[: max(1, max_inputs)]
    endpoint = plan.known_endpoint or "/"
    inputs = [
        SafeValidationInput(
            input_id="VI-0001",
            protocol=plan.known_protocol or "https",
            method="GET",
            path=endpoint,
            category="baseline",
            hypothesis_id=plan.hypothesis_id,
        ),
        SafeValidationInput(
            input_id="VI-0002",
            protocol=plan.known_protocol or "https",
            method="POST",
            path=endpoint,
            headers={"Content-Type": "text/xml; charset=utf-8"},
            body="<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body /></soap:Envelope>",
            category="missing_parameter",
            hypothesis_id=plan.hypothesis_id,
        ),
        SafeValidationInput(
            input_id="VI-0003",
            protocol=plan.known_protocol or "https",
            method="POST",
            path=endpoint,
            headers={"Content-Type": "text/xml; charset=utf-8", "SOAPAction": "urn:fwagent:unknownAction"},
            body="<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><fwagentSafeProbe /></soap:Body></soap:Envelope>",
            category="invalid_value",
            hypothesis_id=plan.hypothesis_id,
        ),
    ]
    return inputs[: max(1, max_inputs)]


def decide_verdict(
    plan: DynamicValidationPlan,
    observations: list[BehaviorObservation],
    differentials: list[BehaviorDifferential],
    *,
    blocked: bool = False,
    safety_stop: bool = False,
    evidence_ids: list[str] | None = None,
) -> DynamicValidationVerdict:
    evidence_ids = list(evidence_ids or [])
    if safety_stop or any(item.side_effect_detected for item in observations) or any(item.side_effect for item in differentials):
        return DynamicValidationVerdict(plan.validation_id, plan.hypothesis_id, "validation_blocked", 0.8, "Validation stopped by safety guard.", evidence_ids, "safety_stop")
    if blocked or not observations:
        return DynamicValidationVerdict(plan.validation_id, plan.hypothesis_id, "validation_blocked", 0.6, "Runtime could not complete the validation plan.", evidence_ids, "runtime_blocked")
    if any(item.process_alive_after is False for item in observations):
        return DynamicValidationVerdict(plan.validation_id, plan.hypothesis_id, "validation_inconclusive", 0.5, "A controlled request changed process liveness; crash is not treated as exploitability confirmation.", evidence_ids, "process_exit_observed")
    if plan.contradictory_observations and all(item.http_status in {404, 405} for item in observations if item.http_status is not None):
        return DynamicValidationVerdict(plan.validation_id, plan.hypothesis_id, "dynamically_rejected", 0.65, "Runtime observations contradict the planned handler reachability condition.", evidence_ids, "contradictory_evidence_obtained")
    relevant = [item for item in differentials if item.relevance in {"medium", "high"}]
    if plan.validation_strategy in {"handler_reachability", "input_behavior_difference", "error_path_validation"}:
        if any((item.response_signature or {}).get("known_error") or item.http_status is not None for item in observations):
            if relevant or len(observations) == 1:
                return DynamicValidationVerdict(
                    plan.validation_id,
                    plan.hypothesis_id,
                    "dynamically_supported",
                    0.7,
                    "Runtime observations support the planned reachability/behavior sub-claim without confirming exploitability.",
                    evidence_ids,
                    "supported_evidence_obtained",
                    supported_observations=[item.observation_id for item in observations],
                    missing_observations=["exploitability intentionally out of scope"],
                )
    return DynamicValidationVerdict(plan.validation_id, plan.hypothesis_id, "validation_inconclusive", 0.45, "Runtime completed but observations were insufficient to support or reject the hypothesis.", evidence_ids, "evidence_insufficient")


def _candidate_functions(evidence: list[dict[str, Any]], needles: list[str]) -> list[str]:
    found: list[str] = []
    for item in evidence:
        for value in (item.get("function"), item.get("symbol"), item.get("name")):
            if value and any(needle in str(value).lower() for needle in needles) and str(value) not in found:
                found.append(str(value))
    return found[:10]


def _candidate_strings(evidence: list[dict[str, Any]], needles: list[str]) -> list[str]:
    found: list[str] = []
    for item in evidence:
        text = json.dumps(item, ensure_ascii=False)
        for needle in needles:
            if needle in text.lower() and needle not in found:
                found.append(needle)
    return found[:10]
