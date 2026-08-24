from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fwagent.config import _parse_simple_yaml


@dataclass(frozen=True)
class DynamicBootSettings:
    timeout_seconds: int = 300


@dataclass(frozen=True)
class DynamicNetworkSettings:
    external_internet: bool = False
    probe_timeout_seconds: int = 5


@dataclass(frozen=True)
class DynamicRuntimeSettings:
    max_memory: str = "4G"
    max_cpu: int = 2


@dataclass(frozen=True)
class DynamicValidationSettings:
    max_actions: int = 15
    max_http_requests: int = 20
    max_steps: int = 12
    max_tool_calls: int = 20
    max_requests: int = 5
    timeout_seconds: int = 30
    max_request_bytes: int = 4096
    max_body_bytes: int = 2048
    max_response_preview: int = 512
    stop_on_side_effect: bool = True
    loopback_only: bool = True


@dataclass(frozen=True)
class DynamicPrioritizationScoring:
    evidence_weight: float = 0.30
    feasibility_weight: float = 0.25
    information_gain_weight: float = 0.25
    security_relevance_weight: float = 0.20
    cost_weight: float = 0.15
    duplicate_penalty: float = 0.15
    inconclusive_penalty: float = 0.10
    already_validated_penalty: float = 0.70
    blocked_penalty: float = 0.35
    safety_penalty: float = 0.25


@dataclass(frozen=True)
class DynamicPrioritizationThresholds:
    critical: float = 85.0
    high: float = 70.0
    medium: float = 50.0
    minimum_validation_priority: float = 45.0
    marginal_information_gain: float = 0.25


@dataclass(frozen=True)
class DynamicPrioritizationBudget:
    max_hypotheses: int = 3
    max_tool_calls: int = 12
    max_requests: int = 9
    max_runtime_seconds: int = 180
    max_runtime_boots: int = 2
    max_repairs: int = 2
    max_failures: int = 2
    max_blocked_validations: int = 2


@dataclass(frozen=True)
class DynamicPrioritizationSettings:
    enabled: bool = True
    assessment_version: str = "4.1"
    runtime_capability_version: str = "round4.1-local-deterministic"
    scoring: DynamicPrioritizationScoring = DynamicPrioritizationScoring()
    thresholds: DynamicPrioritizationThresholds = DynamicPrioritizationThresholds()
    budget: DynamicPrioritizationBudget = DynamicPrioritizationBudget()


@dataclass(frozen=True)
class DynamicCorrelationConfidence:
    string_reference: float = 0.35
    static_reference: float = 0.55
    config_parse: float = 0.70
    decompile: float = 0.75
    runtime_observation: float = 0.92
    runtime_confirmed: float = 0.95
    inferred: float = 0.40
    promotion_bonus: float = 0.15


@dataclass(frozen=True)
class DynamicCorrelationFiltering:
    min_relationship_relevance: float = 0.25
    max_path_depth: int = 5
    max_context_nodes: int = 24
    ignore_library_paths: bool = True


@dataclass(frozen=True)
class DynamicCorrelationSettings:
    enabled: bool = True
    graph_version: str = "4.2"
    confidence: DynamicCorrelationConfidence = DynamicCorrelationConfidence()
    filtering: DynamicCorrelationFiltering = DynamicCorrelationFiltering()


@dataclass(frozen=True)
class AttackSurfaceConfidence:
    config_declared: float = 0.65
    static_reference: float = 0.50
    runtime_listener: float = 0.82
    runtime_request: float = 0.90
    application_response: float = 0.95


@dataclass(frozen=True)
class AttackSurfaceReachability:
    propagate_relationships: tuple[str, ...] = (
        "routes_to",
        "dispatches_to",
        "communicates_with",
        "spawns",
        "handles",
        "forwards_to",
        "serves",
        "provides_backend_for",
        "connects_to",
    )


@dataclass(frozen=True)
class AttackSurfacePrioritization:
    entry_reachability_weight: float = 0.10
    runtime_confirmation_bonus: float = 4.0
    unknown_entry_penalty: float = 0.12


@dataclass(frozen=True)
class AttackSurfaceSettings:
    enabled: bool = True
    max_reachability_depth: int = 5
    max_entries: int = 64
    max_routes: int = 64
    min_relationship_confidence: float = 0.50
    confidence: AttackSurfaceConfidence = AttackSurfaceConfidence()
    reachability: AttackSurfaceReachability = AttackSurfaceReachability()
    prioritization: AttackSurfacePrioritization = AttackSurfacePrioritization()


@dataclass(frozen=True)
class TaintConfidenceSettings:
    same_function: float = 0.62
    direct_argument: float = 0.88
    caller_parameter: float = 0.72
    return_propagation: float = 0.70
    runtime_handler: float = 0.18
    runtime_sink: float = 0.95
    unresolved_argument_penalty: float = 0.22
    sanitizer_unknown_penalty: float = 0.12
    same_component_candidate: float = 0.35


@dataclass(frozen=True)
class TaintPrioritizationSettings:
    taint_path_weight: float = 0.08
    sink_relevance_weight: float = 0.06
    sanitizer_uncertainty_weight: float = 0.04
    runtime_taint_weight: float = 0.05


@dataclass(frozen=True)
class TaintSettings:
    enabled: bool = True
    max_call_depth: int = 4
    max_paths: int = 32
    max_sources: int = 64
    max_sinks: int = 128
    max_function_candidates: int = 64
    confidence: TaintConfidenceSettings = TaintConfidenceSettings()
    prioritization: TaintPrioritizationSettings = TaintPrioritizationSettings()


@dataclass(frozen=True)
class HypothesisEvidenceThreshold:
    minimum_taint_level: str = "L3_argument_propagation"
    minimum_path_confidence: float = 0.60
    minimum_entry_confidence: float = 0.45
    minimum_sink_confidence: float = 0.55
    minimum_static_evidence_count: int = 1
    minimum_security_relevance: float = 0.50
    promotion_minimum_support: str = "supported"
    max_candidates: int = 64
    max_promotions: int = 16
    max_findings: int = 32


@dataclass(frozen=True)
class HypothesisSynthesisSettings:
    enabled: bool = True
    generated_by: str = "deterministic_synthesizer"
    provider_backed: bool = False
    evidence_threshold: HypothesisEvidenceThreshold = HypothesisEvidenceThreshold()


@dataclass(frozen=True)
class InvestigationConvergenceSettings:
    enabled: bool = True
    no_progress_iterations: int = 2


@dataclass(frozen=True)
class InvestigationStopSettings:
    min_priority: float = 45.0
    min_information_gain: float = 0.25
    max_inconclusive: int = 2
    max_blocked: int = 2
    max_failures: int = 2


@dataclass(frozen=True)
class InvestigationRecoverySettings:
    retry_validation_timeout: bool = False
    rebuild_stale_artifact: bool = True
    continue_after_blocked: bool = True


@dataclass(frozen=True)
class InvestigationSettings:
    enabled: bool = True
    max_iterations: int = 5
    max_total_validations: int = 3
    max_total_requests: int = 10
    max_total_tool_calls: int = 30
    max_dynamic_seconds: int = 180
    max_runtime_boots: int = 2
    convergence: InvestigationConvergenceSettings = InvestigationConvergenceSettings()
    stop: InvestigationStopSettings = InvestigationStopSettings()
    recovery: InvestigationRecoverySettings = InvestigationRecoverySettings()


@dataclass(frozen=True)
class DynamicShutdownSettings:
    always_stop_after_task: bool = True


@dataclass(frozen=True)
class DynamicAgentSettings:
    max_steps: int = 12
    max_http_requests: int = 10
    max_port_probes: int = 20
    max_log_reads: int = 5


@dataclass(frozen=True)
class DynamicConfig:
    backend: str = "firmae"
    boot: DynamicBootSettings = DynamicBootSettings()
    network: DynamicNetworkSettings = DynamicNetworkSettings()
    runtime: DynamicRuntimeSettings = DynamicRuntimeSettings()
    validation: DynamicValidationSettings = DynamicValidationSettings()
    prioritization: DynamicPrioritizationSettings = DynamicPrioritizationSettings()
    correlation: DynamicCorrelationSettings = DynamicCorrelationSettings()
    attack_surface: AttackSurfaceSettings = AttackSurfaceSettings()
    taint: TaintSettings = TaintSettings()
    synthesis: HypothesisSynthesisSettings = HypothesisSynthesisSettings()
    investigation: InvestigationSettings = InvestigationSettings()
    shutdown: DynamicShutdownSettings = DynamicShutdownSettings()
    agent: DynamicAgentSettings = DynamicAgentSettings()


def load_dynamic_config(path: str | Path | None = None) -> DynamicConfig:
    config_path = Path(path) if path else Path("config") / "dynamic.yaml"
    data = _parse_simple_yaml(config_path) if config_path.exists() else {}
    dynamic = data.get("dynamic", {})
    boot = dynamic.get("boot", {})
    network = dynamic.get("network", {})
    runtime = dynamic.get("runtime", {})
    validation = dynamic.get("validation", {})
    prioritization = dynamic.get("prioritization", {})
    prioritization_scoring = prioritization.get("scoring", {})
    prioritization_thresholds = prioritization.get("thresholds", {})
    prioritization_budget = prioritization.get("budget", {})
    correlation = dynamic.get("correlation", {})
    correlation_confidence = correlation.get("confidence", {})
    correlation_filtering = correlation.get("filtering", {})
    attack_surface = dynamic.get("attack_surface", {})
    attack_surface_confidence = attack_surface.get("confidence", {})
    attack_surface_reachability = attack_surface.get("reachability", {})
    attack_surface_prioritization = attack_surface.get("prioritization", {})
    taint = dynamic.get("taint", {})
    taint_confidence = taint.get("confidence", {})
    taint_prioritization = taint.get("prioritization", {})
    synthesis = dynamic.get("synthesis", {})
    synthesis_threshold = synthesis.get("evidence_threshold", {})
    investigation = dynamic.get("investigation", {})
    investigation_convergence = investigation.get("convergence", {})
    investigation_stop = investigation.get("stop", {})
    investigation_recovery = investigation.get("recovery", {})
    shutdown = dynamic.get("shutdown", {})
    agent = data.get("dynamic_agent", {})
    return DynamicConfig(
        backend=str(os.environ.get("FWAGENT_DYNAMIC_BACKEND", dynamic.get("backend", "firmae"))),
        boot=DynamicBootSettings(
            timeout_seconds=int(boot.get("timeout_seconds", 300)),
        ),
        network=DynamicNetworkSettings(
            external_internet=bool(network.get("external_internet", False)),
            probe_timeout_seconds=int(network.get("probe_timeout_seconds", 5)),
        ),
        runtime=DynamicRuntimeSettings(
            max_memory=str(runtime.get("max_memory", "4G")),
            max_cpu=int(runtime.get("max_cpu", 2)),
        ),
        validation=DynamicValidationSettings(
            max_actions=int(validation.get("max_actions", 15)),
            max_http_requests=int(validation.get("max_http_requests", 20)),
            max_steps=int(validation.get("max_steps", 12)),
            max_tool_calls=int(validation.get("max_tool_calls", 20)),
            max_requests=int(validation.get("max_requests", 5)),
            timeout_seconds=int(validation.get("timeout_seconds", 30)),
            max_request_bytes=int(validation.get("max_request_bytes", 4096)),
            max_body_bytes=int(validation.get("max_body_bytes", 2048)),
            max_response_preview=int(validation.get("max_response_preview", 512)),
            stop_on_side_effect=bool(validation.get("stop_on_side_effect", True)),
            loopback_only=bool(validation.get("loopback_only", True)),
        ),
        prioritization=DynamicPrioritizationSettings(
            enabled=bool(prioritization.get("enabled", True)),
            assessment_version=str(prioritization.get("assessment_version", "4.1")),
            runtime_capability_version=str(prioritization.get("runtime_capability_version", "round4.1-local-deterministic")),
            scoring=DynamicPrioritizationScoring(
                evidence_weight=_float(prioritization_scoring, "evidence_weight", 0.30),
                feasibility_weight=_float(prioritization_scoring, "feasibility_weight", 0.25),
                information_gain_weight=_float(prioritization_scoring, "information_gain_weight", 0.25),
                security_relevance_weight=_float(prioritization_scoring, "security_relevance_weight", 0.20),
                cost_weight=_float(prioritization_scoring, "cost_weight", 0.15),
                duplicate_penalty=_float(prioritization_scoring, "duplicate_penalty", 0.15),
                inconclusive_penalty=_float(prioritization_scoring, "inconclusive_penalty", 0.10),
                already_validated_penalty=_float(prioritization_scoring, "already_validated_penalty", 0.70),
                blocked_penalty=_float(prioritization_scoring, "blocked_penalty", 0.35),
                safety_penalty=_float(prioritization_scoring, "safety_penalty", 0.25),
            ),
            thresholds=DynamicPrioritizationThresholds(
                critical=_float(prioritization_thresholds, "critical", 85.0),
                high=_float(prioritization_thresholds, "high", 70.0),
                medium=_float(prioritization_thresholds, "medium", 50.0),
                minimum_validation_priority=_float(prioritization_thresholds, "minimum_validation_priority", 45.0),
                marginal_information_gain=_float(prioritization_thresholds, "marginal_information_gain", 0.25),
            ),
            budget=DynamicPrioritizationBudget(
                max_hypotheses=int(prioritization_budget.get("max_hypotheses", 3)),
                max_tool_calls=int(prioritization_budget.get("max_tool_calls", 12)),
                max_requests=int(prioritization_budget.get("max_requests", 9)),
                max_runtime_seconds=int(prioritization_budget.get("max_runtime_seconds", 180)),
                max_runtime_boots=int(prioritization_budget.get("max_runtime_boots", 2)),
                max_repairs=int(prioritization_budget.get("max_repairs", 2)),
                max_failures=int(prioritization_budget.get("max_failures", 2)),
                max_blocked_validations=int(prioritization_budget.get("max_blocked_validations", 2)),
            ),
        ),
        correlation=DynamicCorrelationSettings(
            enabled=bool(correlation.get("enabled", True)),
            graph_version=str(correlation.get("graph_version", "4.2")),
            confidence=DynamicCorrelationConfidence(
                string_reference=_float(correlation_confidence, "string_reference", 0.35),
                static_reference=_float(correlation_confidence, "static_reference", 0.55),
                config_parse=_float(correlation_confidence, "config_parse", 0.70),
                decompile=_float(correlation_confidence, "decompile", 0.75),
                runtime_observation=_float(correlation_confidence, "runtime_observation", 0.92),
                runtime_confirmed=_float(correlation_confidence, "runtime_confirmed", 0.95),
                inferred=_float(correlation_confidence, "inferred", 0.40),
                promotion_bonus=_float(correlation_confidence, "promotion_bonus", 0.15),
            ),
            filtering=DynamicCorrelationFiltering(
                min_relationship_relevance=_float(correlation_filtering, "min_relationship_relevance", 0.25),
                max_path_depth=int(correlation_filtering.get("max_path_depth", 5)),
                max_context_nodes=int(correlation_filtering.get("max_context_nodes", 24)),
                ignore_library_paths=bool(correlation_filtering.get("ignore_library_paths", True)),
            ),
        ),
        attack_surface=AttackSurfaceSettings(
            enabled=bool(attack_surface.get("enabled", True)),
            max_reachability_depth=int(attack_surface.get("max_reachability_depth", 5)),
            max_entries=int(attack_surface.get("max_entries", 64)),
            max_routes=int(attack_surface.get("max_routes", 64)),
            min_relationship_confidence=_float(attack_surface, "min_relationship_confidence", 0.50),
            confidence=AttackSurfaceConfidence(
                config_declared=_float(attack_surface_confidence, "config_declared", 0.65),
                static_reference=_float(attack_surface_confidence, "static_reference", 0.50),
                runtime_listener=_float(attack_surface_confidence, "runtime_listener", 0.82),
                runtime_request=_float(attack_surface_confidence, "runtime_request", 0.90),
                application_response=_float(attack_surface_confidence, "application_response", 0.95),
            ),
            reachability=AttackSurfaceReachability(
                propagate_relationships=_tuple_strings(
                    attack_surface_reachability.get("propagate_relationships"),
                    (
                        "routes_to",
                        "dispatches_to",
                        "communicates_with",
                        "spawns",
                        "handles",
                        "forwards_to",
                        "serves",
                        "provides_backend_for",
                        "connects_to",
                    ),
                ),
            ),
            prioritization=AttackSurfacePrioritization(
                entry_reachability_weight=_float(attack_surface_prioritization, "entry_reachability_weight", 0.10),
                runtime_confirmation_bonus=_float(attack_surface_prioritization, "runtime_confirmation_bonus", 4.0),
                unknown_entry_penalty=_float(attack_surface_prioritization, "unknown_entry_penalty", 0.12),
            ),
        ),
        taint=TaintSettings(
            enabled=bool(taint.get("enabled", True)),
            max_call_depth=int(taint.get("max_call_depth", 4)),
            max_paths=int(taint.get("max_paths", 32)),
            max_sources=int(taint.get("max_sources", 64)),
            max_sinks=int(taint.get("max_sinks", 128)),
            max_function_candidates=int(taint.get("max_function_candidates", 64)),
            confidence=TaintConfidenceSettings(
                same_function=_float(taint_confidence, "same_function", 0.62),
                direct_argument=_float(taint_confidence, "direct_argument", 0.88),
                caller_parameter=_float(taint_confidence, "caller_parameter", 0.72),
                return_propagation=_float(taint_confidence, "return_propagation", 0.70),
                runtime_handler=_float(taint_confidence, "runtime_handler", 0.18),
                runtime_sink=_float(taint_confidence, "runtime_sink", 0.95),
                unresolved_argument_penalty=_float(taint_confidence, "unresolved_argument_penalty", 0.22),
                sanitizer_unknown_penalty=_float(taint_confidence, "sanitizer_unknown_penalty", 0.12),
                same_component_candidate=_float(taint_confidence, "same_component_candidate", 0.35),
            ),
            prioritization=TaintPrioritizationSettings(
                taint_path_weight=_float(taint_prioritization, "taint_path_weight", 0.08),
                sink_relevance_weight=_float(taint_prioritization, "sink_relevance_weight", 0.06),
                sanitizer_uncertainty_weight=_float(taint_prioritization, "sanitizer_uncertainty_weight", 0.04),
                runtime_taint_weight=_float(taint_prioritization, "runtime_taint_weight", 0.05),
            ),
        ),
        synthesis=HypothesisSynthesisSettings(
            enabled=bool(synthesis.get("enabled", True)),
            generated_by=str(synthesis.get("generated_by", "deterministic_synthesizer")),
            provider_backed=bool(synthesis.get("provider_backed", False)),
            evidence_threshold=HypothesisEvidenceThreshold(
                minimum_taint_level=str(synthesis_threshold.get("minimum_taint_level", "L3_argument_propagation")),
                minimum_path_confidence=_float(synthesis_threshold, "minimum_path_confidence", 0.60),
                minimum_entry_confidence=_float(synthesis_threshold, "minimum_entry_confidence", 0.45),
                minimum_sink_confidence=_float(synthesis_threshold, "minimum_sink_confidence", 0.55),
                minimum_static_evidence_count=int(synthesis_threshold.get("minimum_static_evidence_count", 1)),
                minimum_security_relevance=_float(synthesis_threshold, "minimum_security_relevance", 0.50),
                promotion_minimum_support=str(synthesis_threshold.get("promotion_minimum_support", "supported")),
                max_candidates=int(synthesis_threshold.get("max_candidates", 64)),
                max_promotions=int(synthesis_threshold.get("max_promotions", 16)),
                max_findings=int(synthesis_threshold.get("max_findings", 32)),
            ),
        ),
        investigation=InvestigationSettings(
            enabled=bool(investigation.get("enabled", True)),
            max_iterations=int(investigation.get("max_iterations", 5)),
            max_total_validations=int(investigation.get("max_total_validations", 3)),
            max_total_requests=int(investigation.get("max_total_requests", 10)),
            max_total_tool_calls=int(investigation.get("max_total_tool_calls", 30)),
            max_dynamic_seconds=int(investigation.get("max_dynamic_seconds", 180)),
            max_runtime_boots=int(investigation.get("max_runtime_boots", 2)),
            convergence=InvestigationConvergenceSettings(
                enabled=bool(investigation_convergence.get("enabled", True)),
                no_progress_iterations=int(investigation_convergence.get("no_progress_iterations", 2)),
            ),
            stop=InvestigationStopSettings(
                min_priority=_float(investigation_stop, "min_priority", 45.0),
                min_information_gain=_float(investigation_stop, "min_information_gain", 0.25),
                max_inconclusive=int(investigation_stop.get("max_inconclusive", 2)),
                max_blocked=int(investigation_stop.get("max_blocked", 2)),
                max_failures=int(investigation_stop.get("max_failures", 2)),
            ),
            recovery=InvestigationRecoverySettings(
                retry_validation_timeout=bool(investigation_recovery.get("retry_validation_timeout", False)),
                rebuild_stale_artifact=bool(investigation_recovery.get("rebuild_stale_artifact", True)),
                continue_after_blocked=bool(investigation_recovery.get("continue_after_blocked", True)),
            ),
        ),
        shutdown=DynamicShutdownSettings(
            always_stop_after_task=bool(shutdown.get("always_stop_after_task", True)),
        ),
        agent=DynamicAgentSettings(
            max_steps=int(agent.get("max_steps", 12)),
            max_http_requests=int(agent.get("max_http_requests", 10)),
            max_port_probes=int(agent.get("max_port_probes", 20)),
            max_log_reads=int(agent.get("max_log_reads", 5)),
        ),
    )


def _float(mapping: dict[str, Any], key: str, default: float) -> float:
    try:
        return float(mapping.get(key, default))
    except (TypeError, ValueError):
        return default


def _tuple_strings(value: Any, default: tuple[str, ...]) -> tuple[str, ...]:
    if value is None:
        return default
    if isinstance(value, str):
        items = [item.strip() for item in value.split(",")]
        return tuple(item for item in items if item) or default
    if isinstance(value, (list, tuple)):
        items = [str(item).strip() for item in value]
        return tuple(item for item in items if item) or default
    return default
