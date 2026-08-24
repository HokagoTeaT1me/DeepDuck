from __future__ import annotations

import json
import math
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.correlation import CanonicalStateGuard, ComponentGraphBuilder
from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.validation import StaticDynamicContext, build_static_dynamic_context
from fwagent.dynamic.workspace import DynamicWorkspace


PRIORITY_TIERS = {"critical", "high", "medium", "low", "deferred"}
QUEUE_STATUSES = {"pending", "ready", "running", "completed", "blocked", "skipped", "deferred"}
DEPENDENCY_TYPES = {"requires", "supports", "supersedes", "duplicates", "conflicts_with"}
ALREADY_FINAL_STATUSES = {"dynamically_supported", "dynamically_rejected"}
BLOCKED_STATUSES = {"validation_blocked"}
INCONCLUSIVE_STATUSES = {"validation_inconclusive"}


@dataclass
class RuntimeFeasibilityAssessment:
    backend: str
    available: bool
    readiness: str
    required_repairs: list[str] = field(default_factory=list)
    estimated_startup_seconds: int = 0
    network_required: bool = False
    service_required: bool = False
    application_required: bool = False
    blocking_reason: str | None = None
    feasibility_score: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationCostEstimate:
    tool_calls: int
    requests: int
    runtime_startup_seconds: int
    validation_seconds: int
    artifact_cost: float
    runtime_complexity: str
    repair_count: int
    total_cost_score: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InformationGainEstimate:
    information_gain_score: float
    current_uncertainty: float
    runtime_observability: float
    possible_verdict_separation: float
    expected_evidence_directness: float
    estimated_discrimination_power: float
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SecurityRelevanceAssessment:
    security_relevance_score: float
    categories: list[str] = field(default_factory=list)
    reason: str = "generic hypothesis"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisAssessment:
    hypothesis_id: str
    static_evidence_score: float
    evidence_diversity_score: float
    evidence_directness_score: float
    runtime_feasibility_score: float
    validation_cost_score: float
    expected_information_gain: float
    security_relevance_score: float
    confidence: float
    duplicate_penalty: float
    dependency_penalty: float
    already_validated_penalty: float
    safety_penalty: float
    priority_score: float
    priority_tier: str
    recommended_runtime: str
    recommended_strategy: str
    estimated_requests: int
    estimated_tool_calls: int
    estimated_seconds: int
    blocking_reasons: list[str] = field(default_factory=list)
    assessment_reason: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    evidence_count: int = 0
    evidence_types: list[str] = field(default_factory=list)
    cost_estimate: dict[str, Any] = field(default_factory=dict)
    runtime_feasibility: dict[str, Any] = field(default_factory=dict)
    information_gain: dict[str, Any] = field(default_factory=dict)
    security_relevance: dict[str, Any] = field(default_factory=dict)
    assessment_version: str = "4.1"
    runtime_capability_version: str = "round4.1-local-deterministic"
    cross_component_complexity: int = 0
    runtime_path_readiness: float = 0.0
    dependency_chain_length: int = 0
    relationship_confidence: float = 0.0
    entry_reachability_score: float = 0.0
    runtime_entry_confirmation: bool = False
    entry_distance: int = 0
    entry_confidence: float = 0.0
    source_reachability_score: float = 0.0
    sink_relevance_score: float = 0.0
    taint_path_confidence: float = 0.0
    sanitizer_uncertainty: float = 0.0
    runtime_taint_support: float = 0.0

    def __post_init__(self) -> None:
        self.static_evidence_score = _clamp01(self.static_evidence_score)
        self.evidence_diversity_score = _clamp01(self.evidence_diversity_score)
        self.evidence_directness_score = _clamp01(self.evidence_directness_score)
        self.runtime_feasibility_score = _clamp01(self.runtime_feasibility_score)
        self.validation_cost_score = _clamp01(self.validation_cost_score)
        self.expected_information_gain = _clamp01(self.expected_information_gain)
        self.security_relevance_score = _clamp01(self.security_relevance_score)
        self.confidence = _clamp01(self.confidence)
        self.entry_reachability_score = _clamp01(self.entry_reachability_score)
        self.entry_confidence = _clamp01(self.entry_confidence)
        self.source_reachability_score = _clamp01(self.source_reachability_score)
        self.sink_relevance_score = _clamp01(self.sink_relevance_score)
        self.taint_path_confidence = _clamp01(self.taint_path_confidence)
        self.sanitizer_uncertainty = _clamp01(self.sanitizer_uncertainty)
        self.runtime_taint_support = _clamp01(self.runtime_taint_support)
        self.priority_score = round(max(0.0, min(100.0, float(self.priority_score))), 2)
        if self.priority_tier not in PRIORITY_TIERS:
            raise ValueError(f"invalid priority tier: {self.priority_tier}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisCluster:
    cluster_id: str
    hypothesis_ids: list[str]
    representative_hypothesis_id: str
    reason: str
    similarity: float
    shared_target: str | None = None
    shared_evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisDependency:
    source_hypothesis_id: str
    target_hypothesis_id: str
    dependency_type: str
    reason: str
    confidence: float = 0.7

    def __post_init__(self) -> None:
        if self.dependency_type not in DEPENDENCY_TYPES:
            raise ValueError(f"invalid dependency type: {self.dependency_type}")
        self.confidence = _clamp01(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationBudget:
    max_hypotheses: int = 3
    max_total_tool_calls: int = 12
    max_total_requests: int = 9
    max_total_runtime_seconds: int = 180
    max_runtime_boots: int = 2
    max_repairs: int = 2
    max_failures: int = 2
    max_blocked_validations: int = 2
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationQueueItem:
    queue_position: int
    hypothesis_id: str
    priority_score: float
    runtime_backend: str
    strategy: str
    allocated_requests: int
    allocated_tool_calls: int
    allocated_seconds: int
    dependencies: list[str] = field(default_factory=list)
    cluster_id: str | None = None
    queue_status: str = "pending"
    reason: str = ""

    def __post_init__(self) -> None:
        if self.queue_status not in QUEUE_STATUSES:
            raise ValueError(f"invalid queue status: {self.queue_status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ValidationQueue:
    items: list[ValidationQueueItem]
    budget: ValidationBudget
    stop_reason: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "items": [item.to_dict() for item in self.items],
            "budget": self.budget.to_dict(),
            "stop_reason": self.stop_reason,
            "created_at": self.created_at,
        }


@dataclass
class ValidationStopPolicy:
    min_priority_to_validate: float = 45.0
    marginal_information_gain: float = 0.25
    max_failures: int = 2
    safety_stop: bool = False

    def evaluate(
        self,
        assessments: list[HypothesisAssessment],
        queue: ValidationQueue,
        *,
        failures: int = 0,
        blocked_validations: int = 0,
    ) -> str | None:
        if self.safety_stop:
            return "safety_stop"
        if failures >= self.max_failures:
            return "max_failures_reached"
        if not queue.items:
            if not assessments:
                return "no_hypotheses"
            if all(item.blocking_reasons for item in assessments):
                return "all_remaining_blocked"
            if max(item.priority_score for item in assessments) < self.min_priority_to_validate:
                return "remaining_validations_have_low_expected_value"
            if max(item.expected_information_gain for item in assessments) < self.marginal_information_gain:
                return "marginal_information_gain_too_low"
            return "budget_exhausted"
        if blocked_validations >= max(1, queue.budget.max_blocked_validations):
            return "max_blocked_validations_reached"
        return None


class EvidenceQualityScorer:
    directness_weights = {
        "runtime": 1.0,
        "dynamic": 0.95,
        "handler_reached": 0.9,
        "application_response": 0.88,
        "decompile": 0.85,
        "control": 0.82,
        "dangerous_call": 0.80,
        "route": 0.76,
        "caller": 0.72,
        "reference": 0.68,
        "function": 0.65,
        "string": 0.45,
        "boundary": 0.42,
    }

    def score(self, hypothesis: DynamicHypothesis, evidence: list[dict[str, Any]]) -> dict[str, Any]:
        count_score = min(1.0, len(evidence) / 5.0)
        evidence_types = sorted({str(item.get("type") or "unknown") for item in evidence})
        diversity_score = min(1.0, len(evidence_types) / 4.0)
        directness_values = [self._directness(item) for item in evidence]
        directness_score = sum(directness_values) / len(directness_values) if directness_values else 0.0
        confidence_values = []
        for item in evidence:
            try:
                confidence_values.append(float(item.get("confidence", hypothesis.confidence)))
            except (TypeError, ValueError):
                confidence_values.append(hypothesis.confidence)
        source_score = sum(_clamp01(value) for value in confidence_values) / len(confidence_values) if confidence_values else hypothesis.confidence
        consistency_score = 0.75
        evidence_text = _json_text(evidence)
        if any(token in evidence_text for token in ("contradict", "reject", "not reachable", "blocked")):
            consistency_score -= 0.15
        if any(token in evidence_text for token in ("handler_reached", "application_response", "runtime_ready")):
            consistency_score += 0.10
        consistency_score = _clamp01(consistency_score)
        static_evidence_score = _clamp01(
            (0.25 * count_score)
            + (0.20 * diversity_score)
            + (0.30 * directness_score)
            + (0.15 * source_score)
            + (0.10 * consistency_score)
        )
        return {
            "static_evidence_score": round(static_evidence_score, 3),
            "evidence_diversity_score": round(diversity_score, 3),
            "evidence_directness_score": round(directness_score, 3),
            "evidence_count": len(evidence),
            "evidence_types": evidence_types,
            "source_quality_score": round(source_score, 3),
            "consistency_score": round(consistency_score, 3),
        }

    def _directness(self, evidence: dict[str, Any]) -> float:
        text = _json_text(evidence)
        evidence_type = str(evidence.get("type") or "").lower()
        for token, weight in self.directness_weights.items():
            if token in evidence_type or token in text:
                return weight
        if evidence.get("function") or evidence.get("address"):
            return 0.62
        return 0.5


class RuntimeFeasibilityAssessor:
    def assess(
        self,
        hypothesis: DynamicHypothesis,
        context: StaticDynamicContext,
        dynamic_evidence: list[DynamicEvidence],
    ) -> RuntimeFeasibilityAssessment:
        backend = select_minimum_sufficient_runtime(context, hypothesis)
        previous_blocked = any(item.target == hypothesis.id and item.type in {"validation_blocked", "fastcgi_validation_blocked"} for item in dynamic_evidence)
        previous_ready = any(item.target == hypothesis.id and item.type in {"runtime_ready", "fastcgi_integration_reachable", "handler_reached"} for item in dynamic_evidence)
        if backend == "fastcgi-integration":
            score = 0.95 if previous_ready else 0.88
            return RuntimeFeasibilityAssessment(
                backend=backend,
                available=True,
                readiness="READY",
                required_repairs=["lighttpd FastCGI runtime parity repair"],
                estimated_startup_seconds=20,
                network_required=False,
                service_required=True,
                application_required=True,
                feasibility_score=score,
            )
        if backend == "fastcgi-harness":
            return RuntimeFeasibilityAssessment(
                backend=backend,
                available=True,
                readiness="READY",
                estimated_startup_seconds=12,
                application_required=True,
                feasibility_score=0.78,
            )
        if backend == "service-qemu":
            return RuntimeFeasibilityAssessment(
                backend=backend,
                available=True,
                readiness="READY",
                estimated_startup_seconds=15,
                service_required=True,
                feasibility_score=0.74,
            )
        if backend == "process-stdin":
            readiness = "BLOCKED" if previous_blocked else "PARTIAL"
            return RuntimeFeasibilityAssessment(
                backend=backend,
                available=False,
                readiness=readiness,
                estimated_startup_seconds=4,
                blocking_reason="process-stdin backend requires a controlled stdin runner that is not automated",
                feasibility_score=0.15 if previous_blocked else 0.35,
            )
        return RuntimeFeasibilityAssessment(
            backend="whole-system-qemu",
            available=False,
            readiness="BLOCKED",
            estimated_startup_seconds=120,
            network_required=False,
            service_required=True,
            application_required=True,
            blocking_reason="whole-system runtime is expensive or unavailable for this validation target",
            feasibility_score=0.12,
        )


class ValidationCostModel:
    base_costs = {
        "process-stdin": (2, 2, 4, 6, "low", 0),
        "fastcgi-harness": (4, 3, 12, 15, "medium", 0),
        "service-qemu": (5, 3, 15, 20, "medium", 0),
        "fastcgi-integration": (6, 3, 20, 25, "medium", 1),
        "whole-system-qemu": (10, 4, 120, 60, "high", 2),
    }

    def estimate(self, feasibility: RuntimeFeasibilityAssessment, evidence_count: int = 0) -> ValidationCostEstimate:
        tool_calls, requests, startup, validation, complexity, repairs = self.base_costs.get(
            feasibility.backend, self.base_costs["service-qemu"]
        )
        repairs = max(repairs, len(feasibility.required_repairs))
        artifact_cost = min(1.0, 0.10 + (evidence_count * 0.03) + (repairs * 0.08))
        complexity_score = {"low": 0.2, "medium": 0.5, "high": 0.9}.get(complexity, 0.5)
        time_score = min(1.0, (startup + validation) / 180.0)
        request_score = min(1.0, requests / 8.0)
        total_cost_score = _clamp01((0.35 * complexity_score) + (0.25 * time_score) + (0.20 * request_score) + (0.10 * artifact_cost) + (0.10 * min(1.0, repairs / 3.0)))
        return ValidationCostEstimate(
            tool_calls=tool_calls,
            requests=requests,
            runtime_startup_seconds=startup,
            validation_seconds=validation,
            artifact_cost=round(artifact_cost, 3),
            runtime_complexity=complexity,
            repair_count=repairs,
            total_cost_score=round(total_cost_score, 3),
        )


class InformationGainEstimator:
    def estimate(
        self,
        hypothesis: DynamicHypothesis,
        evidence_quality: dict[str, Any],
        feasibility: RuntimeFeasibilityAssessment,
        cost: ValidationCostEstimate,
    ) -> InformationGainEstimate:
        uncertainty = 1.0 - min(1.0, abs(_clamp01(hypothesis.confidence) - 0.5) * 1.6)
        observability = feasibility.feasibility_score
        directness = float(evidence_quality.get("evidence_directness_score") or 0.0)
        verdict_separation = 0.35 + (0.35 * observability) + (0.20 * directness) - (0.10 * cost.total_cost_score)
        if hypothesis.dynamic_status in INCONCLUSIVE_STATUSES:
            verdict_separation += 0.10
        if hypothesis.dynamic_status in BLOCKED_STATUSES:
            verdict_separation -= 0.25
        discrimination = _clamp01((directness + observability + verdict_separation) / 3.0)
        score = _clamp01((0.25 * uncertainty) + (0.25 * observability) + (0.20 * verdict_separation) + (0.15 * directness) + (0.15 * discrimination))
        reason = "runtime can produce discriminating evidence" if observability >= 0.7 else "runtime observability is limited"
        return InformationGainEstimate(
            information_gain_score=round(score, 3),
            current_uncertainty=round(uncertainty, 3),
            runtime_observability=round(observability, 3),
            possible_verdict_separation=round(_clamp01(verdict_separation), 3),
            expected_evidence_directness=round(directness, 3),
            estimated_discrimination_power=round(discrimination, 3),
            reason=reason,
        )


class SecurityRelevanceScorer:
    categories = {
        "memory safety": ("overflow", "stack", "strcpy", "gets", "memcpy", "bounds", "unbounded", "buffer"),
        "authentication boundary": ("auth", "login", "password", "credential", "session"),
        "input validation": ("validation", "parameter", "malformed", "parser", "input"),
        "command execution path": ("command", "system", "exec", "shell"),
        "file/path handling": ("file", "path", "directory", "traversal"),
        "network parser": ("http", "soap", "fastcgi", "network", "upnp", "parser"),
        "privilege boundary": ("root", "privilege", "setuid", "admin"),
    }

    def score(self, hypothesis: DynamicHypothesis, evidence: list[dict[str, Any]]) -> SecurityRelevanceAssessment:
        text = f"{hypothesis.title} {_json_text(evidence)}".lower()
        found = [category for category, needles in self.categories.items() if any(needle in text for needle in needles)]
        if not found:
            return SecurityRelevanceAssessment(0.35, [], "generic behavior, logging, or cosmetic relevance")
        score = min(0.95, 0.48 + (0.12 * len(found)))
        if any(category in found for category in ("memory safety", "authentication boundary", "command execution path", "privilege boundary")):
            score += 0.12
        return SecurityRelevanceAssessment(round(_clamp01(score), 3), found, f"security analysis relevance categories: {', '.join(found)}")


class HypothesisDeduplicator:
    def cluster(self, hypotheses: list[DynamicHypothesis], contexts: dict[str, StaticDynamicContext]) -> list[HypothesisCluster]:
        grouped: dict[tuple[str | None, str | None, str], list[DynamicHypothesis]] = {}
        for hypothesis in hypotheses:
            context = contexts[hypothesis.id]
            shared_function = context.candidate_functions[0] if context.candidate_functions else None
            normalized_title = _normalized_title(hypothesis.title)
            key = (context.target_binary, shared_function, normalized_title)
            grouped.setdefault(key, []).append(hypothesis)

        clusters: list[HypothesisCluster] = []
        used: set[str] = set()
        for items in grouped.values():
            if len(items) <= 1:
                continue
            cluster = self._make_cluster(len(clusters) + 1, items, contexts, "same binary/function and normalized title")
            clusters.append(cluster)
            used.update(cluster.hypothesis_ids)

        for left_index, left in enumerate(hypotheses):
            if left.id in used:
                continue
            for right in hypotheses[left_index + 1 :]:
                if right.id in used:
                    continue
                shared_evidence = sorted(set(left.evidence_ids) & set(right.evidence_ids))
                same_target = contexts[left.id].target_binary and contexts[left.id].target_binary == contexts[right.id].target_binary
                similarity = _jaccard(_title_tokens(left.title), _title_tokens(right.title))
                if shared_evidence or (same_target and similarity >= 0.58):
                    cluster = self._make_cluster(len(clusters) + 1, [left, right], contexts, "shared evidence or same target with textual similarity")
                    clusters.append(cluster)
                    used.update(cluster.hypothesis_ids)
                    break
        return clusters

    def _make_cluster(
        self,
        number: int,
        hypotheses: list[DynamicHypothesis],
        contexts: dict[str, StaticDynamicContext],
        reason: str,
    ) -> HypothesisCluster:
        representative = max(hypotheses, key=lambda item: (item.confidence, len(item.evidence_ids), item.id))
        shared_evidence = sorted(set.intersection(*(set(item.evidence_ids) for item in hypotheses))) if all(item.evidence_ids for item in hypotheses) else []
        targets = {contexts[item.id].target_binary for item in hypotheses if contexts[item.id].target_binary}
        similarity = max(_jaccard(_title_tokens(hypotheses[0].title), _title_tokens(item.title)) for item in hypotheses[1:]) if len(hypotheses) > 1 else 1.0
        return HypothesisCluster(
            cluster_id=f"HC-{number:04d}",
            hypothesis_ids=[item.id for item in hypotheses],
            representative_hypothesis_id=representative.id,
            reason=reason,
            similarity=round(max(0.75, similarity), 3),
            shared_target=sorted(targets)[0] if len(targets) == 1 else None,
            shared_evidence_ids=shared_evidence,
        )


class HypothesisDependencyAnalyzer:
    def analyze(self, hypotheses: list[DynamicHypothesis], contexts: dict[str, StaticDynamicContext], clusters: list[HypothesisCluster]) -> list[HypothesisDependency]:
        dependencies: list[HypothesisDependency] = []
        for cluster in clusters:
            for hypothesis_id in cluster.hypothesis_ids:
                if hypothesis_id != cluster.representative_hypothesis_id:
                    dependencies.append(
                        HypothesisDependency(
                            source_hypothesis_id=hypothesis_id,
                            target_hypothesis_id=cluster.representative_hypothesis_id,
                            dependency_type="duplicates",
                            reason=f"duplicate cluster {cluster.cluster_id}",
                            confidence=cluster.similarity,
                        )
                    )
        by_id = {item.id: item for item in hypotheses}
        for child in hypotheses:
            child_text = child.title.lower()
            if "unsafe" not in child_text and "overflow" not in child_text and "operation" not in child_text:
                continue
            child_context = contexts[child.id]
            for parent in hypotheses:
                if parent.id == child.id:
                    continue
                parent_text = parent.title.lower()
                same_target = child_context.target_binary and child_context.target_binary == contexts[parent.id].target_binary
                if same_target and any(token in parent_text for token in ("reachable", "handler", "route", "endpoint")):
                    if parent.id in by_id:
                        dependencies.append(
                            HypothesisDependency(
                                source_hypothesis_id=child.id,
                                target_hypothesis_id=parent.id,
                                dependency_type="requires",
                                reason="unsafe behavior validation depends on target reachability",
                                confidence=0.72,
                            )
                        )
        return _dedupe_dependencies(dependencies)


class HypothesisPriorityScorer:
    def __init__(self, config: DynamicConfig):
        self.config = config
        self.evidence_scorer = EvidenceQualityScorer()
        self.feasibility_assessor = RuntimeFeasibilityAssessor()
        self.cost_model = ValidationCostModel()
        self.information_gain = InformationGainEstimator()
        self.security = SecurityRelevanceScorer()

    def assess(
        self,
        hypothesis: DynamicHypothesis,
        evidence: list[dict[str, Any]],
        context: StaticDynamicContext,
        dynamic_evidence: list[DynamicEvidence],
        *,
        cluster: HypothesisCluster | None = None,
        dependencies: list[HypothesisDependency] | None = None,
    ) -> HypothesisAssessment:
        scoring = self.config.prioritization.scoring
        thresholds = self.config.prioritization.thresholds
        quality = self.evidence_scorer.score(hypothesis, evidence)
        feasibility = self.feasibility_assessor.assess(hypothesis, context, dynamic_evidence)
        cost = self.cost_model.estimate(feasibility, evidence_count=int(quality["evidence_count"]))
        gain = self.information_gain.estimate(hypothesis, quality, feasibility, cost)
        relevance = self.security.score(hypothesis, evidence)
        duplicate_penalty = scoring.duplicate_penalty if cluster and cluster.representative_hypothesis_id != hypothesis.id else 0.0
        dependency_penalty = _dependency_penalty(hypothesis, dependencies or [])
        already_validated_penalty = 0.0
        blocking_reasons: list[str] = []
        if hypothesis.dynamic_status in ALREADY_FINAL_STATUSES:
            already_validated_penalty = scoring.already_validated_penalty
            blocking_reasons.append(f"already {hypothesis.dynamic_status}")
        elif hypothesis.dynamic_status in INCONCLUSIVE_STATUSES:
            already_validated_penalty = scoring.inconclusive_penalty
        elif hypothesis.dynamic_status in BLOCKED_STATUSES:
            already_validated_penalty = scoring.blocked_penalty
            blocking_reasons.append("previous validation blocked")
        if feasibility.blocking_reason:
            blocking_reasons.append(feasibility.blocking_reason)
        safety_penalty = _safety_penalty(hypothesis, evidence, scoring.safety_penalty)
        if safety_penalty >= scoring.safety_penalty:
            blocking_reasons.append("safety constraints disallow the requested validation shape")
        positive_weight_sum = (
            scoring.evidence_weight
            + scoring.feasibility_weight
            + scoring.information_gain_weight
            + scoring.security_relevance_weight
        ) or 1.0
        positive_score = (
            (float(quality["static_evidence_score"]) * scoring.evidence_weight)
            + (feasibility.feasibility_score * scoring.feasibility_weight)
            + (gain.information_gain_score * scoring.information_gain_weight)
            + (relevance.security_relevance_score * scoring.security_relevance_weight)
        ) / positive_weight_sum
        penalty = (
            (cost.total_cost_score * scoring.cost_weight)
            + duplicate_penalty
            + dependency_penalty
            + already_validated_penalty
            + safety_penalty
        )
        priority_score = (positive_score - penalty) * 100.0
        if feasibility.readiness == "BLOCKED" and not feasibility.available:
            priority_score = min(priority_score, 35.0)
        if safety_penalty >= scoring.safety_penalty:
            priority_score = min(priority_score, thresholds.minimum_validation_priority - 1)
        priority_tier = _tier(priority_score, thresholds.critical, thresholds.high, thresholds.medium, thresholds.minimum_validation_priority)
        strategy = _strategy_for_runtime(feasibility.backend)
        assessment_reason = _assessment_reason(hypothesis, quality, feasibility, cost, gain, relevance, duplicate_penalty, dependency_penalty, already_validated_penalty, safety_penalty)
        return HypothesisAssessment(
            hypothesis_id=hypothesis.id,
            static_evidence_score=float(quality["static_evidence_score"]),
            evidence_diversity_score=float(quality["evidence_diversity_score"]),
            evidence_directness_score=float(quality["evidence_directness_score"]),
            runtime_feasibility_score=feasibility.feasibility_score,
            validation_cost_score=cost.total_cost_score,
            expected_information_gain=gain.information_gain_score,
            security_relevance_score=relevance.security_relevance_score,
            confidence=hypothesis.confidence,
            duplicate_penalty=duplicate_penalty,
            dependency_penalty=dependency_penalty,
            already_validated_penalty=already_validated_penalty,
            safety_penalty=safety_penalty,
            priority_score=priority_score,
            priority_tier=priority_tier,
            recommended_runtime=feasibility.backend,
            recommended_strategy=strategy,
            estimated_requests=cost.requests,
            estimated_tool_calls=cost.tool_calls,
            estimated_seconds=cost.runtime_startup_seconds + cost.validation_seconds,
            blocking_reasons=blocking_reasons,
            assessment_reason=assessment_reason,
            evidence_count=int(quality["evidence_count"]),
            evidence_types=list(quality["evidence_types"]),
            cost_estimate=cost.to_dict(),
            runtime_feasibility=feasibility.to_dict(),
            information_gain=gain.to_dict(),
            security_relevance=relevance.to_dict(),
            assessment_version=self.config.prioritization.assessment_version,
            runtime_capability_version=self.config.prioritization.runtime_capability_version,
        )


class ValidationBudgetAllocator:
    def allocate(
        self,
        assessments: list[HypothesisAssessment],
        budget: ValidationBudget,
        clusters: list[HypothesisCluster],
        dependencies: list[HypothesisDependency],
        *,
        minimum_priority: float,
    ) -> ValidationQueue:
        cluster_by_hypothesis = {hypothesis_id: cluster.cluster_id for cluster in clusters for hypothesis_id in cluster.hypothesis_ids}
        dependencies_by_hypothesis: dict[str, list[str]] = {}
        for dependency in dependencies:
            if dependency.dependency_type == "requires":
                dependencies_by_hypothesis.setdefault(dependency.source_hypothesis_id, []).append(dependency.target_hypothesis_id)
        candidates = [
            item
            for item in assessments
            if item.priority_score >= minimum_priority
            and item.recommended_runtime != "whole-system-qemu"
            and not any(reason.startswith("already dynamically_") for reason in item.blocking_reasons)
            and "safety constraints disallow the requested validation shape" not in item.blocking_reasons
            and item.runtime_feasibility_score >= 0.3
        ]
        candidates.sort(key=lambda item: (item.priority_score / (1.0 + item.validation_cost_score), item.priority_score), reverse=True)
        items: list[ValidationQueueItem] = []
        remaining_hypotheses = budget.max_hypotheses
        remaining_tool_calls = budget.max_total_tool_calls
        remaining_requests = budget.max_total_requests
        remaining_seconds = budget.max_total_runtime_seconds
        for assessment in candidates:
            if remaining_hypotheses <= 0:
                break
            if assessment.estimated_tool_calls > remaining_tool_calls or assessment.estimated_requests > remaining_requests or assessment.estimated_seconds > remaining_seconds:
                continue
            status = "ready" if not dependencies_by_hypothesis.get(assessment.hypothesis_id) else "pending"
            items.append(
                ValidationQueueItem(
                    queue_position=len(items) + 1,
                    hypothesis_id=assessment.hypothesis_id,
                    priority_score=assessment.priority_score,
                    runtime_backend=assessment.recommended_runtime,
                    strategy=assessment.recommended_strategy,
                    allocated_requests=assessment.estimated_requests,
                    allocated_tool_calls=assessment.estimated_tool_calls,
                    allocated_seconds=assessment.estimated_seconds,
                    dependencies=dependencies_by_hypothesis.get(assessment.hypothesis_id, []),
                    cluster_id=cluster_by_hypothesis.get(assessment.hypothesis_id),
                    queue_status=status,
                    reason=assessment.assessment_reason,
                )
            )
            remaining_hypotheses -= 1
            remaining_tool_calls -= assessment.estimated_tool_calls
            remaining_requests -= assessment.estimated_requests
            remaining_seconds -= assessment.estimated_seconds
        stop_reason = None if items else "remaining_validations_have_low_expected_value"
        return ValidationQueue(items=items, budget=budget, stop_reason=stop_reason)


class HypothesisValidationScheduler:
    def __init__(self, workspace_root: str | Path, task_id: str, *, config: DynamicConfig):
        self.workspace = DynamicWorkspace(workspace_root, task_id)
        self.config = config
        self.scorer = HypothesisPriorityScorer(config)
        self.deduplicator = HypothesisDeduplicator()
        self.dependency_analyzer = HypothesisDependencyAnalyzer()
        self.allocator = ValidationBudgetAllocator()
        self.stop_policy = ValidationStopPolicy(
            min_priority_to_validate=config.prioritization.thresholds.minimum_validation_priority,
            marginal_information_gain=config.prioritization.thresholds.marginal_information_gain,
            max_failures=config.prioritization.budget.max_failures,
        )

    def load_hypothesis_pool(self) -> list[DynamicHypothesis]:
        hypotheses = self.workspace.load_hypotheses()
        static_path = self.workspace.task_dir / "hypotheses" / "hypotheses.json"
        if static_path.exists():
            existing = {item.id for item in hypotheses}
            try:
                static = json.loads(static_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                static = []
            for item in static if isinstance(static, list) else []:
                hypothesis_id = str(item.get("id") or f"H-{len(hypotheses) + 1:04d}")
                if hypothesis_id in existing:
                    continue
                hypotheses.append(
                    DynamicHypothesis(
                        id=hypothesis_id,
                        title=str(item.get("title") or "Dynamic validation hypothesis"),
                        status=str(item.get("status") or "candidate"),
                        confidence=float(item.get("confidence", 0.5)),
                        cwe=item.get("cwe"),
                        evidence_ids=list(item.get("evidence_ids") or []),
                        missing_evidence=list(item.get("missing_evidence") or []),
                        next_actions=list(item.get("next_actions") or []),
                        static_status=str(item.get("status") or "candidate"),
                        dynamic_status="not_tested",
                    )
                )
        generated_path = self.workspace.task_dir / "hypotheses" / "canonical_generated.json"
        if generated_path.exists():
            existing = {item.id for item in hypotheses}
            try:
                generated = json.loads(generated_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                generated = []
            for item in generated if isinstance(generated, list) else []:
                hypothesis_id = str(item.get("id") or f"HG-{len(hypotheses) + 1:04d}")
                if hypothesis_id in existing:
                    continue
                hypotheses.append(
                    DynamicHypothesis(
                        id=hypothesis_id,
                        title=str(item.get("title") or "Generated dynamic validation hypothesis"),
                        status=str(item.get("status") or "candidate"),
                        confidence=float(item.get("confidence", 0.5)),
                        cwe=item.get("cwe"),
                        evidence_ids=list(item.get("evidence_ids") or []),
                        missing_evidence=list(item.get("missing_evidence") or []),
                        next_actions=list(item.get("next_actions") or []),
                        static_status=str(item.get("static_status") or item.get("status") or "candidate"),
                        dynamic_status=str(item.get("dynamic_status") or "not_tested"),
                    )
                )
        if hypotheses:
            self.workspace.save_hypotheses(hypotheses)
        return hypotheses

    def assess(self) -> dict[str, Any]:
        hypotheses = self.load_hypothesis_pool()
        dynamic_evidence = self.workspace.load_evidence()
        static_report = self._static_report()
        static_evidence = self._static_evidence(static_report)
        contexts: dict[str, StaticDynamicContext] = {}
        evidence_by_hypothesis: dict[str, list[dict[str, Any]]] = {}
        for hypothesis in hypotheses:
            evidence = self._evidence_for_hypothesis(hypothesis, static_evidence, dynamic_evidence)
            contexts[hypothesis.id] = build_static_dynamic_context(hypothesis.to_dict(), evidence, static_report)
            evidence_by_hypothesis[hypothesis.id] = evidence
        clusters = self.deduplicator.cluster(hypotheses, contexts)
        dependencies = self.dependency_analyzer.analyze(hypotheses, contexts, clusters)
        clusters_by_hypothesis = {hypothesis_id: cluster for cluster in clusters for hypothesis_id in cluster.hypothesis_ids}
        dependencies_by_hypothesis: dict[str, list[HypothesisDependency]] = {}
        for dependency in dependencies:
            dependencies_by_hypothesis.setdefault(dependency.source_hypothesis_id, []).append(dependency)
        assessments = [
            self.scorer.assess(
                hypothesis,
                evidence_by_hypothesis[hypothesis.id],
                contexts[hypothesis.id],
                dynamic_evidence,
                cluster=clusters_by_hypothesis.get(hypothesis.id),
                dependencies=dependencies_by_hypothesis.get(hypothesis.id, []),
            )
            for hypothesis in hypotheses
        ]
        self._apply_cross_component_inputs(assessments)
        assessments.sort(key=lambda item: item.priority_score, reverse=True)
        budget = self.default_budget()
        queue = self.allocator.allocate(
            assessments,
            budget,
            clusters,
            dependencies,
            minimum_priority=self.config.prioritization.thresholds.minimum_validation_priority,
        )
        stop_reason = self.stop_policy.evaluate(assessments, queue)
        if stop_reason and queue.stop_reason is None:
            queue.stop_reason = stop_reason
        state = {
            "success": True,
            "provider_backed": False,
            "real_model_validation": "deferred",
            "assessment_version": self.config.prioritization.assessment_version,
            "runtime_capability_version": self.config.prioritization.runtime_capability_version,
            "hypotheses": [item.to_dict() for item in hypotheses],
            "assessments": [item.to_dict() for item in assessments],
            "clusters": [item.to_dict() for item in clusters],
            "dependencies": [item.to_dict() for item in dependencies],
            "budget": budget.to_dict(),
            "queue": queue.to_dict(),
            "stop_reason": queue.stop_reason,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save_state(state)
        return state

    def _apply_cross_component_inputs(self, assessments: list[HypothesisAssessment]) -> None:
        surface_contexts: dict[str, dict[str, Any]] = {}
        taint_contexts: dict[str, dict[str, Any]] = {}
        try:
            builder = ComponentGraphBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config)
            contexts = {item.hypothesis_id: builder.security_context_for_hypothesis(item.hypothesis_id) for item in assessments}
        except Exception:  # noqa: BLE001 - prioritization remains usable without correlation artifacts
            return
        try:
            from fwagent.dynamic.surface import AttackSurfaceBuilder

            surface = AttackSurfaceBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).load_or_build()
            surface_contexts = {
                item.get("hypothesis_id"): item
                for item in surface.get("hypothesis_reachability", [])
                if item.get("hypothesis_id")
            }
        except Exception:  # noqa: BLE001 - entry reachability is an optional Round 4.3 signal
            surface_contexts = {}
        try:
            from fwagent.dynamic.taint import TaintAnalysisBuilder

            taint = TaintAnalysisBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).load_or_build()
            taint_contexts = {
                item.get("hypothesis_id"): item
                for item in taint.get("hypothesis_links", [])
                if item.get("hypothesis_id")
            }
            taint_paths = taint.get("taint_paths", [])
            taint_sinks = {item.get("sink_id"): item for item in taint.get("sinks", [])}
        except Exception:  # noqa: BLE001 - prioritization remains usable without taint artifacts
            taint_contexts = {}
            taint_paths = []
            taint_sinks = {}
        for assessment in assessments:
            context = contexts.get(assessment.hypothesis_id)
            if context is None or not context.root_component_id:
                continue
            assessment.cross_component_complexity = context.cross_component_complexity
            assessment.runtime_path_readiness = context.runtime_path_readiness
            assessment.dependency_chain_length = context.dependency_chain_length
            assessment.relationship_confidence = context.relationship_confidence
            if context.runtime_path_readiness >= 0.85 and assessment.recommended_runtime == "fastcgi-integration":
                assessment.runtime_feasibility_score = min(1.0, max(assessment.runtime_feasibility_score, context.runtime_path_readiness))
                assessment.priority_score = round(min(100.0, assessment.priority_score + 4.0), 2)
                assessment.assessment_reason += "; cross-component runtime path is supported by correlated static/dynamic evidence"
            if context.cross_component_complexity > 8:
                assessment.validation_cost_score = min(1.0, assessment.validation_cost_score + 0.05)
                assessment.estimated_seconds += min(30, context.cross_component_complexity * 2)
                assessment.assessment_reason += f"; cross-component complexity {context.cross_component_complexity} increases validation cost"
            surface_context = surface_contexts.get(assessment.hypothesis_id)
            if not surface_context:
                continue
            assessment.entry_reachability_score = float(surface_context.get("entry_reachability_score") or 0.0)
            assessment.runtime_entry_confirmation = bool(surface_context.get("runtime_confirmed"))
            assessment.entry_distance = int(surface_context.get("entry_distance") or 0)
            assessment.entry_confidence = float(surface_context.get("entry_confidence") or 0.0)
            if surface_context.get("state") == "runtime_confirmed" and assessment.recommended_runtime == "fastcgi-integration":
                bonus = self.config.attack_surface.prioritization.runtime_confirmation_bonus
                assessment.priority_score = round(min(100.0, assessment.priority_score + bonus), 2)
                assessment.validation_cost_score = max(0.0, round(assessment.validation_cost_score - 0.05, 3))
                assessment.estimated_seconds = max(10, assessment.estimated_seconds - 10)
                assessment.assessment_reason += "; runtime-confirmed entry route lowers discovery uncertainty"
            elif surface_context.get("state") in {"no_known_entry", "entry_unknown"}:
                penalty = self.config.attack_surface.prioritization.unknown_entry_penalty * 100.0
                assessment.priority_score = round(max(0.0, assessment.priority_score - penalty), 2)
                assessment.blocking_reasons.append("no known input entry point; not marked unreachable without evidence")
                assessment.assessment_reason += "; no known entry lowers validation priority without proving unreachability"
            elif surface_context.get("state") == "blocked":
                assessment.blocking_reasons.append(str(surface_context.get("blocking_reason") or "entry validation blocked"))
                assessment.assessment_reason += "; entry is local/blocked and not external firmware network exposure"
            taint_context = taint_contexts.get(assessment.hypothesis_id)
            if not taint_context:
                continue
            linked_paths = [path for path in taint_paths if path.get("path_id") in set(taint_context.get("taint_path_ids") or [])]
            linked_sinks = [taint_sinks.get(sink_id) for sink_id in taint_context.get("sink_ids") or [] if taint_sinks.get(sink_id)]
            assessment.taint_path_confidence = max((float(path.get("confidence") or 0.0) for path in linked_paths), default=0.0)
            assessment.sink_relevance_score = max((float(sink.get("security_relevance") or 0.0) for sink in linked_sinks), default=0.0)
            assessment.runtime_taint_support = 0.35 if assessment.runtime_entry_confirmation and linked_paths else 0.0
            assessment.source_reachability_score = max(assessment.entry_reachability_score, 0.45 if taint_context.get("source_ids") else 0.0)
            assessment.sanitizer_uncertainty = 1.0 if linked_paths and not any(path.get("sanitizers") for path in linked_paths) else 0.35
            taint_signal = (
                assessment.taint_path_confidence * self.config.taint.prioritization.taint_path_weight
                + assessment.sink_relevance_score * self.config.taint.prioritization.sink_relevance_weight
                + assessment.runtime_taint_support * self.config.taint.prioritization.runtime_taint_weight
                - assessment.sanitizer_uncertainty * self.config.taint.prioritization.sanitizer_uncertainty_weight
            )
            if any(path.get("path_state") in {"statically_supported", "runtime_supported", "validated"} for path in linked_paths):
                assessment.priority_score = round(min(100.0, assessment.priority_score + max(0.0, taint_signal * 100.0)), 2)
                assessment.validation_cost_score = max(0.0, round(assessment.validation_cost_score - 0.03, 3))
                assessment.assessment_reason += "; supported source-to-sink evidence increases validation value without confirming vulnerability"
            elif linked_paths:
                assessment.priority_score = round(min(100.0, assessment.priority_score + max(0.0, taint_signal * 35.0)), 2)
                assessment.validation_cost_score = min(1.0, round(assessment.validation_cost_score + 0.02, 3))
                assessment.assessment_reason += "; candidate source/sink context is useful but CALL PATH != DATA FLOW"

    def execute_next_mock(self, *, verdict_status: str = "validation_inconclusive") -> dict[str, Any]:
        state = self.assess()
        queue_items = [ValidationQueueItem(**item) for item in state["queue"]["items"]]
        next_item = next((item for item in queue_items if item.queue_status in {"ready", "pending"}), None)
        if next_item is None:
            state["executed"] = None
            state["stop_reason"] = state.get("stop_reason") or "no_ready_queue_items"
            self.workspace.save_prioritization_artifact("mock_scheduler_state.json", state)
            return state
        can_update = CanonicalStateGuard.can_update_canonical(
            execution_mode="mock",
            runtime_observation_real=False,
            synthetic=True,
        )
        mock_evidence = {
            "id": f"MDE-{len(self.workspace.load_prioritization_artifact('simulation_evidence.json') or []) + 1:04d}",
            "type": {
                "dynamically_supported": "validation_supported",
                "dynamically_rejected": "validation_rejected",
                "validation_blocked": "validation_blocked",
                "validation_inconclusive": "validation_inconclusive",
            }.get(verdict_status, "validation_inconclusive"),
            "target": next_item.hypothesis_id,
            "observation": f"Mock scheduler set {next_item.hypothesis_id} to {verdict_status}",
            "source_tool": "validation.scheduler.mock",
            "confidence": 0.75,
            "provenance": "mock_agent",
            "execution_mode": "mock",
            "provider_backed": False,
            "runtime_observation_real": False,
            "canonical_update_allowed": can_update,
            "metadata": {
                "runtime_backend": next_item.runtime_backend,
                "strategy": next_item.strategy,
                "safe": True,
            },
        }
        simulation_evidence = list(self.workspace.load_prioritization_artifact("simulation_evidence.json") or [])
        simulation_evidence.append(mock_evidence)
        self.workspace.save_prioritization_artifact("simulation_evidence.json", simulation_evidence)
        reranked = json.loads(json.dumps(state))
        reranked["previous_queue"] = state["queue"]
        reranked["executed"] = {
            "hypothesis_id": next_item.hypothesis_id,
            "verdict_status": verdict_status,
            "evidence_id": mock_evidence["id"],
            "provider_backed": False,
            "execution_mode": "mock",
            "canonical_update_allowed": can_update,
        }
        for assessment in reranked.get("assessments", []):
            if assessment.get("hypothesis_id") == next_item.hypothesis_id:
                if verdict_status in {"dynamically_supported", "dynamically_rejected"}:
                    assessment["already_validated_penalty"] = max(float(assessment.get("already_validated_penalty") or 0), self.config.prioritization.scoring.already_validated_penalty)
                    assessment["priority_score"] = min(float(assessment.get("priority_score") or 0), 10.0)
                    assessment["priority_tier"] = "deferred"
                    assessment.setdefault("blocking_reasons", []).append(f"mock {verdict_status}; canonical state unchanged")
                elif verdict_status == "validation_blocked":
                    assessment["priority_score"] = min(float(assessment.get("priority_score") or 0), 25.0)
                    assessment["priority_tier"] = "deferred"
                    assessment.setdefault("blocking_reasons", []).append("mock validation blocked; canonical state unchanged")
                elif verdict_status == "validation_inconclusive":
                    assessment["priority_score"] = max(0.0, float(assessment.get("priority_score") or 0) - 10.0)
                    assessment["already_validated_penalty"] = max(float(assessment.get("already_validated_penalty") or 0), self.config.prioritization.scoring.inconclusive_penalty)
        reranked["assessments"].sort(key=lambda item: item.get("priority_score", 0), reverse=True)
        minimum = self.config.prioritization.thresholds.minimum_validation_priority
        queue_items = []
        for assessment in reranked["assessments"]:
            if assessment.get("priority_score", 0) < minimum or assessment.get("blocking_reasons"):
                continue
            if len(queue_items) >= reranked["budget"]["max_hypotheses"]:
                break
            queue_items.append(
                {
                    "queue_position": len(queue_items) + 1,
                    "hypothesis_id": assessment["hypothesis_id"],
                    "priority_score": assessment["priority_score"],
                    "runtime_backend": assessment["recommended_runtime"],
                    "strategy": assessment["recommended_strategy"],
                    "allocated_requests": assessment["estimated_requests"],
                    "allocated_tool_calls": assessment["estimated_tool_calls"],
                    "allocated_seconds": assessment["estimated_seconds"],
                    "dependencies": [],
                    "cluster_id": None,
                    "queue_status": "ready",
                    "reason": assessment["assessment_reason"],
                }
            )
        reranked["queue"]["items"] = queue_items
        reranked["queue"]["stop_reason"] = None if queue_items else "remaining_validations_have_low_expected_value"
        reranked["stop_reason"] = reranked["queue"]["stop_reason"]
        reranked["simulation_evidence"] = simulation_evidence
        self.workspace.save_prioritization_artifact("mock_scheduler_state.json", reranked)
        return reranked

    def default_budget(self) -> ValidationBudget:
        configured = self.config.prioritization.budget
        return ValidationBudget(
            max_hypotheses=configured.max_hypotheses,
            max_total_tool_calls=configured.max_tool_calls,
            max_total_requests=configured.max_requests,
            max_total_runtime_seconds=configured.max_runtime_seconds,
            max_runtime_boots=configured.max_runtime_boots,
            max_repairs=configured.max_repairs,
            max_failures=configured.max_failures,
            max_blocked_validations=configured.max_blocked_validations,
        )

    def _save_state(self, state: dict[str, Any]) -> None:
        self.workspace.save_prioritization_artifact("assessment.json", state["assessments"])
        self.workspace.save_prioritization_artifact("clusters.json", state["clusters"])
        self.workspace.save_prioritization_artifact("dependencies.json", state["dependencies"])
        self.workspace.save_prioritization_artifact("budget.json", state["budget"])
        self.workspace.save_prioritization_artifact("queue.json", state["queue"])
        self.workspace.save_prioritization_artifact("scheduler_state.json", state)

    def _static_report(self) -> dict[str, Any]:
        try:
            return self.workspace.load_report()
        except Exception:  # noqa: BLE001 - missing reports are valid for deterministic fixtures
            return {}

    def _static_evidence(self, report: dict[str, Any]) -> list[dict[str, Any]]:
        evidence: list[dict[str, Any]] = []
        for key in ("evidence", "security_candidates"):
            items = report.get(key)
            if isinstance(items, list):
                evidence.extend(item for item in items if isinstance(item, dict))
        static_path = self.workspace.task_dir / "evidence" / "evidence.json"
        if static_path.exists():
            try:
                items = json.loads(static_path.read_text(encoding="utf-8"))
                if isinstance(items, list):
                    evidence.extend(item for item in items if isinstance(item, dict))
            except json.JSONDecodeError:
                pass
        return evidence

    def _evidence_for_hypothesis(
        self,
        hypothesis: DynamicHypothesis,
        static_evidence: list[dict[str, Any]],
        dynamic_evidence: list[DynamicEvidence],
    ) -> list[dict[str, Any]]:
        selected = [item for item in static_evidence if str(item.get("id")) in set(hypothesis.evidence_ids)]
        selected.extend(item.to_dict() for item in dynamic_evidence if item.id in set(hypothesis.evidence_ids) or item.target == hypothesis.id)
        if selected:
            return selected
        return static_evidence[:50]


def select_minimum_sufficient_runtime(context: StaticDynamicContext, hypothesis: DynamicHypothesis) -> str:
    text = f"{hypothesis.title} {context.known_protocol or ''} {context.known_endpoint or ''} {context.target_binary or ''}".lower()
    if context.runtime_backend == "fastcgi-integration" or "soap" in text or "fastcgi" in text:
        return "fastcgi-integration"
    if context.runtime_backend == "process-stdin" or "stdin" in text or "ret2text" in text or "gets" in text:
        return "process-stdin"
    if "whole-system" in text or "boot" in text:
        return "whole-system-qemu"
    if context.candidate_service:
        return "service-qemu"
    return "service-qemu"


def budget_from_config(config: DynamicConfig) -> ValidationBudget:
    configured = config.prioritization.budget
    return ValidationBudget(
        max_hypotheses=configured.max_hypotheses,
        max_total_tool_calls=configured.max_tool_calls,
        max_total_requests=configured.max_requests,
        max_total_runtime_seconds=configured.max_runtime_seconds,
        max_runtime_boots=configured.max_runtime_boots,
        max_repairs=configured.max_repairs,
        max_failures=configured.max_failures,
        max_blocked_validations=configured.max_blocked_validations,
    )


def _dependency_penalty(hypothesis: DynamicHypothesis, dependencies: list[HypothesisDependency]) -> float:
    penalty = 0.0
    for dependency in dependencies:
        if dependency.source_hypothesis_id != hypothesis.id:
            continue
        if dependency.dependency_type == "duplicates":
            penalty += 0.08
        elif dependency.dependency_type == "requires":
            penalty += 0.18
        elif dependency.dependency_type in {"conflicts_with", "supersedes"}:
            penalty += 0.12
    return _clamp01(penalty)


def _safety_penalty(hypothesis: DynamicHypothesis, evidence: list[dict[str, Any]], max_penalty: float) -> float:
    text = f"{hypothesis.title} {_json_text(evidence)}".lower()
    dangerous = any(token in text for token in ("exploit payload", "reverse shell", "public target", "destructive", "credential access"))
    exploit_framing = any(token in text for token in ("redirect execution", "shell function", "control-flow hijack"))
    safe_boundary = any(token in text for token in ("safe", "bounded", "out of scope", "hypothesis_boundary"))
    if dangerous and not safe_boundary:
        return max_penalty
    if exploit_framing and not safe_boundary:
        return round(max_penalty * 0.6, 3)
    if exploit_framing and safe_boundary:
        return round(max_penalty * 0.3, 3)
    return 0.0


def _assessment_reason(
    hypothesis: DynamicHypothesis,
    quality: dict[str, Any],
    feasibility: RuntimeFeasibilityAssessment,
    cost: ValidationCostEstimate,
    gain: InformationGainEstimate,
    relevance: SecurityRelevanceAssessment,
    duplicate_penalty: float,
    dependency_penalty: float,
    already_validated_penalty: float,
    safety_penalty: float,
) -> str:
    reasons = [
        f"{quality['evidence_count']} evidence entries across {len(quality['evidence_types'])} type(s)",
        f"runtime {feasibility.backend} is {feasibility.readiness.lower()} with feasibility {feasibility.feasibility_score:.2f}",
        f"expected information gain {gain.information_gain_score:.2f}: {gain.reason}",
        f"security relevance {relevance.security_relevance_score:.2f}: {relevance.reason}",
        f"cost {cost.runtime_complexity} ({cost.requests} requests, {cost.tool_calls} tool calls)",
    ]
    penalties = []
    if duplicate_penalty:
        penalties.append(f"duplicate penalty {duplicate_penalty:.2f}")
    if dependency_penalty:
        penalties.append(f"dependency penalty {dependency_penalty:.2f}")
    if already_validated_penalty:
        penalties.append(f"prior validation penalty {already_validated_penalty:.2f}")
    if safety_penalty:
        penalties.append(f"safety penalty {safety_penalty:.2f}")
    if penalties:
        reasons.append("penalties: " + ", ".join(penalties))
    return "; ".join(reasons)


def _strategy_for_runtime(runtime: str) -> str:
    if runtime == "fastcgi-integration":
        return "input_behavior_difference"
    if runtime == "process-stdin":
        return "handler_reachability"
    if runtime == "whole-system-qemu":
        return "service_reachability"
    return "handler_reachability"


def _tier(score: float, critical: float, high: float, medium: float, minimum: float) -> str:
    if score >= critical:
        return "critical"
    if score >= high:
        return "high"
    if score >= medium:
        return "medium"
    if score >= minimum:
        return "low"
    return "deferred"


def _dedupe_dependencies(dependencies: list[HypothesisDependency]) -> list[HypothesisDependency]:
    seen: set[tuple[str, str, str]] = set()
    output: list[HypothesisDependency] = []
    for dependency in dependencies:
        key = (dependency.source_hypothesis_id, dependency.target_hypothesis_id, dependency.dependency_type)
        if key in seen:
            continue
        seen.add(key)
        output.append(dependency)
    return output


def _normalized_title(title: str) -> str:
    tokens = sorted(_title_tokens(title) - {"unsafe", "possible", "can", "specific", "request", "handling"})
    return " ".join(tokens[:8])


def _title_tokens(title: str) -> set[str]:
    return {token for token in "".join(ch.lower() if ch.isalnum() else " " for ch in title).split() if len(token) > 2}


def _jaccard(left: set[str], right: set[str]) -> float:
    if not left or not right:
        return 0.0
    return len(left & right) / len(left | right)


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True).lower()


def _clamp01(value: float) -> float:
    if isinstance(value, float) and math.isnan(value):
        return 0.0
    return max(0.0, min(1.0, float(value)))
