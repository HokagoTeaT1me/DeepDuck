from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent.dynamic.config import DynamicConfig, HypothesisEvidenceThreshold
from fwagent.dynamic.correlation import CanonicalStateGuard
from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.taint import TaintAnalysisBuilder
from fwagent.dynamic.workspace import DynamicWorkspace


HYPOTHESIS_TYPES = {
    "unsafe_input_handling",
    "possible_memory_safety_issue",
    "possible_command_influence",
    "possible_path_influence",
    "possible_file_write_influence",
    "authentication_logic_concern",
    "authorization_logic_concern",
    "unsafe_deserialization",
    "unsafe_dynamic_load",
    "unvalidated_external_input",
    "security_sensitive_reachability",
    "runtime_behavior_anomaly",
    "unknown_security_relevant_flow",
}

SUPPORT_LEVELS = {"weak_candidate", "candidate", "supported", "strongly_supported", "runtime_supported"}
SUPPORT_ORDER = {
    "weak_candidate": 0,
    "candidate": 1,
    "supported": 2,
    "strongly_supported": 3,
    "runtime_supported": 4,
}
SECURITY_CATEGORIES = {
    "memory_safety",
    "command_execution",
    "input_validation",
    "filesystem",
    "authentication",
    "authorization",
    "configuration",
    "dynamic_loading",
    "network_parsing",
    "unknown",
}
FINDING_STATUSES = {"candidate", "needs_validation", "supported", "inconclusive", "rejected"}
FORBIDDEN_CLAIM_PHRASES = (
    "confirmed rce",
    "remote code execution confirmed",
    "exploitable buffer overflow",
    "buffer overflow confirmed",
    "authentication bypass confirmed",
    "confirmed command injection",
    "shell access confirmed",
)
RUNTIME_ANOMALY_EVIDENCE = {
    "runtime_error",
    "process_crash",
    "service_exit",
    "fastcgi_child_exit",
    "request_response_difference",
    "behavior_difference",
}


@dataclass
class HypothesisTemplate:
    hypothesis_type: str
    required_sources: tuple[str, ...] = ()
    required_sinks: tuple[str, ...] = ()
    minimum_evidence_level: str = "L1_same_component"
    minimum_flow_confidence: float = 0.45
    required_runtime_state: str = "not_required"
    forbidden_claims: tuple[str, ...] = FORBIDDEN_CLAIM_PHRASES
    default_missing_evidence: tuple[str, ...] = ()
    validation_goal: str = "Determine whether current evidence supports the security-relevant relationship."
    validation_strategy: str = "handler_reachability"

    def __post_init__(self) -> None:
        if self.hypothesis_type not in HYPOTHESIS_TYPES:
            raise ValueError(f"invalid hypothesis_type: {self.hypothesis_type}")
        self.minimum_flow_confidence = _clamp01(self.minimum_flow_confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HypothesisTemplateRegistry:
    def __init__(self) -> None:
        self.templates = self._default_templates()

    def get(self, hypothesis_type: str) -> HypothesisTemplate:
        return self.templates[hypothesis_type]

    def list(self) -> list[HypothesisTemplate]:
        return [self.templates[key] for key in sorted(self.templates)]

    def to_dict(self) -> list[dict[str, Any]]:
        return [item.to_dict() for item in self.list()]

    @staticmethod
    def _default_templates() -> dict[str, HypothesisTemplate]:
        return {
            "unsafe_input_handling": HypothesisTemplate(
                "unsafe_input_handling",
                required_sinks=("unsafe_copy",),
                minimum_evidence_level="L3_argument_propagation",
                minimum_flow_confidence=0.60,
                default_missing_evidence=("runtime observation", "sanitizer behavior", "exploitability evidence"),
                validation_goal="Determine whether externally supplied input is passed into the identified unsafe input primitive.",
                validation_strategy="safe_boundary_probe",
            ),
            "possible_memory_safety_issue": HypothesisTemplate(
                "possible_memory_safety_issue",
                required_sinks=("unsafe_copy", "memory_copy"),
                minimum_evidence_level="L3_argument_propagation",
                minimum_flow_confidence=0.70,
                default_missing_evidence=("buffer bounds", "argument size relationship", "runtime sink observation"),
                validation_goal="Determine whether externally reachable input is passed into the identified copy operation.",
                validation_strategy="sink_observation",
            ),
            "possible_command_influence": HypothesisTemplate(
                "possible_command_influence",
                required_sinks=("command_execution", "process_execution"),
                minimum_evidence_level="L3_argument_propagation",
                minimum_flow_confidence=0.70,
                default_missing_evidence=("command argument mapping", "runtime sink observation", "sanitizer behavior"),
                validation_goal="Determine whether request-derived data influences the command-execution sink argument.",
                validation_strategy="sink_observation",
            ),
            "possible_path_influence": HypothesisTemplate(
                "possible_path_influence",
                required_sinks=("file_open", "path_operation"),
                minimum_evidence_level="L3_argument_propagation",
                minimum_flow_confidence=0.65,
                default_missing_evidence=("user-controlled path evidence", "path normalization behavior"),
                validation_goal="Determine whether input-derived data influences the filesystem path argument.",
                validation_strategy="runtime_branch_observation",
            ),
            "possible_file_write_influence": HypothesisTemplate(
                "possible_file_write_influence",
                required_sinks=("file_write",),
                minimum_evidence_level="L3_argument_propagation",
                minimum_flow_confidence=0.65,
                default_missing_evidence=("write path mapping", "write data mapping", "runtime sink observation"),
                validation_goal="Determine whether input-derived data influences a file write operation.",
                validation_strategy="runtime_branch_observation",
            ),
            "authentication_logic_concern": HypothesisTemplate(
                "authentication_logic_concern",
                required_sinks=("authentication_decision",),
                minimum_evidence_level="L3_argument_propagation",
                minimum_flow_confidence=0.75,
                default_missing_evidence=("credential context", "security decision branch", "role or session semantics"),
                validation_goal="Determine whether external input reaches an authentication decision with credential context.",
                validation_strategy="runtime_branch_observation",
            ),
            "authorization_logic_concern": HypothesisTemplate(
                "authorization_logic_concern",
                required_sinks=("authorization_decision",),
                minimum_evidence_level="L3_argument_propagation",
                minimum_flow_confidence=0.75,
                default_missing_evidence=("role context", "permission branch", "resource access context"),
                validation_goal="Determine whether external input reaches an authorization decision with permission context.",
                validation_strategy="runtime_branch_observation",
            ),
            "unsafe_deserialization": HypothesisTemplate(
                "unsafe_deserialization",
                required_sinks=("deserialization",),
                minimum_evidence_level="L3_argument_propagation",
                minimum_flow_confidence=0.70,
                default_missing_evidence=("serialized input format", "object construction context"),
                validation_goal="Determine whether external input reaches a deserialization operation.",
                validation_strategy="safe_boundary_probe",
            ),
            "unsafe_dynamic_load": HypothesisTemplate(
                "unsafe_dynamic_load",
                required_sinks=("dynamic_load",),
                minimum_evidence_level="L3_argument_propagation",
                minimum_flow_confidence=0.70,
                default_missing_evidence=("library path mapping", "runtime load observation"),
                validation_goal="Determine whether external input influences a dynamic load path.",
                validation_strategy="runtime_branch_observation",
            ),
            "unvalidated_external_input": HypothesisTemplate(
                "unvalidated_external_input",
                minimum_evidence_level="L1_same_component",
                minimum_flow_confidence=0.40,
                default_missing_evidence=("sink mapping", "sanitizer behavior", "runtime effect"),
                validation_goal="Determine whether externally reachable input reaches security-relevant code without validation evidence.",
                validation_strategy="input_behavior_difference",
            ),
            "security_sensitive_reachability": HypothesisTemplate(
                "security_sensitive_reachability",
                minimum_evidence_level="L1_same_component",
                minimum_flow_confidence=0.45,
                default_missing_evidence=("argument-level data flow", "runtime sink observation", "sanitizer behavior"),
                validation_goal="Determine whether the runtime-reachable handler passes request-derived data to the sensitive operation.",
                validation_strategy="input_behavior_difference",
            ),
            "runtime_behavior_anomaly": HypothesisTemplate(
                "runtime_behavior_anomaly",
                minimum_evidence_level="L0_source_sink_exist",
                minimum_flow_confidence=0.45,
                required_runtime_state="anomaly_observed",
                default_missing_evidence=("repeatability", "root cause", "source-to-branch mapping"),
                validation_goal="Determine whether the request-dependent runtime anomaly is repeatable and security relevant.",
                validation_strategy="process_liveness",
            ),
            "unknown_security_relevant_flow": HypothesisTemplate(
                "unknown_security_relevant_flow",
                minimum_evidence_level="L1_same_component",
                minimum_flow_confidence=0.35,
                default_missing_evidence=("source mapping", "sink mapping", "argument-level propagation"),
                validation_goal="Determine whether the weak source/sink context represents a real data-flow relationship.",
                validation_strategy="handler_reachability",
            ),
        }


@dataclass
class HypothesisCandidate:
    candidate_id: str
    hypothesis_type: str
    title: str
    claim: str
    component_ids: list[str] = field(default_factory=list)
    binary_paths: list[str] = field(default_factory=list)
    function_names: list[str] = field(default_factory=list)
    entry_point_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    sink_ids: list[str] = field(default_factory=list)
    taint_path_ids: list[str] = field(default_factory=list)
    static_evidence_ids: list[str] = field(default_factory=list)
    dynamic_evidence_ids: list[str] = field(default_factory=list)
    supporting_relationship_ids: list[str] = field(default_factory=list)
    support_level: str = "weak_candidate"
    confidence: float = 0.0
    security_relevance: float = 0.0
    runtime_reachability: float = 0.0
    validation_feasibility: float = 0.0
    dedup_key: str = ""
    generation_reason: str = ""
    missing_evidence: list[str] = field(default_factory=list)
    contradictory_evidence: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    provenance: str = "real_static_analysis"
    execution_mode: str = "real"
    provider_backed: bool = False
    generated_by: str = "deterministic_synthesizer"
    source_evidence_provenance: list[str] = field(default_factory=list)
    validation_goal: str = ""
    validation_strategy: str = "handler_reachability"
    static_status: str = "candidate"
    dynamic_status: str = "not_tested"
    security_category: str = "unknown"
    candidate_cwe_ids: list[str] = field(default_factory=list)
    existing_hypothesis_ids: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.hypothesis_type not in HYPOTHESIS_TYPES:
            raise ValueError(f"invalid hypothesis_type: {self.hypothesis_type}")
        if self.support_level not in SUPPORT_LEVELS:
            raise ValueError(f"invalid support_level: {self.support_level}")
        if self.security_category not in SECURITY_CATEGORIES:
            raise ValueError(f"invalid security_category: {self.security_category}")
        self.confidence = _clamp01(self.confidence)
        self.security_relevance = _clamp01(self.security_relevance)
        self.runtime_reachability = _clamp01(self.runtime_reachability)
        self.validation_feasibility = _clamp01(self.validation_feasibility)
        self.component_ids = _unique(self.component_ids)
        self.binary_paths = _unique(self.binary_paths)
        self.function_names = _unique(self.function_names)
        self.entry_point_ids = _unique(self.entry_point_ids)
        self.source_ids = _unique(self.source_ids)
        self.sink_ids = _unique(self.sink_ids)
        self.taint_path_ids = _unique(self.taint_path_ids)
        self.static_evidence_ids = _unique(self.static_evidence_ids)
        self.dynamic_evidence_ids = _unique(self.dynamic_evidence_ids)
        self.missing_evidence = _unique(self.missing_evidence)
        self.contradictory_evidence = _unique(self.contradictory_evidence)
        self.out_of_scope = _unique(self.out_of_scope + _overclaim_flags(self.claim))
        if not self.dedup_key:
            self.dedup_key = _dedup_key(self.hypothesis_type, self.entry_point_ids, self.sink_ids, self.function_names)
        self.static_status = "supported" if SUPPORT_ORDER[self.support_level] >= SUPPORT_ORDER["supported"] else "candidate"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisEvidenceBundle:
    candidate_id: str
    entry_evidence: list[str] = field(default_factory=list)
    source_evidence: list[str] = field(default_factory=list)
    sink_evidence: list[str] = field(default_factory=list)
    taint_evidence: list[str] = field(default_factory=list)
    component_evidence: list[str] = field(default_factory=list)
    runtime_evidence: list[str] = field(default_factory=list)
    contradictory_evidence: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    provider_backed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisPromotionDecision:
    candidate_id: str
    promote: bool
    reason: str
    confidence: float
    canonical_hypothesis_id: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        self.confidence = _clamp01(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FindingCandidate:
    finding_candidate_id: str
    hypothesis_ids: list[str]
    title: str
    affected_components: list[str]
    entry_points: list[str]
    sources: list[str]
    sinks: list[str]
    evidence_bundle: dict[str, Any]
    confidence: float
    status: str
    missing_validation: list[str] = field(default_factory=list)
    security_category: str = "unknown"
    candidate_cwe_ids: list[str] = field(default_factory=list)
    provider_backed: bool = False

    def __post_init__(self) -> None:
        if self.status not in FINDING_STATUSES:
            raise ValueError(f"invalid finding status: {self.status}")
        if self.security_category not in SECURITY_CATEGORIES:
            raise ValueError(f"invalid security_category: {self.security_category}")
        self.confidence = _clamp01(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisSynthesisSummary:
    candidate_count: int
    promoted_count: int
    deduplicated_count: int
    rejected_by_gate: int
    weak_candidate_count: int
    supported_count: int
    runtime_supported_count: int
    finding_candidate_count: int
    top_candidates: list[dict[str, Any]] = field(default_factory=list)
    safety_notes: list[str] = field(default_factory=list)
    provider_backed: bool = False
    real_model_validation: str = "deferred"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class HypothesisDeduplicator:
    def deduplicate(
        self,
        candidates: list[HypothesisCandidate],
        existing_hypotheses: list[DynamicHypothesis],
    ) -> tuple[list[HypothesisCandidate], dict[str, list[str]], int]:
        by_key: dict[str, HypothesisCandidate] = {}
        duplicate_map: dict[str, list[str]] = {}
        duplicates = 0
        existing = {item.id: item for item in existing_hypotheses}
        for candidate in candidates:
            for path_hint in candidate.existing_hypothesis_ids:
                if path_hint in existing:
                    duplicate_map.setdefault(candidate.candidate_id, []).append(path_hint)
            for hypothesis in existing_hypotheses:
                if _overlaps_existing(candidate, hypothesis):
                    duplicate_map.setdefault(candidate.candidate_id, []).append(hypothesis.id)
            candidate.existing_hypothesis_ids = _unique(duplicate_map.get(candidate.candidate_id, []))
            previous = by_key.get(candidate.dedup_key)
            if previous is None:
                by_key[candidate.dedup_key] = candidate
                continue
            duplicates += 1
            if _candidate_rank(candidate) > _candidate_rank(previous):
                duplicate_map.setdefault(candidate.candidate_id, []).append(previous.candidate_id)
                by_key[candidate.dedup_key] = candidate
            else:
                duplicate_map.setdefault(previous.candidate_id, []).append(candidate.candidate_id)
        return list(by_key.values()), duplicate_map, duplicates + sum(1 for ids in duplicate_map.values() if ids)


class HypothesisSynthesizer:
    def __init__(self, workspace_root: str | Path, task_id: str, *, config: DynamicConfig):
        self.workspace = DynamicWorkspace(workspace_root, task_id)
        self.config = config
        self.templates = HypothesisTemplateRegistry()
        self.deduplicator = HypothesisDeduplicator()

    def build(self, *, apply_promotions: bool = True) -> dict[str, Any]:
        taint = TaintAnalysisBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).load_or_build()
        existing_hypotheses = self.workspace.load_hypotheses()
        dynamic_evidence = self.workspace.load_evidence()
        candidates = self._generate_candidates(taint, dynamic_evidence)
        candidates, duplicate_map, deduplicated_count = self.deduplicator.deduplicate(candidates, existing_hypotheses)
        candidates = sorted(candidates, key=_candidate_rank, reverse=True)[: self.config.synthesis.evidence_threshold.max_candidates]
        bundles = [self._bundle(candidate, taint) for candidate in candidates]
        decisions = self._promotion_decisions(candidates)
        canonical_generated = self._canonical_generated(candidates, decisions)
        if apply_promotions:
            self._apply_promotions(candidates, decisions)
        findings = self._finding_candidates(candidates, bundles)[: self.config.synthesis.evidence_threshold.max_findings]
        summary = self._summary(candidates, decisions, deduplicated_count, findings)
        payload = {
            "success": True,
            "provider_backed": False,
            "real_model_validation": "deferred",
            "templates": self.templates.to_dict(),
            "candidates": [item.to_dict() for item in candidates],
            "promotion_decisions": [item.to_dict() for item in decisions],
            "canonical_generated": canonical_generated,
            "evidence_bundles": [item.to_dict() for item in bundles],
            "finding_candidates": [item.to_dict() for item in findings],
            "summary": summary.to_dict(),
            "duplicate_map": duplicate_map,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self._persist(payload)
        return payload

    def load_or_build(self) -> dict[str, Any]:
        payload = self.workspace.load_hypothesis_artifact("synthesis_analysis.json")
        if payload:
            return payload
        return self.build()

    def candidate(self, candidate_id: str) -> dict[str, Any] | None:
        payload = self.load_or_build()
        return next((item for item in payload.get("candidates", []) if item.get("candidate_id") == candidate_id), None)

    def evidence_bundle(self, candidate_id: str) -> dict[str, Any] | None:
        payload = self.load_or_build()
        return next((item for item in payload.get("evidence_bundles", []) if item.get("candidate_id") == candidate_id), None)

    def mock_generate_candidate(self, title: str) -> dict[str, Any]:
        candidate = HypothesisCandidate(
            candidate_id="MH-CAND-0001",
            hypothesis_type="unknown_security_relevant_flow",
            title=title,
            claim=f"Mock-only candidate for inspection: {title}",
            support_level="weak_candidate",
            confidence=0.1,
            security_relevance=0.1,
            provenance="mock_agent",
            execution_mode="mock",
            provider_backed=False,
            missing_evidence=["real evidence", "non-mock provenance"],
        )
        can_update = CanonicalStateGuard.can_update_canonical(
            execution_mode=candidate.execution_mode,
            runtime_observation_real=False,
            synthetic=True,
        )
        self.workspace.save_hypothesis_artifact(
            "mock_synthesis_state.json",
            {"candidate": candidate.to_dict(), "canonical_update_allowed": can_update, "provider_backed": False},
        )
        return {"success": True, "canonical_update_allowed": can_update, "provider_backed": False}

    def _generate_candidates(self, taint: dict[str, Any], dynamic_evidence: list[DynamicEvidence]) -> list[HypothesisCandidate]:
        sources = {item.get("source_id"): item for item in taint.get("sources", [])}
        sinks = {item.get("sink_id"): item for item in taint.get("sinks", [])}
        candidates: list[HypothesisCandidate] = []
        for path in taint.get("taint_paths", []):
            source = sources.get(path.get("source_id"))
            sink = sinks.get(path.get("sink_id"))
            if not source or not sink:
                continue
            candidates.extend(self._candidates_for_path(path, source, sink))
        candidates.extend(self._fastcgi_reachability_candidates(taint))
        candidates.extend(self._runtime_anomaly_candidates(dynamic_evidence))
        return _unique_candidates(candidates)

    def _candidates_for_path(self, path: dict[str, Any], source: dict[str, Any], sink: dict[str, Any]) -> list[HypothesisCandidate]:
        sink_type = str(sink.get("sink_type") or "unknown")
        support = _support_level(path)
        if SUPPORT_ORDER[support] < SUPPORT_ORDER["supported"]:
            return []
        if sink_type in {"command_execution", "process_execution"}:
            return [self._path_candidate("possible_command_influence", path, source, sink, support)]
        if sink_type == "unsafe_copy" and str(sink.get("callee_name") or "").lower() == "gets":
            return [self._path_candidate("unsafe_input_handling", path, source, sink, support)]
        if sink_type in {"unsafe_copy", "memory_copy"}:
            return [self._path_candidate("possible_memory_safety_issue", path, source, sink, support)]
        if sink_type in {"file_open", "path_operation"}:
            return [self._path_candidate("possible_path_influence", path, source, sink, support)]
        if sink_type == "file_write":
            return [self._path_candidate("possible_file_write_influence", path, source, sink, support)]
        if sink_type == "dynamic_load":
            return [self._path_candidate("unsafe_dynamic_load", path, source, sink, support)]
        return []

    def _path_candidate(
        self,
        hypothesis_type: str,
        path: dict[str, Any],
        source: dict[str, Any],
        sink: dict[str, Any],
        support: str,
    ) -> HypothesisCandidate:
        template = self.templates.get(hypothesis_type)
        confidence = self._confidence(source, sink, path)
        title, claim = _claim_for_path(hypothesis_type, source, sink, path)
        evidence_ids = _unique(list(path.get("evidence_ids") or []) + list(source.get("evidence_ids") or []) + list(sink.get("evidence_ids") or []))
        candidate = HypothesisCandidate(
            candidate_id=f"HC-{_slug(hypothesis_type)}-{_slug(str(path.get('path_id')))}",
            hypothesis_type=hypothesis_type,
            title=title,
            claim=claim,
            component_ids=list(path.get("component_ids") or []),
            binary_paths=[str(sink.get("binary_path") or "")],
            function_names=list(path.get("function_chain") or []),
            entry_point_ids=[str(path.get("entry_point_id") or source.get("entry_point_id") or "")],
            source_ids=[str(source.get("source_id") or "")],
            sink_ids=[str(sink.get("sink_id") or "")],
            taint_path_ids=[str(path.get("path_id") or "")],
            static_evidence_ids=evidence_ids,
            dynamic_evidence_ids=[item for item in evidence_ids if str(item).startswith("DE-")],
            support_level=support,
            confidence=confidence,
            security_relevance=float(sink.get("security_relevance") or 0.5),
            runtime_reachability=0.75 if path.get("entry_point_id") else 0.35,
            validation_feasibility=0.55 if source.get("source_type") != "stdin" else 0.25,
            generation_reason=f"{support} taint path satisfies {hypothesis_type} template without exploit confirmation",
            missing_evidence=self._missing_evidence(template, path),
            contradictory_evidence=self._contradictory_evidence(path),
            provenance="real_static_analysis",
            execution_mode="real",
            provider_backed=False,
            generated_by=self.config.synthesis.generated_by,
            source_evidence_provenance=["real_static_analysis"],
            validation_goal=template.validation_goal,
            validation_strategy=template.validation_strategy,
            security_category=_security_category(hypothesis_type),
            candidate_cwe_ids=_candidate_cwes(hypothesis_type, sink, support),
            existing_hypothesis_ids=list(path.get("hypothesis_ids") or []),
        )
        return candidate

    def _fastcgi_reachability_candidates(self, taint: dict[str, Any]) -> list[HypothesisCandidate]:
        paths = [item for item in taint.get("taint_paths", []) if "H-FCGI-0001" in (item.get("hypothesis_ids") or [])]
        if not paths:
            return []
        if any(SUPPORT_ORDER[_support_level(path)] >= SUPPORT_ORDER["supported"] for path in paths):
            return []
        sources = {item.get("source_id"): item for item in taint.get("sources", [])}
        sinks = {item.get("sink_id"): item for item in taint.get("sinks", [])}
        source_ids = _unique([str(path.get("source_id")) for path in paths])
        sink_ids = _unique([str(path.get("sink_id")) for path in paths])
        linked_sources = [sources[item] for item in source_ids if item in sources]
        linked_sinks = [sinks[item] for item in sink_ids if item in sinks]
        if not linked_sources or not linked_sinks:
            return []
        confidence = round(max(float(path.get("confidence") or 0.0) for path in paths), 3)
        support = "candidate" if confidence >= 0.45 else "weak_candidate"
        sink_names = _unique([str(item.get("callee_name") or item.get("function_name") or "sink") for item in linked_sinks])
        binaries = _unique([str(item.get("binary_path") or "") for item in linked_sinks])
        source_types = _unique([str(item.get("source_type") or "") for item in linked_sources])
        template = self.templates.get("security_sensitive_reachability")
        evidence_ids = _unique([evidence for path in paths for evidence in list(path.get("evidence_ids") or [])])
        return [
            HypothesisCandidate(
                candidate_id="HC-FCGI-security-sensitive-reachability",
                hypothesis_type="security_sensitive_reachability",
                title="Request-derived FastCGI input has candidate correlation with sensitive operations",
                claim=(
                    "Request-derived input in device_manager.fcgi has candidate correlation with security-sensitive "
                    f"operations ({', '.join(sink_names)}) in {', '.join(binaries)}; argument-level propagation is unresolved."
                ),
                component_ids=_unique([component for path in paths for component in list(path.get("component_ids") or [])]),
                binary_paths=binaries,
                function_names=_unique([fn for path in paths for fn in list(path.get("function_chain") or [])]),
                entry_point_ids=_unique([str(path.get("entry_point_id") or "") for path in paths]),
                source_ids=source_ids,
                sink_ids=sink_ids,
                taint_path_ids=_unique([str(path.get("path_id") or "") for path in paths]),
                static_evidence_ids=evidence_ids,
                dynamic_evidence_ids=[item for item in evidence_ids if str(item).startswith("DE-")],
                support_level=support,
                confidence=confidence,
                security_relevance=max((float(item.get("security_relevance") or 0.0) for item in linked_sinks), default=0.5),
                runtime_reachability=max((float(item.get("confidence") or 0.0) for item in linked_sources), default=0.45),
                validation_feasibility=0.80,
                dedup_key=f"security_sensitive_reachability|fcgi|{','.join(sorted(sink_names))}",
                generation_reason=f"FastCGI source types {', '.join(source_types)} share L1 candidate context with sensitive sinks; CALL PATH != DATA FLOW",
                missing_evidence=self._missing_evidence(template, paths[0]),
                provenance="real_static_analysis",
                execution_mode="real",
                provider_backed=False,
                generated_by=self.config.synthesis.generated_by,
                source_evidence_provenance=["real_static_analysis", "real_runtime_observation"],
                validation_goal=template.validation_goal,
                validation_strategy=template.validation_strategy,
                security_category="network_parsing",
                existing_hypothesis_ids=["H-FCGI-0001"],
            )
        ]

    def _runtime_anomaly_candidates(self, dynamic_evidence: list[DynamicEvidence]) -> list[HypothesisCandidate]:
        candidates = []
        for evidence in dynamic_evidence:
            if evidence.type not in RUNTIME_ANOMALY_EVIDENCE:
                continue
            template = self.templates.get("runtime_behavior_anomaly")
            candidates.append(
                HypothesisCandidate(
                    candidate_id=f"HC-RUNTIME-ANOMALY-{_slug(evidence.id)}",
                    hypothesis_type="runtime_behavior_anomaly",
                    title="Runtime behavior anomaly observed during safe validation",
                    claim=f"Runtime evidence {evidence.id} shows a request-dependent anomaly; vulnerability is not established.",
                    dynamic_evidence_ids=[evidence.id],
                    support_level="candidate",
                    confidence=evidence.confidence,
                    security_relevance=0.55,
                    runtime_reachability=evidence.confidence,
                    validation_feasibility=0.55,
                    generation_reason="runtime anomaly evidence can seed a non-vulnerability validation hypothesis",
                    missing_evidence=list(template.default_missing_evidence),
                    provenance=evidence.provenance,
                    execution_mode=evidence.execution_mode,
                    provider_backed=False,
                    generated_by=self.config.synthesis.generated_by,
                    source_evidence_provenance=[evidence.provenance],
                    validation_goal=template.validation_goal,
                    validation_strategy=template.validation_strategy,
                    security_category="unknown",
                    existing_hypothesis_ids=[evidence.target] if evidence.target else [],
                )
            )
        return candidates

    def _confidence(self, source: dict[str, Any], sink: dict[str, Any], path: dict[str, Any]) -> float:
        runtime_bonus = 0.08 if path.get("runtime_supported") or path.get("runtime_sink_confirmed") else 0.0
        sanitizer_penalty = 0.06 if not path.get("sanitizers") else 0.0
        score = (
            (0.20 * float(source.get("confidence") or 0.0))
            + (0.25 * float(sink.get("confidence") or 0.0))
            + (0.40 * float(path.get("confidence") or 0.0))
            + (0.15 * float(sink.get("security_relevance") or 0.0))
            + runtime_bonus
            - sanitizer_penalty
        )
        return _clamp01(score)

    def _missing_evidence(self, template: HypothesisTemplate, path: dict[str, Any]) -> list[str]:
        missing = list(template.default_missing_evidence)
        if _evidence_level_rank(path.get("evidence_level")) < _evidence_level_rank("L3_argument_propagation"):
            missing.append("argument-level source-to-sink mapping")
        if not path.get("runtime_sink_confirmed"):
            missing.append("runtime sink observation")
        if not path.get("sanitizers"):
            missing.append("sanitizer behavior")
        return _unique(missing)

    def _contradictory_evidence(self, path: dict[str, Any]) -> list[str]:
        if path.get("path_state") in {"blocked", "contradicted"}:
            return list(path.get("evidence_ids") or [])
        return []

    def _bundle(self, candidate: HypothesisCandidate, taint: dict[str, Any]) -> HypothesisEvidenceBundle:
        sources = {item.get("source_id"): item for item in taint.get("sources", [])}
        sinks = {item.get("sink_id"): item for item in taint.get("sinks", [])}
        paths = {item.get("path_id"): item for item in taint.get("taint_paths", [])}
        entry_evidence = _unique([sources[item].get("entry_point_id") for item in candidate.source_ids if item in sources and sources[item].get("entry_point_id")])
        source_evidence = _unique([evidence for source_id in candidate.source_ids if source_id in sources for evidence in list(sources[source_id].get("evidence_ids") or [])])
        sink_evidence = _unique([evidence for sink_id in candidate.sink_ids if sink_id in sinks for evidence in list(sinks[sink_id].get("evidence_ids") or [])])
        taint_evidence = _unique([evidence for path_id in candidate.taint_path_ids if path_id in paths for evidence in list(paths[path_id].get("evidence_ids") or [])])
        runtime_evidence = _unique(candidate.dynamic_evidence_ids + [evidence for evidence in taint_evidence if str(evidence).startswith("DE-")])
        return HypothesisEvidenceBundle(
            candidate_id=candidate.candidate_id,
            entry_evidence=entry_evidence,
            source_evidence=source_evidence,
            sink_evidence=sink_evidence,
            taint_evidence=taint_evidence,
            component_evidence=candidate.component_ids,
            runtime_evidence=runtime_evidence,
            contradictory_evidence=candidate.contradictory_evidence,
            missing_evidence=candidate.missing_evidence,
            provider_backed=False,
        )

    def _promotion_decisions(self, candidates: list[HypothesisCandidate]) -> list[HypothesisPromotionDecision]:
        decisions = []
        for candidate in candidates:
            promote, reason = self._passes_promotion_gate(candidate)
            canonical_id = None
            if promote:
                canonical_id = candidate.existing_hypothesis_ids[0] if candidate.existing_hypothesis_ids else f"HG-{len(decisions) + 1:04d}"
            elif candidate.existing_hypothesis_ids:
                canonical_id = candidate.existing_hypothesis_ids[0]
            decisions.append(HypothesisPromotionDecision(candidate.candidate_id, promote, reason, candidate.confidence, canonical_id))
        return decisions

    def _passes_promotion_gate(self, candidate: HypothesisCandidate) -> tuple[bool, str]:
        threshold = self.config.synthesis.evidence_threshold
        if not CanonicalStateGuard.can_update_canonical(
            execution_mode=candidate.execution_mode,
            runtime_observation_real=candidate.execution_mode == "real",
            synthetic=candidate.provenance in {"mock_agent", "fixture", "simulation"} or candidate.candidate_id.startswith("MH-"),
        ):
            return False, "mock, fixture, simulation, or non-real provenance cannot promote to canonical"
        if candidate.out_of_scope:
            return False, "claim contains prohibited overclaim wording"
        if SUPPORT_ORDER[candidate.support_level] < SUPPORT_ORDER.get(threshold.promotion_minimum_support, SUPPORT_ORDER["supported"]):
            return False, "support level below promotion threshold"
        if candidate.confidence < threshold.minimum_path_confidence:
            return False, "confidence below promotion threshold"
        if candidate.security_relevance < threshold.minimum_security_relevance:
            return False, "security relevance below promotion threshold"
        if len(candidate.static_evidence_ids) < threshold.minimum_static_evidence_count and not candidate.dynamic_evidence_ids:
            return False, "insufficient evidence count"
        return True, "deterministic real evidence passed promotion gate; Candidate != Vulnerability"

    def _canonical_generated(
        self,
        candidates: list[HypothesisCandidate],
        decisions: list[HypothesisPromotionDecision],
    ) -> list[dict[str, Any]]:
        by_candidate = {item.candidate_id: item for item in candidates}
        generated = []
        for decision in decisions:
            if not decision.promote or not decision.canonical_hypothesis_id:
                continue
            candidate = by_candidate[decision.candidate_id]
            generated.append(
                {
                    "id": decision.canonical_hypothesis_id,
                    "title": candidate.title,
                    "status": candidate.static_status,
                    "confidence": candidate.confidence,
                    "cwe": ", ".join(candidate.candidate_cwe_ids) if candidate.candidate_cwe_ids else None,
                    "evidence_ids": _unique(candidate.static_evidence_ids + candidate.dynamic_evidence_ids),
                    "missing_evidence": candidate.missing_evidence,
                    "next_actions": [candidate.validation_goal],
                    "static_status": candidate.static_status,
                    "dynamic_status": "not_tested",
                    "derived_candidate_ids": [candidate.candidate_id],
                    "provider_backed": False,
                    "generated_by": self.config.synthesis.generated_by,
                }
            )
        return generated

    def _apply_promotions(self, candidates: list[HypothesisCandidate], decisions: list[HypothesisPromotionDecision]) -> None:
        existing = {item.id: item for item in self.workspace.load_hypotheses()}
        changed = False
        for decision in decisions:
            if not decision.promote or not decision.canonical_hypothesis_id:
                continue
            candidate = next(item for item in candidates if item.candidate_id == decision.candidate_id)
            hypothesis = existing.get(decision.canonical_hypothesis_id)
            if hypothesis:
                hypothesis.evidence_ids = _unique(hypothesis.evidence_ids + candidate.static_evidence_ids + candidate.dynamic_evidence_ids)
                hypothesis.missing_evidence = _unique(hypothesis.missing_evidence + candidate.missing_evidence)
                hypothesis.next_actions = _unique(hypothesis.next_actions + [candidate.validation_goal])
                hypothesis.static_status = hypothesis.static_status or candidate.static_status
                hypothesis.dynamic_status = hypothesis.dynamic_status or "not_tested"
                changed = True
            else:
                existing[decision.canonical_hypothesis_id] = DynamicHypothesis(
                    id=decision.canonical_hypothesis_id,
                    title=candidate.title,
                    status=candidate.static_status,
                    confidence=candidate.confidence,
                    cwe=", ".join(candidate.candidate_cwe_ids) if candidate.candidate_cwe_ids else None,
                    evidence_ids=_unique(candidate.static_evidence_ids + candidate.dynamic_evidence_ids),
                    missing_evidence=candidate.missing_evidence,
                    next_actions=[candidate.validation_goal],
                    static_status=candidate.static_status,
                    dynamic_status="not_tested",
                )
                changed = True
        if changed:
            self.workspace.save_hypotheses(list(existing.values()))

    def _finding_candidates(
        self,
        candidates: list[HypothesisCandidate],
        bundles: list[HypothesisEvidenceBundle],
    ) -> list[FindingCandidate]:
        bundle_map = {item.candidate_id: item for item in bundles}
        groups: dict[tuple[str, str], list[HypothesisCandidate]] = {}
        for candidate in candidates:
            component = candidate.component_ids[0] if candidate.component_ids else "unknown"
            groups.setdefault((candidate.security_category, component), []).append(candidate)
        findings = []
        for index, ((category, component), items) in enumerate(sorted(groups.items()), start=1):
            confidence = max(item.confidence for item in items)
            status = "supported" if any(SUPPORT_ORDER[item.support_level] >= SUPPORT_ORDER["supported"] for item in items) else "needs_validation"
            bundle = {
                "candidate_ids": [item.candidate_id for item in items],
                "bundles": [bundle_map[item.candidate_id].to_dict() for item in items if item.candidate_id in bundle_map],
            }
            findings.append(
                FindingCandidate(
                    finding_candidate_id=f"FC-{index:04d}",
                    hypothesis_ids=[item.candidate_id for item in items],
                    title=f"{category.replace('_', ' ').title()} investigation candidate",
                    affected_components=_unique([component] + [c for item in items for c in item.component_ids]),
                    entry_points=_unique([entry for item in items for entry in item.entry_point_ids]),
                    sources=_unique([source for item in items for source in item.source_ids]),
                    sinks=_unique([sink for item in items for sink in item.sink_ids]),
                    evidence_bundle=bundle,
                    confidence=confidence,
                    status=status,
                    missing_validation=_unique([missing for item in items for missing in item.missing_evidence]),
                    security_category=category,
                    candidate_cwe_ids=_unique([cwe for item in items for cwe in item.candidate_cwe_ids]),
                    provider_backed=False,
                )
            )
        return findings

    def _summary(
        self,
        candidates: list[HypothesisCandidate],
        decisions: list[HypothesisPromotionDecision],
        deduplicated_count: int,
        findings: list[FindingCandidate],
    ) -> HypothesisSynthesisSummary:
        counts = Counter(item.support_level for item in candidates)
        rejected = sum(1 for item in decisions if not item.promote)
        top = [
            {
                "candidate_id": item.candidate_id,
                "hypothesis_type": item.hypothesis_type,
                "support_level": item.support_level,
                "confidence": item.confidence,
                "title": item.title,
            }
            for item in sorted(candidates, key=_candidate_rank, reverse=True)[:5]
        ]
        return HypothesisSynthesisSummary(
            candidate_count=len(candidates),
            promoted_count=sum(1 for item in decisions if item.promote),
            deduplicated_count=deduplicated_count,
            rejected_by_gate=rejected,
            weak_candidate_count=counts.get("weak_candidate", 0) + counts.get("candidate", 0),
            supported_count=counts.get("supported", 0) + counts.get("strongly_supported", 0),
            runtime_supported_count=counts.get("runtime_supported", 0),
            finding_candidate_count=len(findings),
            top_candidates=top,
            safety_notes=[
                "Candidate != Vulnerability",
                "Supported Hypothesis != Confirmed Exploit",
                "source + sink != vulnerability",
                "call path != data flow",
                "runtime handler reachable != runtime sink reached",
            ],
            provider_backed=False,
        )

    def _persist(self, payload: dict[str, Any]) -> None:
        self.workspace.save_hypothesis_artifact("templates.json", payload["templates"])
        self.workspace.save_hypothesis_artifact("candidates.json", payload["candidates"])
        self.workspace.save_hypothesis_artifact("promotion_decisions.json", payload["promotion_decisions"])
        self.workspace.save_hypothesis_artifact("canonical_generated.json", payload["canonical_generated"])
        self.workspace.save_hypothesis_artifact("evidence_bundles.json", payload["evidence_bundles"])
        self.workspace.save_hypothesis_artifact("finding_candidates.json", payload["finding_candidates"])
        self.workspace.save_hypothesis_artifact("summary.json", payload["summary"])
        self.workspace.save_hypothesis_artifact("synthesis_analysis.json", payload)


def _claim_for_path(hypothesis_type: str, source: dict[str, Any], sink: dict[str, Any], path: dict[str, Any]) -> tuple[str, str]:
    source_label = str(source.get("parameter_name") or source.get("source_type") or source.get("source_id"))
    entry = str(path.get("entry_point_id") or source.get("entry_point_id") or "entry")
    sink_name = str(sink.get("callee_name") or sink.get("function_name") or sink.get("sink_id"))
    function = " -> ".join(str(item) for item in path.get("function_chain") or [] if item) or str(sink.get("function_name") or "function")
    if hypothesis_type == "unsafe_input_handling":
        return (
            f"Input reaches unsafe input primitive {sink_name}",
            f"Input from {source_label} reaches the unsafe {sink_name} input primitive in {function}; exploitability is not established.",
        )
    if hypothesis_type == "possible_command_influence":
        return (
            f"Input may influence command execution sink {sink_name}",
            f"Input from {entry} may influence command-execution sink {sink_name}; command influence is not established.",
        )
    if hypothesis_type == "possible_memory_safety_issue":
        return (
            f"Input may reach copy operation {sink_name}",
            f"Input derived from {entry} may reach {sink_name} in {function}; memory corruption is not established.",
        )
    if hypothesis_type in {"possible_path_influence", "possible_file_write_influence"}:
        return (
            f"Input may influence filesystem operation {sink_name}",
            f"Input derived from {entry} may influence filesystem operation {sink_name}; path control is not established.",
        )
    return (
        f"Input has security-relevant relationship with {sink_name}",
        f"Input from {entry} may reach security-relevant operation {sink_name}; missing evidence prevents stronger claims.",
    )


def _support_level(path: dict[str, Any]) -> str:
    if path.get("runtime_sink_confirmed") or path.get("runtime_supported"):
        return "runtime_supported"
    state = path.get("path_state")
    if state == "validated":
        return "strongly_supported"
    if state == "statically_supported" or _evidence_level_rank(path.get("evidence_level")) >= _evidence_level_rank("L3_argument_propagation"):
        return "supported"
    if _evidence_level_rank(path.get("evidence_level")) >= _evidence_level_rank("L1_same_component"):
        return "candidate"
    return "weak_candidate"


def _evidence_level_rank(level: Any) -> int:
    text = str(level or "")
    if text.startswith("L5"):
        return 5
    if text.startswith("L4"):
        return 4
    if text.startswith("L3"):
        return 3
    if text.startswith("L2"):
        return 2
    if text.startswith("L1"):
        return 1
    return 0


def _candidate_cwes(hypothesis_type: str, sink: dict[str, Any], support: str) -> list[str]:
    if SUPPORT_ORDER[support] < SUPPORT_ORDER["supported"]:
        return []
    callee = str(sink.get("callee_name") or "").lower()
    if hypothesis_type == "unsafe_input_handling" and callee == "gets":
        return ["CWE-120", "CWE-242"]
    return []


def _security_category(hypothesis_type: str) -> str:
    return {
        "unsafe_input_handling": "input_validation",
        "possible_memory_safety_issue": "memory_safety",
        "possible_command_influence": "command_execution",
        "possible_path_influence": "filesystem",
        "possible_file_write_influence": "filesystem",
        "authentication_logic_concern": "authentication",
        "authorization_logic_concern": "authorization",
        "unsafe_dynamic_load": "dynamic_loading",
        "unvalidated_external_input": "input_validation",
        "security_sensitive_reachability": "network_parsing",
    }.get(hypothesis_type, "unknown")


def _overlaps_existing(candidate: HypothesisCandidate, hypothesis: DynamicHypothesis) -> bool:
    text = f"{hypothesis.id} {hypothesis.title}".lower()
    if "ret2text" in text and any("RET2TEXT" in item for item in candidate.source_ids + candidate.sink_ids + candidate.taint_path_ids):
        return True
    if ("fcgi" in text or "device_manager" in text) and any("FCGI" in item for item in candidate.source_ids + candidate.sink_ids + candidate.taint_path_ids):
        return True
    return bool(set(candidate.static_evidence_ids) & set(hypothesis.evidence_ids))


def _candidate_rank(candidate: HypothesisCandidate) -> tuple[int, float, float]:
    return (SUPPORT_ORDER[candidate.support_level], candidate.confidence, candidate.security_relevance)


def _unique_candidates(candidates: list[HypothesisCandidate]) -> list[HypothesisCandidate]:
    seen = set()
    result = []
    for candidate in candidates:
        if candidate.candidate_id in seen:
            continue
        seen.add(candidate.candidate_id)
        result.append(candidate)
    return result


def _dedup_key(hypothesis_type: str, entries: list[str], sinks: list[str], functions: list[str]) -> str:
    return "|".join(
        [
            hypothesis_type,
            ",".join(sorted(item for item in entries if item)),
            ",".join(sorted(item for item in sinks if item)),
            ",".join(sorted(item for item in functions if item)),
        ]
    )


def _overclaim_flags(text: str) -> list[str]:
    lower = text.lower()
    return [phrase for phrase in FORBIDDEN_CLAIM_PHRASES if phrase in lower]


def _unique(values: list[Any]) -> list[Any]:
    result = []
    seen = set()
    for value in values:
        if value in (None, ""):
            continue
        marker = json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(value)
    return result


def _slug(value: str) -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value))
    return "-".join(part for part in normalized.split("-") if part)[:80] or "unknown"


def _clamp01(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 3)

