from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.workspace import DynamicWorkspace


FINDING_STATUSES = {
    "candidate",
    "supported",
    "runtime_supported",
    "inconclusive",
    "rejected",
    "blocked",
    "informational",
}

FINDING_CATEGORIES = {
    "memory_safety",
    "input_validation",
    "command_execution",
    "filesystem",
    "authentication",
    "authorization",
    "configuration",
    "dynamic_loading",
    "network_parsing",
    "runtime_anomaly",
    "informational",
    "unknown",
}

SEVERITY_HINTS = {"informational", "low", "medium", "high", "unknown"}

FORBIDDEN_FINDING_CLAIMS = (
    "confirmed rce",
    "rce confirmed",
    "remote code execution confirmed",
    "confirmed command injection",
    "command injection confirmed",
    "confirmed stack overflow exploit",
    "stack overflow exploit confirmed",
    "exploitable stack overflow",
    "authentication bypass confirmed",
    "weaponized",
    "exploited",
    "ret2secure exploit",
)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class FindingEvidenceChain:
    entry: list[str] = field(default_factory=list)
    route: list[str] = field(default_factory=list)
    component_path: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)
    taint_path: list[str] = field(default_factory=list)
    sink: list[str] = field(default_factory=list)
    static_evidence: list[str] = field(default_factory=list)
    dynamic_evidence: list[str] = field(default_factory=list)
    validation_result: str = "not_executed"
    confidence_by_stage: dict[str, float] = field(default_factory=dict)
    missing_links: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    finding_id: str
    title: str
    category: str
    status: str
    confidence: float
    severity_hint: str
    affected_components: list[str] = field(default_factory=list)
    binary_paths: list[str] = field(default_factory=list)
    service_names: list[str] = field(default_factory=list)
    entry_point_ids: list[str] = field(default_factory=list)
    route_ids: list[str] = field(default_factory=list)
    source_ids: list[str] = field(default_factory=list)
    sink_ids: list[str] = field(default_factory=list)
    taint_path_ids: list[str] = field(default_factory=list)
    hypothesis_ids: list[str] = field(default_factory=list)
    static_evidence_ids: list[str] = field(default_factory=list)
    dynamic_evidence_ids: list[str] = field(default_factory=list)
    runtime_validation_ids: list[str] = field(default_factory=list)
    summary: str = ""
    technical_detail: str = ""
    evidence_chain: FindingEvidenceChain = field(default_factory=FindingEvidenceChain)
    runtime_support: str = "not_established"
    remaining_uncertainty: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    validation_status: str = "not_executed"
    remediation_note: str = ""
    candidate_cwe_ids: list[str] = field(default_factory=list)
    provenance: str = "canonical_artifacts"
    execution_mode: str = "real"
    provider_backed: bool = False
    merge_reason: str | None = None
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def __post_init__(self) -> None:
        if self.status not in FINDING_STATUSES:
            raise ValueError(f"invalid finding status: {self.status}")
        if self.category not in FINDING_CATEGORIES:
            raise ValueError(f"invalid finding category: {self.category}")
        if self.severity_hint not in SEVERITY_HINTS:
            raise ValueError(f"invalid severity hint: {self.severity_hint}")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence_chain"] = self.evidence_chain.to_dict()
        return payload


@dataclass
class FindingPromotionDecision:
    source_candidate_id: str
    promote: bool
    status: str
    reason: str
    confidence: float
    severity_hint: str
    canonical_evidence_ids: list[str] = field(default_factory=list)
    excluded_evidence_ids: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    provider_backed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class FindingClaimGuard:
    def validate(self, text: str, *, allow_confirmed_exploit: bool = False) -> tuple[bool, str]:
        normalized = re.sub(r"\s+", " ", text.lower())
        if allow_confirmed_exploit:
            return True, "allowed by explicit exploit evidence level"
        for phrase in FORBIDDEN_FINDING_CLAIMS:
            if phrase in normalized:
                return False, f"prohibited overclaim phrase: {phrase}"
        return True, "claim accepted"


class FindingFinalizer:
    def __init__(self, workspace_root: str, task_id: str):
        self.workspace = DynamicWorkspace(workspace_root, task_id)
        self.guard = FindingClaimGuard()

    def finalize(self, *, dynamic_executed: bool = True) -> dict[str, Any]:
        candidates = self.workspace.load_hypothesis_artifact("finding_candidates.json") or []
        synthesis = self.workspace.load_hypothesis_artifact("synthesis_analysis.json") or {}
        candidate_index = {item.get("candidate_id"): item for item in synthesis.get("candidates", [])}
        hypotheses = {item.id: item for item in self.workspace.load_hypotheses()}
        evidence = {item.id: item for item in self.workspace.load_evidence()}
        findings: list[Finding] = []
        rejected: list[dict[str, Any]] = []
        decisions: list[FindingPromotionDecision] = []
        for raw in candidates:
            decision = self._decision(raw, candidate_index, hypotheses, evidence, dynamic_executed=dynamic_executed)
            decisions.append(decision)
            if not decision.promote:
                rejected.append({"candidate_id": decision.source_candidate_id, "reason": decision.reason, "status": decision.status})
                continue
            finding = self._finding(len(findings) + 1, raw, decision, candidate_index, hypotheses, evidence, dynamic_executed=dynamic_executed)
            ok, reason = self.guard.validate(f"{finding.title} {finding.summary} {finding.technical_detail}")
            if not ok:
                finding.status = "informational"
                finding.severity_hint = "unknown"
                finding.remaining_uncertainty.append(reason)
            findings.append(finding)
        payload = {
            "success": True,
            "findings": [item.to_dict() for item in findings],
            "promotion_decisions": [item.to_dict() for item in decisions],
            "rejected_candidates": rejected,
            "provider_backed": False,
            "real_model_validation": "deferred",
            "created_at": utc_now_iso(),
        }
        self.workspace.task_dir.joinpath("findings").mkdir(parents=True, exist_ok=True)
        (self.workspace.task_dir / "findings" / "findings.json").write_text(_json(payload), encoding="utf-8")
        return payload

    def _decision(
        self,
        raw: dict[str, Any],
        candidate_index: dict[str, dict[str, Any]],
        hypotheses: dict[str, DynamicHypothesis],
        evidence: dict[str, DynamicEvidence],
        *,
        dynamic_executed: bool,
    ) -> FindingPromotionDecision:
        candidate_ids = list((raw.get("evidence_bundle") or {}).get("candidate_ids") or raw.get("hypothesis_ids") or [])
        candidates = [candidate_index[item] for item in candidate_ids if item in candidate_index]
        canonical_hypothesis_ids = _unique([hyp_id for item in candidates for hyp_id in list(item.get("existing_hypothesis_ids") or [])])
        related_hypotheses = [hypotheses[item] for item in canonical_hypothesis_ids if item in hypotheses]
        bundled_ids = _evidence_ids(raw)
        canonical, excluded = _canonical_evidence_ids(bundled_ids, evidence)
        missing = _unique(list(raw.get("missing_validation") or []) + [m for hyp in related_hypotheses for m in hyp.missing_evidence])
        if raw.get("provider_backed"):
            return FindingPromotionDecision(str(raw.get("finding_candidate_id")), False, "rejected", "provider-backed candidate is not canonical in deterministic Round 5", 0.0, "unknown", [], bundled_ids, missing)
        if not canonical and bundled_ids:
            return FindingPromotionDecision(str(raw.get("finding_candidate_id")), False, "rejected", "mock-only or non-canonical evidence excluded", 0.0, "unknown", [], bundled_ids, missing)
        if any((hyp.dynamic_status or hyp.status) == "dynamically_rejected" or hyp.status == "rejected" for hyp in related_hypotheses):
            return FindingPromotionDecision(str(raw.get("finding_candidate_id")), False, "rejected", "related canonical hypothesis was rejected", float(raw.get("confidence") or 0.0), "unknown", canonical, excluded, missing)
        status = _status(raw, related_hypotheses, dynamic_executed)
        confidence = _confidence(raw, candidates, related_hypotheses, evidence)
        severity = _severity(raw, status, confidence, related_hypotheses)
        return FindingPromotionDecision(str(raw.get("finding_candidate_id")), True, status, "canonical evidence supports a conservative security-relevant finding", confidence, severity, canonical, excluded, missing)

    def _finding(
        self,
        index: int,
        raw: dict[str, Any],
        decision: FindingPromotionDecision,
        candidate_index: dict[str, dict[str, Any]],
        hypotheses: dict[str, DynamicHypothesis],
        evidence: dict[str, DynamicEvidence],
        *,
        dynamic_executed: bool,
    ) -> Finding:
        candidate_ids = list((raw.get("evidence_bundle") or {}).get("candidate_ids") or raw.get("hypothesis_ids") or [])
        candidates = [candidate_index[item] for item in candidate_ids if item in candidate_index]
        canonical_hypothesis_ids = _unique([hyp_id for item in candidates for hyp_id in list(item.get("existing_hypothesis_ids") or [])])
        related_hypotheses = [hypotheses[item] for item in canonical_hypothesis_ids if item in hypotheses]
        dynamic_ids = [item for item in decision.canonical_evidence_ids if item.startswith("DE-")]
        static_ids = [item for item in decision.canonical_evidence_ids if not item.startswith("DE-")]
        validation_ids = _validation_ids(evidence, dynamic_ids)
        category = str(raw.get("security_category") or "unknown")
        if category not in FINDING_CATEGORIES:
            category = "unknown"
        title = _safe_title(raw, related_hypotheses)
        chain = FindingEvidenceChain(
            entry=list(raw.get("entry_points") or []),
            route=[],
            component_path=list(raw.get("affected_components") or []),
            source=list(raw.get("sources") or []),
            taint_path=_unique([path_id for item in candidates for path_id in list(item.get("taint_path_ids") or [])]),
            sink=list(raw.get("sinks") or []),
            static_evidence=static_ids,
            dynamic_evidence=dynamic_ids,
            validation_result=_validation_status(related_hypotheses, dynamic_executed),
            confidence_by_stage=_confidence_by_stage(raw, candidates, related_hypotheses),
            missing_links=_missing_links(raw),
        )
        return Finding(
            finding_id=f"F-{index:04d}",
            title=title,
            category=category,
            status=decision.status,
            confidence=decision.confidence,
            severity_hint=decision.severity_hint,
            affected_components=list(raw.get("affected_components") or []),
            binary_paths=_unique([path for item in candidates for path in list(item.get("binary_paths") or []) if path]),
            service_names=[],
            entry_point_ids=list(raw.get("entry_points") or []),
            source_ids=list(raw.get("sources") or []),
            sink_ids=list(raw.get("sinks") or []),
            taint_path_ids=chain.taint_path,
            hypothesis_ids=canonical_hypothesis_ids or list(raw.get("hypothesis_ids") or []),
            static_evidence_ids=static_ids,
            dynamic_evidence_ids=dynamic_ids,
            runtime_validation_ids=validation_ids,
            summary=_summary(raw, decision.status),
            technical_detail=_technical_detail(raw, chain, related_hypotheses),
            evidence_chain=chain,
            runtime_support=_runtime_support(related_hypotheses, dynamic_ids, dynamic_executed),
            remaining_uncertainty=decision.missing_evidence or ["not established"],
            missing_evidence=decision.missing_evidence,
            validation_status=chain.validation_result,
            remediation_note=_remediation(category),
            candidate_cwe_ids=list(raw.get("candidate_cwe_ids") or []),
            provenance="canonical_artifacts",
            execution_mode="real",
            provider_backed=False,
        )


def _json(payload: Any) -> str:
    import json

    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def _evidence_ids(raw: dict[str, Any]) -> list[str]:
    bundle = raw.get("evidence_bundle") or {}
    ids: list[str] = []
    for item in bundle.get("bundles") or []:
        for key in ("source_evidence", "sink_evidence", "taint_evidence", "runtime_evidence", "entry_evidence", "component_evidence"):
            ids.extend(str(value) for value in list(item.get(key) or []))
    return _unique(ids)


def _canonical_evidence_ids(ids: list[str], evidence: dict[str, DynamicEvidence]) -> tuple[list[str], list[str]]:
    canonical: list[str] = []
    excluded: list[str] = []
    for evidence_id in ids:
        if evidence_id.startswith("MDE-"):
            excluded.append(evidence_id)
            continue
        item = evidence.get(evidence_id)
        if item and (item.execution_mode == "mock" or item.provider_backed or item.provenance.startswith("mock")):
            excluded.append(evidence_id)
            continue
        canonical.append(evidence_id)
    return _unique(canonical), _unique(excluded)


def _status(raw: dict[str, Any], hypotheses: list[DynamicHypothesis], dynamic_executed: bool) -> str:
    statuses = {(hyp.dynamic_status or hyp.status) for hyp in hypotheses}
    if "dynamically_supported" in statuses or "validated" in statuses:
        return "runtime_supported"
    if "dynamically_rejected" in statuses or "rejected" in statuses:
        return "rejected"
    if "validation_blocked" in statuses:
        return "supported" if raw.get("status") == "supported" else "blocked"
    if "validation_inconclusive" in statuses:
        return "inconclusive" if raw.get("status") != "supported" else "supported"
    if not dynamic_executed:
        return "supported" if raw.get("status") == "supported" else "candidate"
    if raw.get("status") in {"supported", "runtime_supported"}:
        return "supported"
    if raw.get("status") == "needs_validation":
        return "candidate"
    return "candidate"


def _confidence(raw: dict[str, Any], candidates: list[dict[str, Any]], hypotheses: list[DynamicHypothesis], evidence: dict[str, DynamicEvidence]) -> float:
    values = [float(raw.get("confidence") or 0.0)]
    values.extend(float(item.get("confidence") or 0.0) for item in candidates)
    values.extend(float(item.confidence or 0.0) for item in hypotheses)
    runtime_bonus = 0.08 if any(item.runtime_observation_real for item in evidence.values()) else 0.0
    missing_penalty = min(0.25, len(raw.get("missing_validation") or []) * 0.03)
    return round(max(0.0, min(1.0, (sum(values) / max(1, len(values))) + runtime_bonus - missing_penalty)), 3)


def _severity(raw: dict[str, Any], status: str, confidence: float, hypotheses: list[DynamicHypothesis]) -> str:
    category = raw.get("security_category")
    if status in {"candidate", "informational"} or confidence < 0.45:
        return "unknown"
    if category in {"command_execution", "memory_safety"} and status == "runtime_supported" and confidence >= 0.8:
        return "high"
    if category in {"command_execution", "memory_safety", "input_validation"} and confidence >= 0.6:
        return "medium"
    if hypotheses or confidence >= 0.5:
        return "low"
    return "unknown"


def _validation_status(hypotheses: list[DynamicHypothesis], dynamic_executed: bool) -> str:
    if not dynamic_executed:
        return "not_executed"
    for status in ("dynamically_supported", "dynamically_rejected", "validation_blocked", "validation_inconclusive", "validated"):
        if any((hyp.dynamic_status or hyp.status) == status for hyp in hypotheses):
            return status
    return "not_established"


def _validation_ids(evidence: dict[str, DynamicEvidence], ids: list[str]) -> list[str]:
    return _unique([str(evidence[item].metadata.get("validation_id")) for item in ids if item in evidence and evidence[item].metadata.get("validation_id")])


def _confidence_by_stage(raw: dict[str, Any], candidates: list[dict[str, Any]], hypotheses: list[DynamicHypothesis]) -> dict[str, float]:
    return {
        "candidate": round(float(raw.get("confidence") or 0.0), 3),
        "hypothesis": round(max([float(item.confidence or 0.0) for item in hypotheses] or [0.0]), 3),
        "taint": round(max([float(item.get("confidence") or 0.0) for item in candidates] or [0.0]), 3),
        "runtime": 0.0 if raw.get("missing_validation") else 0.5,
    }


def _missing_links(raw: dict[str, Any]) -> list[str]:
    missing = []
    if not raw.get("entry_points"):
        missing.append("entry")
    if not raw.get("sources"):
        missing.append("source")
    if not raw.get("sinks"):
        missing.append("sink")
    missing.extend(str(item) for item in list(raw.get("missing_validation") or []))
    return _unique(missing) or ["not established"]


def _safe_title(raw: dict[str, Any], hypotheses: list[DynamicHypothesis]) -> str:
    text = str(raw.get("title") or (hypotheses[0].title if hypotheses else "Security-relevant firmware finding"))
    lowered = text.lower()
    replacements = {
        "ret2text stack overflow": "Unsafe stdin input handling",
        "command injection": "command-execution-related",
        "rce": "security impact",
    }
    for old, new in replacements.items():
        lowered = lowered.replace(old, new)
    if "unsafe input" in lowered or "input validation" in lowered:
        return "Stdin data reaches unsafe input handling primitive"
    if "network parsing" in lowered or "fastcgi" in lowered:
        return "Security-sensitive FastCGI request handling path requires further validation"
    return text


def _summary(raw: dict[str, Any], status: str) -> str:
    if raw.get("security_category") == "input_validation":
        return "Canonical static evidence supports that stdin-derived input reaches an unsafe input primitive; exploitability is not established."
    if raw.get("security_category") == "network_parsing":
        return "Canonical evidence shows a security-sensitive FastCGI request handling path, but argument-level source-to-sink flow and runtime sink observation remain unestablished."
    return f"Canonical evidence supports a conservative {status} security-relevant finding."


def _technical_detail(raw: dict[str, Any], chain: FindingEvidenceChain, hypotheses: list[DynamicHypothesis]) -> str:
    parts = [
        f"Entry: {', '.join(chain.entry) or 'not established'}.",
        f"Source: {', '.join(chain.source) or 'not established'}.",
        f"Sink: {', '.join(chain.sink) or 'not established'}.",
        f"Validation: {chain.validation_result}.",
    ]
    if hypotheses:
        parts.append("Hypotheses: " + ", ".join(item.id for item in hypotheses) + ".")
    return " ".join(parts)


def _runtime_support(hypotheses: list[DynamicHypothesis], dynamic_ids: list[str], dynamic_executed: bool) -> str:
    if not dynamic_executed:
        return "not_executed"
    if any((hyp.dynamic_status or hyp.status) == "validation_blocked" for hyp in hypotheses):
        return "blocked"
    if any((hyp.dynamic_status or hyp.status) == "validation_inconclusive" for hyp in hypotheses):
        return "inconclusive"
    if dynamic_ids:
        return "runtime_observed"
    return "not_established"


def _remediation(category: str) -> str:
    if category == "input_validation":
        return "Review input length handling and replace unsafe input primitives with bounded alternatives."
    if category == "network_parsing":
        return "Review request parsing and validate whether request-derived fields can reach sensitive operations."
    return "Review the referenced component and validate the missing evidence before treating this as a vulnerability."
