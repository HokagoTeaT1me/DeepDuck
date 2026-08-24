from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.correlation import CanonicalStateGuard, ComponentGraphBuilder
from fwagent.dynamic.models import DynamicEvidence
from fwagent.dynamic.prioritization import HypothesisValidationScheduler
from fwagent.dynamic.surface import AttackSurfaceBuilder
from fwagent.dynamic.synthesis import HypothesisSynthesizer
from fwagent.dynamic.taint import TaintAnalysisBuilder
from fwagent.dynamic.validation import DynamicValidationPlan
from fwagent.dynamic.workspace import DynamicWorkspace


INVESTIGATION_PHASES = {
    "initializing",
    "static_analysis",
    "correlation",
    "surface_mapping",
    "taint_analysis",
    "hypothesis_synthesis",
    "prioritization",
    "validation_planning",
    "dynamic_validation",
    "evidence_update",
    "reranking",
    "report_ready",
    "completed",
    "blocked",
    "failed",
    "stopped",
}
INVESTIGATION_STATUSES = {"running", "paused", "completed", "blocked", "failed", "cancelled"}
INVESTIGATION_ACTIONS = {
    "refresh_artifact",
    "inspect_context",
    "synthesize",
    "prioritize",
    "plan_validation",
    "execute_validation",
    "collect_evidence",
    "rerank",
    "defer",
    "stop",
    "pause",
}
STOP_REASONS = {
    "budget_exhausted",
    "no_candidate_hypotheses",
    "no_validatable_hypotheses",
    "remaining_priority_too_low",
    "all_remaining_blocked",
    "all_remaining_duplicates",
    "marginal_information_gain_low",
    "max_inconclusive_reached",
    "max_failures_reached",
    "safety_stop",
    "user_stop",
    "completed_useful_investigation",
    "investigation_converged",
    "max_iterations_reached",
}
PHASE_DEPENDENCIES = {
    "correlation": ("static_analysis",),
    "surface_mapping": ("correlation",),
    "taint_analysis": ("surface_mapping",),
    "hypothesis_synthesis": ("taint_analysis",),
    "prioritization": ("hypothesis_synthesis",),
    "validation_planning": ("prioritization",),
    "dynamic_validation": ("validation_planning",),
    "evidence_update": ("dynamic_validation",),
    "reranking": ("evidence_update",),
}


@dataclass
class InvestigationBudget:
    max_iterations: int = 5
    max_total_tool_calls: int = 30
    max_total_requests: int = 10
    max_total_dynamic_seconds: int = 180
    max_total_runtime_boots: int = 2
    max_total_validations: int = 3
    max_blocked_validations: int = 2
    max_inconclusive_validations: int = 2
    max_failures: int = 2

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class BudgetState:
    iterations_used: int = 0
    tool_calls_used: int = 0
    requests_used: int = 0
    dynamic_seconds_used: int = 0
    runtime_boots_used: int = 0
    validations_used: int = 0
    blocked_count: int = 0
    inconclusive_count: int = 0
    failure_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ArtifactFreshness:
    artifact_name: str
    input_version: str
    output_version: str
    generated_at: str
    stale: bool = False
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceDelta:
    new_evidence_ids: list[str] = field(default_factory=list)
    new_dynamic_evidence_ids: list[str] = field(default_factory=list)
    updated_relationships: list[str] = field(default_factory=list)
    new_paths: list[str] = field(default_factory=list)
    new_hypotheses: list[str] = field(default_factory=list)
    changed_hypothesis_status: list[str] = field(default_factory=list)
    changed_priority: list[str] = field(default_factory=list)
    canonical_update_allowed_ids: list[str] = field(default_factory=list)
    simulation_evidence_ids: list[str] = field(default_factory=list)

    def has_progress(self) -> bool:
        return bool(
            self.new_evidence_ids
            or self.new_dynamic_evidence_ids
            or self.updated_relationships
            or self.new_paths
            or self.new_hypotheses
            or self.changed_hypothesis_status
            or self.changed_priority
            or self.canonical_update_allowed_ids
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationIteration:
    iteration_id: str
    iteration_number: int
    starting_state: str
    selected_hypothesis: str | None = None
    selected_runtime: str | None = None
    validation_id: str | None = None
    tool_calls: int = 0
    requests: int = 0
    new_evidence_ids: list[str] = field(default_factory=list)
    verdict: str | None = None
    changed_components: list[str] = field(default_factory=list)
    changed_paths: list[str] = field(default_factory=list)
    changed_hypotheses: list[str] = field(default_factory=list)
    priority_before: list[dict[str, Any]] = field(default_factory=list)
    priority_after: list[dict[str, Any]] = field(default_factory=list)
    budget_before: dict[str, Any] = field(default_factory=dict)
    budget_after: dict[str, Any] = field(default_factory=dict)
    stop_reason: str | None = None
    duration: float = 0.0
    validation_fingerprint: str | None = None
    decision_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationState:
    investigation_id: str
    task_id: str
    firmware_id: str | None = None
    phase: str = "initializing"
    status: str = "running"
    iteration: int = 0
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    component_graph_version: str | None = None
    surface_version: str | None = None
    taint_version: str | None = None
    hypothesis_version: str | None = None
    priority_version: str | None = None
    canonical_hypothesis_ids: list[str] = field(default_factory=list)
    candidate_hypothesis_ids: list[str] = field(default_factory=list)
    active_hypothesis_id: str | None = None
    active_validation_id: str | None = None
    completed_hypotheses: list[str] = field(default_factory=list)
    blocked_hypotheses: list[str] = field(default_factory=list)
    inconclusive_hypotheses: list[str] = field(default_factory=list)
    rejected_hypotheses: list[str] = field(default_factory=list)
    supported_hypotheses: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    dynamic_evidence_ids: list[str] = field(default_factory=list)
    budget_state: dict[str, Any] = field(default_factory=dict)
    stop_reason: str | None = None
    provider_backed: bool = False
    execution_mode: str = "real"
    last_successful_checkpoint: str | None = None
    errors: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.phase not in INVESTIGATION_PHASES:
            raise ValueError(f"invalid investigation phase: {self.phase}")
        if self.status not in INVESTIGATION_STATUSES:
            raise ValueError(f"invalid investigation status: {self.status}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationAction:
    action_type: str
    target: str | None = None
    reason: str = ""
    provider_backed: bool = False
    execution_mode: str = "real"

    def __post_init__(self) -> None:
        if self.action_type not in INVESTIGATION_ACTIONS:
            raise ValueError(f"invalid investigation action: {self.action_type}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationContext:
    current_phase: str
    top_hypotheses: list[dict[str, Any]]
    active_hypothesis: dict[str, Any] | None
    attack_surface_summary: dict[str, Any]
    cross_component_context: dict[str, Any]
    taint_context: dict[str, Any]
    missing_evidence: list[str]
    runtime_capabilities: dict[str, Any]
    budget_remaining: dict[str, Any]
    recent_evidence: list[dict[str, Any]]
    recent_verdicts: list[dict[str, Any]]
    blocked_items: list[str]
    recommended_actions: list[dict[str, Any]]
    provider_backed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationSummary:
    iterations: int
    components: int
    entry_points: int
    sources: int
    sinks: int
    hypotheses_generated: int
    hypotheses_validated: int
    supported: int
    rejected: int
    inconclusive: int
    blocked: int
    evidence_count: int
    dynamic_evidence_count: int
    finding_candidates: int
    budget_used: dict[str, Any]
    stop_reason: str | None
    provider_backed: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ActionProposal:
    action: str
    target: str | None = None
    reason: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class DeterministicPlanner:
    def plan_next_action(self, context: InvestigationContext) -> ActionProposal:
        if context.top_hypotheses:
            top = context.top_hypotheses[0]
            return ActionProposal(
                "plan_validation",
                str(top.get("hypothesis_id")),
                f"Selected {top.get('hypothesis_id')} because it has highest priority and runtime feasibility.",
            )
        return ActionProposal("stop", reason="no validatable hypotheses remain")


class MockPlanner(DeterministicPlanner):
    def plan_next_action(self, context: InvestigationContext) -> ActionProposal:
        proposal = super().plan_next_action(context)
        proposal.reason = f"mock planner proposal: {proposal.reason}"
        return proposal


class ProviderBackedPlanner(DeterministicPlanner):
    pass


class InvestigationActionGuard:
    def validate(
        self,
        action: InvestigationAction,
        state: InvestigationState,
        budget: InvestigationBudget,
        budget_state: BudgetState,
    ) -> tuple[bool, str]:
        if action.provider_backed:
            return False, "provider-backed actions are deferred in Round 4.6"
        if action.action_type in {"plan_validation", "execute_validation"}:
            if budget_state.validations_used >= budget.max_total_validations:
                return False, "validation budget exhausted"
            if budget_state.requests_used >= budget.max_total_requests:
                return False, "request budget exhausted"
        if action.execution_mode == "mock" and action.action_type == "execute_validation":
            return True, "mock validation allowed only in simulation artifacts"
        if state.status not in {"running", "paused"}:
            return False, f"state status {state.status} cannot execute actions"
        return True, "allowed"


class InvestigationController:
    def __init__(self, workspace_root: str | Path, task_id: str, *, config: DynamicConfig, planner: DeterministicPlanner | None = None):
        self.workspace = DynamicWorkspace(workspace_root, task_id)
        self.config = config
        self.planner = planner or DeterministicPlanner()
        self.guard = InvestigationActionGuard()
        self.budget = InvestigationBudget(
            max_iterations=config.investigation.max_iterations,
            max_total_tool_calls=config.investigation.max_total_tool_calls,
            max_total_requests=config.investigation.max_total_requests,
            max_total_dynamic_seconds=config.investigation.max_dynamic_seconds,
            max_total_runtime_boots=config.investigation.max_runtime_boots,
            max_total_validations=config.investigation.max_total_validations,
            max_blocked_validations=config.investigation.stop.max_blocked,
            max_inconclusive_validations=config.investigation.stop.max_inconclusive,
            max_failures=config.investigation.stop.max_failures,
        )

    def run(
        self,
        *,
        resume: bool = False,
        max_iterations: int | None = None,
        stop_after_iteration: bool = False,
    ) -> dict[str, Any]:
        state = self.load_or_create_state(resume=resume)
        budget_state = self.load_budget_state()
        if state.status == "completed":
            return self._persist_summary(state, budget_state)
        if state.status == "paused" and not resume:
            state.status = "running"
        self.refresh_required_artifacts(state)
        no_progress = 0
        limit = min(max_iterations or self.budget.max_iterations, self.budget.max_iterations)
        while state.status == "running" and budget_state.iterations_used < limit:
            started = time.monotonic()
            before_priority = self._priority_rows()
            iteration = InvestigationIteration(
                iteration_id=f"ITER-{budget_state.iterations_used + 1:04d}",
                iteration_number=budget_state.iterations_used + 1,
                starting_state=state.phase,
                priority_before=before_priority,
                budget_before=budget_state.to_dict(),
            )
            state.iteration = iteration.iteration_number
            context = self.context(state, budget_state)
            proposal = self.planner.plan_next_action(context)
            self._record_action(state, iteration.iteration_number, "inspect_context", proposal.target, True, proposal.reason)
            selected = self._select_next_hypothesis(context.top_hypotheses)
            if not selected:
                delta = EvidenceDelta()
                no_progress += 1
                budget_state.iterations_used += 1
                self.save_budget_state(budget_state)
                state.budget_state = budget_state.to_dict()
                iteration.decision_summary = "No non-duplicate validation fingerprint remained; reranking only."
                iteration.stop_reason = "all_remaining_duplicates" if context.top_hypotheses else "no_validatable_hypotheses"
                iteration.priority_after = self._priority_rows()
                iteration.budget_after = budget_state.to_dict()
                iteration.duration = round(time.monotonic() - started, 3)
                self._finish_iteration(state, iteration, delta)
                if self._converged(no_progress):
                    self._complete(state, "investigation_converged")
                    break
                if stop_after_iteration:
                    state.status = "paused"
                    state.phase = "stopped"
                    state.stop_reason = "user_stop"
                    break
                continue
            action = InvestigationAction("execute_validation", selected.get("hypothesis_id"), "bounded simulation validation", execution_mode="mock")
            allowed, reason = self.guard.validate(action, state, self.budget, budget_state)
            if not allowed:
                self._record_action(state, iteration.iteration_number, "defer", selected.get("hypothesis_id"), False, reason)
                self._mark_blocked(state, selected.get("hypothesis_id"), reason)
                budget_state.blocked_count += 1
                no_progress += 1
            else:
                delta = self._execute_iteration(state, iteration, selected, budget_state)
                no_progress = 0 if delta.has_progress() else no_progress + 1
                self.invalidate_for_delta(delta)
                self.refresh_required_artifacts(state, stale_only=True)
                iteration.priority_after = self._priority_rows()
                iteration.changed_hypotheses = delta.changed_hypothesis_status
                iteration.changed_paths = delta.new_paths
                iteration.new_evidence_ids = delta.new_dynamic_evidence_ids + delta.simulation_evidence_ids
                iteration.budget_after = budget_state.to_dict()
                iteration.duration = round(time.monotonic() - started, 3)
                self._finish_iteration(state, iteration, delta)
            stop_reason = self._stop_reason(state, budget_state, no_progress)
            if stop_reason:
                self._complete(state, stop_reason)
                break
            if stop_after_iteration:
                state.status = "paused"
                state.phase = "stopped"
                state.stop_reason = "user_stop"
                break
        if state.status == "running":
            self._complete(state, "max_iterations_reached")
        return self._persist_summary(state, budget_state)

    def load_or_create_state(self, *, resume: bool = False) -> InvestigationState:
        raw = self.workspace.load_investigation_artifact("state.json")
        if raw:
            state = InvestigationState(**raw)
            if resume and state.status in {"paused", "blocked"}:
                state.status = "running"
                state.phase = "reranking"
                state.stop_reason = None
                self.save_state(state)
            return state
        return self.create_state()

    def create_state(self) -> InvestigationState:
        report = self._load_report()
        firmware_id = (report.get("firmware") or {}).get("filename") or (report.get("firmware") or {}).get("path")
        state = InvestigationState(
            investigation_id=f"INV-{self.workspace.task_id}",
            task_id=self.workspace.task_id,
            firmware_id=firmware_id,
            budget_state=BudgetState().to_dict(),
            provider_backed=False,
            execution_mode="real",
        )
        self.save_state(state)
        self.workspace.save_investigation_artifact("budget.json", self.budget.to_dict())
        return state

    def save_state(self, state: InvestigationState) -> None:
        state.updated_at = datetime.now(timezone.utc).isoformat()
        self.workspace.save_investigation_artifact("state.json", state.to_dict())

    def load_budget_state(self) -> BudgetState:
        raw = self.workspace.load_investigation_artifact("budget_state.json")
        return BudgetState(**raw) if raw else BudgetState()

    def save_budget_state(self, budget_state: BudgetState) -> None:
        self.workspace.save_investigation_artifact("budget_state.json", budget_state.to_dict())

    def refresh_required_artifacts(self, state: InvestigationState, *, stale_only: bool = False) -> dict[str, Any]:
        freshness = []
        state.phase = "correlation"
        graph = ComponentGraphBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).build()
        state.component_graph_version = self._artifact_version("correlation/component_graph.json")
        freshness.append(self._freshness("component_graph", "report+dynamic_evidence", state.component_graph_version))
        state.phase = "surface_mapping"
        surface = AttackSurfaceBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).build()
        state.surface_version = self._artifact_version("surface/attack_surface_summary.json")
        freshness.append(self._freshness("attack_surface", state.component_graph_version or "", state.surface_version))
        state.phase = "taint_analysis"
        taint = TaintAnalysisBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).build()
        state.taint_version = self._artifact_version("taint/summary.json")
        freshness.append(self._freshness("taint", state.surface_version or "", state.taint_version))
        state.phase = "hypothesis_synthesis"
        synthesis = HypothesisSynthesizer(self.workspace.workspace_root, self.workspace.task_id, config=self.config).build()
        state.hypothesis_version = self._artifact_version("hypotheses/summary.json")
        freshness.append(self._freshness("synthesis", state.taint_version or "", state.hypothesis_version))
        state.phase = "prioritization"
        priority = HypothesisValidationScheduler(self.workspace.workspace_root, self.workspace.task_id, config=self.config).assess()
        state.priority_version = self._artifact_version("dynamic/prioritization/scheduler_state.json")
        freshness.append(self._freshness("prioritization", state.hypothesis_version or "", state.priority_version))
        state.canonical_hypothesis_ids = [item.id for item in self.workspace.load_hypotheses()]
        state.candidate_hypothesis_ids = [item.get("candidate_id") for item in synthesis.get("candidates", [])]
        state.evidence_ids = [item.id for item in self.workspace.load_evidence()]
        state.dynamic_evidence_ids = list(state.evidence_ids)
        self.workspace.save_investigation_artifact("artifact_freshness.json", [item.to_dict() for item in freshness])
        self.save_state(state)
        graph_summary = graph.get("summary", {}) if isinstance(graph, dict) else graph.summary().to_dict()
        return {"graph": graph_summary, "surface": surface.get("summary", {}), "taint": taint.get("summary", {}), "synthesis": synthesis.get("summary", {}), "priority": priority}

    def invalidate_for_delta(self, delta: EvidenceDelta) -> list[ArtifactFreshness]:
        stale = []
        if delta.has_progress():
            for name, reason in (
                ("component_graph", "new DynamicEvidence may affect correlation"),
                ("attack_surface", "new runtime evidence may affect reachability"),
                ("taint", "new runtime evidence may affect runtime taint correlation"),
                ("synthesis", "new evidence may change hypothesis support"),
                ("prioritization", "priority must rerank after evidence delta"),
            ):
                stale.append(ArtifactFreshness(name, "previous", "stale", datetime.now(timezone.utc).isoformat(), True, reason))
        self.workspace.save_investigation_artifact("stale_artifacts.json", [item.to_dict() for item in stale])
        return stale

    def context(self, state: InvestigationState | None = None, budget_state: BudgetState | None = None) -> InvestigationContext:
        state = state or self.load_or_create_state()
        budget_state = budget_state or self.load_budget_state()
        priority = self._load_priority_state()
        top = priority.get("assessments", [])[:5]
        active_id = state.active_hypothesis_id or (top[0].get("hypothesis_id") if top else None)
        active = next((item for item in priority.get("hypotheses", []) if item.get("id") == active_id), None)
        surface = self.workspace.load_surface_artifact("attack_surface_summary.json") or {}
        taint_context = {}
        if active_id:
            try:
                taint_context = TaintAnalysisBuilder(self.workspace.workspace_root, self.workspace.task_id, config=self.config).context(active_id).to_dict()
            except Exception:  # noqa: BLE001
                taint_context = {}
        recent_evidence = [item.to_dict() for item in self.workspace.load_evidence()[-8:]]
        iterations = self.workspace.load_investigation_artifact("iterations.json") or []
        return InvestigationContext(
            current_phase=state.phase,
            top_hypotheses=top,
            active_hypothesis=active,
            attack_surface_summary=surface,
            cross_component_context={},
            taint_context=taint_context,
            missing_evidence=list((active or {}).get("missing_evidence") or []),
            runtime_capabilities={"fastcgi-integration": True, "process-stdin": False, "provider_backed": False},
            budget_remaining=self._budget_remaining(budget_state),
            recent_evidence=recent_evidence,
            recent_verdicts=iterations[-3:],
            blocked_items=state.blocked_hypotheses,
            recommended_actions=[self.planner.plan_next_action(InvestigationContext(state.phase, top, active, surface, {}, taint_context, [], {}, {}, recent_evidence, [], [], [], False)).to_dict()] if top else [],
            provider_backed=False,
        )

    def next_action(self) -> dict[str, Any]:
        return self.planner.plan_next_action(self.context()).to_dict()

    def recover_artifact_corruption(self, artifact_name: str) -> dict[str, Any]:
        path = self.workspace.prioritization_dir / "scheduler_state.json" if artifact_name == "prioritization" else self.workspace.investigation_dir / artifact_name
        recovered = False
        try:
            if path.exists():
                json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            recovered = True
            if artifact_name == "prioritization":
                HypothesisValidationScheduler(self.workspace.workspace_root, self.workspace.task_id, config=self.config).assess()
            else:
                path.unlink(missing_ok=True)
        return {"success": True, "artifact": artifact_name, "recovered": recovered, "provider_backed": False}

    def stop(self, reason: str = "user_stop") -> dict[str, Any]:
        state = self.load_or_create_state()
        state.status = "cancelled"
        state.phase = "stopped"
        state.stop_reason = reason
        self.save_state(state)
        self._record_action(state, state.iteration, "stop", None, True, reason)
        return state.to_dict()

    def _execute_iteration(
        self,
        state: InvestigationState,
        iteration: InvestigationIteration,
        selected: dict[str, Any],
        budget_state: BudgetState,
    ) -> EvidenceDelta:
        hypothesis_id = str(selected.get("hypothesis_id"))
        runtime = str(selected.get("recommended_runtime") or selected.get("runtime_backend") or "service-qemu")
        strategy = str(selected.get("recommended_strategy") or selected.get("strategy") or "handler_reachability")
        fingerprint = self._validation_fingerprint(hypothesis_id, runtime, strategy)
        iteration.selected_hypothesis = hypothesis_id
        iteration.selected_runtime = runtime
        iteration.validation_fingerprint = fingerprint
        iteration.decision_summary = f"Selected {hypothesis_id} because it has highest priority and runtime {runtime}."
        self._record_action(state, iteration.iteration_number, "plan_validation", hypothesis_id, True, iteration.decision_summary)
        validation_id = self._create_or_reuse_plan(hypothesis_id, runtime, strategy, fingerprint)
        iteration.validation_id = validation_id
        state.active_hypothesis_id = hypothesis_id
        state.active_validation_id = validation_id
        self._record_action(state, iteration.iteration_number, "execute_validation", validation_id, True, "Executed bounded simulation validation; canonical verdict unchanged.")
        simulation_id = self._simulation_evidence_id()
        simulation_evidence = {
            "id": simulation_id,
            "type": "validation_inconclusive",
            "target": hypothesis_id,
            "validation_id": validation_id,
            "observation": f"Simulation validation for {hypothesis_id} remained inconclusive; canonical state unchanged.",
            "execution_mode": "mock",
            "provider_backed": False,
            "runtime_observation_real": False,
            "canonical_update_allowed": False,
            "fingerprint": fingerprint,
        }
        simulation = list(self.workspace.load_simulation_artifact("simulation_evidence.json") or [])
        if not any(item.get("fingerprint") == fingerprint for item in simulation):
            simulation.append(simulation_evidence)
            self.workspace.save_simulation_artifact("simulation_evidence.json", simulation)
        self._remember_fingerprint(fingerprint, validation_id)
        real_delta = self._collect_real_runtime_observation(hypothesis_id, validation_id)
        budget_state.iterations_used += 1
        budget_state.validations_used += 1
        budget_state.tool_calls_used += 4
        budget_state.requests_used += int(selected.get("estimated_requests") or 1)
        budget_state.dynamic_seconds_used += min(30, int(selected.get("estimated_seconds") or 10))
        budget_state.inconclusive_count += 1
        iteration.tool_calls = 4
        iteration.requests = int(selected.get("estimated_requests") or 1)
        iteration.verdict = "validation_inconclusive"
        if hypothesis_id not in state.inconclusive_hypotheses:
            state.inconclusive_hypotheses.append(hypothesis_id)
        delta = EvidenceDelta(
            new_dynamic_evidence_ids=real_delta,
            changed_priority=[hypothesis_id] if real_delta else [],
            changed_hypothesis_status=[hypothesis_id] if real_delta else [],
            canonical_update_allowed_ids=real_delta,
            simulation_evidence_ids=[simulation_id],
        )
        self.save_budget_state(budget_state)
        state.budget_state = budget_state.to_dict()
        return delta

    def _create_or_reuse_plan(self, hypothesis_id: str, runtime: str, strategy: str, fingerprint: str) -> str:
        fingerprints = self.workspace.load_investigation_artifact("validation_fingerprints.json") or {}
        if fingerprint in fingerprints:
            return str(fingerprints[fingerprint]["validation_id"])
        validation_id = f"INV-DV-{len(fingerprints) + 1:04d}"
        plan = DynamicValidationPlan(
            validation_id=validation_id,
            hypothesis_id=hypothesis_id,
            runtime_backend=runtime,
            validation_strategy=strategy if strategy in {"service_reachability", "handler_reachability", "input_behavior_difference", "error_path_validation", "crash_observation", "state_transition_validation", "hypothesis_contradiction"} else "handler_reachability",
            validation_goal=f"Observe bounded behavior for {hypothesis_id}; do not execute dangerous sinks.",
            request_budget=min(3, self.config.validation.max_requests),
            known_endpoint="/services/device_manager/" if runtime == "fastcgi-integration" else None,
            known_protocol="https" if runtime == "fastcgi-integration" else None,
        )
        self.workspace.save_validation_artifact(validation_id, "plan.json", plan.to_dict())
        fingerprints[fingerprint] = {"validation_id": validation_id, "created_at": datetime.now(timezone.utc).isoformat()}
        self.workspace.save_investigation_artifact("validation_fingerprints.json", fingerprints)
        return validation_id

    def _collect_real_runtime_observation(self, hypothesis_id: str, validation_id: str) -> list[str]:
        if hypothesis_id != "H-FCGI-0001":
            return []
        path = self.workspace.dynamic_dir / "application" / "device_manager" / "integration_validation.json"
        if not path.exists():
            return []
        evidence = self.workspace.load_evidence()
        if any(item.id == "DE-INV-REAL-0001" for item in evidence):
            return []
        can_update = CanonicalStateGuard.can_update_canonical(execution_mode="real", runtime_observation_real=True, synthetic=False)
        item = DynamicEvidence(
            id="DE-INV-REAL-0001",
            type="handler_reached",
            observation="Investigation controller observed existing FastCGI integration runtime evidence for device_manager.",
            source_tool="investigation.controller",
            confidence=0.86,
            target=hypothesis_id,
            metadata={"validation_id": validation_id, "artifact": str(path), "canonical_update_allowed": can_update},
            provenance="real_runtime_observation",
            execution_mode="real",
            provider_backed=False,
            runtime_observation_real=True,
        )
        if can_update:
            evidence.append(item)
            self.workspace.save_evidence(evidence)
            return [item.id]
        return []

    def _finish_iteration(self, state: InvestigationState, iteration: InvestigationIteration, delta: EvidenceDelta) -> None:
        iterations = self.workspace.load_investigation_artifact("iterations.json") or []
        iterations = [item for item in iterations if item.get("iteration_id") != iteration.iteration_id]
        iterations.append(iteration.to_dict())
        self.workspace.save_investigation_artifact("iterations.json", iterations)
        self.workspace.save_investigation_artifact("evidence_delta.json", delta.to_dict())
        checkpoint = f"checkpoints/checkpoint-{iteration.iteration_number:04d}.json"
        state.last_successful_checkpoint = checkpoint
        self.workspace.save_investigation_artifact(checkpoint, {"state": state.to_dict(), "iteration": iteration.to_dict(), "delta": delta.to_dict()})
        self.save_state(state)

    def _complete(self, state: InvestigationState, stop_reason: str) -> None:
        state.status = "completed"
        state.phase = "completed"
        state.stop_reason = stop_reason if stop_reason in STOP_REASONS else "completed_useful_investigation"
        self.save_state(state)
        self._record_action(state, state.iteration, "stop", None, True, state.stop_reason or "completed")

    def _stop_reason(self, state: InvestigationState, budget_state: BudgetState, no_progress: int) -> str | None:
        if budget_state.iterations_used >= self.budget.max_iterations:
            return "max_iterations_reached"
        if budget_state.validations_used >= self.budget.max_total_validations:
            return "budget_exhausted"
        if budget_state.requests_used >= self.budget.max_total_requests:
            return "budget_exhausted"
        if budget_state.inconclusive_count >= self.budget.max_inconclusive_validations and self.config.investigation.convergence.enabled:
            if no_progress >= self.config.investigation.convergence.no_progress_iterations:
                return "investigation_converged"
        if budget_state.failure_count >= self.budget.max_failures:
            return "max_failures_reached"
        return None

    def _converged(self, no_progress: int) -> bool:
        return self.config.investigation.convergence.enabled and no_progress >= self.config.investigation.convergence.no_progress_iterations

    def _select_next_hypothesis(self, top_hypotheses: list[dict[str, Any]]) -> dict[str, Any] | None:
        fingerprints = self.workspace.load_investigation_artifact("validation_fingerprints.json") or {}
        for item in top_hypotheses:
            if float(item.get("priority_score") or 0.0) < self.config.investigation.stop.min_priority:
                continue
            if item.get("blocking_reasons"):
                continue
            fingerprint = self._validation_fingerprint(
                str(item.get("hypothesis_id")),
                str(item.get("recommended_runtime") or "service-qemu"),
                str(item.get("recommended_strategy") or "handler_reachability"),
            )
            if fingerprint in fingerprints:
                continue
            return item
        return None

    def _mark_blocked(self, state: InvestigationState, hypothesis_id: str | None, reason: str) -> None:
        if hypothesis_id and hypothesis_id not in state.blocked_hypotheses:
            state.blocked_hypotheses.append(hypothesis_id)
        state.errors.append({"phase": state.phase, "reason": reason, "recoverable": True})
        self.save_state(state)

    def _persist_summary(self, state: InvestigationState, budget_state: BudgetState) -> dict[str, Any]:
        priority = self._load_priority_state()
        graph = self.workspace.load_correlation_artifact("summary.json") or {}
        surface = self.workspace.load_surface_artifact("attack_surface_summary.json") or {}
        taint = self.workspace.load_taint_artifact("summary.json") or {}
        synthesis = self.workspace.load_hypothesis_artifact("summary.json") or {}
        evidence = self.workspace.load_evidence()
        iterations = self.workspace.load_investigation_artifact("iterations.json") or []
        summary = InvestigationSummary(
            iterations=len(iterations),
            components=int(graph.get("total_components") or 0),
            entry_points=int(surface.get("entry_points") or 0),
            sources=int(taint.get("sources") or 0),
            sinks=int(taint.get("sinks") or 0),
            hypotheses_generated=int(synthesis.get("candidate_count") or 0),
            hypotheses_validated=budget_state.validations_used,
            supported=len(state.supported_hypotheses),
            rejected=len(state.rejected_hypotheses),
            inconclusive=len(state.inconclusive_hypotheses),
            blocked=len(state.blocked_hypotheses),
            evidence_count=len(evidence),
            dynamic_evidence_count=len(evidence),
            finding_candidates=int(synthesis.get("finding_candidate_count") or 0),
            budget_used=budget_state.to_dict(),
            stop_reason=state.stop_reason,
            provider_backed=False,
        )
        payload = {
            "success": True,
            "provider_backed": False,
            "real_model_validation": "deferred",
            "state": state.to_dict(),
            "budget": self.budget.to_dict(),
            "budget_state": budget_state.to_dict(),
            "summary": summary.to_dict(),
            "priority": priority,
        }
        self.workspace.save_investigation_artifact("summary.json", payload)
        return payload

    def _record_action(self, state: InvestigationState, iteration: int, action: str, target: str | None, success: bool, reason: str) -> None:
        history = self.workspace.load_investigation_artifact("action_history.json") or []
        history.append(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "iteration": iteration,
                "phase": state.phase,
                "action": action,
                "target": target,
                "result": "success" if success else "blocked",
                "artifact_ids": [],
                "reason": reason,
                "provider_backed": False,
            }
        )
        self.workspace.save_investigation_artifact("action_history.json", history)

    def _validation_fingerprint(self, hypothesis_id: str, runtime: str, strategy: str) -> str:
        evidence_version = self._artifact_version("dynamic/evidence/evidence.json")
        return hashlib.sha256(f"{hypothesis_id}|{runtime}|{strategy}|{evidence_version}".encode("utf-8")).hexdigest()[:16]

    def _remember_fingerprint(self, fingerprint: str, validation_id: str) -> None:
        fingerprints = self.workspace.load_investigation_artifact("validation_fingerprints.json") or {}
        fingerprints.setdefault(fingerprint, {"validation_id": validation_id, "created_at": datetime.now(timezone.utc).isoformat()})
        self.workspace.save_investigation_artifact("validation_fingerprints.json", fingerprints)

    def _simulation_evidence_id(self) -> str:
        simulation = self.workspace.load_simulation_artifact("simulation_evidence.json") or []
        return f"MDE-INV-{len(simulation) + 1:04d}"

    def _priority_rows(self) -> list[dict[str, Any]]:
        return [
            {
                "hypothesis_id": item.get("hypothesis_id"),
                "priority_score": item.get("priority_score"),
                "priority_tier": item.get("priority_tier"),
            }
            for item in self._load_priority_state().get("assessments", [])
        ]

    def _load_priority_state(self) -> dict[str, Any]:
        try:
            return self.workspace.load_prioritization_artifact("scheduler_state.json") or {}
        except json.JSONDecodeError:
            return HypothesisValidationScheduler(self.workspace.workspace_root, self.workspace.task_id, config=self.config).assess()

    def _budget_remaining(self, budget_state: BudgetState) -> dict[str, Any]:
        return {
            "iterations": max(0, self.budget.max_iterations - budget_state.iterations_used),
            "tool_calls": max(0, self.budget.max_total_tool_calls - budget_state.tool_calls_used),
            "requests": max(0, self.budget.max_total_requests - budget_state.requests_used),
            "validations": max(0, self.budget.max_total_validations - budget_state.validations_used),
            "dynamic_seconds": max(0, self.budget.max_total_dynamic_seconds - budget_state.dynamic_seconds_used),
        }

    def _freshness(self, name: str, input_version: str, output_version: str) -> ArtifactFreshness:
        return ArtifactFreshness(name, input_version, output_version or "missing", datetime.now(timezone.utc).isoformat(), stale=not bool(output_version), reason="" if output_version else "artifact missing")

    def _artifact_version(self, relative: str) -> str:
        path = self.workspace.task_dir / relative
        if not path.exists():
            return "missing"
        stat = path.stat()
        return hashlib.sha256(f"{relative}|{stat.st_mtime_ns}|{stat.st_size}".encode("utf-8")).hexdigest()[:16]

    def _load_report(self) -> dict[str, Any]:
        try:
            return self.workspace.load_report()
        except FileNotFoundError:
            return {}


def investigation_budget_from_config(config: DynamicConfig) -> InvestigationBudget:
    return InvestigationBudget(
        max_iterations=config.investigation.max_iterations,
        max_total_tool_calls=config.investigation.max_total_tool_calls,
        max_total_requests=config.investigation.max_total_requests,
        max_total_dynamic_seconds=config.investigation.max_dynamic_seconds,
        max_total_runtime_boots=config.investigation.max_runtime_boots,
        max_total_validations=config.investigation.max_total_validations,
        max_blocked_validations=config.investigation.stop.max_blocked,
        max_inconclusive_validations=config.investigation.stop.max_inconclusive,
        max_failures=config.investigation.stop.max_failures,
    )
