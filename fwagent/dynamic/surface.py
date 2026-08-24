from __future__ import annotations

import json
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.correlation import (
    CanonicalStateGuard,
    ComponentGraph,
    ComponentGraphBuilder,
    ComponentRelationship,
)
from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.workspace import DynamicWorkspace


ENTRY_POINT_TYPES = {
    "http_route",
    "https_route",
    "cgi",
    "fastcgi",
    "tcp_service",
    "udp_service",
    "unix_socket",
    "local_ipc",
    "service_port",
    "web_resource",
    "protocol_handler",
    "stdin",
    "file_input",
    "device_input",
}

EXPOSURE_SCOPES = {
    "external_network",
    "local_network",
    "loopback",
    "local_process",
    "filesystem",
    "device",
    "unknown",
}

ENTRY_SOURCES = {
    "config_declared",
    "static_reference",
    "init_script",
    "runtime_listener",
    "runtime_http",
    "runtime_fastcgi",
    "runtime_process",
    "manual_seed",
    "inferred",
}

REACHABILITY_STATES = {
    "runtime_confirmed",
    "statically_reachable",
    "candidate",
    "blocked",
    "unknown",
    "no_known_entry",
    "entry_unknown",
    "unreachable",
}


@dataclass
class EntryPoint:
    entry_id: str
    entry_type: str
    name: str
    protocol: str | None = None
    transport: str | None = None
    address: str | None = None
    port: int | None = None
    path: str | None = None
    method: str | None = None
    service: str | None = None
    component_id: str | None = None
    handler_component_id: str | None = None
    source: str = "inferred"
    static_or_dynamic: str = "static"
    exposure_scope: str = "unknown"
    authentication_known: bool | None = None
    runtime_confirmed: bool = False
    confidence: float = 0.5
    evidence_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.entry_type not in ENTRY_POINT_TYPES:
            raise ValueError(f"invalid entry_type: {self.entry_type}")
        if self.source not in ENTRY_SOURCES:
            raise ValueError(f"invalid entry source: {self.source}")
        if self.exposure_scope not in EXPOSURE_SCOPES:
            raise ValueError(f"invalid exposure_scope: {self.exposure_scope}")
        self.confidence = _clamp01(self.confidence)
        self.evidence_ids = sorted(set(self.evidence_ids))
        self.relationship_ids = sorted(set(self.relationship_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RouteMapping:
    route_id: str
    entry_point_id: str
    protocol: str | None
    path: str
    methods: list[str]
    service_component_id: str | None
    backend_component_id: str | None
    source: str
    runtime_confirmed: bool
    confidence: float
    evidence_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence = _clamp01(self.confidence)
        self.evidence_ids = sorted(set(self.evidence_ids))
        self.relationship_ids = sorted(set(self.relationship_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ReachabilityState:
    state: str
    reason: str
    runtime_confirmed: bool = False

    def __post_init__(self) -> None:
        if self.state not in REACHABILITY_STATES:
            raise ValueError(f"invalid reachability state: {self.state}")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EntryReachability:
    entry_point_id: str
    state: str
    reachable_component_ids: list[str]
    component_path_ids: list[str]
    evidence_ids: list[str]
    relationship_ids: list[str]
    confidence: float
    entry_distance: int
    runtime_confirmed: bool = False
    blocking_reason: str | None = None

    def __post_init__(self) -> None:
        if self.state not in REACHABILITY_STATES:
            raise ValueError(f"invalid reachability state: {self.state}")
        self.confidence = _clamp01(self.confidence)
        self.reachable_component_ids = sorted(set(self.reachable_component_ids))
        self.component_path_ids = sorted(set(self.component_path_ids))
        self.evidence_ids = sorted(set(self.evidence_ids))
        self.relationship_ids = sorted(set(self.relationship_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HandlerDescriptor:
    handler_id: str
    entry_point_id: str
    component_id: str | None
    handler_type: str
    name: str
    path: str | None
    runtime_confirmed: bool
    confidence: float
    evidence_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.confidence = _clamp01(self.confidence)
        self.evidence_ids = sorted(set(self.evidence_ids))
        self.relationship_ids = sorted(set(self.relationship_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class InputSource:
    input_id: str
    entry_point_id: str
    source_type: str
    exposure_scope: str
    description: str
    network_exposed: bool
    runtime_confirmed: bool
    evidence_ids: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.exposure_scope not in EXPOSURE_SCOPES:
            raise ValueError(f"invalid exposure_scope: {self.exposure_scope}")
        self.evidence_ids = sorted(set(self.evidence_ids))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class HypothesisReachability:
    hypothesis_id: str
    entry_point_ids: list[str]
    state: str
    reachable: bool
    network_exposed: bool
    exposure_scopes: list[str]
    runtime_confirmed: bool
    entry_distance: int
    entry_confidence: float
    entry_reachability_score: float
    evidence_ids: list[str] = field(default_factory=list)
    relationship_ids: list[str] = field(default_factory=list)
    component_path_ids: list[str] = field(default_factory=list)
    blocking_reason: str | None = None

    def __post_init__(self) -> None:
        if self.state not in REACHABILITY_STATES:
            raise ValueError(f"invalid reachability state: {self.state}")
        self.entry_point_ids = sorted(set(self.entry_point_ids))
        self.exposure_scopes = sorted(set(self.exposure_scopes))
        self.evidence_ids = sorted(set(self.evidence_ids))
        self.relationship_ids = sorted(set(self.relationship_ids))
        self.component_path_ids = sorted(set(self.component_path_ids))
        self.entry_confidence = _clamp01(self.entry_confidence)
        self.entry_reachability_score = _clamp01(self.entry_reachability_score)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EntryPointAssessment:
    entry_point_id: str
    priority_rank: int
    priority_score: float
    runtime_confidence: float
    reachable_component_count: int
    reachable_hypothesis_count: int
    security_relevance: str
    validation_cost: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackSurfaceSummary:
    total_entries: int
    runtime_confirmed_entries: int
    network_entries: int
    local_entries: int
    route_entries: int
    service_entries: int
    reachable_hypotheses: int
    blocked_hypotheses: int
    unknown_hypotheses: int
    entries_by_type: dict[str, int]
    entries_by_exposure_scope: dict[str, int]
    entry_priority_ranking: list[dict[str, Any]]
    safety_notes: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EntryPointContext:
    entry_point: dict[str, Any]
    service_component: dict[str, Any] | None
    handler: dict[str, Any] | None
    route: dict[str, Any] | None
    reachable_components: list[dict[str, Any]]
    reachable_hypotheses: list[dict[str, Any]]
    runtime_evidence_ids: list[str]
    known_blockers: list[str]
    confidence_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AttackSurfaceMap:
    entry_points: list[EntryPoint]
    routes: list[RouteMapping]
    reachability: list[EntryReachability]
    hypothesis_reachability: list[HypothesisReachability]
    handlers: list[HandlerDescriptor]
    input_sources: list[InputSource]
    assessments: list[EntryPointAssessment]
    summary: AttackSurfaceSummary
    entry_contexts: list[EntryPointContext]

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_points": [item.to_dict() for item in self.entry_points],
            "routes": [item.to_dict() for item in self.routes],
            "reachability": [item.to_dict() for item in self.reachability],
            "hypothesis_reachability": [item.to_dict() for item in self.hypothesis_reachability],
            "handlers": [item.to_dict() for item in self.handlers],
            "input_sources": [item.to_dict() for item in self.input_sources],
            "assessments": [item.to_dict() for item in self.assessments],
            "summary": self.summary.to_dict(),
            "entry_contexts": [item.to_dict() for item in self.entry_contexts],
            "provider_backed": False,
            "real_model_validation": "deferred",
        }


class AttackSurfaceBuilder:
    def __init__(self, workspace_root: str | Path, task_id: str, *, config: DynamicConfig):
        self.workspace = DynamicWorkspace(workspace_root, task_id)
        self.config = config
        self.graph = ComponentGraphBuilder(workspace_root, task_id, config=config).load_or_build_graph()
        self.hypotheses = self.workspace.load_hypotheses()
        self.dynamic_evidence = self.workspace.load_evidence()

    def build(self) -> dict[str, Any]:
        entries = self._discover_entries()[: self.config.attack_surface.max_entries]
        routes = self._discover_routes(entries)[: self.config.attack_surface.max_routes]
        handlers = self._describe_handlers(entries)
        input_sources = self._describe_inputs(entries)
        reachability = self._build_reachability(entries)
        hypothesis_reachability = self._map_hypotheses(entries, reachability)
        assessments = self._assess_entries(entries, reachability, hypothesis_reachability)
        summary = self._summarize(entries, routes, hypothesis_reachability, assessments)
        contexts = self._build_contexts(entries, routes, reachability, hypothesis_reachability, handlers)
        surface = AttackSurfaceMap(
            entry_points=entries,
            routes=routes,
            reachability=reachability,
            hypothesis_reachability=hypothesis_reachability,
            handlers=handlers,
            input_sources=input_sources,
            assessments=assessments,
            summary=summary,
            entry_contexts=contexts,
        )
        payload = surface.to_dict()
        self._persist(payload)
        return {"success": True, **payload}

    def load_or_build(self) -> dict[str, Any]:
        summary = self.workspace.load_surface_artifact("attack_surface_summary.json")
        entries = self.workspace.load_surface_artifact("entry_points.json")
        if summary and entries:
            return {
                "success": True,
                "entry_points": entries,
                "routes": self.workspace.load_surface_artifact("routes.json") or [],
                "reachability": self.workspace.load_surface_artifact("reachability.json") or [],
                "hypothesis_reachability": self.workspace.load_surface_artifact("hypothesis_reachability.json") or [],
                "handlers": self.workspace.load_surface_artifact("handlers.json") or [],
                "input_sources": self.workspace.load_surface_artifact("input_sources.json") or [],
                "assessments": self.workspace.load_surface_artifact("entry_assessments.json") or [],
                "summary": summary,
                "entry_contexts": self.workspace.load_surface_artifact("entry_contexts.json") or [],
                "provider_backed": False,
                "real_model_validation": "deferred",
            }
        return self.build()

    def hypothesis_reachability_context(self, hypothesis_id: str) -> HypothesisReachability | None:
        payload = self.load_or_build()
        for item in payload.get("hypothesis_reachability") or []:
            if item.get("hypothesis_id") == hypothesis_id:
                return HypothesisReachability(**item)
        return None

    def incremental_update_from_dynamic_evidence(self, evidence: DynamicEvidence) -> dict[str, Any]:
        allowed = CanonicalStateGuard.can_update_canonical(
            execution_mode=evidence.execution_mode,
            runtime_observation_real=evidence.runtime_observation_real,
            synthetic=evidence.provenance in {"mock_agent", "simulation", "fixture"},
        )
        if not allowed:
            self.workspace.save_surface_artifact(
                "mock_surface_state.json",
                {
                    "accepted": False,
                    "reason": "mock/simulation evidence cannot mutate canonical attack surface",
                    "evidence": evidence.to_dict(),
                    "provider_backed": False,
                },
            )
            return {"success": True, "canonical_update_allowed": False, "provider_backed": False}
        payload = self.build()
        return {"success": True, "canonical_update_allowed": True, "summary": payload["summary"], "provider_backed": False}

    def mock_discover_entry(self, entry_name: str) -> dict[str, Any]:
        state = self.workspace.load_surface_artifact("mock_surface_state.json") or {"mock_entries": []}
        state.setdefault("mock_entries", []).append(
            {
                "name": entry_name,
                "provenance": "mock_agent",
                "execution_mode": "mock",
                "canonical_update_allowed": False,
                "provider_backed": False,
            }
        )
        self.workspace.save_surface_artifact("mock_surface_state.json", state)
        return {"success": True, "canonical_update_allowed": False, "provider_backed": False}

    def _discover_entries(self) -> list[EntryPoint]:
        entries: list[EntryPoint] = []
        profile, profile_path = self._load_lighttpd_profile()
        runtime = self._load_fastcgi_runtime()
        service_id = self.graph.resolve_component_id("lighttpd")
        handler_id = self.graph.resolve_component_id("device_manager.fcgi")
        endpoint_id = self.graph.resolve_component_id("/services/device_manager/")
        runtime_confirmed = bool(runtime.get("application_response_reached")) if runtime else False
        port = _safe_int((profile.get("config") or {}).get("server.port")) if profile else None
        protocol = "https" if profile and (profile.get("config") or {}).get("ssl.pemfile") else "http"
        evidence_ids = self._entry_evidence_ids(runtime_confirmed)
        relationship_ids = self._relationship_ids_between({service_id, handler_id, endpoint_id})
        if service_id and port:
            entries.append(
                EntryPoint(
                    entry_id=f"EP-SERVICE-lighttpd-{port}",
                    entry_type="service_port",
                    name=f"lighttpd TCP {port}",
                    protocol="tcp",
                    transport="tcp",
                    address=None,
                    port=port,
                    service="lighttpd",
                    component_id=service_id,
                    source="config_declared",
                    static_or_dynamic="static",
                    exposure_scope="local_network",
                    authentication_known=None,
                    runtime_confirmed=False,
                    confidence=self.config.attack_surface.confidence.config_declared,
                    evidence_ids=["ART:lighttpd-launch-profile"],
                    relationship_ids=self._relationship_ids_for_component(service_id, {"listens_on"}),
                )
            )
        if service_id and handler_id and endpoint_id and port:
            entries.append(
                EntryPoint(
                    entry_id="EP-HTTPS-lighttpd-device-manager",
                    entry_type="https_route" if protocol == "https" else "http_route",
                    name=f"{protocol.upper()} {port} /services/device_manager/",
                    protocol=protocol,
                    transport="tcp",
                    address=None,
                    port=port,
                    path="/services/device_manager/",
                    method=None,
                    service="lighttpd",
                    component_id=service_id,
                    handler_component_id=handler_id,
                    source="runtime_fastcgi" if runtime_confirmed else "config_declared",
                    static_or_dynamic="dynamic" if runtime_confirmed else "static",
                    exposure_scope="local_network",
                    authentication_known=None,
                    runtime_confirmed=runtime_confirmed,
                    confidence=self.config.attack_surface.confidence.application_response if runtime_confirmed else self.config.attack_surface.confidence.config_declared,
                    evidence_ids=evidence_ids,
                    relationship_ids=relationship_ids,
                )
            )
        for generic_profile_path in (self.workspace.dynamic_dir / "services").glob("*/launch_profile.json") if (self.workspace.dynamic_dir / "services").exists() else []:
            if generic_profile_path.parent.name == "lighttpd":
                continue
            try:
                generic_profile = json.loads(generic_profile_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
            service_name = str(generic_profile.get("service") or generic_profile_path.parent.name)
            generic_service_id = self.graph.resolve_component_id(service_name)
            generic_config = generic_profile.get("config") if isinstance(generic_profile.get("config"), dict) else {}
            generic_ports = []
            for key in ("server.port", "port", "listen_port"):
                if generic_config.get(key):
                    generic_ports.append(_safe_int(generic_config.get(key)))
            for generic_port in sorted({item for item in generic_ports if item}):
                entries.append(
                    EntryPoint(
                        entry_id=f"EP-SERVICE-{_surface_slug(service_name)}-{generic_port}",
                        entry_type="service_port",
                        name=f"{service_name} TCP {generic_port}",
                        protocol="tcp",
                        transport="tcp",
                        port=generic_port,
                        service=service_name,
                        component_id=generic_service_id,
                        source="config_declared",
                        static_or_dynamic="static",
                        exposure_scope="local_network",
                        authentication_known=None,
                        runtime_confirmed=False,
                        confidence=self.config.attack_surface.confidence.config_declared,
                        evidence_ids=[f"ART:{service_name}-launch-profile"],
                        relationship_ids=self._relationship_ids_for_component(generic_service_id, {"listens_on"}) if generic_service_id else [],
                    )
                )
        listener = (runtime.get("backend_child") or {}).get("listener") if runtime else {}
        if handler_id and listener:
            entries.append(
                EntryPoint(
                    entry_id=f"EP-LOOPBACK-FCGI-{listener.get('port')}",
                    entry_type="local_ipc",
                    name=f"FastCGI loopback {listener.get('host')}:{listener.get('port')}",
                    protocol="fastcgi",
                    transport="tcp",
                    address=str(listener.get("host") or "127.0.0.1"),
                    port=_safe_int(listener.get("port")),
                    service="device_manager.fcgi",
                    component_id=handler_id,
                    handler_component_id=handler_id,
                    source="runtime_listener",
                    static_or_dynamic="dynamic",
                    exposure_scope="loopback",
                    authentication_known=None,
                    runtime_confirmed=True,
                    confidence=self.config.attack_surface.confidence.runtime_listener,
                    evidence_ids=evidence_ids,
                    relationship_ids=self._relationship_ids_for_component(handler_id, {"listens_on", "connects_to"}),
                )
            )
        socket_component = next((item for item in self.graph.components.values() if item.component_type == "socket" and "device_manager" in item.name), None)
        if socket_component:
            entries.append(
                EntryPoint(
                    entry_id="EP-UNIX-device-manager-socket",
                    entry_type="unix_socket",
                    name=socket_component.name,
                    protocol="fastcgi",
                    transport="unix",
                    path=socket_component.path,
                    service="device_manager.fcgi",
                    component_id=socket_component.component_id,
                    handler_component_id=handler_id,
                    source="config_declared",
                    static_or_dynamic="static",
                    exposure_scope="local_process",
                    authentication_known=None,
                    runtime_confirmed=False,
                    confidence=self.config.attack_surface.confidence.config_declared,
                    evidence_ids=["ART:lighttpd-launch-profile"],
                    relationship_ids=self._relationship_ids_for_component(socket_component.component_id, {"communicates_with"}),
                )
            )
        report = self._load_report()
        firmware_name = str((report.get("firmware") or {}).get("filename") or "").lower()
        ret2text_id = self.graph.resolve_component_id("ret2text") if not firmware_name or "ret2text" in firmware_name else None
        if ret2text_id:
            evidence = sorted({evidence_id for hypothesis in self.hypotheses if "ret2text" in (hypothesis.id + hypothesis.title).lower() for evidence_id in hypothesis.evidence_ids})
            entries.append(
                EntryPoint(
                    entry_id="EP-STDIN-ret2text",
                    entry_type="stdin",
                    name="ret2text stdin",
                    protocol="stdin",
                    transport="process",
                    service="ret2text",
                    component_id=ret2text_id,
                    handler_component_id=ret2text_id,
                    source="static_reference",
                    static_or_dynamic="static",
                    exposure_scope="local_process",
                    authentication_known=None,
                    runtime_confirmed=False,
                    confidence=self.config.attack_surface.confidence.static_reference,
                    evidence_ids=evidence or ["ART:ret2text-static"],
                    relationship_ids=self._relationship_ids_for_component(ret2text_id, {"contains"}),
                )
            )
        if profile_path and not entries:
            entries.append(
                EntryPoint(
                    entry_id="EP-UNKNOWN-lighttpd",
                    entry_type="protocol_handler",
                    name="lighttpd entry unknown",
                    protocol=None,
                    source="inferred",
                    exposure_scope="unknown",
                    confidence=0.3,
                    evidence_ids=[str(profile_path)],
                )
            )
        return _unique_entries(entries)

    def _discover_routes(self, entries: list[EntryPoint]) -> list[RouteMapping]:
        routes: list[RouteMapping] = []
        route_entry = next((item for item in entries if item.path == "/services/device_manager/"), None)
        if not route_entry:
            return routes
        routes.append(
            RouteMapping(
                route_id="ROUTE-services-device-manager",
                entry_point_id=route_entry.entry_id,
                protocol=route_entry.protocol,
                path="/services/device_manager/",
                methods=["unknown"],
                service_component_id=route_entry.component_id,
                backend_component_id=route_entry.handler_component_id,
                source=route_entry.source,
                runtime_confirmed=route_entry.runtime_confirmed,
                confidence=route_entry.confidence,
                evidence_ids=route_entry.evidence_ids,
                relationship_ids=route_entry.relationship_ids,
            )
        )
        return routes

    def _describe_handlers(self, entries: list[EntryPoint]) -> list[HandlerDescriptor]:
        handlers = []
        for entry in entries:
            component_id = entry.handler_component_id or entry.component_id
            component = self.graph.components.get(component_id or "")
            if not component:
                continue
            handlers.append(
                HandlerDescriptor(
                    handler_id=f"HD-{entry.entry_id}",
                    entry_point_id=entry.entry_id,
                    component_id=component.component_id,
                    handler_type=component.component_type,
                    name=component.name,
                    path=component.path,
                    runtime_confirmed=entry.runtime_confirmed,
                    confidence=min(entry.confidence, component.confidence),
                    evidence_ids=entry.evidence_ids,
                    relationship_ids=entry.relationship_ids,
                )
            )
        return handlers

    def _describe_inputs(self, entries: list[EntryPoint]) -> list[InputSource]:
        inputs = []
        for entry in entries:
            network_exposed = entry.exposure_scope in {"external_network", "local_network", "loopback"}
            inputs.append(
                InputSource(
                    input_id=f"IN-{entry.entry_id}",
                    entry_point_id=entry.entry_id,
                    source_type=entry.entry_type,
                    exposure_scope=entry.exposure_scope,
                    description=_input_description(entry),
                    network_exposed=network_exposed,
                    runtime_confirmed=entry.runtime_confirmed,
                    evidence_ids=entry.evidence_ids,
                )
            )
        return inputs

    def _build_reachability(self, entries: list[EntryPoint]) -> list[EntryReachability]:
        reachability = []
        for entry in entries:
            start = entry.handler_component_id or entry.component_id
            if not start:
                reachability.append(
                    EntryReachability(entry.entry_id, "entry_unknown", [], [], entry.evidence_ids, entry.relationship_ids, entry.confidence, 0, blocking_reason="entry has no known graph component")
                )
                continue
            component_ids, relationship_ids = self._walk_reachable(start)
            if entry.component_id:
                component_ids.add(entry.component_id)
            paths = self._paths_for_entry(entry)
            for path in paths:
                component_ids.update(path.get("component_ids", []))
                relationship_ids.update(path.get("relationship_ids", []))
            state = "runtime_confirmed" if entry.runtime_confirmed else "statically_reachable"
            blocking = None
            if entry.entry_type == "stdin" and entry.exposure_scope == "local_process":
                state = "blocked"
                blocking = "local process stdin entry is not firmware external network exposure"
            reachability.append(
                EntryReachability(
                    entry_point_id=entry.entry_id,
                    state=state,
                    reachable_component_ids=sorted(component_ids),
                    component_path_ids=[path["path_id"] for path in paths],
                    evidence_ids=sorted(set(entry.evidence_ids) | self._relationship_evidence(relationship_ids)),
                    relationship_ids=sorted(set(entry.relationship_ids) | relationship_ids),
                    confidence=entry.confidence,
                    entry_distance=max((len(path["relationship_ids"]) for path in paths), default=0) or (1 if component_ids else 0),
                    runtime_confirmed=entry.runtime_confirmed,
                    blocking_reason=blocking,
                )
            )
        return reachability

    def _map_hypotheses(self, entries: list[EntryPoint], reachability: list[EntryReachability]) -> list[HypothesisReachability]:
        by_entry = {item.entry_point_id: item for item in reachability}
        mappings: list[HypothesisReachability] = []
        for hypothesis in self.hypotheses:
            text = f"{hypothesis.id} {hypothesis.title}".lower()
            if "fcgi" in text or "soap" in text or "device_manager" in text:
                candidates = [entry for entry in entries if entry.entry_id == "EP-HTTPS-lighttpd-device-manager"]
                state = "runtime_confirmed" if candidates and candidates[0].runtime_confirmed else "statically_reachable"
                blocking = None
            elif "ret2text" in text:
                candidates = [entry for entry in entries if entry.entry_id == "EP-STDIN-ret2text"]
                state = "blocked" if candidates else "no_known_entry"
                blocking = "process-stdin runtime blocked; local-process stdin entry is not firmware network exposure"
            else:
                candidates = []
                state = "no_known_entry"
                blocking = "no known entry point evidence"
            if not candidates:
                mappings.append(
                    HypothesisReachability(
                        hypothesis_id=hypothesis.id,
                        entry_point_ids=[],
                        state=state,
                        reachable=False,
                        network_exposed=False,
                        exposure_scopes=[],
                        runtime_confirmed=False,
                        entry_distance=0,
                        entry_confidence=0.0,
                        entry_reachability_score=0.0,
                        evidence_ids=hypothesis.evidence_ids,
                        blocking_reason=blocking,
                    )
                )
                continue
            entry_ids = [entry.entry_id for entry in candidates]
            selected = candidates[0]
            selected_reachability = by_entry.get(selected.entry_id)
            network_exposed = any(entry.exposure_scope in {"external_network", "local_network", "loopback"} for entry in candidates)
            score = _entry_score(selected, selected_reachability)
            mappings.append(
                HypothesisReachability(
                    hypothesis_id=hypothesis.id,
                    entry_point_ids=entry_ids,
                    state=state,
                    reachable=state != "no_known_entry",
                    network_exposed=network_exposed,
                    exposure_scopes=[entry.exposure_scope for entry in candidates],
                    runtime_confirmed=any(entry.runtime_confirmed for entry in candidates),
                    entry_distance=selected_reachability.entry_distance if selected_reachability else 0,
                    entry_confidence=selected.confidence,
                    entry_reachability_score=score,
                    evidence_ids=sorted(set(hypothesis.evidence_ids) | set(selected.evidence_ids)),
                    relationship_ids=selected_reachability.relationship_ids if selected_reachability else selected.relationship_ids,
                    component_path_ids=selected_reachability.component_path_ids if selected_reachability else [],
                    blocking_reason=blocking,
                )
            )
        return mappings

    def _assess_entries(
        self,
        entries: list[EntryPoint],
        reachability: list[EntryReachability],
        hypothesis_reachability: list[HypothesisReachability],
    ) -> list[EntryPointAssessment]:
        reachability_by_entry = {item.entry_point_id: item for item in reachability}
        hypotheses_by_entry: dict[str, list[HypothesisReachability]] = {}
        for mapping in hypothesis_reachability:
            for entry_id in mapping.entry_point_ids:
                hypotheses_by_entry.setdefault(entry_id, []).append(mapping)
        assessments = []
        for entry in entries:
            reachable = reachability_by_entry.get(entry.entry_id)
            mapped_hypotheses = hypotheses_by_entry.get(entry.entry_id, [])
            score = _entry_score(entry, reachable) * 100.0
            if entry.exposure_scope == "local_process":
                score *= 0.45
            if entry.runtime_confirmed:
                reason = "runtime-confirmed route increases validation priority, not severity"
            elif entry.exposure_scope == "local_process":
                reason = "local-process input is not firmware network attack surface"
            else:
                reason = "declared entry point requires additional runtime confirmation"
            assessments.append(
                EntryPointAssessment(
                    entry_point_id=entry.entry_id,
                    priority_rank=0,
                    priority_score=round(score, 2),
                    runtime_confidence=entry.confidence if entry.runtime_confirmed else 0.0,
                    reachable_component_count=len(reachable.reachable_component_ids) if reachable else 0,
                    reachable_hypothesis_count=len(mapped_hypotheses),
                    security_relevance="network_route" if entry.exposure_scope in {"external_network", "local_network", "loopback"} else "local_or_unknown",
                    validation_cost="low" if entry.runtime_confirmed else "medium" if entry.exposure_scope != "local_process" else "blocked",
                    reason=reason,
                )
            )
        assessments.sort(key=lambda item: item.priority_score, reverse=True)
        for index, assessment in enumerate(assessments, start=1):
            assessment.priority_rank = index
        return assessments

    def _summarize(
        self,
        entries: list[EntryPoint],
        routes: list[RouteMapping],
        hypothesis_reachability: list[HypothesisReachability],
        assessments: list[EntryPointAssessment],
    ) -> AttackSurfaceSummary:
        network_scopes = {"external_network", "local_network", "loopback"}
        return AttackSurfaceSummary(
            total_entries=len(entries),
            runtime_confirmed_entries=sum(1 for entry in entries if entry.runtime_confirmed),
            network_entries=sum(1 for entry in entries if entry.exposure_scope in network_scopes),
            local_entries=sum(1 for entry in entries if entry.exposure_scope not in network_scopes),
            route_entries=len(routes),
            service_entries=sum(1 for entry in entries if entry.entry_type in {"service_port", "tcp_service", "udp_service"}),
            reachable_hypotheses=sum(1 for item in hypothesis_reachability if item.reachable),
            blocked_hypotheses=sum(1 for item in hypothesis_reachability if item.state == "blocked"),
            unknown_hypotheses=sum(1 for item in hypothesis_reachability if item.state in {"unknown", "no_known_entry", "entry_unknown"}),
            entries_by_type=dict(sorted(Counter(entry.entry_type for entry in entries).items())),
            entries_by_exposure_scope=dict(sorted(Counter(entry.exposure_scope for entry in entries).items())),
            entry_priority_ranking=[item.to_dict() for item in assessments],
            safety_notes=[
                "EXPOSED != VULNERABLE",
                "REACHABLE != EXPLOITABLE",
                "HTTP 500 != VULNERABILITY",
                "LISTENING PORT != SECURITY BUG",
                "0.0.0.0 or an unspecified bind address does not imply public internet exposure",
            ],
        )

    def _build_contexts(
        self,
        entries: list[EntryPoint],
        routes: list[RouteMapping],
        reachability: list[EntryReachability],
        hypothesis_reachability: list[HypothesisReachability],
        handlers: list[HandlerDescriptor],
    ) -> list[EntryPointContext]:
        route_by_entry = {item.entry_point_id: item for item in routes}
        reachability_by_entry = {item.entry_point_id: item for item in reachability}
        handlers_by_entry = {item.entry_point_id: item for item in handlers}
        hypothesis_by_entry: dict[str, list[HypothesisReachability]] = {}
        for mapping in hypothesis_reachability:
            for entry_id in mapping.entry_point_ids:
                hypothesis_by_entry.setdefault(entry_id, []).append(mapping)
        contexts = []
        for entry in entries:
            reachable = reachability_by_entry.get(entry.entry_id)
            components = [self.graph.components[item].to_dict() for item in (reachable.reachable_component_ids if reachable else []) if item in self.graph.components]
            hypotheses = [item.to_dict() for item in hypothesis_by_entry.get(entry.entry_id, [])]
            known_blockers = [reachable.blocking_reason] if reachable and reachable.blocking_reason else []
            confidence_values = [entry.confidence] + [item.entry_confidence for item in hypothesis_by_entry.get(entry.entry_id, [])]
            contexts.append(
                EntryPointContext(
                    entry_point=entry.to_dict(),
                    service_component=self.graph.components[entry.component_id].to_dict() if entry.component_id in self.graph.components else None,
                    handler=handlers_by_entry[entry.entry_id].to_dict() if entry.entry_id in handlers_by_entry else None,
                    route=route_by_entry[entry.entry_id].to_dict() if entry.entry_id in route_by_entry else None,
                    reachable_components=components,
                    reachable_hypotheses=hypotheses,
                    runtime_evidence_ids=[evidence.id for evidence in self.dynamic_evidence if evidence.runtime_observation_real and evidence.execution_mode == "real"],
                    known_blockers=known_blockers,
                    confidence_summary={
                        "entry": entry.confidence,
                        "average": round(sum(confidence_values) / len(confidence_values), 3) if confidence_values else 0.0,
                        "runtime_confirmed": entry.runtime_confirmed,
                    },
                )
            )
        return contexts

    def _persist(self, payload: dict[str, Any]) -> None:
        self.workspace.save_surface_artifact("entry_points.json", payload["entry_points"])
        self.workspace.save_surface_artifact("routes.json", payload["routes"])
        self.workspace.save_surface_artifact("reachability.json", payload["reachability"])
        self.workspace.save_surface_artifact("hypothesis_reachability.json", payload["hypothesis_reachability"])
        self.workspace.save_surface_artifact("handlers.json", payload["handlers"])
        self.workspace.save_surface_artifact("input_sources.json", payload["input_sources"])
        self.workspace.save_surface_artifact("entry_assessments.json", payload["assessments"])
        self.workspace.save_surface_artifact("attack_surface_summary.json", payload["summary"])
        self.workspace.save_surface_artifact("entry_contexts.json", payload["entry_contexts"])
        self.workspace.save_surface_artifact("attack_surface_map.json", payload)

    def _load_lighttpd_profile(self) -> tuple[dict[str, Any], Path | None]:
        path = self.workspace.dynamic_dir / "services" / "lighttpd" / "launch_profile.json"
        if not path.exists():
            return {}, None
        try:
            return json.loads(path.read_text(encoding="utf-8")), path
        except json.JSONDecodeError:
            return {}, path

    def _load_fastcgi_runtime(self) -> dict[str, Any]:
        paths = [
            self.workspace.dynamic_dir / "application" / "device_manager" / "integration_validation.json",
            self.workspace.dynamic_dir / "validation" / "DV-0002" / "runtime.json",
        ]
        for path in paths:
            if not path.exists():
                continue
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                continue
        return {}

    def _entry_evidence_ids(self, runtime_confirmed: bool) -> list[str]:
        ids = ["ART:lighttpd-launch-profile"]
        if runtime_confirmed:
            ids.extend(item.id for item in self.dynamic_evidence if item.type in {"fastcgi_integration_reachable", "fastcgi_application_response", "handler_reached", "application_response"})
            ids.append("ART:fastcgi-runtime")
        return sorted(set(ids))

    def _load_report(self) -> dict[str, Any]:
        try:
            return self.workspace.load_report()
        except Exception:  # noqa: BLE001
            return {}

    def _relationship_ids_between(self, component_ids: set[str | None]) -> list[str]:
        known = {item for item in component_ids if item}
        return sorted(
            relationship.relationship_id
            for relationship in self.graph.relationships.values()
            if relationship.source_component_id in known or relationship.target_component_id in known
        )

    def _relationship_ids_for_component(self, component_id: str, relationship_types: set[str]) -> list[str]:
        return sorted(
            relationship.relationship_id
            for relationship in self.graph.relationships.values()
            if relationship.relationship_type in relationship_types and component_id in {relationship.source_component_id, relationship.target_component_id}
        )

    def _relationship_evidence(self, relationship_ids: set[str]) -> set[str]:
        return {evidence_id for relationship_id in relationship_ids for evidence_id in self.graph.relationships.get(relationship_id, ComponentRelationship("CR-X", "A", "B", "reads")).evidence_ids}

    def _walk_reachable(self, start_component_id: str) -> tuple[set[str], set[str]]:
        allowed = set(self.config.attack_surface.reachability.propagate_relationships)
        min_confidence = self.config.attack_surface.min_relationship_confidence
        max_depth = self.config.attack_surface.max_reachability_depth
        seen = {start_component_id}
        relationships_seen: set[str] = set()
        queue = deque([(start_component_id, 0)])
        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for relationship_id in self.graph.outgoing.get(current, []):
                relationship = self.graph.relationships[relationship_id]
                if relationship.relationship_type not in allowed or relationship.confidence < min_confidence:
                    continue
                relationships_seen.add(relationship_id)
                if relationship.target_component_id not in seen:
                    seen.add(relationship.target_component_id)
                    queue.append((relationship.target_component_id, depth + 1))
        return seen, relationships_seen

    def _paths_for_entry(self, entry: EntryPoint) -> list[dict[str, Any]]:
        paths = []
        if entry.component_id and entry.handler_component_id and entry.component_id != entry.handler_component_id:
            paths.extend(path.to_dict() for path in self.graph.find_paths(entry.component_id, entry.handler_component_id, max_depth=self.config.attack_surface.max_reachability_depth))
        if entry.component_id:
            paths.extend(path.to_dict() for path in self.graph.find_paths(entry.component_id, "application response", max_depth=self.config.attack_surface.max_reachability_depth))
        return paths[:5]


def _unique_entries(entries: list[EntryPoint]) -> list[EntryPoint]:
    by_id = {}
    for entry in entries:
        by_id.setdefault(entry.entry_id, entry)
    return list(by_id.values())


def _safe_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _surface_slug(value: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in value).strip("-") or "service"


def _input_description(entry: EntryPoint) -> str:
    if entry.entry_type in {"http_route", "https_route"}:
        method = entry.method or "method unknown"
        return f"{entry.protocol or 'http'} {entry.path or ''} on TCP {entry.port or 'unknown'} ({method})"
    if entry.entry_type == "stdin":
        return "local process standard input"
    if entry.entry_type in {"unix_socket", "local_ipc"}:
        return f"local IPC for {entry.service or entry.name}"
    return entry.name


def _entry_score(entry: EntryPoint, reachability: EntryReachability | None) -> float:
    score = entry.confidence
    if entry.runtime_confirmed:
        score += 0.15
    if reachability and reachability.state == "runtime_confirmed":
        score += 0.10
    if entry.exposure_scope == "local_process":
        score *= 0.65
    return _clamp01(score)


def _clamp01(value: float) -> float:
    return round(max(0.0, min(1.0, float(value))), 3)
