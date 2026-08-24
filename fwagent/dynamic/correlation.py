from __future__ import annotations

import json
import math
from collections import Counter, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.workspace import DynamicWorkspace


COMPONENT_TYPES = {
    "binary",
    "library",
    "service",
    "cgi",
    "fastcgi",
    "script",
    "config_file",
    "web_resource",
    "nvram_key",
    "socket",
    "port",
    "filesystem_path",
    "device",
    "certificate",
    "init_script",
    "runtime_process",
    "function",
    "runtime_endpoint",
    "runtime_observation",
}

RELATIONSHIP_TYPES = {
    "executes",
    "loads",
    "calls",
    "references",
    "reads",
    "writes",
    "configures",
    "starts",
    "spawns",
    "connects_to",
    "listens_on",
    "proxies_to",
    "serves",
    "uses_library",
    "uses_interpreter",
    "uses_certificate",
    "reads_nvram",
    "writes_nvram",
    "opens_path",
    "depends_on",
    "provides_backend_for",
    "routes_to",
    "communicates_with",
    "contains",
    "belongs_to",
    "exposes",
    "accepts_input_from",
    "dispatches_to",
    "handles",
    "maps_route_to",
    "forwards_to",
    "reachable_via",
    "entry_for",
}

SOURCE_TYPES = {
    "static_reference",
    "decompile",
    "string_reference",
    "init_script",
    "config_parse",
    "runtime_process",
    "runtime_socket",
    "runtime_http",
    "runtime_fastcgi",
    "manual_seed",
    "inferred",
}

RELATIONSHIP_STATUSES = {"candidate", "supported", "confirmed", "contradicted", "inactive", "unknown"}
CORRELATION_TYPES = {
    "same_target",
    "same_function",
    "same_path",
    "same_service",
    "same_runtime_event",
    "static_dynamic_match",
    "supporting_chain",
    "contradictory_chain",
}
EXECUTION_MODES = {"real", "mock", "simulation", "test"}
PROVENANCE_VALUES = {"real_static_analysis", "real_runtime_observation", "mock_agent", "simulation", "fixture", "manual"}


@dataclass
class FirmwareComponent:
    component_id: str
    component_type: str
    name: str
    path: str | None = None
    binary_id: str | None = None
    service_name: str | None = None
    architecture: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    source: str = "correlation"
    confidence: float = 0.7
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.component_type not in COMPONENT_TYPES:
            raise ValueError(f"invalid component_type: {self.component_type}")
        self.confidence = _clamp01(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentRelationship:
    relationship_id: str
    source_component_id: str
    target_component_id: str
    relationship_type: str
    evidence_ids: list[str] = field(default_factory=list)
    confidence: float = 0.5
    source_type: str = "inferred"
    static_or_dynamic: str = "static"
    observation: str = ""
    artifact_path: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status: str = "candidate"
    provenance: str = "real_static_analysis"
    execution_mode: str = "real"
    runtime_observation_real: bool = False
    provider_backed: bool = False
    relationship_relevance: float = 0.5

    def __post_init__(self) -> None:
        if self.relationship_type not in RELATIONSHIP_TYPES:
            raise ValueError(f"invalid relationship_type: {self.relationship_type}")
        if self.source_type not in SOURCE_TYPES:
            raise ValueError(f"invalid source_type: {self.source_type}")
        if self.status not in RELATIONSHIP_STATUSES:
            raise ValueError(f"invalid relationship status: {self.status}")
        if self.execution_mode not in EXECUTION_MODES:
            raise ValueError(f"invalid execution_mode: {self.execution_mode}")
        self.confidence = _clamp01(self.confidence)
        self.relationship_relevance = _clamp01(self.relationship_relevance)

    def promote(self, confidence: float, evidence_ids: list[str], *, status: str | None = None) -> None:
        self.confidence = _clamp01(max(self.confidence, confidence))
        self.evidence_ids = sorted(set(self.evidence_ids) | set(evidence_ids))
        if status:
            self.status = status

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceCorrelation:
    correlation_id: str
    evidence_ids: list[str]
    component_ids: list[str]
    relationship_ids: list[str]
    correlation_type: str
    confidence: float
    reason: str
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if self.correlation_type not in CORRELATION_TYPES:
            raise ValueError(f"invalid correlation_type: {self.correlation_type}")
        self.confidence = _clamp01(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentPath:
    path_id: str
    component_ids: list[str]
    relationship_ids: list[str]
    evidence_ids: list[str]
    confidence: float
    path_type: str
    reachable: bool = False
    runtime_backend: str | None = None
    path_semantics: str = "runtime_flow"

    def __post_init__(self) -> None:
        self.confidence = _clamp01(self.confidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CrossComponentContext:
    root_component_id: str
    related_components: list[dict[str, Any]]
    relationships: list[dict[str, Any]]
    evidence_ids: list[str]
    dynamic_evidence_ids: list[str]
    candidate_paths: list[dict[str, Any]]
    config_dependencies: list[str]
    runtime_dependencies: list[str]
    reachable_services: list[str]
    known_blockers: list[str]
    confidence_summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CrossComponentSecurityContext:
    hypothesis_id: str
    root_component_id: str
    component_path_ids: list[str]
    security_relevant_components: list[str]
    runtime_path_readiness: float
    cross_component_complexity: int
    dependency_chain_length: int
    relationship_confidence: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ComponentGraphSummary:
    component_counts: dict[str, int]
    relationship_counts: dict[str, int]
    total_components: int
    total_relationships: int
    static_relationships: int
    dynamic_relationships: int
    evidence_correlations: int
    high_confidence_paths: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class CanonicalStateGuard:
    @staticmethod
    def can_update_canonical(
        *,
        execution_mode: str,
        runtime_observation_real: bool,
        synthetic: bool = False,
    ) -> bool:
        return execution_mode == "real" and runtime_observation_real and not synthetic


class ComponentGraph:
    def __init__(self) -> None:
        self.components: dict[str, FirmwareComponent] = {}
        self.relationships: dict[str, ComponentRelationship] = {}
        self.outgoing: dict[str, list[str]] = {}
        self.incoming: dict[str, list[str]] = {}
        self.evidence_correlations: dict[str, EvidenceCorrelation] = {}

    def add_component(self, component: FirmwareComponent) -> FirmwareComponent:
        existing = self.components.get(component.component_id)
        if existing:
            existing.confidence = max(existing.confidence, component.confidence)
            existing.metadata.update({k: v for k, v in component.metadata.items() if v not in (None, "", [], {})})
            return existing
        self.components[component.component_id] = component
        return component

    def add_relationship(self, relationship: ComponentRelationship) -> ComponentRelationship:
        key = self._relationship_key(relationship)
        existing = next((item for item in self.relationships.values() if self._relationship_key(item) == key), None)
        if existing:
            existing.promote(relationship.confidence, relationship.evidence_ids, status=_stronger_status(existing.status, relationship.status))
            existing.relationship_relevance = max(existing.relationship_relevance, relationship.relationship_relevance)
            return existing
        self.relationships[relationship.relationship_id] = relationship
        self.outgoing.setdefault(relationship.source_component_id, []).append(relationship.relationship_id)
        self.incoming.setdefault(relationship.target_component_id, []).append(relationship.relationship_id)
        return relationship

    def add_evidence_correlation(self, correlation: EvidenceCorrelation) -> EvidenceCorrelation:
        self.evidence_correlations[correlation.correlation_id] = correlation
        return correlation

    def get_neighbors(self, component_id: str, *, direction: str = "both") -> list[FirmwareComponent]:
        ids: set[str] = set()
        if direction in {"out", "both"}:
            ids.update(self.relationships[rel].target_component_id for rel in self.outgoing.get(component_id, []))
        if direction in {"in", "both"}:
            ids.update(self.relationships[rel].source_component_id for rel in self.incoming.get(component_id, []))
        return [self.components[item] for item in sorted(ids) if item in self.components]

    def get_upstream(self, component_id: str) -> list[FirmwareComponent]:
        return self.get_neighbors(component_id, direction="in")

    def get_downstream(self, component_id: str) -> list[FirmwareComponent]:
        return self.get_neighbors(component_id, direction="out")

    def find_components_by_type(self, component_type: str) -> list[FirmwareComponent]:
        return [item for item in self.components.values() if item.component_type == component_type]

    def find_relationships(
        self,
        *,
        source_component_id: str | None = None,
        target_component_id: str | None = None,
        relationship_type: str | None = None,
    ) -> list[ComponentRelationship]:
        relationships = list(self.relationships.values())
        if source_component_id:
            relationships = [item for item in relationships if item.source_component_id == source_component_id]
        if target_component_id:
            relationships = [item for item in relationships if item.target_component_id == target_component_id]
        if relationship_type:
            relationships = [item for item in relationships if item.relationship_type == relationship_type]
        return relationships

    def find_paths(self, source: str, target: str, *, max_depth: int = 5) -> list[ComponentPath]:
        source_id = self.resolve_component_id(source)
        target_id = self.resolve_component_id(target)
        if not source_id or not target_id:
            return []
        queue = deque([(source_id, [source_id], [])])
        paths: list[ComponentPath] = []
        while queue:
            current, components, relationships = queue.popleft()
            if len(relationships) >= max_depth:
                continue
            for relationship_id in self.outgoing.get(current, []):
                relationship = self.relationships[relationship_id]
                next_component = relationship.target_component_id
                if next_component in components:
                    continue
                next_components = components + [next_component]
                next_relationships = relationships + [relationship_id]
                if next_component == target_id:
                    rels = [self.relationships[item] for item in next_relationships]
                    paths.append(
                        ComponentPath(
                            path_id=f"CPATH-{len(paths) + 1:04d}",
                            component_ids=next_components,
                            relationship_ids=next_relationships,
                            evidence_ids=sorted({evidence_id for rel in rels for evidence_id in rel.evidence_ids}),
                            confidence=_path_confidence(rels),
                            path_type="runtime_reachable" if any(rel.static_or_dynamic == "dynamic" for rel in rels) else "static",
                            reachable=any(rel.status == "confirmed" for rel in rels),
                            runtime_backend="fastcgi-integration" if any(rel.source_type == "runtime_fastcgi" for rel in rels) else None,
                        )
                    )
                else:
                    queue.append((next_component, next_components, next_relationships))
        return sorted(paths, key=lambda item: (item.reachable, item.confidence, -len(item.relationship_ids)), reverse=True)

    def subgraph(self, root: str, *, max_depth: int = 2, max_nodes: int = 24) -> "ComponentGraph":
        root_id = self.resolve_component_id(root)
        sub = ComponentGraph()
        if not root_id:
            return sub
        seen = {root_id}
        queue = deque([(root_id, 0)])
        while queue and len(seen) <= max_nodes:
            current, depth = queue.popleft()
            if current in self.components:
                sub.add_component(self.components[current])
            if depth >= max_depth:
                continue
            relationship_ids = self.outgoing.get(current, []) + self.incoming.get(current, [])
            relationship_ids = sorted(relationship_ids, key=lambda item: self.relationships[item].relationship_relevance, reverse=True)
            for relationship_id in relationship_ids:
                relationship = self.relationships[relationship_id]
                other = relationship.target_component_id if relationship.source_component_id == current else relationship.source_component_id
                if other not in seen and len(seen) >= max_nodes:
                    continue
                seen.add(other)
                if other in self.components:
                    sub.add_component(self.components[other])
                sub.add_relationship(relationship)
                queue.append((other, depth + 1))
        return sub

    def resolve_component_id(self, value: str) -> str | None:
        if value in self.components:
            return value
        lowered = value.lower()
        exact = [component for component in self.components.values() if lowered in {component.name.lower(), str(component.path or "").lower()}]
        if exact:
            exact.sort(key=lambda item: 0 if item.component_type == "service" else 1)
            return exact[0].component_id
        for component in self.components.values():
            if lowered in component.name.lower() or lowered in str(component.path or "").lower():
                return component.component_id
        return None

    def summary(self, paths: list[ComponentPath] | None = None) -> ComponentGraphSummary:
        component_counts = Counter(item.component_type for item in self.components.values())
        relationship_counts = Counter(item.relationship_type for item in self.relationships.values())
        return ComponentGraphSummary(
            component_counts=dict(sorted(component_counts.items())),
            relationship_counts=dict(sorted(relationship_counts.items())),
            total_components=len(self.components),
            total_relationships=len(self.relationships),
            static_relationships=sum(1 for item in self.relationships.values() if item.static_or_dynamic == "static"),
            dynamic_relationships=sum(1 for item in self.relationships.values() if item.static_or_dynamic == "dynamic"),
            evidence_correlations=len(self.evidence_correlations),
            high_confidence_paths=[item.to_dict() for item in (paths or []) if item.confidence >= 0.7][:10],
        )

    def serialize(self) -> dict[str, Any]:
        return {
            "components": [item.to_dict() for item in self.components.values()],
            "relationships": [item.to_dict() for item in self.relationships.values()],
            "evidence_correlations": [item.to_dict() for item in self.evidence_correlations.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ComponentGraph":
        graph = cls()
        for item in data.get("components", []):
            graph.add_component(FirmwareComponent(**item))
        for item in data.get("relationships", []):
            graph.add_relationship(ComponentRelationship(**item))
        for item in data.get("evidence_correlations", []):
            graph.add_evidence_correlation(EvidenceCorrelation(**item))
        return graph

    @staticmethod
    def _relationship_key(relationship: ComponentRelationship) -> tuple[str, str, str]:
        return (relationship.source_component_id, relationship.target_component_id, relationship.relationship_type)


class ComponentGraphBuilder:
    def __init__(self, workspace_root: str | Path, task_id: str, *, config: DynamicConfig):
        self.workspace = DynamicWorkspace(workspace_root, task_id)
        self.config = config
        self.graph = ComponentGraph()
        self.dynamic_evidence = self.workspace.load_evidence()
        self.dynamic_by_type: dict[str, list[DynamicEvidence]] = {}
        for evidence in self.dynamic_evidence:
            self.dynamic_by_type.setdefault(evidence.type, []).append(evidence)

    def build(self) -> dict[str, Any]:
        report = self._load_report()
        self._ingest_binaries(report)
        self._ingest_services(report)
        self._ingest_lighttpd_profile()
        self._ingest_fastcgi_runtime()
        self._ingest_hypothesis_context()
        paths = self._high_confidence_paths()
        self._correlate_static_dynamic()
        paths = self._high_confidence_paths()
        summary = self.graph.summary(paths)
        payload = {
            "success": True,
            "provider_backed": False,
            "graph_version": self.config.correlation.graph_version,
            "components": [item.to_dict() for item in self.graph.components.values()],
            "relationships": [item.to_dict() for item in self.graph.relationships.values()],
            "evidence_correlations": [item.to_dict() for item in self.graph.evidence_correlations.values()],
            "paths": [item.to_dict() for item in paths],
            "summary": summary.to_dict(),
        }
        self._persist(payload)
        return payload

    def load_or_build_graph(self) -> ComponentGraph:
        artifact = self.workspace.load_correlation_artifact("component_graph.json")
        if artifact:
            return ComponentGraph.from_dict(artifact)
        self.build()
        return ComponentGraph.from_dict(self.workspace.load_correlation_artifact("component_graph.json") or {})

    def cross_component_context(
        self,
        hypothesis_id: str,
        *,
        root_component: str | None = None,
        max_depth: int | None = None,
        max_nodes: int | None = None,
    ) -> CrossComponentContext:
        graph = self.load_or_build_graph()
        root = root_component or self._root_for_hypothesis(hypothesis_id, graph)
        root_id = graph.resolve_component_id(root) if root else None
        if not root_id:
            return CrossComponentContext("", [], [], [], [], [], [], [], [], ["root component not found"], {"average": 0.0})
        sub = graph.subgraph(
            root_id,
            max_depth=max_depth or self.config.correlation.filtering.max_path_depth,
            max_nodes=max_nodes or self.config.correlation.filtering.max_context_nodes,
        )
        relationships = list(sub.relationships.values())
        evidence_ids = sorted({evidence_id for rel in relationships for evidence_id in rel.evidence_ids})
        dynamic_ids = sorted({item for item in evidence_ids if item.startswith("DE-")})
        config_dependencies = [component.path or component.name for component in sub.components.values() if component.component_type == "config_file"]
        runtime_dependencies = [component.name for component in sub.components.values() if component.component_type in {"runtime_endpoint", "runtime_observation", "socket", "port"}]
        reachable_services = [component.name for component in sub.components.values() if component.component_type == "service"]
        candidate_paths = [path.to_dict() for component_id in sub.components for path in graph.find_paths(root_id, component_id, max_depth=max_depth or 5)[:1]][:10]
        confidences = [rel.confidence for rel in relationships]
        return CrossComponentContext(
            root_component_id=root_id,
            related_components=[item.to_dict() for item in sub.components.values()],
            relationships=[item.to_dict() for item in relationships],
            evidence_ids=evidence_ids,
            dynamic_evidence_ids=dynamic_ids,
            candidate_paths=candidate_paths,
            config_dependencies=config_dependencies,
            runtime_dependencies=runtime_dependencies,
            reachable_services=reachable_services,
            known_blockers=self._known_blockers(hypothesis_id),
            confidence_summary={
                "average": round(sum(confidences) / len(confidences), 3) if confidences else 0.0,
                "max": round(max(confidences), 3) if confidences else 0.0,
                "relationship_count": len(confidences),
            },
        )

    def security_context_for_hypothesis(self, hypothesis_id: str) -> CrossComponentSecurityContext:
        graph = self.load_or_build_graph()
        context = self.cross_component_context(hypothesis_id)
        relationship_confidence = float(context.confidence_summary.get("average") or 0.0)
        path_ids = [path.get("path_id") for path in context.candidate_paths if path.get("path_id")]
        runtime_ready = 1.0 if any(item.get("reachable") for item in context.candidate_paths) else relationship_confidence
        return CrossComponentSecurityContext(
            hypothesis_id=hypothesis_id,
            root_component_id=context.root_component_id,
            component_path_ids=path_ids,
            security_relevant_components=[item["component_id"] for item in context.related_components if _security_relevant_component(item)],
            runtime_path_readiness=round(_clamp01(runtime_ready), 3),
            cross_component_complexity=len(context.related_components),
            dependency_chain_length=max((len(path.get("relationship_ids") or []) for path in context.candidate_paths), default=0),
            relationship_confidence=relationship_confidence,
        )

    def incremental_update_from_dynamic_evidence(self, evidence: DynamicEvidence) -> dict[str, Any]:
        graph = self.load_or_build_graph()
        if evidence.execution_mode != "real" or not evidence.runtime_observation_real:
            return {"success": False, "updated": False, "reason": "non-real evidence is kept out of canonical correlation graph"}
        source_id = graph.resolve_component_id("device_manager.fcgi")
        response_id = graph.resolve_component_id("application response")
        if source_id and response_id:
            relationship = graph.add_relationship(
                ComponentRelationship(
                    relationship_id=f"CR-{len(graph.relationships) + 1:04d}",
                    source_component_id=source_id,
                    target_component_id=response_id,
                    relationship_type="serves",
                    evidence_ids=[evidence.id],
                    confidence=self.config.correlation.confidence.runtime_confirmed,
                    source_type="runtime_fastcgi",
                    static_or_dynamic="dynamic",
                    observation=evidence.observation,
                    status="confirmed",
                    provenance=evidence.provenance,
                    execution_mode=evidence.execution_mode,
                    runtime_observation_real=evidence.runtime_observation_real,
                    provider_backed=evidence.provider_backed,
                    relationship_relevance=0.95,
                )
            )
            self.workspace.save_correlation_artifact("component_graph.json", graph.serialize())
            return {"success": True, "updated": True, "relationship": relationship.to_dict()}
        return {"success": False, "updated": False, "reason": "FastCGI response components not found"}

    def _persist(self, payload: dict[str, Any]) -> None:
        self.workspace.save_correlation_artifact("components.json", payload["components"])
        self.workspace.save_correlation_artifact("relationships.json", payload["relationships"])
        self.workspace.save_correlation_artifact("evidence_correlations.json", payload["evidence_correlations"])
        self.workspace.save_correlation_artifact("component_graph.json", self.graph.serialize())
        self.workspace.save_correlation_artifact("paths.json", payload["paths"])
        self.workspace.save_correlation_artifact("summary.json", payload["summary"])

    def _load_report(self) -> dict[str, Any]:
        try:
            return self.workspace.load_report()
        except Exception:  # noqa: BLE001
            return {}

    def _ingest_binaries(self, report: dict[str, Any]) -> None:
        for binary in report.get("binaries", []) if isinstance(report.get("binaries"), list) else []:
            path = str(binary.get("path") or "")
            if not path or self._noise_path(path):
                continue
            if "lighttpd" not in path and "device_manager" not in path and "ret2text" not in path:
                continue
            component_type = "fastcgi" if path.endswith(".fcgi") else "binary"
            component = self._component(component_type, Path(path).name, path=path, architecture=binary.get("architecture"), metadata={"linked_libraries": binary.get("linked_libraries", [])})
            for library in binary.get("linked_libraries", [])[:12]:
                if self.config.correlation.filtering.ignore_library_paths and library in {"libc.so.0", "libgcc_s.so.1"}:
                    continue
                lib = self._component("library", str(library), path=str(library), confidence=0.6)
                self._relationship(component, lib, "uses_library", "static_reference", [f"BIN:{path}"], 0.55, f"{path} links {library}")

    def _ingest_services(self, report: dict[str, Any]) -> None:
        for service in report.get("services", []) if isinstance(report.get("services"), list) else []:
            name = str(service.get("name") or "")
            if not name or name != "lighttpd":
                continue
            self._component("service", name, service_name=name, metadata=service)

    def _ingest_lighttpd_profile(self) -> None:
        profile_path = self.workspace.dynamic_dir / "services" / "lighttpd" / "launch_profile.json"
        if not profile_path.exists():
            return
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        service = self._component("service", str(profile.get("service") or "lighttpd"), service_name=str(profile.get("service") or "lighttpd"), metadata={"profile": "launch_profile"})
        binary = self._component("binary", Path(str(profile.get("binary") or "/usr/sbin/lighttpd")).name, path=str(profile.get("binary") or "/usr/sbin/lighttpd"))
        self._relationship(service, binary, "starts", "init_script", ["ART:lighttpd-launch-profile"], 0.82, "init/service profile starts lighttpd binary", artifact_path=str(profile_path))
        if profile.get("startup_source"):
            init = self._component("init_script", Path(str(profile["startup_source"])).name, path=str(profile["startup_source"]))
            self._relationship(init, service, "starts", "init_script", ["ART:lighttpd-launch-profile"], 0.75, "init script starts service", artifact_path=str(profile_path))
        for config_file in profile.get("config_files", []):
            config = self._component("config_file", Path(str(config_file)).name, path=str(config_file), confidence=0.86)
            self._relationship(service, config, "reads", "config_parse", ["ART:lighttpd-launch-profile"], self.config.correlation.confidence.config_parse, "lighttpd profile reads config", artifact_path=str(profile_path))
            self._relationship(config, service, "configures", "config_parse", ["ART:lighttpd-launch-profile"], self.config.correlation.confidence.config_parse, "lighttpd config configures service", artifact_path=str(profile_path))
        config_data = profile.get("config") or {}
        if config_data.get("server.port"):
            port = self._component("port", f"TCP {config_data['server.port']}", metadata={"port": config_data["server.port"], "protocol": "tcp"})
            self._relationship(service, port, "listens_on", "config_parse", ["ART:lighttpd-launch-profile"], 0.72, "lighttpd config declares listening TCP port", artifact_path=str(profile_path))
        if config_data.get("ssl.pemfile"):
            cert = self._component("certificate", Path(str(config_data["ssl.pemfile"])).name, path=str(config_data["ssl.pemfile"]))
            self._relationship(service, cert, "uses_certificate", "config_parse", ["ART:lighttpd-launch-profile"], 0.70, "lighttpd config declares SSL certificate", artifact_path=str(profile_path))
        if config_data.get("server.document-root"):
            root = self._component("filesystem_path", str(config_data["server.document-root"]), path=str(config_data["server.document-root"]))
            self._relationship(service, root, "serves", "config_parse", ["ART:lighttpd-launch-profile"], 0.66, "lighttpd serves document root", artifact_path=str(profile_path))
        self._ingest_fastcgi_config(profile, profile_path)

    def _ingest_fastcgi_config(self, profile: dict[str, Any], profile_path: Path) -> None:
        config_data = profile.get("config") or {}
        values = [str(item) for item in config_data.get("fastcgi.server", [])]
        if not values:
            return
        service = self._component("service", str(profile.get("service") or "lighttpd"), service_name=str(profile.get("service") or "lighttpd"))
        config = self._component("config_file", "lighttpd.conf", path="/etc/lighttpd/lighttpd.conf")
        endpoint_value = next((item for item in values if item.startswith("/services/")), "/services/device_manager/")
        bin_path = next((item for item in values if item.endswith(".fcgi")), "/device_manager/device_manager.fcgi")
        full_bin = bin_path if bin_path.startswith("/www") else f"/www/services{bin_path}" if bin_path.startswith("/") else bin_path
        fastcgi = self._component("fastcgi", Path(full_bin).name, path=full_bin, confidence=0.85)
        endpoint = self._component("runtime_endpoint", endpoint_value, path=endpoint_value, metadata={"protocol": "http"})
        socket_name = "".join(values[values.index("socket") + 1 : values.index("bin-path")]) if "socket" in values and "bin-path" in values else "/tmp/device_manager-.socket"
        socket = self._component("socket", socket_name, path=socket_name, metadata={"socket_type": "unix_socket"})
        self._relationship(config, fastcgi, "routes_to", "config_parse", ["ART:lighttpd-launch-profile"], 0.78, "fastcgi.server maps URL to backend binary", artifact_path=str(profile_path), relevance=0.9)
        self._relationship(config, endpoint, "routes_to", "config_parse", ["ART:lighttpd-launch-profile"], 0.75, "fastcgi.server maps URL endpoint", artifact_path=str(profile_path), relevance=0.85)
        self._relationship(service, fastcgi, "spawns", "config_parse", ["ART:lighttpd-launch-profile"], 0.72, "lighttpd config includes FastCGI bin-path", artifact_path=str(profile_path), relevance=0.9)
        self._relationship(service, socket, "communicates_with", "config_parse", ["ART:lighttpd-launch-profile"], 0.68, "lighttpd config defines FastCGI socket", artifact_path=str(profile_path), relevance=0.75)
        self._relationship(fastcgi, endpoint, "provides_backend_for", "config_parse", ["ART:lighttpd-launch-profile"], 0.76, "FastCGI backend serves URL endpoint", artifact_path=str(profile_path), relevance=0.9)

    def _ingest_fastcgi_runtime(self) -> None:
        runtime_paths = [
            self.workspace.dynamic_dir / "application" / "device_manager" / "integration_validation.json",
            self.workspace.dynamic_dir / "validation" / "DV-0002" / "runtime.json",
        ]
        runtime = next((json.loads(path.read_text(encoding="utf-8")) for path in runtime_paths if path.exists()), None)
        if not runtime:
            return
        service = self._component("service", "lighttpd", service_name="lighttpd")
        fastcgi = self._component("fastcgi", "device_manager.fcgi", path="/www/services/device_manager/device_manager.fcgi", confidence=0.92)
        endpoint = self._component("runtime_endpoint", str(runtime.get("endpoint") or "/services/device_manager/"), path=str(runtime.get("endpoint") or "/services/device_manager/"), metadata={"runtime_backend": "fastcgi-integration"})
        response = self._component("runtime_observation", "application response", metadata={"diagnosis": runtime.get("diagnosis"), "success": runtime.get("success")}, confidence=0.92)
        runtime_evidence_ids = self._runtime_evidence_ids()
        if runtime.get("backend_child", {}).get("listener", {}).get("port"):
            port_value = int(runtime["backend_child"]["listener"]["port"])
            port = self._component("port", f"127.0.0.1:{port_value}", metadata={"host": "127.0.0.1", "port": port_value, "protocol": "tcp_loopback"})
            self._relationship(fastcgi, port, "listens_on", "runtime_socket", runtime_evidence_ids, 0.92, "external FastCGI child listened on loopback TCP", static_or_dynamic="dynamic", status="confirmed", provenance="real_runtime_observation", runtime_real=True, relevance=0.88)
            self._relationship(service, port, "connects_to", "runtime_fastcgi", runtime_evidence_ids, 0.92, "lighttpd repair connected to external FastCGI loopback listener", static_or_dynamic="dynamic", status="confirmed", provenance="real_runtime_observation", runtime_real=True, relevance=0.9)
        if runtime.get("application_response_reached"):
            self._relationship(service, fastcgi, "communicates_with", "runtime_fastcgi", runtime_evidence_ids, 0.95, "lighttpd forwarded local request to FastCGI backend", static_or_dynamic="dynamic", status="confirmed", provenance="real_runtime_observation", runtime_real=True, relevance=0.98)
            self._relationship(endpoint, fastcgi, "routes_to", "runtime_fastcgi", runtime_evidence_ids, 0.95, "runtime request reached FastCGI backend", static_or_dynamic="dynamic", status="confirmed", provenance="real_runtime_observation", runtime_real=True, relevance=0.98)
            self._relationship(fastcgi, response, "serves", "runtime_http", runtime_evidence_ids, 0.95, "FastCGI backend produced application-level response", static_or_dynamic="dynamic", status="confirmed", provenance="real_runtime_observation", runtime_real=True, relevance=1.0)

    def _ingest_hypothesis_context(self) -> None:
        hypotheses = self.workspace.load_hypotheses()
        for hypothesis in hypotheses:
            if "ret2text" in hypothesis.title.lower() or "ret2text" in hypothesis.id.lower():
                binary = self._component("binary", "ret2text", path="ret2text", confidence=0.65)
                self._component("function", "main", binary_id=binary.component_id, metadata={"hypothesis_id": hypothesis.id}, confidence=0.7)
                secure = self._component("function", "secure", binary_id=binary.component_id, metadata={"hypothesis_id": hypothesis.id}, confidence=0.65)
                self._relationship(binary, secure, "contains", "static_reference", hypothesis.evidence_ids, 0.55, "ret2text evidence references secure function", relevance=0.5)

    def _correlate_static_dynamic(self) -> None:
        static_rels = [item for item in self.graph.relationships.values() if item.static_or_dynamic == "static"]
        dynamic_rels = [item for item in self.graph.relationships.values() if item.static_or_dynamic == "dynamic"]
        for static in static_rels:
            for dynamic in dynamic_rels:
                same_pair = {static.source_component_id, static.target_component_id} & {dynamic.source_component_id, dynamic.target_component_id}
                if static.target_component_id == dynamic.target_component_id or len(same_pair) >= 1 and static.relationship_type in {"routes_to", "spawns", "communicates_with"}:
                    correlation = EvidenceCorrelation(
                        correlation_id=f"EC-{len(self.graph.evidence_correlations) + 1:04d}",
                        evidence_ids=sorted(set(static.evidence_ids) | set(dynamic.evidence_ids)),
                        component_ids=sorted({static.source_component_id, static.target_component_id, dynamic.source_component_id, dynamic.target_component_id}),
                        relationship_ids=[static.relationship_id, dynamic.relationship_id],
                        correlation_type="static_dynamic_match",
                        confidence=min(1.0, max(static.confidence, dynamic.confidence) + self.config.correlation.confidence.promotion_bonus),
                        reason="static relationship is supported by dynamic FastCGI/runtime evidence",
                    )
                    self.graph.add_evidence_correlation(correlation)
                    static.promote(correlation.confidence, correlation.evidence_ids, status="supported")

    def _high_confidence_paths(self) -> list[ComponentPath]:
        candidates = [
            ("lighttpd", "application response"),
            ("lighttpd", "device_manager.fcgi"),
            ("/etc/lighttpd/lighttpd.conf", "device_manager.fcgi"),
        ]
        paths: list[ComponentPath] = []
        for source, target in candidates:
            paths.extend(self.graph.find_paths(source, target, max_depth=self.config.correlation.filtering.max_path_depth))
        unique: dict[tuple[str, ...], ComponentPath] = {}
        for path in paths:
            unique.setdefault(tuple(path.relationship_ids), path)
        return sorted(unique.values(), key=lambda item: (item.reachable, item.confidence), reverse=True)[:10]

    def _root_for_hypothesis(self, hypothesis_id: str, graph: ComponentGraph) -> str | None:
        hypothesis = next((item for item in self.workspace.load_hypotheses() if item.id == hypothesis_id), None)
        text = f"{hypothesis_id} {hypothesis.title if hypothesis else ''}".lower()
        if "fcgi" in text or "soap" in text or "device_manager" in text:
            return graph.resolve_component_id("device_manager.fcgi")
        if "ret2text" in text:
            return graph.resolve_component_id("ret2text")
        return next(iter(graph.components), None)

    def _known_blockers(self, hypothesis_id: str) -> list[str]:
        blockers = []
        for evidence in self.dynamic_evidence:
            if evidence.target == hypothesis_id and evidence.type == "validation_blocked":
                blockers.append(evidence.observation)
        return blockers

    def _runtime_evidence_ids(self) -> list[str]:
        useful = []
        for evidence_type in ("fastcgi_integration_reachable", "fastcgi_application_response", "handler_reached", "application_response", "runtime_ready", "baseline_response", "validation_request"):
            useful.extend(item.id for item in self.dynamic_by_type.get(evidence_type, []))
        return sorted(set(useful)) or ["ART:fastcgi-runtime"]

    def _component(
        self,
        component_type: str,
        name: str,
        *,
        path: str | None = None,
        binary_id: str | None = None,
        service_name: str | None = None,
        architecture: str | None = None,
        metadata: dict[str, Any] | None = None,
        confidence: float = 0.75,
    ) -> FirmwareComponent:
        component = FirmwareComponent(
            component_id=_component_id(component_type, path or name),
            component_type=component_type,
            name=name,
            path=path,
            binary_id=binary_id,
            service_name=service_name,
            architecture=architecture,
            metadata=metadata or {},
            confidence=confidence,
        )
        return self.graph.add_component(component)

    def _relationship(
        self,
        source: FirmwareComponent,
        target: FirmwareComponent,
        relationship_type: str,
        source_type: str,
        evidence_ids: list[str],
        confidence: float,
        observation: str,
        *,
        artifact_path: str | None = None,
        static_or_dynamic: str = "static",
        status: str | None = None,
        provenance: str | None = None,
        runtime_real: bool = False,
        relevance: float = 0.6,
    ) -> ComponentRelationship:
        return self.graph.add_relationship(
            ComponentRelationship(
                relationship_id=f"CR-{len(self.graph.relationships) + 1:04d}",
                source_component_id=source.component_id,
                target_component_id=target.component_id,
                relationship_type=relationship_type,
                evidence_ids=sorted(set(evidence_ids)),
                confidence=confidence,
                source_type=source_type,
                static_or_dynamic=static_or_dynamic,
                observation=observation,
                artifact_path=artifact_path,
                status=status or ("confirmed" if static_or_dynamic == "dynamic" and runtime_real else "supported"),
                provenance=provenance or ("real_runtime_observation" if static_or_dynamic == "dynamic" else "real_static_analysis"),
                execution_mode="real",
                runtime_observation_real=runtime_real,
                provider_backed=False,
                relationship_relevance=relevance,
            )
        )

    def _noise_path(self, path: str) -> bool:
        if path.startswith("/lib/") or path.startswith("/usr/lib/"):
            return self.config.correlation.filtering.ignore_library_paths
        return False


def _component_id(component_type: str, value: str) -> str:
    normalized = "".join(ch.lower() if ch.isalnum() else "-" for ch in value.strip("/"))
    normalized = "-".join(token for token in normalized.split("-") if token)
    return f"C-{component_type.upper()}-{normalized or 'root'}"[:96]


def _path_confidence(relationships: list[ComponentRelationship]) -> float:
    if not relationships:
        return 0.0
    product = 1.0
    for relationship in relationships:
        product *= relationship.confidence
    return round(product ** (1.0 / len(relationships)), 3)


def _stronger_status(left: str, right: str) -> str:
    order = ["unknown", "candidate", "inactive", "contradicted", "supported", "confirmed"]
    return right if order.index(right) > order.index(left) else left


def _security_relevant_component(component: dict[str, Any]) -> bool:
    text = json.dumps(component, ensure_ascii=False).lower()
    return any(token in text for token in ("fastcgi", "http", "soap", "ssl", "certificate", "nvram", "device_manager", "ret2text", "secure"))


def _clamp01(value: float) -> float:
    if isinstance(value, float) and math.isnan(value):
        return 0.0
    return max(0.0, min(1.0, float(value)))
