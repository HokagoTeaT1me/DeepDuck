from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwagent.cli import build_parser, main
from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.config import DynamicConfig
from fwagent.dynamic.correlation import (
    CanonicalStateGuard,
    ComponentGraph,
    ComponentGraphBuilder,
    ComponentRelationship,
    EvidenceCorrelation,
    FirmwareComponent,
)
from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.prioritization import HypothesisValidationScheduler
from fwagent.dynamic.workspace import DynamicWorkspace


class Round42Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.task_id = "round42-fixture"
        self.task = self.root / self.task_id
        for name in ("reports", "hypotheses", "evidence"):
            (self.task / name).mkdir(parents=True, exist_ok=True)
        workspace = DynamicWorkspace(self.root, self.task_id)
        (workspace.dynamic_dir / "services" / "lighttpd").mkdir(parents=True, exist_ok=True)
        (workspace.dynamic_dir / "application" / "device_manager").mkdir(parents=True, exist_ok=True)
        (workspace.validation_dir / "DV-0002").mkdir(parents=True, exist_ok=True)
        self._write_fixture(workspace)
        self.config = DynamicConfig(backend="service-qemu")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fixture(self, workspace: DynamicWorkspace) -> None:
        report = {
            "binaries": [
                {"path": "/usr/sbin/lighttpd", "architecture": "arm", "linked_libraries": ["libssl.so.1.0.0", "libcrypto.so.1.0.0", "libc.so.0"]},
                {"path": "/www/services/device_manager/device_manager.fcgi", "architecture": "arm", "linked_libraries": ["libnvram.so", "libshared.so"]},
                {"path": "/lib/libc.so.0", "architecture": "arm", "linked_libraries": []},
            ],
            "services": [{"name": "lighttpd"}],
            "evidence": [{"id": "SE-FCGI-0001", "type": "route_mapping", "description": "lighttpd routes to device_manager.fcgi"}],
        }
        (self.task / "reports" / "analysis.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        profile = {
            "service": "lighttpd",
            "binary": "/usr/sbin/lighttpd",
            "startup_source": "/etc/init.d/lighttpd",
            "config_files": ["/etc/lighttpd/lighttpd.conf"],
            "expected_ports": [3000],
            "nvram_dependencies": [],
            "config": {
                "server.port": 3000,
                "server.document-root": "/www",
                "ssl.pemfile": "/etc/ssl/private/he_device_cert_nopasswd.pem",
                "fastcgi.server": ["/services/device_manager/", "localhost", "socket", "/device_manager-", ".socket", "bin-path", "/device_manager/device_manager.fcgi", "max-procs"],
            },
        }
        (workspace.dynamic_dir / "services" / "lighttpd" / "launch_profile.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")
        runtime = {
            "success": True,
            "diagnosis": "fastcgi_integration_reachable",
            "endpoint": "/services/device_manager/",
            "application_response_reached": True,
            "backend_child": {"listener": {"host": "127.0.0.1", "port": 44171}, "alive_after_startup": True},
        }
        (workspace.dynamic_dir / "application" / "device_manager" / "integration_validation.json").write_text(json.dumps(runtime, indent=2), encoding="utf-8")
        (workspace.validation_dir / "DV-0002" / "runtime.json").write_text(json.dumps(runtime, indent=2), encoding="utf-8")
        workspace.save_hypotheses(
            [
                DynamicHypothesis(
                    "H-FCGI-0001",
                    "Specific SOAP request handling reaches device_manager.fcgi application logic",
                    "validation_inconclusive",
                    0.45,
                    evidence_ids=["SE-FCGI-0001", "DE-0001"],
                    static_status="supported",
                    dynamic_status="validation_inconclusive",
                ),
                DynamicHypothesis(
                    "H-RET2TEXT-0001",
                    "Ret2text stack overflow in main can redirect execution to secure shell function",
                    "validation_blocked",
                    0.6,
                    evidence_ids=["SE-RET2TEXT-0001"],
                    static_status="supported",
                    dynamic_status="validation_blocked",
                ),
            ]
        )
        workspace.save_evidence(
            [
                DynamicEvidence("DE-0001", "fastcgi_application_response", "FastCGI application response reached", "fastcgi", 0.9, target="H-FCGI-0001"),
                DynamicEvidence("DE-0002", "handler_reached", "Handler reached", "dynamic.run_safe_validation", 0.8, target="H-FCGI-0001"),
                DynamicEvidence("DE-0003", "validation_blocked", "process-stdin blocked", "dynamic.run_safe_validation", 0.7, target="H-RET2TEXT-0001"),
            ]
        )

    def builder(self) -> ComponentGraphBuilder:
        return ComponentGraphBuilder(self.root, self.task_id, config=self.config)

    def graph(self) -> ComponentGraph:
        self.builder().build()
        return self.builder().load_or_build_graph()

    def test_firmware_component(self):
        component = FirmwareComponent("C-BINARY-X", "binary", "x", path="/bin/x")
        self.assertEqual(component.to_dict()["component_type"], "binary")

    def test_component_relationship(self):
        relationship = ComponentRelationship("CR-1", "A", "B", "starts", evidence_ids=["E1"], confidence=0.5)
        self.assertEqual(relationship.relationship_type, "starts")

    def test_component_graph_add_get(self):
        graph = ComponentGraph()
        graph.add_component(FirmwareComponent("C-SERVICE-A", "service", "a"))
        self.assertEqual(graph.resolve_component_id("a"), "C-SERVICE-A")

    def test_path_search(self):
        paths = self.graph().find_paths("lighttpd", "application response")
        self.assertTrue(paths)

    def test_path_depth_limit(self):
        paths = self.graph().find_paths("lighttpd", "application response", max_depth=1)
        self.assertEqual(paths, [])

    def test_service_binary_relationship(self):
        relationships = self.graph().find_relationships(relationship_type="starts")
        self.assertTrue(any("lighttpd binary" in item.observation for item in relationships))

    def test_config_consumer_correlation(self):
        relationships = self.graph().find_relationships(relationship_type="reads")
        self.assertTrue(any("/etc/lighttpd/lighttpd.conf" in item.observation or item.target_component_id.endswith("lighttpd-conf") for item in relationships))

    def test_binary_exec_correlation(self):
        relationships = self.graph().find_relationships(relationship_type="spawns")
        self.assertTrue(any("FastCGI" in item.observation for item in relationships))

    def test_fastcgi_relationship(self):
        paths = self.graph().find_paths("lighttpd", "device_manager.fcgi")
        self.assertTrue(any(path.reachable for path in paths))

    def test_socket_port_relationship(self):
        relationships = self.graph().find_relationships(relationship_type="listens_on")
        self.assertTrue(any("127.0.0.1" in item.target_component_id or "TCP" in item.observation for item in relationships))

    def test_nvram_candidate_correlation(self):
        graph = self.graph()
        nvram = graph.find_components_by_type("nvram_key")
        self.assertEqual(nvram, [])

    def test_filesystem_path_filtering(self):
        graph = self.graph()
        self.assertIsNone(graph.resolve_component_id("/lib/libc.so.0"))

    def test_evidence_correlation(self):
        graph = self.graph()
        self.assertTrue(graph.evidence_correlations)

    def test_static_dynamic_correlation(self):
        correlations = self.graph().evidence_correlations.values()
        self.assertTrue(any(item.correlation_type == "static_dynamic_match" for item in correlations))

    def test_confidence_promotion(self):
        graph = self.graph()
        routes = graph.find_relationships(relationship_type="routes_to")
        self.assertTrue(any(item.status == "supported" and item.confidence > 0.78 for item in routes))

    def test_confidence_cap(self):
        relationship = ComponentRelationship("CR-X", "A", "B", "reads", confidence=0.99)
        relationship.promote(1.5, ["E2"], status="confirmed")
        self.assertEqual(relationship.confidence, 1.0)

    def test_contradiction_semantics(self):
        relationship = ComponentRelationship("CR-X", "A", "B", "connects_to", status="contradicted")
        self.assertEqual(relationship.status, "contradicted")

    def test_missing_observation_not_contradiction(self):
        relationships = self.graph().find_relationships(relationship_type="connects_to")
        self.assertTrue(all(item.status != "contradicted" for item in relationships))

    def test_cross_component_context(self):
        context = self.builder().cross_component_context("H-FCGI-0001")
        self.assertIn("DE-0001", context.dynamic_evidence_ids)

    def test_component_path(self):
        path = self.graph().find_paths("lighttpd", "application response")[0]
        self.assertTrue(path.to_dict()["relationship_ids"])

    def test_context_slicing(self):
        context = self.builder().cross_component_context("H-FCGI-0001", max_nodes=5)
        self.assertLessEqual(len(context.related_components), 5)

    def test_noise_filtering(self):
        summary = self.builder().build()["summary"]
        self.assertLess(summary["component_counts"].get("library", 0), 5)

    def test_prioritization_feasibility_integration(self):
        self.builder().build()
        state = HypothesisValidationScheduler(self.root, self.task_id, config=self.config).assess()
        fcgi = next(item for item in state["assessments"] if item["hypothesis_id"] == "H-FCGI-0001")
        self.assertGreater(fcgi["runtime_path_readiness"], 0.8)

    def test_cost_integration(self):
        self.builder().build()
        state = HypothesisValidationScheduler(self.root, self.task_id, config=self.config).assess()
        fcgi = next(item for item in state["assessments"] if item["hypothesis_id"] == "H-FCGI-0001")
        self.assertGreaterEqual(fcgi["cross_component_complexity"], 1)

    def test_dependency_integration(self):
        context = self.builder().security_context_for_hypothesis("H-FCGI-0001")
        self.assertGreaterEqual(context.dependency_chain_length, 1)

    def test_graph_persistence(self):
        self.builder().build()
        self.assertTrue((self.task / "correlation" / "component_graph.json").exists())

    def test_incremental_update(self):
        self.builder().build()
        evidence = DynamicEvidence("DE-9999", "application_response", "real response", "runtime", 0.9, target="H-FCGI-0001")
        result = self.builder().incremental_update_from_dynamic_evidence(evidence)
        self.assertTrue(result["success"])

    def test_mock_state_isolation(self):
        workspace = DynamicWorkspace(self.root, self.task_id)
        before = [item.to_dict() for item in workspace.load_hypotheses()]
        HypothesisValidationScheduler(self.root, self.task_id, config=self.config).execute_next_mock(verdict_status="dynamically_rejected")
        after = [item.to_dict() for item in workspace.load_hypotheses()]
        self.assertEqual(before, after)

    def test_mock_verdict_cannot_mutate_canonical_hypothesis(self):
        state = HypothesisValidationScheduler(self.root, self.task_id, config=self.config).execute_next_mock(verdict_status="dynamically_rejected")
        self.assertFalse(state["executed"]["canonical_update_allowed"])

    def test_mock_evidence_provenance(self):
        HypothesisValidationScheduler(self.root, self.task_id, config=self.config).execute_next_mock()
        evidence = DynamicWorkspace(self.root, self.task_id).load_prioritization_artifact("simulation_evidence.json")
        self.assertEqual(evidence[-1]["provenance"], "mock_agent")

    def test_real_runtime_evidence_allowed_canonical_correlation(self):
        self.assertTrue(CanonicalStateGuard.can_update_canonical(execution_mode="real", runtime_observation_real=True))

    def test_provider_backed_false_preserved(self):
        self.assertFalse(self.builder().build()["provider_backed"])

    def test_cli_graph_build(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["graph-build", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("provider_backed=false", output.getvalue())

    def test_cli_graph_summary(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["graph-summary", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("Components:", output.getvalue())

    def test_cli_graph_path(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["graph-path", self.task_id, "lighttpd", "application response", "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("Evidence:", output.getvalue())

    def test_forbidden_graph_mutation_tool_not_registered(self):
        tools = DynamicToolAPI(self.root, self.task_id, config=self.config).tools
        self.assertIn("graph.get_cross_component_context", tools)
        self.assertNotIn("graph.add_relationship", tools)

    def test_parser_commands(self):
        commands = build_parser()._subparsers._group_actions[0].choices
        for name in ("graph-build", "graph-summary", "component", "graph-path", "correlation-context"):
            self.assertIn(name, commands)


if __name__ == "__main__":
    unittest.main()
