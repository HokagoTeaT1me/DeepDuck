from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwagent.cli import build_parser, main
from fwagent.dynamic.api import DynamicToolAPI
from fwagent.dynamic.config import DynamicConfig, load_dynamic_config
from fwagent.dynamic.correlation import ComponentGraphBuilder
from fwagent.dynamic.models import DYNAMIC_EVIDENCE_TYPES, DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.taint import (
    PATH_STATES,
    SANITIZER_TYPES,
    SINK_TYPES,
    SOURCE_TYPES,
    TAINT_EDGE_TYPES,
    TAINT_STATES,
    TRANSFORM_TYPES,
    DataTransformation,
    InputSourceDescriptor,
    SanitizerDescriptor,
    SensitiveSink,
    SensitiveSinkRegistry,
    StaticDataFlowBridge,
    TaintAnalysisBuilder,
    TaintEdge,
    TaintFact,
    TaintGraph,
    TaintPath,
)
from fwagent.dynamic.workspace import DynamicWorkspace


class Round44Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.task_id = "round44-fixture"
        self.task = self.root / self.task_id
        for name in ("reports", "hypotheses", "evidence"):
            (self.task / name).mkdir(parents=True, exist_ok=True)
        self.workspace = DynamicWorkspace(self.root, self.task_id)
        (self.workspace.dynamic_dir / "services" / "lighttpd").mkdir(parents=True, exist_ok=True)
        (self.workspace.dynamic_dir / "application" / "device_manager").mkdir(parents=True, exist_ok=True)
        (self.workspace.validation_dir / "DV-0002").mkdir(parents=True, exist_ok=True)
        self._write_fixture()
        self.config = DynamicConfig(backend="service-qemu")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fixture(self) -> None:
        report = {
            "binaries": [
                {"path": "/usr/sbin/lighttpd", "architecture": "arm", "linked_libraries": ["libssl.so.1.0.0"], "dangerous_symbols": []},
                {
                    "path": "/www/services/device_manager/device_manager.fcgi",
                    "architecture": "arm",
                    "linked_libraries": ["libnvram.so", "libshared.so"],
                    "dangerous_symbols": ["system", "popen", "strcpy", "sprintf", "memcpy", "open", "write", "nvram_set"],
                },
                {"path": "ret2text", "architecture": "x86", "linked_libraries": [], "dangerous_symbols": ["gets", "system"]},
            ],
            "services": [{"name": "lighttpd"}],
            "evidence": [
                {"id": "SE-FCGI-0001", "type": "route_mapping", "description": "lighttpd routes to device_manager.fcgi", "confidence": 0.8},
                {"id": "SE-FCGI-0002", "type": "decompile", "function": "soap_dispatch", "description": "SOAP action dispatch exists", "confidence": 0.7},
                {"id": "SE-RET2TEXT-0001", "type": "dangerous_call", "function": "main", "description": "Static analysis found gets() in main.", "confidence": 0.82},
                {"id": "SE-RET2TEXT-0002", "type": "security_relevant_function", "function": "secure", "description": "secure contains system shell function", "confidence": 0.75},
            ],
        }
        (self.task / "reports" / "analysis.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        profile = {
            "service": "lighttpd",
            "binary": "/usr/sbin/lighttpd",
            "startup_source": "/etc/init.d/lighttpd",
            "config_files": ["/etc/lighttpd/lighttpd.conf"],
            "expected_ports": [3000],
            "config": {
                "server.port": 3000,
                "server.document-root": "/www",
                "ssl.pemfile": "/etc/ssl/private/he_device_cert_nopasswd.pem",
                "fastcgi.server": ["/services/device_manager/", "localhost", "socket", "/device_manager-", ".socket", "bin-path", "/device_manager/device_manager.fcgi", "max-procs"],
            },
        }
        (self.workspace.dynamic_dir / "services" / "lighttpd" / "launch_profile.json").write_text(json.dumps(profile, indent=2), encoding="utf-8")
        runtime = {
            "success": True,
            "diagnosis": "fastcgi_integration_reachable",
            "endpoint": "/services/device_manager/",
            "application_response_reached": True,
            "backend_child": {"listener": {"host": "127.0.0.1", "port": 44171}, "alive_after_startup": True},
        }
        (self.workspace.dynamic_dir / "application" / "device_manager" / "integration_validation.json").write_text(json.dumps(runtime, indent=2), encoding="utf-8")
        (self.workspace.validation_dir / "DV-0002" / "runtime.json").write_text(json.dumps(runtime, indent=2), encoding="utf-8")
        self.workspace.save_hypotheses(
            [
                DynamicHypothesis(
                    "H-FCGI-0001",
                    "Specific SOAP request handling reaches device_manager.fcgi application logic",
                    "validation_inconclusive",
                    0.45,
                    evidence_ids=["SE-FCGI-0001", "SE-FCGI-0002", "DE-0001"],
                    static_status="supported",
                    dynamic_status="validation_inconclusive",
                ),
                DynamicHypothesis(
                    "H-RET2TEXT-0001",
                    "Ret2text stack overflow in main can redirect execution to secure shell function",
                    "validation_blocked",
                    0.6,
                    evidence_ids=["SE-RET2TEXT-0001", "SE-RET2TEXT-0002"],
                    static_status="supported",
                    dynamic_status="validation_blocked",
                ),
            ]
        )
        self.workspace.save_evidence(
            [
                DynamicEvidence("DE-0001", "fastcgi_application_response", "FastCGI application response reached", "fastcgi", 0.9, target="H-FCGI-0001"),
                DynamicEvidence("DE-0002", "handler_reached", "Handler reached", "dynamic.run_safe_validation", 0.8, target="H-FCGI-0001"),
                DynamicEvidence("DE-0003", "validation_blocked", "process-stdin blocked", "dynamic.run_safe_validation", 0.7, target="H-RET2TEXT-0001"),
            ]
        )

    def builder(self) -> TaintAnalysisBuilder:
        ComponentGraphBuilder(self.root, self.task_id, config=self.config).build()
        return TaintAnalysisBuilder(self.root, self.task_id, config=self.config)

    def taint(self) -> dict:
        return self.builder().build()

    def test_input_source_descriptor(self):
        source = InputSourceDescriptor("SRC", "http_body", confidence=1.5)
        self.assertEqual(source.confidence, 1.0)

    def test_sensitive_sink(self):
        sink = SensitiveSink("SINK", "command_execution", callee_name="system", security_relevance=1.4)
        self.assertEqual(sink.security_relevance, 1.0)

    def test_sink_registry(self):
        registry = SensitiveSinkRegistry()
        self.assertEqual(registry.sink_type_for("system"), "command_execution")
        self.assertEqual(registry.sink_type_for("execve"), "process_execution")

    def test_symbol_normalization(self):
        registry = SensitiveSinkRegistry()
        self.assertEqual(registry.normalize_symbol("system@plt"), "system")
        self.assertEqual(registry.normalize_symbol("__GI_memcpy"), "memcpy")

    def test_wrapper_sink_resolution(self):
        candidate = SensitiveSinkRegistry().resolve_wrapper_candidate("FUN_1234", "void FUN_1234(char *x){ system(x); }")
        self.assertIsNotNone(candidate)
        self.assertIn("system", candidate.reason)

    def test_sanitizer_descriptor(self):
        sanitizer = SanitizerDescriptor("SAN", "length_check", effectiveness="unknown_effectiveness")
        self.assertEqual(sanitizer.transform_type, "length_check")

    def test_data_transformation(self):
        transform = DataTransformation("TR", "format", source_value="input", destination_value="cmd")
        self.assertEqual(transform.transform_type, "format")

    def test_taint_fact(self):
        fact = TaintFact("TF", taint_state="source")
        self.assertEqual(fact.taint_state, "source")

    def test_taint_graph(self):
        graph = TaintGraph()
        graph.add_node("A", "source", "input")
        graph.add_node("B", "sink", "system")
        graph.add_edge(TaintEdge("E", "A", "B", "flows_to"))
        self.assertEqual(len(graph.to_dict()["edges"]), 1)

    def test_taint_path(self):
        path = TaintPath("TP", "SRC", "SINK", [], ["main"], [], [], [], [], 0.5, "candidate", False, False)
        self.assertEqual(path.path_state, "candidate")

    def test_source_type_catalog(self):
        for source_type in ("http_parameter", "http_header", "http_body", "soap_action", "cgi_parameter", "fastcgi_parameter", "tcp_stream", "udp_datagram", "stdin", "file_input", "ipc_message", "environment", "config_input", "device_input", "unknown"):
            self.assertIn(source_type, SOURCE_TYPES)

    def test_sink_type_catalog(self):
        for sink_type in ("command_execution", "process_execution", "unsafe_copy", "formatted_output", "memory_copy", "file_write", "file_open", "path_operation", "authentication_decision", "authorization_decision", "nvram_write", "network_connect", "dynamic_load", "deserialization", "memory_allocation", "unknown"):
            self.assertIn(sink_type, SINK_TYPES)

    def test_state_catalogs(self):
        self.assertIn("source", TAINT_STATES)
        self.assertIn("format", TRANSFORM_TYPES)
        self.assertIn("length_check", SANITIZER_TYPES)
        self.assertIn("runtime_correlated", TAINT_EDGE_TYPES)
        self.assertIn("candidate", PATH_STATES)

    def test_source_discovery_from_entrypoint(self):
        sources = self.taint()["sources"]
        self.assertTrue(any(item["source_id"] == "SRC-FCGI-SOAP-ACTION" for item in sources))

    def test_http_source(self):
        source = next(item for item in self.taint()["sources"] if item["source_id"] == "SRC-FCGI-HTTP-BODY")
        self.assertEqual(source["source_type"], "http_body")

    def test_fastcgi_source(self):
        source = next(item for item in self.taint()["sources"] if item["source_id"] == "SRC-FCGI-REQUEST-URI")
        self.assertEqual(source["source_type"], "fastcgi_parameter")

    def test_stdin_source(self):
        source = next(item for item in self.taint()["sources"] if item["source_id"] == "SRC-RET2TEXT-STDIN")
        self.assertEqual(source["source_type"], "stdin")

    def test_sink_catalog_from_report(self):
        sinks = self.taint()["sinks"]
        self.assertTrue(any(item["sink_id"].startswith("SINK-FCGI") and item["callee_name"] == "system" for item in sinks))

    def test_direct_same_function_flow(self):
        evidence = StaticDataFlowBridge(self.config).analyze_same_function_flow(
            source_id="SRC",
            sink_id="SINK",
            function_name="main",
            source_variable="input",
            sink_name="strcpy",
            decompile_text="void main(char *input){ strcpy(buf, input); }",
        )
        self.assertIsNotNone(evidence)
        self.assertEqual(evidence.evidence_level, "L3_argument_propagation")

    def test_argument_propagation(self):
        mapped = StaticDataFlowBridge(self.config).map_argument("handler(user_input);", "handler", "user_input")
        self.assertTrue(mapped["mapped"])

    def test_return_propagation(self):
        transforms = StaticDataFlowBridge(self.config).return_value_propagation("x = parse(input); system(x);", "input")
        self.assertEqual(transforms[0].destination_value, "x")

    def test_local_copy_propagation(self):
        aliases = StaticDataFlowBridge(self.config).local_aliases("cmd = input; system(cmd);", "input")
        self.assertIn("cmd", aliases)

    def test_formatting_propagation(self):
        transforms = StaticDataFlowBridge(self.config).formatting_propagation('sprintf(cmd, "x%s", input); system(cmd);', "input")
        self.assertEqual(transforms[0].transform_type, "format")

    def test_call_chain_not_taint_flow_guard(self):
        chain = StaticDataFlowBridge(self.config).bounded_call_chain([{"caller": "a", "callee": "b"}], "a", "b", 2)
        self.assertEqual(chain, ["a", "b"])
        self.assertIsNone(StaticDataFlowBridge(self.config).analyze_same_function_flow(source_id="S", sink_id="K", function_name="a", source_variable="x", sink_name="b", decompile_text="b(y);"))

    def test_source_sink_not_vulnerability_guard(self):
        notes = self.taint()["summary"]["safety_notes"]
        self.assertIn("SOURCE + SINK != VULNERABILITY", notes)

    def test_sanitizer_detection(self):
        sanitizers = StaticDataFlowBridge(self.config).detect_sanitizers("if (strlen(input) < 32) { strcpy(buf,input); }", "main", "input")
        self.assertEqual(sanitizers[0].effectiveness, "unknown_effectiveness")

    def test_strlen_alone_not_sanitizer(self):
        sanitizers = StaticDataFlowBridge(self.config).detect_sanitizers("n = strlen(input); strcpy(buf,input);", "main", "input")
        self.assertEqual(sanitizers, [])

    def test_bounded_interprocedural_depth(self):
        chain = StaticDataFlowBridge(self.config).bounded_call_chain([{"caller": "a", "callee": "b"}, {"caller": "b", "callee": "c"}], "a", "c", 1)
        self.assertEqual(chain, [])

    def test_sink_confidence(self):
        sink = next(item for item in self.taint()["sinks"] if item["sink_id"] == "SINK-RET2TEXT-main-gets")
        self.assertGreater(sink["confidence"], 0.8)

    def test_path_confidence(self):
        path = next(item for item in self.taint()["taint_paths"] if item["path_id"] == "TP-RET2TEXT-STDIN-GETS")
        self.assertGreater(path["confidence"], 0.75)

    def test_confidence_penalty_candidate(self):
        path = next(item for item in self.taint()["taint_paths"] if item["path_state"] == "candidate")
        self.assertLess(path["confidence"], 0.7)

    def test_static_runtime_separation(self):
        path = next(item for item in self.taint()["taint_paths"] if item["path_id"] == "TP-RET2TEXT-STDIN-GETS")
        self.assertFalse(path["runtime_supported"])
        self.assertFalse(path["runtime_sink_confirmed"])

    def test_runtime_handler_confirmation(self):
        source = next(item for item in self.taint()["sources"] if item["source_id"] == "SRC-FCGI-SOAP-ACTION")
        self.assertTrue(source["runtime_confirmed"])

    def test_sink_runtime_not_falsely_confirmed(self):
        paths = [item for item in self.taint()["taint_paths"] if "H-FCGI-0001" in item["hypothesis_ids"]]
        self.assertTrue(paths)
        self.assertTrue(all(not item["runtime_sink_confirmed"] for item in paths))

    def test_source_sink_hypothesis_link(self):
        link = next(item for item in self.taint()["hypothesis_links"] if item["hypothesis_id"] == "H-FCGI-0001")
        self.assertEqual(link["relationship"], "candidate_source_sink_context")

    def test_prioritization_integration(self):
        self.taint()
        state = self.priority()
        fcgi = next(item for item in state["assessments"] if item["hypothesis_id"] == "H-FCGI-0001")
        self.assertGreater(fcgi["taint_path_confidence"], 0.0)

    def priority(self) -> dict:
        return __import__("fwagent.dynamic.prioritization", fromlist=["HypothesisValidationScheduler"]).HypothesisValidationScheduler(self.root, self.task_id, config=self.config).assess()

    def test_cost_integration(self):
        self.taint()
        fcgi = next(item for item in self.priority()["assessments"] if item["hypothesis_id"] == "H-FCGI-0001")
        self.assertGreaterEqual(fcgi["validation_cost_score"], 0.0)

    def test_information_gain_integration(self):
        self.taint()
        fcgi = next(item for item in self.priority()["assessments"] if item["hypothesis_id"] == "H-FCGI-0001")
        self.assertGreater(fcgi["expected_information_gain"], 0.5)

    def test_cross_component_runtime_flow(self):
        graph = self.taint()["taint_graph"]
        self.assertTrue(any(edge["edge_type"] == "runtime_correlated" for edge in graph["edges"]))

    def test_non_input_relationship_cannot_propagate(self):
        fcgi_paths = [item for item in self.taint()["taint_paths"] if "H-FCGI-0001" in item["hypothesis_ids"]]
        self.assertTrue(all(item["evidence_level"] == "L1_same_component" for item in fcgi_paths))

    def test_mock_state_isolation(self):
        before = [item.to_dict() for item in self.workspace.load_hypotheses()]
        result = self.builder().mock_add_taint_path("mock-flow")
        after = [item.to_dict() for item in self.workspace.load_hypotheses()]
        self.assertFalse(result["canonical_update_allowed"])
        self.assertEqual(before, after)

    def test_mock_path_cannot_update_canonical_hypothesis(self):
        evidence = DynamicEvidence("MDE-TAINT", "taint_path_supported", "mock path", "taint.mock", 0.9, provenance="mock_agent", execution_mode="mock", runtime_observation_real=False)
        result = self.builder().incremental_update_from_dynamic_evidence(evidence)
        self.assertFalse(result["canonical_update_allowed"])

    def test_provenance(self):
        source = next(item for item in self.taint()["sources"] if item["source_id"] == "SRC-FCGI-SOAP-ACTION")
        self.assertEqual(source["provenance"], "real_runtime_observation")
        self.assertFalse(source["provider_backed"])

    def test_real_runtime_evidence_accepted(self):
        evidence = DynamicEvidence("DE-REAL", "taint_runtime_correlated", "real", "taint", 0.8)
        result = self.builder().incremental_update_from_dynamic_evidence(evidence)
        self.assertTrue(result["canonical_update_allowed"])

    def test_ret2text_gets_source_sink_sanity(self):
        paths = self.taint()["taint_paths"]
        self.assertTrue(any(item["source_id"] == "SRC-RET2TEXT-STDIN" and item["sink_id"] == "SINK-RET2TEXT-main-gets" for item in paths))

    def test_ret2text_does_not_auto_link_to_system(self):
        paths = self.taint()["taint_paths"]
        self.assertFalse(any(item["source_id"] == "SRC-RET2TEXT-STDIN" and item["sink_id"] == "SINK-RET2TEXT-secure-system" for item in paths))

    def test_cli_taint_build(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["taint-build", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("Taint Analysis Summary", output.getvalue())

    def test_cli_taint_summary(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["taint-summary", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("SOURCE + SINK != VULNERABILITY", output.getvalue())

    def test_cli_hypothesis_context(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["taint-hypothesis", self.task_id, "H-FCGI-0001", "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("candidate_or_unknown", output.getvalue())

    def test_cli_taint_path(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["taint-path", self.task_id, "TP-RET2TEXT-STDIN-GETS", "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("Validated means data-flow evidence validation", output.getvalue())

    def test_forbidden_mutation_payload_tools_absent(self):
        tools = DynamicToolAPI(self.root, self.task_id, config=self.config).tools
        for forbidden in ("taint.mark_vulnerable", "taint.force_flow", "taint.add_sink", "taint.execute_sink", "taint.generate_payload"):
            self.assertNotIn(forbidden, tools)

    def test_api_taint_tools(self):
        tools = DynamicToolAPI(self.root, self.task_id, config=self.config).tools
        for name in ("taint.list_sources", "taint.list_sinks", "taint.find_paths", "taint.get_hypothesis_context", "taint.get_summary"):
            self.assertIn(name, tools)

    def test_api_taint_summary(self):
        result = DynamicToolAPI(self.root, self.task_id, config=self.config).execute("taint.get_summary", {})
        self.assertTrue(result["success"])
        self.assertGreater(result["result"]["summary"]["sources"], 0)

    def test_api_taint_source_sink_path(self):
        api = DynamicToolAPI(self.root, self.task_id, config=self.config)
        self.assertTrue(api.execute("taint.get_source", {"source_id": "SRC-RET2TEXT-STDIN"})["success"])
        self.assertTrue(api.execute("taint.get_sink", {"sink_id": "SINK-RET2TEXT-main-gets"})["success"])
        self.assertTrue(api.execute("taint.get_path", {"path_id": "TP-RET2TEXT-STDIN-GETS"})["success"])

    def test_parser_commands(self):
        commands = build_parser()._subparsers._group_actions[0].choices
        for command in ("taint-build", "taint-summary", "taint-sources", "taint-sinks", "taint-paths", "taint-hypothesis", "taint-path"):
            self.assertIn(command, commands)

    def test_round44_evidence_types_registered(self):
        for evidence_type in ("taint_source_discovered", "sensitive_sink_discovered", "taint_path_candidate", "taint_path_supported", "taint_runtime_correlated", "taint_validation_blocked", "taint_validation_inconclusive"):
            self.assertIn(evidence_type, DYNAMIC_EVIDENCE_TYPES)

    def test_taint_workspace_artifacts(self):
        self.taint()
        for name in ("sources.json", "sinks.json", "sink_catalog.json", "taint_facts.json", "taint_graph.json", "taint_paths.json", "sanitizers.json", "hypothesis_links.json", "summary.json"):
            self.assertTrue((self.task / "taint" / name).exists())

    def test_config_taint_yaml(self):
        config_path = self.root / "dynamic.yaml"
        config_path.write_text("dynamic:\n  taint:\n    max_call_depth: 2\n    confidence:\n      same_function: 0.7\n", encoding="utf-8")
        config = load_dynamic_config(config_path)
        self.assertEqual(config.taint.max_call_depth, 2)
        self.assertEqual(config.taint.confidence.same_function, 0.7)


if __name__ == "__main__":
    unittest.main()
