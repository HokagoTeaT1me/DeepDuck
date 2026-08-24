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
from fwagent.dynamic.correlation import ComponentGraphBuilder, ComponentPath, RELATIONSHIP_TYPES
from fwagent.dynamic.models import DYNAMIC_EVIDENCE_TYPES, DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.prioritization import HypothesisValidationScheduler
from fwagent.dynamic.surface import (
    ENTRY_POINT_TYPES,
    ENTRY_SOURCES,
    EXPOSURE_SCOPES,
    AttackSurfaceBuilder,
    EntryPoint,
)
from fwagent.dynamic.workspace import DynamicWorkspace


class Round43Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.task_id = "round43-fixture"
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
                {"path": "/usr/sbin/lighttpd", "architecture": "arm", "linked_libraries": ["libssl.so.1.0.0", "libcrypto.so.1.0.0", "libc.so.0"]},
                {"path": "/www/services/device_manager/device_manager.fcgi", "architecture": "arm", "linked_libraries": ["libnvram.so", "libshared.so"]},
                {"path": "ret2text", "architecture": "x86", "linked_libraries": []},
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
                DynamicHypothesis(
                    "H-UNKNOWN-0001",
                    "Unmapped opaque parser hypothesis",
                    "candidate",
                    0.3,
                    evidence_ids=["SE-UNKNOWN-0001"],
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

    def builder(self) -> AttackSurfaceBuilder:
        ComponentGraphBuilder(self.root, self.task_id, config=self.config).build()
        return AttackSurfaceBuilder(self.root, self.task_id, config=self.config)

    def surface(self) -> dict:
        return self.builder().build()

    def entry(self, entry_id: str) -> dict:
        return next(item for item in self.surface()["entry_points"] if item["entry_id"] == entry_id)

    def mapping(self, hypothesis_id: str) -> dict:
        return next(item for item in self.surface()["hypothesis_reachability"] if item["hypothesis_id"] == hypothesis_id)

    def test_entry_type_catalog(self):
        for entry_type in ("http_route", "https_route", "cgi", "fastcgi", "tcp_service", "udp_service", "unix_socket", "local_ipc", "service_port", "web_resource", "protocol_handler", "stdin", "file_input", "device_input"):
            self.assertIn(entry_type, ENTRY_POINT_TYPES)

    def test_exposure_scope_catalog(self):
        for scope in ("external_network", "local_network", "loopback", "local_process", "filesystem", "device", "unknown"):
            self.assertIn(scope, EXPOSURE_SCOPES)

    def test_entry_source_catalog(self):
        for source in ("config_declared", "static_reference", "init_script", "runtime_listener", "runtime_http", "runtime_fastcgi", "runtime_process", "manual_seed", "inferred"):
            self.assertIn(source, ENTRY_SOURCES)

    def test_entry_point_validation(self):
        with self.assertRaises(ValueError):
            EntryPoint("EP-X", "exploit", "bad")

    def test_config_attack_surface_defaults(self):
        config = DynamicConfig()
        self.assertTrue(config.attack_surface.enabled)
        self.assertIn("routes_to", config.attack_surface.reachability.propagate_relationships)

    def test_yaml_attack_surface_config(self):
        config_path = self.root / "dynamic.yaml"
        config_path.write_text(
            "dynamic:\n  attack_surface:\n    reachability:\n      propagate_relationships: routes_to,handles\n",
            encoding="utf-8",
        )
        config = load_dynamic_config(config_path)
        self.assertEqual(config.attack_surface.reachability.propagate_relationships, ("routes_to", "handles"))

    def test_workspace_surface_directory(self):
        self.assertTrue(self.workspace.surface_dir.exists())

    def test_build_success_provider_false(self):
        result = self.surface()
        self.assertTrue(result["success"])
        self.assertFalse(result["provider_backed"])

    def test_surface_artifacts_persisted(self):
        self.surface()
        for name in ("entry_points.json", "routes.json", "reachability.json", "hypothesis_reachability.json", "attack_surface_summary.json", "entry_contexts.json"):
            self.assertTrue((self.task / "surface" / name).exists())

    def test_summary_counts(self):
        summary = self.surface()["summary"]
        self.assertEqual(summary["total_entries"], 5)
        self.assertEqual(summary["route_entries"], 1)
        self.assertEqual(summary["service_entries"], 1)

    def test_summary_safety_notes(self):
        notes = self.surface()["summary"]["safety_notes"]
        self.assertIn("EXPOSED != VULNERABLE", notes)
        self.assertIn("HTTP 500 != VULNERABILITY", notes)

    def test_https_fastcgi_entry_fields(self):
        entry = self.entry("EP-HTTPS-lighttpd-device-manager")
        self.assertEqual(entry["entry_type"], "https_route")
        self.assertEqual(entry["protocol"], "https")
        self.assertEqual(entry["port"], 3000)
        self.assertEqual(entry["path"], "/services/device_manager/")

    def test_https_entry_runtime_confirmed(self):
        entry = self.entry("EP-HTTPS-lighttpd-device-manager")
        self.assertTrue(entry["runtime_confirmed"])
        self.assertEqual(entry["source"], "runtime_fastcgi")

    def test_unknown_methods_not_guessed(self):
        entry = self.entry("EP-HTTPS-lighttpd-device-manager")
        route = self.surface()["routes"][0]
        self.assertIsNone(entry["method"])
        self.assertEqual(route["methods"], ["unknown"])

    def test_fastcgi_evidence_ids(self):
        evidence_ids = set(self.entry("EP-HTTPS-lighttpd-device-manager")["evidence_ids"])
        self.assertIn("ART:lighttpd-launch-profile", evidence_ids)
        self.assertIn("DE-0001", evidence_ids)

    def test_fastcgi_relationship_ids(self):
        self.assertTrue(self.entry("EP-HTTPS-lighttpd-device-manager")["relationship_ids"])

    def test_service_port_entry_not_runtime_bug(self):
        entry = self.entry("EP-SERVICE-lighttpd-3000")
        self.assertEqual(entry["entry_type"], "service_port")
        self.assertFalse(entry["runtime_confirmed"])
        self.assertEqual(entry["exposure_scope"], "local_network")

    def test_loopback_entry_scope(self):
        entry = self.entry("EP-LOOPBACK-FCGI-44171")
        self.assertEqual(entry["exposure_scope"], "loopback")
        self.assertTrue(entry["runtime_confirmed"])

    def test_unix_socket_entry_scope(self):
        entry = self.entry("EP-UNIX-device-manager-socket")
        self.assertEqual(entry["entry_type"], "unix_socket")
        self.assertEqual(entry["exposure_scope"], "local_process")

    def test_stdin_entry_scope(self):
        entry = self.entry("EP-STDIN-ret2text")
        self.assertEqual(entry["entry_type"], "stdin")
        self.assertEqual(entry["exposure_scope"], "local_process")

    def test_https_reachability_runtime_confirmed(self):
        reachability = next(item for item in self.surface()["reachability"] if item["entry_point_id"] == "EP-HTTPS-lighttpd-device-manager")
        self.assertEqual(reachability["state"], "runtime_confirmed")
        self.assertTrue(reachability["runtime_confirmed"])

    def test_https_reachable_components_include_chain(self):
        result = self.surface()
        reachability = next(item for item in result["reachability"] if item["entry_point_id"] == "EP-HTTPS-lighttpd-device-manager")
        components = {component["name"] for context in result["entry_contexts"] if context["entry_point"]["entry_id"] == "EP-HTTPS-lighttpd-device-manager" for component in context["reachable_components"]}
        self.assertTrue({"lighttpd", "device_manager.fcgi", "application response"}.issubset(components))
        self.assertTrue(reachability["component_path_ids"])

    def test_hypothesis_fcgi_reachability(self):
        mapping = self.mapping("H-FCGI-0001")
        self.assertEqual(mapping["state"], "runtime_confirmed")
        self.assertTrue(mapping["network_exposed"])
        self.assertIn("EP-HTTPS-lighttpd-device-manager", mapping["entry_point_ids"])

    def test_hypothesis_fcgi_score(self):
        mapping = self.mapping("H-FCGI-0001")
        self.assertTrue(mapping["runtime_confirmed"])
        self.assertGreaterEqual(mapping["entry_reachability_score"], 0.95)

    def test_hypothesis_ret2text_reachability(self):
        mapping = self.mapping("H-RET2TEXT-0001")
        self.assertEqual(mapping["state"], "blocked")
        self.assertFalse(mapping["network_exposed"])
        self.assertIn("local_process", mapping["exposure_scopes"])

    def test_hypothesis_unknown_not_marked_unreachable(self):
        mapping = self.mapping("H-UNKNOWN-0001")
        self.assertEqual(mapping["state"], "no_known_entry")
        self.assertFalse(mapping["reachable"])

    def test_entry_priority_ranking(self):
        ranking = self.surface()["summary"]["entry_priority_ranking"]
        self.assertEqual(ranking[0]["entry_point_id"], "EP-HTTPS-lighttpd-device-manager")

    def test_api_surface_tools(self):
        tools = DynamicToolAPI(self.root, self.task_id, config=self.config).tools
        self.assertIn("surface.list_entry_points", tools)
        self.assertNotIn("surface.add_entry", tools)

    def test_api_surface_summary(self):
        result = DynamicToolAPI(self.root, self.task_id, config=self.config).execute("surface.get_attack_surface_summary", {})
        self.assertTrue(result["success"])
        self.assertEqual(result["result"]["summary"]["route_entries"], 1)

    def test_api_get_entry_point(self):
        result = DynamicToolAPI(self.root, self.task_id, config=self.config).execute("surface.get_entry_point", {"entry_id": "EP-HTTPS-lighttpd-device-manager"})
        self.assertEqual(result["result"]["entry_point"]["port"], 3000)

    def test_api_get_reachability(self):
        result = DynamicToolAPI(self.root, self.task_id, config=self.config).execute("surface.get_reachability", {"entry_id": "EP-HTTPS-lighttpd-device-manager"})
        self.assertEqual(result["result"]["reachability"][0]["state"], "runtime_confirmed")

    def test_api_get_hypothesis_entries(self):
        result = DynamicToolAPI(self.root, self.task_id, config=self.config).execute("surface.get_hypothesis_entries", {"hypothesis_id": "H-FCGI-0001"})
        self.assertTrue(result["result"]["hypothesis_reachability"][0]["runtime_confirmed"])

    def test_api_runtime_confirmed_entries(self):
        result = DynamicToolAPI(self.root, self.task_id, config=self.config).execute("surface.get_runtime_confirmed_entries", {})
        ids = {item["entry_id"] for item in result["result"]["entry_points"]}
        self.assertIn("EP-HTTPS-lighttpd-device-manager", ids)

    def test_cli_parser_commands(self):
        commands = build_parser()._subparsers._group_actions[0].choices
        for command in ("surface-build", "surface-summary", "surface-list", "surface-entry", "reachable-from", "hypothesis-entry"):
            self.assertIn(command, commands)

    def test_cli_surface_build(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["surface-build", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("Attack Surface Summary", output.getvalue())

    def test_cli_surface_summary(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["surface-summary", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("LISTENING PORT != SECURITY BUG", output.getvalue())

    def test_cli_surface_list(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["surface-list", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("EP-HTTPS-lighttpd-device-manager", output.getvalue())

    def test_cli_surface_entry(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["surface-entry", self.task_id, "EP-HTTPS-lighttpd-device-manager", "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("REACHABLE != EXPLOITABLE", output.getvalue())

    def test_cli_reachable_from(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["reachable-from", self.task_id, "EP-HTTPS-lighttpd-device-manager", "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("runtime_confirmed", output.getvalue())

    def test_cli_hypothesis_entry(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["hypothesis-entry", self.task_id, "H-FCGI-0001", "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("EP-HTTPS-lighttpd-device-manager", output.getvalue())

    def test_prioritization_entry_fields(self):
        self.surface()
        state = HypothesisValidationScheduler(self.root, self.task_id, config=self.config).assess()
        fcgi = next(item for item in state["assessments"] if item["hypothesis_id"] == "H-FCGI-0001")
        self.assertTrue(fcgi["runtime_entry_confirmation"])
        self.assertGreaterEqual(fcgi["entry_reachability_score"], 0.95)

    def test_ret2text_prioritization_local_blocker(self):
        self.surface()
        state = HypothesisValidationScheduler(self.root, self.task_id, config=self.config).assess()
        ret = next(item for item in state["assessments"] if item["hypothesis_id"] == "H-RET2TEXT-0001")
        self.assertFalse(ret["runtime_entry_confirmation"])
        self.assertTrue(any("stdin" in reason or "local" in reason for reason in ret["blocking_reasons"]))

    def test_mock_surface_state_isolation(self):
        before = self.surface()["entry_points"]
        result = self.builder().mock_discover_entry("mock-public-admin")
        after = self.builder().load_or_build()["entry_points"]
        self.assertFalse(result["canonical_update_allowed"])
        self.assertEqual(before, after)

    def test_incremental_mock_update_rejected(self):
        evidence = DynamicEvidence("MDE-0001", "entry_runtime_confirmed", "mock route", "surface.mock", 0.9, provenance="mock_agent", execution_mode="mock", runtime_observation_real=False)
        result = self.builder().incremental_update_from_dynamic_evidence(evidence)
        self.assertFalse(result["canonical_update_allowed"])

    def test_round43_evidence_types_registered(self):
        for evidence_type in ("entry_point_discovered", "route_discovered", "listener_observed", "entry_runtime_confirmed", "handler_reachable", "hypothesis_reachable", "entry_validation_blocked", "entry_validation_inconclusive"):
            self.assertIn(evidence_type, DYNAMIC_EVIDENCE_TYPES)

    def test_round43_relationship_types_registered(self):
        for relationship_type in ("exposes", "accepts_input_from", "dispatches_to", "handles", "maps_route_to", "forwards_to", "reachable_via", "entry_for"):
            self.assertIn(relationship_type, RELATIONSHIP_TYPES)

    def test_component_path_semantics(self):
        path = ComponentPath("P", ["A"], [], [], 0.8, "static")
        self.assertEqual(path.path_semantics, "runtime_flow")

    def test_attack_surface_not_vulnerability_claim(self):
        summary = json.dumps(self.surface()["summary"])
        self.assertIn("EXPOSED != VULNERABLE", summary)
        self.assertNotIn("exploitable\": true", summary)


if __name__ == "__main__":
    unittest.main()
