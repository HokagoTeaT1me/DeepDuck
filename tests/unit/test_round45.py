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
from fwagent.dynamic.correlation import CanonicalStateGuard, ComponentGraphBuilder
from fwagent.dynamic.models import DYNAMIC_EVIDENCE_TYPES, DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.synthesis import (
    FORBIDDEN_CLAIM_PHRASES,
    HYPOTHESIS_TYPES,
    SECURITY_CATEGORIES,
    SUPPORT_LEVELS,
    FindingCandidate,
    HypothesisCandidate,
    HypothesisDeduplicator,
    HypothesisEvidenceBundle,
    HypothesisPromotionDecision,
    HypothesisSynthesizer,
    HypothesisTemplate,
    HypothesisTemplateRegistry,
)
from fwagent.dynamic.taint import TaintAnalysisBuilder
from fwagent.dynamic.workspace import DynamicWorkspace


class Round45Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.task_id = "round45-fixture"
        self.task = self.root / self.task_id
        self.workspace = DynamicWorkspace(self.root, self.task_id)
        (self.task / "reports").mkdir(parents=True, exist_ok=True)
        (self.workspace.dynamic_dir / "services" / "lighttpd").mkdir(parents=True, exist_ok=True)
        (self.workspace.dynamic_dir / "application" / "device_manager").mkdir(parents=True, exist_ok=True)
        (self.workspace.validation_dir / "DV-0002").mkdir(parents=True, exist_ok=True)
        self.config = DynamicConfig(backend="service-qemu")
        self._write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fixture(self) -> None:
        report = {
            "binaries": [
                {"path": "/usr/sbin/lighttpd", "architecture": "arm", "linked_libraries": [], "dangerous_symbols": []},
                {
                    "path": "/usr/lib/libdevice_manager.so",
                    "architecture": "arm",
                    "linked_libraries": [],
                    "dangerous_symbols": ["system", "popen", "strcpy", "sprintf", "memcpy"],
                },
                {"path": "/www/services/device_manager/device_manager.fcgi", "architecture": "arm", "linked_libraries": ["libdevice_manager.so"], "dangerous_symbols": []},
                {"path": "ret2text", "architecture": "x86", "linked_libraries": [], "dangerous_symbols": ["gets", "system"]},
            ],
            "services": [{"name": "lighttpd"}],
            "evidence": [
                {"id": "SE-FCGI-0001", "type": "route_mapping", "description": "lighttpd routes to device_manager.fcgi", "confidence": 0.8},
                {"id": "SE-RET2TEXT-0001", "type": "dangerous_call", "function": "main", "description": "Static analysis found gets() in main.", "confidence": 0.82},
                {"id": "SE-RET2TEXT-0002", "type": "security_relevant_function", "function": "secure", "description": "secure contains system", "confidence": 0.75},
            ],
        }
        (self.task / "reports" / "analysis.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        launch = {
            "service": "lighttpd",
            "binary": "/usr/sbin/lighttpd",
            "expected_ports": [3000],
            "config": {"server.port": 3000, "fastcgi.server": ["/services/device_manager/", "bin-path", "/device_manager/device_manager.fcgi"]},
        }
        (self.workspace.dynamic_dir / "services" / "lighttpd" / "launch_profile.json").write_text(json.dumps(launch, indent=2), encoding="utf-8")
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
                DynamicHypothesis("H-FCGI-0001", "Specific SOAP request handling reaches device_manager.fcgi application logic", "validation_inconclusive", 0.45, evidence_ids=["SE-FCGI-0001"], static_status="supported", dynamic_status="validation_inconclusive"),
                DynamicHypothesis("H-RET2TEXT-0001", "Ret2text stack overflow in main can redirect execution to secure shell function", "validation_blocked", 0.6, evidence_ids=["SE-RET2TEXT-0001", "SE-RET2TEXT-0002"], static_status="supported", dynamic_status="validation_blocked"),
            ]
        )
        self.workspace.save_evidence(
            [
                DynamicEvidence("DE-0001", "fastcgi_application_response", "FastCGI application response reached", "fastcgi", 0.9, target="H-FCGI-0001"),
                DynamicEvidence("DE-0002", "handler_reached", "Handler reached", "dynamic.run_safe_validation", 0.8, target="H-FCGI-0001"),
                DynamicEvidence("DE-0003", "validation_blocked", "process-stdin blocked", "dynamic.run_safe_validation", 0.7, target="H-RET2TEXT-0001"),
            ]
        )

    def synth(self) -> dict:
        ComponentGraphBuilder(self.root, self.task_id, config=self.config).build()
        TaintAnalysisBuilder(self.root, self.task_id, config=self.config).build()
        return HypothesisSynthesizer(self.root, self.task_id, config=self.config).build()

    def candidate(self, candidate_id: str) -> dict:
        return next(item for item in self.synth()["candidates"] if item["candidate_id"] == candidate_id)

    def test_hypothesis_candidate(self):
        candidate = HypothesisCandidate("HC", "unsafe_input_handling", "title", "claim", support_level="supported", confidence=2.0)
        self.assertEqual(candidate.confidence, 1.0)

    def test_hypothesis_template(self):
        template = HypothesisTemplate("possible_command_influence", required_sinks=("command_execution",))
        self.assertEqual(template.required_sinks, ("command_execution",))

    def test_template_registry(self):
        registry = HypothesisTemplateRegistry()
        self.assertIn("unsafe_input_handling", {item.hypothesis_type for item in registry.list()})

    def test_evidence_threshold(self):
        config_path = self.root / "dynamic.yaml"
        config_path.write_text("dynamic:\n  synthesis:\n    evidence_threshold:\n      minimum_path_confidence: 0.7\n", encoding="utf-8")
        self.assertEqual(load_dynamic_config(config_path).synthesis.evidence_threshold.minimum_path_confidence, 0.7)

    def test_support_levels(self):
        self.assertIn("runtime_supported", SUPPORT_LEVELS)

    def test_unsafe_input_synthesis(self):
        candidate = self.candidate("HC-unsafe-input-handling-tp-ret2text-stdin-gets")
        self.assertEqual(candidate["hypothesis_type"], "unsafe_input_handling")

    def test_memory_safety_candidate(self):
        candidate = self._path_candidate("strcpy", "unsafe_copy", "statically_supported", "L3_argument_propagation")
        self.assertEqual(candidate[0].hypothesis_type, "possible_memory_safety_issue")

    def test_command_influence_candidate(self):
        candidate = self._path_candidate("system", "command_execution", "statically_supported", "L3_argument_propagation")
        self.assertEqual(candidate[0].hypothesis_type, "possible_command_influence")

    def test_command_candidate_requires_flow(self):
        candidate = self._path_candidate("system", "command_execution", "candidate", "L1_same_component")
        self.assertEqual(candidate, [])

    def test_source_system_presence_alone_not_command_injection(self):
        fcgi = self.candidate("HC-FCGI-security-sensitive-reachability")
        self.assertNotEqual(fcgi["hypothesis_type"], "possible_command_influence")

    def test_path_hypothesis(self):
        candidate = self._path_candidate("fopen", "file_open", "statically_supported", "L3_argument_propagation")
        self.assertEqual(candidate[0].hypothesis_type, "possible_path_influence")

    def test_authentication_conservative_rule(self):
        candidate = self._path_candidate("strcmp", "authentication_decision", "candidate", "L1_same_component")
        self.assertEqual(candidate, [])

    def test_runtime_anomaly_candidate(self):
        self.workspace.save_evidence([DynamicEvidence("DE-X", "process_crash", "safe probe changed liveness", "test", 0.6)])
        candidates = HypothesisSynthesizer(self.root, self.task_id, config=self.config).build()["candidates"]
        self.assertTrue(any(item["hypothesis_type"] == "runtime_behavior_anomaly" for item in candidates))

    def test_missing_evidence(self):
        fcgi = self.candidate("HC-FCGI-security-sensitive-reachability")
        self.assertIn("argument-level source-to-sink mapping", fcgi["missing_evidence"])

    def test_contradictory_evidence(self):
        candidate = self._path_candidate("strcpy", "unsafe_copy", "contradicted", "L3_argument_propagation")
        self.assertEqual(candidate[0].contradictory_evidence, ["E"])

    def test_confidence_scoring(self):
        candidate = self.candidate("HC-unsafe-input-handling-tp-ret2text-stdin-gets")
        self.assertGreater(candidate["confidence"], 0.6)

    def test_deterministic_claim_generation(self):
        first = self.candidate("HC-unsafe-input-handling-tp-ret2text-stdin-gets")["claim"]
        second = self.candidate("HC-unsafe-input-handling-tp-ret2text-stdin-gets")["claim"]
        self.assertEqual(first, second)

    def test_prohibited_overclaim_wording(self):
        candidate = HypothesisCandidate("HC", "unsafe_input_handling", "x", "confirmed RCE", support_level="supported")
        self.assertIn("confirmed rce", candidate.out_of_scope)

    def test_deduplication(self):
        dedup = HypothesisDeduplicator()
        c1 = HypothesisCandidate("HC1", "unsafe_input_handling", "a", "a", sink_ids=["S"], function_names=["f"])
        c2 = HypothesisCandidate("HC2", "unsafe_input_handling", "b", "b", sink_ids=["S"], function_names=["f"])
        candidates, _, count = dedup.deduplicate([c1, c2], [])
        self.assertEqual(len(candidates), 1)
        self.assertGreater(count, 0)

    def test_existing_hypothesis_merge(self):
        candidate = self.candidate("HC-unsafe-input-handling-tp-ret2text-stdin-gets")
        self.assertIn("H-RET2TEXT-0001", candidate["existing_hypothesis_ids"])

    def test_promotion_decision(self):
        decision = next(item for item in self.synth()["promotion_decisions"] if item["candidate_id"].startswith("HC-unsafe"))
        self.assertTrue(decision["promote"])

    def test_mock_candidate_not_promoted(self):
        result = HypothesisSynthesizer(self.root, self.task_id, config=self.config).mock_generate_candidate("mock")
        self.assertFalse(result["canonical_update_allowed"])

    def test_real_deterministic_evidence_promotion(self):
        generated = self.synth()["canonical_generated"]
        self.assertTrue(any(item["id"] == "H-RET2TEXT-0001" for item in generated))

    def test_provenance(self):
        self.assertEqual(self.candidate("HC-FCGI-security-sensitive-reachability")["provider_backed"], False)

    def test_canonical_state_guard(self):
        self.assertTrue(CanonicalStateGuard.can_update_canonical(execution_mode="real", runtime_observation_real=True))

    def test_finding_candidate(self):
        finding = FindingCandidate("FC", ["HC"], "title", [], [], [], [], {}, 0.5, "candidate")
        self.assertEqual(finding.status, "candidate")

    def test_finding_grouping(self):
        self.assertEqual(self.synth()["summary"]["finding_candidate_count"], 2)

    def test_candidate_cwe_optional_mapping(self):
        candidate = self.candidate("HC-unsafe-input-handling-tp-ret2text-stdin-gets")
        self.assertIn("CWE-242", candidate["candidate_cwe_ids"])

    def test_strcpy_alone_not_cwe(self):
        fcgi = self.candidate("HC-FCGI-security-sensitive-reachability")
        self.assertEqual(fcgi["candidate_cwe_ids"], [])

    def test_system_alone_not_cwe78(self):
        fcgi = self.candidate("HC-FCGI-security-sensitive-reachability")
        self.assertNotIn("CWE-78", fcgi["candidate_cwe_ids"])

    def test_evidence_bundle(self):
        bundles = self.synth()["evidence_bundles"]
        self.assertTrue(any(item["candidate_id"] == "HC-FCGI-security-sensitive-reachability" for item in bundles))

    def test_validation_goal(self):
        candidate = self.candidate("HC-FCGI-security-sensitive-reachability")
        self.assertIn("Determine whether", candidate["validation_goal"])

    def test_safe_strategy(self):
        candidate = self.candidate("HC-FCGI-security-sensitive-reachability")
        self.assertEqual(candidate["validation_strategy"], "input_behavior_difference")

    def test_prioritization_integration(self):
        self.synth()
        state = __import__("fwagent.dynamic.prioritization", fromlist=["HypothesisValidationScheduler"]).HypothesisValidationScheduler(self.root, self.task_id, config=self.config).assess()
        self.assertTrue(any(item["hypothesis_id"] == "H-RET2TEXT-0001" for item in state["assessments"]))

    def test_budget_integration(self):
        self.synth()
        state = __import__("fwagent.dynamic.prioritization", fromlist=["HypothesisValidationScheduler"]).HypothesisValidationScheduler(self.root, self.task_id, config=self.config).assess()
        self.assertLessEqual(len(state["queue"]["items"]), self.config.prioritization.budget.max_hypotheses)

    def test_information_gain_integration(self):
        self.synth()
        state = __import__("fwagent.dynamic.prioritization", fromlist=["HypothesisValidationScheduler"]).HypothesisValidationScheduler(self.root, self.task_id, config=self.config).assess()
        self.assertTrue(all("expected_information_gain" in item for item in state["assessments"]))

    def test_fastcgi_weak_candidate_behavior(self):
        fcgi = self.candidate("HC-FCGI-security-sensitive-reachability")
        self.assertEqual(fcgi["support_level"], "candidate")

    def test_fastcgi_no_false_rce_hypothesis(self):
        text = json.dumps(self.synth()["candidates"]).lower()
        self.assertNotIn("confirmed rce", text)
        self.assertNotIn("remote code execution", text)

    def test_ret2text_unsafe_input_hypothesis(self):
        candidate = self.candidate("HC-unsafe-input-handling-tp-ret2text-stdin-gets")
        self.assertEqual(candidate["support_level"], "supported")

    def test_ret2text_no_auto_control_flow_exploit_claim(self):
        claim = self.candidate("HC-unsafe-input-handling-tp-ret2text-stdin-gets")["claim"].lower()
        self.assertNotIn("redirect", claim)

    def test_secure_system_remains_separate(self):
        candidate = self.candidate("HC-unsafe-input-handling-tp-ret2text-stdin-gets")
        self.assertEqual(candidate["sink_ids"], ["SINK-RET2TEXT-main-gets"])

    def test_mock_isolation(self):
        before = (self.workspace.dynamic_dir / "hypotheses.json").read_text(encoding="utf-8")
        HypothesisSynthesizer(self.root, self.task_id, config=self.config).mock_generate_candidate("mock")
        after = (self.workspace.dynamic_dir / "hypotheses.json").read_text(encoding="utf-8")
        self.assertEqual(before, after)

    def test_cli_synthesis(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["synthesize-hypotheses", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)

    def test_cli_candidate_view(self):
        self.synth()
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["hypothesis-candidate", self.task_id, "HC-FCGI-security-sensitive-reachability", "--workspace", str(self.root)])
        self.assertEqual(code, 0)

    def test_cli_summary(self):
        self.synth()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["synthesis-summary", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("Candidates", output.getvalue())

    def test_forbidden_confirmation_tools_absent(self):
        tools = DynamicToolAPI(self.root, self.task_id, config=self.config).tools
        for forbidden in ("hypothesis.force_confirm", "hypothesis.mark_vulnerable", "finding.mark_exploitable"):
            self.assertNotIn(forbidden, tools)

    def test_agent_api_tools(self):
        tools = DynamicToolAPI(self.root, self.task_id, config=self.config).tools
        for name in ("hypothesis.list_candidates", "hypothesis.get_candidate", "hypothesis.get_missing_evidence", "finding.list_candidates"):
            self.assertIn(name, tools)

    def test_api_candidate(self):
        self.synth()
        result = DynamicToolAPI(self.root, self.task_id, config=self.config).execute("hypothesis.get_candidate", {"candidate_id": "HC-FCGI-security-sensitive-reachability"})
        self.assertTrue(result["success"])

    def test_summary_artifacts(self):
        self.synth()
        for name in ("candidates.json", "promotion_decisions.json", "canonical_generated.json", "evidence_bundles.json", "finding_candidates.json", "summary.json"):
            self.assertTrue((self.task / "hypotheses" / name).exists())

    def test_security_taxonomy(self):
        self.assertIn("memory_safety", SECURITY_CATEGORIES)

    def test_hypothesis_types(self):
        self.assertIn("security_sensitive_reachability", HYPOTHESIS_TYPES)

    def test_forbidden_phrase_catalog(self):
        self.assertIn("confirmed rce", FORBIDDEN_CLAIM_PHRASES)

    def test_round45_evidence_types_registered(self):
        self.assertIn("hypothesis_candidate_generated", DYNAMIC_EVIDENCE_TYPES)

    def _path_candidate(self, callee: str, sink_type: str, path_state: str, level: str):
        synth = HypothesisSynthesizer(self.root, self.task_id, config=self.config)
        source = {"source_id": "SRC", "source_type": "http_body", "entry_point_id": "EP", "confidence": 0.8, "evidence_ids": ["E"]}
        sink = {"sink_id": f"SINK-{callee}", "sink_type": sink_type, "callee_name": callee, "function_name": "fn", "binary_path": "bin", "confidence": 0.8, "security_relevance": 0.8, "evidence_ids": ["E"]}
        path = {
            "path_id": "TP",
            "source_id": "SRC",
            "sink_id": f"SINK-{callee}",
            "component_ids": ["C"],
            "function_chain": ["handler", callee],
            "evidence_ids": ["E"],
            "confidence": 0.8,
            "path_state": path_state,
            "evidence_level": level,
            "runtime_sink_confirmed": False,
            "sanitizers": [],
        }
        return synth._candidates_for_path(path, source, sink)


if __name__ == "__main__":
    unittest.main()
