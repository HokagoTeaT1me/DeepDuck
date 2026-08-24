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
from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.prioritization import (
    EvidenceQualityScorer,
    HypothesisAssessment,
    HypothesisDeduplicator,
    HypothesisDependency,
    HypothesisDependencyAnalyzer,
    HypothesisPriorityScorer,
    HypothesisValidationScheduler,
    InformationGainEstimator,
    RuntimeFeasibilityAssessor,
    SecurityRelevanceScorer,
    ValidationBudget,
    ValidationBudgetAllocator,
    ValidationCostEstimate,
    ValidationCostModel,
    ValidationQueueItem,
    ValidationStopPolicy,
    budget_from_config,
    select_minimum_sufficient_runtime,
)
from fwagent.dynamic.validation import build_static_dynamic_context
from fwagent.dynamic.workspace import DynamicWorkspace


class Round41Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.task_id = "round41-fixture"
        self.task = self.root / self.task_id
        for name in ("reports", "hypotheses", "evidence"):
            (self.task / name).mkdir(parents=True, exist_ok=True)
        self._write_fixture()
        self.config = DynamicConfig(backend="service-qemu")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fixture(self) -> None:
        hypotheses = [
            {
                "id": "H-A",
                "title": "SOAP handler reachable in device_manager.fcgi with distinguishable malformed request behavior",
                "status": "supported",
                "confidence": 0.68,
                "evidence_ids": ["SE-A1", "SE-A2", "SE-A3", "SE-A4"],
            },
            {
                "id": "H-B",
                "title": "Whole-system boot authentication boundary issue requires full firmware runtime",
                "status": "supported",
                "confidence": 0.8,
                "evidence_ids": ["SE-B1", "SE-B2", "SE-B3"],
            },
            {
                "id": "H-C",
                "title": "Generic logging string may indicate cosmetic error handling issue",
                "status": "candidate",
                "confidence": 0.45,
                "evidence_ids": ["SE-C1"],
            },
            {
                "id": "H-D",
                "title": "Buffer overflow possible in device_manager SOAP handler",
                "status": "supported",
                "confidence": 0.62,
                "evidence_ids": ["SE-A1", "SE-A2", "SE-D1"],
            },
            {
                "id": "H-E",
                "title": "Old endpoint parser hypothesis already dynamically rejected",
                "status": "dynamically_rejected",
                "confidence": 0.55,
                "evidence_ids": ["SE-E1", "DE-E1"],
            },
            {
                "id": "H-F",
                "title": "SOAP parser validation_inconclusive can be retried with bounded requests",
                "status": "validation_inconclusive",
                "confidence": 0.55,
                "evidence_ids": ["SE-F1", "SE-F2", "DE-F1"],
            },
            {
                "id": "H-G",
                "title": "Unsafe overflow operation reachable through device_manager SOAP handler",
                "status": "supported",
                "confidence": 0.64,
                "evidence_ids": ["SE-G1", "SE-A1"],
            },
            {
                "id": "H-RET2TEXT",
                "title": "Ret2text stack overflow in main can redirect execution to secure shell function",
                "status": "validation_blocked",
                "confidence": 0.6,
                "evidence_ids": ["SE-R1", "SE-R2", "DE-R1"],
            },
        ]
        evidence = [
            {"id": "SE-A1", "type": "route_mapping", "description": "Static lighttpd config maps /services/device_manager/ to device_manager.fcgi.", "confidence": 0.9},
            {"id": "SE-A2", "type": "decompile", "function": "soap_dispatch", "description": "Decompiler shows SOAPAction dispatch and malformed request handling.", "confidence": 0.86},
            {"id": "SE-A3", "type": "reference", "function": "soap_dispatch", "description": "Reference to Unknown SOAP action.", "confidence": 0.78},
            {"id": "SE-A4", "type": "control-flow", "function": "soap_dispatch", "description": "Caller reaches application response path.", "confidence": 0.82},
            {"id": "SE-B1", "type": "decompile", "description": "Authentication boundary observed during boot service init.", "confidence": 0.85},
            {"id": "SE-B2", "type": "caller", "description": "Caller chain requires whole-system service ordering.", "confidence": 0.8},
            {"id": "SE-B3", "type": "reference", "description": "Boot-only NVRAM state required.", "confidence": 0.8},
            {"id": "SE-C1", "type": "string_reference", "description": "String only: log error.", "confidence": 0.4},
            {"id": "SE-D1", "type": "dangerous_call", "function": "soap_dispatch", "description": "Possible unchecked copy in same function.", "confidence": 0.76},
            {"id": "SE-E1", "type": "decompile", "description": "Parser condition appeared reachable statically.", "confidence": 0.8},
            {"id": "SE-F1", "type": "route_mapping", "description": "SOAP endpoint mapped to FastCGI.", "confidence": 0.85},
            {"id": "SE-F2", "type": "runtime observation", "description": "Previous response reached SOAP fault but did not distinguish variants.", "confidence": 0.75},
            {"id": "SE-G1", "type": "dangerous_call", "function": "soap_dispatch", "description": "Unsafe overflow operation depends on handler reachability.", "confidence": 0.75},
            {"id": "SE-R1", "type": "dangerous_call", "function": "main", "description": "Static analysis found gets() in main.", "confidence": 0.82},
            {"id": "SE-R2", "type": "hypothesis_boundary", "description": "Dynamic validation may only test short bounded stdin reachability, not control-flow hijack.", "confidence": 0.9},
        ]
        (self.task / "hypotheses" / "hypotheses.json").write_text(json.dumps(hypotheses, indent=2), encoding="utf-8")
        (self.task / "evidence" / "evidence.json").write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        (self.task / "reports" / "analysis.json").write_text(
            json.dumps({"evidence": evidence, "services": [{"name": "lighttpd"}], "priority_binaries": [{"path": "/www/services/device_manager/device_manager.fcgi"}]}, indent=2),
            encoding="utf-8",
        )
        workspace = DynamicWorkspace(self.root, self.task_id)
        dynamic_hypotheses = [
            DynamicHypothesis(
                id=item["id"],
                title=item["title"],
                status=item["status"],
                confidence=item["confidence"],
                evidence_ids=list(item["evidence_ids"]),
                static_status="supported" if item["status"] != "candidate" else "candidate",
                dynamic_status=item["status"] if item["status"].startswith(("dynamic", "validation")) else "not_tested",
            )
            for item in hypotheses
        ]
        workspace.save_hypotheses(dynamic_hypotheses)
        workspace.save_evidence(
            [
                DynamicEvidence("DE-E1", "validation_rejected", "Rejected old parser hypothesis", "dynamic.finalize_validation", 0.8, target="H-E"),
                DynamicEvidence("DE-F1", "validation_inconclusive", "Previous SOAP behavior was inconclusive", "dynamic.finalize_validation", 0.6, target="H-F"),
                DynamicEvidence("DE-R1", "validation_blocked", "process-stdin runtime blocked validation", "dynamic.run_safe_validation", 0.75, target="H-RET2TEXT"),
            ]
        )

    def scheduler(self) -> HypothesisValidationScheduler:
        return HypothesisValidationScheduler(self.root, self.task_id, config=self.config)

    def state(self) -> dict:
        return self.scheduler().assess()

    def assessment(self, hypothesis_id: str) -> dict:
        return next(item for item in self.state()["assessments"] if item["hypothesis_id"] == hypothesis_id)

    def test_hypothesis_assessment_serialization(self):
        assessment = HypothesisAssessment("H-X", 0.5, 0.5, 0.5, 0.5, 0.2, 0.5, 0.5, 0.5, 0, 0, 0, 0, 50, "medium", "service-qemu", "handler_reachability", 2, 3, 10)
        self.assertEqual(assessment.to_dict()["hypothesis_id"], "H-X")

    def test_evidence_quality_score(self):
        high = self.assessment("H-A")
        low = self.assessment("H-C")
        self.assertGreater(high["static_evidence_score"], low["static_evidence_score"])

    def test_runtime_feasibility(self):
        assessment = self.assessment("H-A")
        self.assertEqual(assessment["recommended_runtime"], "fastcgi-integration")
        self.assertGreater(assessment["runtime_feasibility_score"], 0.8)

    def test_validation_cost(self):
        feasibility = RuntimeFeasibilityAssessor().assess(
            DynamicHypothesis("H", "SOAP handler", "supported", 0.6),
            build_static_dynamic_context({"id": "H", "title": "SOAP handler"}, [], {}),
            [],
        )
        cost = ValidationCostModel().estimate(feasibility, evidence_count=4)
        self.assertIsInstance(cost, ValidationCostEstimate)
        self.assertGreater(cost.requests, 0)

    def test_information_gain(self):
        assessment = self.assessment("H-A")
        self.assertGreater(assessment["expected_information_gain"], 0.5)

    def test_security_relevance(self):
        scorer = SecurityRelevanceScorer()
        result = scorer.score(DynamicHypothesis("H", "network parser input validation", "supported", 0.5), [])
        self.assertGreater(result.security_relevance_score, 0.5)

    def test_duplicate_clustering(self):
        state = self.state()
        clusters = state["clusters"]
        self.assertTrue(any({"H-A", "H-D"} <= set(item["hypothesis_ids"]) for item in clusters))

    def test_dependency_graph(self):
        dependencies = self.state()["dependencies"]
        self.assertTrue(any(item["source_hypothesis_id"] == "H-G" and item["dependency_type"] == "requires" for item in dependencies))

    def test_priority_calculation(self):
        assessment = self.assessment("H-A")
        self.assertGreater(assessment["priority_score"], 50)

    def test_priority_tier(self):
        self.assertIn(self.assessment("H-A")["priority_tier"], {"critical", "high", "medium", "low"})

    def test_explanation_generation(self):
        self.assertIn("evidence entries", self.assessment("H-A")["assessment_reason"])

    def test_budget_model(self):
        budget = budget_from_config(self.config)
        self.assertEqual(budget.max_hypotheses, 3)

    def test_budget_allocation(self):
        state = self.state()
        self.assertLessEqual(len(state["queue"]["items"]), state["budget"]["max_hypotheses"])

    def test_high_value_low_cost_preference(self):
        queue_ids = [item["hypothesis_id"] for item in self.state()["queue"]["items"]]
        self.assertIn("H-A", queue_ids)
        self.assertNotIn("H-B", queue_ids)

    def test_blocked_hypothesis(self):
        assessment = self.assessment("H-RET2TEXT")
        self.assertLess(assessment["runtime_feasibility_score"], 0.3)
        self.assertTrue(assessment["blocking_reasons"])

    def test_already_validated_hypothesis(self):
        assessment = self.assessment("H-E")
        self.assertGreater(assessment["already_validated_penalty"], 0.5)
        self.assertNotIn("H-E", [item["hypothesis_id"] for item in self.state()["queue"]["items"]])

    def test_inconclusive_penalty(self):
        assessment = self.assessment("H-F")
        self.assertGreater(assessment["already_validated_penalty"], 0.0)
        self.assertLess(assessment["already_validated_penalty"], 0.2)

    def test_duplicate_penalty(self):
        assessments = {item["hypothesis_id"]: item for item in self.state()["assessments"]}
        self.assertTrue(assessments["H-A"]["duplicate_penalty"] or assessments["H-D"]["duplicate_penalty"])

    def test_dependency_blocked(self):
        assessment = self.assessment("H-G")
        self.assertGreater(assessment["dependency_penalty"], 0.0)

    def test_dynamic_reranking(self):
        before = [item["hypothesis_id"] for item in self.state()["assessments"]]
        after_state = self.scheduler().execute_next_mock(verdict_status="dynamically_rejected")
        after = [item["hypothesis_id"] for item in after_state["assessments"]]
        self.assertNotEqual(before[:3], after[:3])

    def test_stop_policy(self):
        policy = ValidationStopPolicy(min_priority_to_validate=90)
        queue = ValidationBudgetAllocator().allocate([], ValidationBudget(), [], [], minimum_priority=90)
        self.assertIsNotNone(policy.evaluate([], queue))

    def test_marginal_value_stop(self):
        policy = ValidationStopPolicy(min_priority_to_validate=5, marginal_information_gain=0.9)
        assessment = HypothesisAssessment("H-X", 0.2, 0.2, 0.2, 0.2, 0.2, 0.1, 0.2, 0.5, 0, 0, 0, 0, 10, "deferred", "service-qemu", "handler_reachability", 1, 1, 1)
        queue = ValidationBudgetAllocator().allocate([assessment], ValidationBudget(), [], [], minimum_priority=50)
        self.assertEqual(policy.evaluate([assessment], queue), "marginal_information_gain_too_low")

    def test_backend_selection(self):
        context = build_static_dynamic_context({"id": "H", "title": "SOAP handler"}, [{"type": "route_mapping", "description": "SOAP"}], {})
        self.assertEqual(select_minimum_sufficient_runtime(context, DynamicHypothesis("H", "SOAP handler", "supported", 0.5)), "fastcgi-integration")

    def test_minimum_sufficient_runtime(self):
        context = build_static_dynamic_context({"id": "H", "title": "Ret2text gets"}, [{"type": "dangerous_call", "description": "gets"}], {})
        self.assertEqual(select_minimum_sufficient_runtime(context, DynamicHypothesis("H", "Ret2text gets", "supported", 0.5)), "process-stdin")

    def test_mock_agent_integration(self):
        state = self.scheduler().execute_next_mock()
        self.assertFalse(state["executed"]["provider_backed"])

    def test_provider_backed_false_preserved(self):
        self.assertFalse(self.state()["provider_backed"])

    def test_safety_constraint_cannot_be_overridden(self):
        scorer = HypothesisPriorityScorer(self.config)
        hypothesis = DynamicHypothesis("H-SAFE", "Exploit payload against public target", "supported", 0.9)
        context = build_static_dynamic_context(hypothesis.to_dict(), [], {})
        assessment = scorer.assess(hypothesis, [{"id": "E", "type": "decompile", "description": "destructive exploit payload"}], context, [])
        self.assertIn("safety constraints", " ".join(assessment.blocking_reasons))

    def test_cli_prioritize(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["prioritize", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("Priority is validation priority", output.getvalue())

    def test_cli_queue(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["validation-queue", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("provider_backed=false", output.getvalue())

    def test_cli_explain(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["prioritize", self.task_id, "--workspace", str(self.root), "--explain", "H-A"])
        self.assertEqual(code, 0)
        self.assertIn("Final priority", output.getvalue())

    def test_api_priority_tools(self):
        tools = DynamicToolAPI(self.root, self.task_id, config=self.config).tools
        self.assertIn("hypothesis.list", tools)
        self.assertIn("validation.get_queue", tools)

    def test_artifact_creation(self):
        self.state()
        root = self.task / "dynamic" / "prioritization"
        self.assertTrue((root / "assessment.json").exists())
        self.assertTrue((root / "queue.json").exists())

    def test_parser_commands(self):
        commands = build_parser()._subparsers._group_actions[0].choices
        for name in ("hypotheses", "prioritize", "validation-budget", "validation-queue", "validate-next"):
            self.assertIn(name, commands)


if __name__ == "__main__":
    unittest.main()
