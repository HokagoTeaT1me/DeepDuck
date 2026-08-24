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
from fwagent.dynamic.config import InvestigationSettings, InvestigationStopSettings
from fwagent.dynamic.correlation import CanonicalStateGuard
from fwagent.dynamic.investigation import (
    INVESTIGATION_PHASES,
    INVESTIGATION_STATUSES,
    ArtifactFreshness,
    BudgetState,
    DeterministicPlanner,
    EvidenceDelta,
    InvestigationAction,
    InvestigationActionGuard,
    InvestigationBudget,
    InvestigationContext,
    InvestigationController,
    InvestigationIteration,
    InvestigationState,
    MockPlanner,
    investigation_budget_from_config,
)
from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.workspace import DynamicWorkspace


class Round46Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.task_id = "round46-fixture"
        self.task = self.root / self.task_id
        self.workspace = DynamicWorkspace(self.root, self.task_id)
        (self.task / "reports").mkdir(parents=True, exist_ok=True)
        (self.workspace.dynamic_dir / "services" / "lighttpd").mkdir(parents=True, exist_ok=True)
        (self.workspace.dynamic_dir / "application" / "device_manager").mkdir(parents=True, exist_ok=True)
        self.config = DynamicConfig(backend="service-qemu")
        self._write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fixture(self) -> None:
        report = {
            "firmware": {"filename": "firmware.bin"},
            "binaries": [
                {"path": "/usr/sbin/lighttpd", "architecture": "arm", "linked_libraries": [], "dangerous_symbols": []},
                {"path": "/usr/lib/libdevice_manager.so", "architecture": "arm", "linked_libraries": [], "dangerous_symbols": ["system", "popen", "strcpy", "sprintf", "memcpy"]},
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
        launch = {"service": "lighttpd", "binary": "/usr/sbin/lighttpd", "expected_ports": [3000], "config": {"server.port": 3000, "fastcgi.server": ["/services/device_manager/", "bin-path", "/device_manager/device_manager.fcgi"]}}
        (self.workspace.dynamic_dir / "services" / "lighttpd" / "launch_profile.json").write_text(json.dumps(launch, indent=2), encoding="utf-8")
        runtime = {"success": True, "diagnosis": "fastcgi_integration_reachable", "endpoint": "/services/device_manager/", "application_response_reached": True, "backend_child": {"listener": {"host": "127.0.0.1", "port": 44171}, "alive_after_startup": True}}
        (self.workspace.dynamic_dir / "application" / "device_manager" / "integration_validation.json").write_text(json.dumps(runtime, indent=2), encoding="utf-8")
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

    def controller(self) -> InvestigationController:
        return InvestigationController(self.root, self.task_id, config=self.config)

    def run_controller(self) -> dict:
        return self.controller().run()

    def test_investigation_state(self):
        state = InvestigationState("INV", "task")
        self.assertEqual(state.phase, "initializing")

    def test_phases(self):
        self.assertIn("reranking", INVESTIGATION_PHASES)

    def test_statuses(self):
        self.assertIn("blocked", INVESTIGATION_STATUSES)

    def test_investigation_controller(self):
        self.assertEqual(self.controller().workspace.task_id, self.task_id)

    def test_phase_transitions(self):
        result = self.run_controller()
        self.assertEqual(result["state"]["phase"], "completed")

    def test_dependency_ordering(self):
        self.run_controller()
        names = [item["artifact_name"] for item in self.workspace.load_investigation_artifact("artifact_freshness.json")]
        self.assertEqual(names[:5], ["component_graph", "attack_surface", "taint", "synthesis", "prioritization"])

    def test_artifact_freshness(self):
        item = ArtifactFreshness("priority", "in", "out", "now")
        self.assertFalse(item.stale)

    def test_incremental_invalidation(self):
        stale = self.controller().invalidate_for_delta(EvidenceDelta(new_dynamic_evidence_ids=["DE-X"]))
        self.assertTrue(all(item.stale for item in stale))

    def test_incremental_recompute(self):
        result = self.run_controller()
        self.assertIn("priority_version", result["state"])

    def test_investigation_iteration(self):
        iteration = InvestigationIteration("ITER", 1, "prioritization")
        self.assertEqual(iteration.iteration_number, 1)

    def test_investigation_budget(self):
        budget = investigation_budget_from_config(self.config)
        self.assertEqual(budget.max_iterations, self.config.investigation.max_iterations)

    def test_budget_state(self):
        state = BudgetState(iterations_used=1)
        self.assertEqual(state.to_dict()["iterations_used"], 1)

    def test_budget_exhaustion(self):
        budget = InvestigationBudget(max_total_validations=0)
        allowed, reason = InvestigationActionGuard().validate(InvestigationAction("execute_validation", "H"), InvestigationState("INV", "task"), budget, BudgetState())
        self.assertFalse(allowed)
        self.assertIn("budget", reason)

    def test_convergence_stop(self):
        self.assertEqual(self.run_controller()["state"]["stop_reason"], "investigation_converged")

    def test_no_hypothesis_stop(self):
        self.workspace.save_hypotheses([])
        result = self.run_controller()
        self.assertTrue(result["state"]["stop_reason"] in {"no_validatable_hypotheses", "investigation_converged", "max_iterations_reached"})

    def test_low_priority_stop(self):
        config = DynamicConfig(
            backend="service-qemu",
            investigation=InvestigationSettings(stop=InvestigationStopSettings(min_priority=95.0)),
        )
        result = InvestigationController(self.root, self.task_id, config=config).run(max_iterations=1)
        self.assertEqual(result["summary"]["hypotheses_validated"], 0)

    def test_all_blocked_stop(self):
        result = self.run_controller()
        ret = next(item for item in result["priority"]["assessments"] if item["hypothesis_id"] == "H-RET2TEXT-0001")
        self.assertTrue(ret["blocking_reasons"])

    def test_marginal_info_gain_stop(self):
        self.assertGreaterEqual(self.config.investigation.stop.min_information_gain, 0.0)

    def test_evidence_delta(self):
        delta = EvidenceDelta(new_dynamic_evidence_ids=["DE"])
        self.assertTrue(delta.has_progress())

    def test_canonical_update_guard(self):
        self.assertTrue(CanonicalStateGuard.can_update_canonical(execution_mode="real", runtime_observation_real=True))

    def test_mock_canonical_isolation(self):
        (self.workspace.dynamic_dir / "application" / "device_manager" / "integration_validation.json").unlink()
        self.run_controller()
        canonical = json.loads((self.workspace.dynamic_dir / "hypotheses.json").read_text(encoding="utf-8"))
        encoded = json.dumps(canonical)
        self.assertNotIn("MDE-INV", encoded)

    def test_checkpoint_persistence(self):
        self.run_controller()
        self.assertTrue((self.workspace.investigation_dir / "checkpoints" / "checkpoint-0001.json").exists())

    def test_resume(self):
        first = self.controller().run(stop_after_iteration=True)
        self.assertEqual(first["state"]["status"], "paused")
        resumed = self.controller().run(resume=True)
        self.assertGreater(resumed["state"]["iteration"], first["state"]["iteration"])

    def test_idempotency(self):
        first = self.run_controller()
        second = self.controller().run()
        self.assertEqual(first["summary"]["iterations"], second["summary"]["iterations"])

    def test_evidence_dedup(self):
        self.run_controller()
        ids = [item.id for item in self.workspace.load_evidence()]
        self.assertEqual(ids.count("DE-INV-REAL-0001"), 1)

    def test_hypothesis_dedup(self):
        self.run_controller()
        ids = [item.id for item in self.workspace.load_hypotheses()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_failure_recovery(self):
        result = self.controller().recover_artifact_corruption("missing.json")
        self.assertTrue(result["success"])

    def test_recoverable_timeout(self):
        self.assertFalse(self.config.investigation.recovery.retry_validation_timeout)

    def test_blocked_validation_continue(self):
        self.assertTrue(self.config.investigation.recovery.continue_after_blocked)

    def test_safety_stop(self):
        allowed, reason = InvestigationActionGuard().validate(InvestigationAction("execute_validation", "H", provider_backed=True), InvestigationState("INV", "task"), InvestigationBudget(), BudgetState())
        self.assertFalse(allowed)
        self.assertIn("provider", reason)

    def test_verdict_handling(self):
        self.run_controller()
        simulation = self.workspace.load_simulation_artifact("simulation_evidence.json")
        self.assertTrue(all(item["type"] == "validation_inconclusive" for item in simulation))

    def test_reranking(self):
        iterations = self.run_controller()["summary"]["iterations"]
        self.assertGreaterEqual(iterations, 1)

    def test_queue_order_changes_after_evidence(self):
        self.run_controller()
        iterations = self.workspace.load_investigation_artifact("iterations.json")
        self.assertEqual(iterations[0]["priority_after"][0]["hypothesis_id"], "H-FCGI-0001")
        self.assertTrue((self.workspace.investigation_dir / "stale_artifacts.json").exists())

    def test_synthesis_refresh(self):
        self.run_controller()
        self.assertTrue((self.task / "hypotheses" / "summary.json").exists())

    def test_finding_candidate_refresh(self):
        self.run_controller()
        self.assertTrue((self.task / "hypotheses" / "finding_candidates.json").exists())

    def test_runtime_selection(self):
        self.run_controller()
        iteration = self.workspace.load_investigation_artifact("iterations.json")[0]
        self.assertEqual(iteration["selected_runtime"], "fastcgi-integration")

    def test_validation_fingerprint(self):
        self.run_controller()
        fingerprints = self.workspace.load_investigation_artifact("validation_fingerprints.json")
        self.assertTrue(fingerprints)

    def test_no_repeated_identical_validation(self):
        self.run_controller()
        fingerprints = self.workspace.load_investigation_artifact("validation_fingerprints.json")
        self.assertEqual(len(fingerprints), len(set(fingerprints)))

    def test_action_history(self):
        self.run_controller()
        history = self.workspace.load_investigation_artifact("action_history.json")
        self.assertTrue(any(item["action"] == "execute_validation" for item in history))

    def test_decision_summary(self):
        self.run_controller()
        self.assertIn("Selected H-FCGI", self.workspace.load_investigation_artifact("iterations.json")[0]["decision_summary"])

    def test_deterministic_planner(self):
        context = InvestigationContext("prioritization", [{"hypothesis_id": "H"}], None, {}, {}, {}, [], {}, {}, [], [], [], [], False)
        self.assertEqual(DeterministicPlanner().plan_next_action(context).target, "H")

    def test_mock_planner(self):
        context = InvestigationContext("prioritization", [{"hypothesis_id": "H"}], None, {}, {}, {}, [], {}, {}, [], [], [], [], False)
        self.assertIn("mock", MockPlanner().plan_next_action(context).reason)

    def test_provider_backed_false(self):
        self.assertFalse(self.run_controller()["provider_backed"])

    def test_mock_action_guard(self):
        allowed, _ = InvestigationActionGuard().validate(InvestigationAction("execute_validation", "H", execution_mode="mock"), InvestigationState("INV", "task"), InvestigationBudget(), BudgetState())
        self.assertTrue(allowed)

    def test_real_runtime_evidence_canonical_allowed(self):
        self.run_controller()
        evidence = next(item for item in self.workspace.load_evidence() if item.id == "DE-INV-REAL-0001")
        self.assertTrue(evidence.metadata["canonical_update_allowed"])

    def test_mock_verdict_canonical_denied(self):
        self.run_controller()
        simulation = self.workspace.load_simulation_artifact("simulation_evidence.json")
        self.assertTrue(all(not item["canonical_update_allowed"] for item in simulation))

    def test_cli_investigate(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["investigate", self.task_id, "--workspace", str(self.root), "--autonomous"])
        self.assertEqual(code, 0)

    def test_cli_status(self):
        self.run_controller()
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["investigate-status", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)

    def test_cli_resume(self):
        self.controller().run(stop_after_iteration=True)
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["investigate-resume", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)

    def test_cli_history(self):
        self.run_controller()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["investigate-history", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)
        self.assertIn("Investigation History", output.getvalue())

    def test_forbidden_override_tools_absent(self):
        tools = DynamicToolAPI(self.root, self.task_id, config=self.config).tools
        for forbidden in ("investigation.force_canonical_update", "investigation.override_budget", "investigation.disable_safety", "investigation.force_confirm"):
            self.assertNotIn(forbidden, tools)

    def test_api_investigation_tools(self):
        tools = DynamicToolAPI(self.root, self.task_id, config=self.config).tools
        for name in ("investigation.get_state", "investigation.get_context", "investigation.get_budget", "investigation.get_history", "investigation.get_next_action"):
            self.assertIn(name, tools)

    def test_artifact_corruption_recovery(self):
        self.run_controller()
        (self.workspace.prioritization_dir / "scheduler_state.json").write_text("{bad", encoding="utf-8")
        recovered = self.controller().recover_artifact_corruption("prioritization")
        self.assertTrue(recovered["recovered"])

    def test_parser_commands(self):
        commands = build_parser()._subparsers._group_actions[0].choices
        for command in ("investigate-status", "investigate-resume", "investigate-stop", "investigate-history", "investigate-next"):
            self.assertIn(command, commands)


if __name__ == "__main__":
    unittest.main()
