from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from fwagent.cli import build_parser, main
from fwagent.dynamic.models import DynamicEvidence, DynamicHypothesis
from fwagent.dynamic.workspace import DynamicWorkspace
from fwagent.findings import (
    FINDING_CATEGORIES,
    FINDING_STATUSES,
    Finding,
    FindingClaimGuard,
    FindingEvidenceChain,
    FindingFinalizer,
    FindingPromotionDecision,
)
from fwagent.pipeline.product import AnalysisPipelineController, AnalysisTask, parse_report_formats
from fwagent.reporting.final_report import REPORT_SCHEMA_VERSION, ReportGenerator, ReportValidator


class Round5Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.task_id = "round5-fixture"
        self.workspace = DynamicWorkspace(self.root, self.task_id)
        (self.workspace.task_dir / "reports").mkdir(parents=True, exist_ok=True)
        self._write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write_fixture(self) -> None:
        analysis = {
            "schema_version": "0.1",
            "task": {"id": self.task_id},
            "firmware": {"filename": "firmware.bin", "sha256": "a" * 64, "file_type": "fixture"},
            "binaries": [{"path": "ret2text"}, {"path": "/www/services/device_manager/device_manager.fcgi"}],
        }
        (self.workspace.task_dir / "reports" / "analysis.json").write_text(json.dumps(analysis, indent=2), encoding="utf-8")
        self.workspace.save_evidence(
            [
                DynamicEvidence("DE-RET-0001", "taint_path_supported", "stdin reaches gets", "fixture", 0.8, target="H-RET2TEXT-0001", provenance="real_static_analysis", runtime_observation_real=False),
                DynamicEvidence("DE-FCGI-0001", "handler_reached", "FastCGI handler reached", "fixture", 0.8, target="H-FCGI-0001", metadata={"validation_id": "VAL-FCGI"}, runtime_observation_real=True),
                DynamicEvidence("MDE-0001", "validation_inconclusive", "mock", "fixture", 0.1, target="H-FCGI-0001", provenance="mock", execution_mode="mock", runtime_observation_real=False),
            ]
        )
        self.workspace.save_hypotheses(
            [
                DynamicHypothesis("H-RET2TEXT-0001", "Ret2text stack overflow in main can redirect execution to secure shell function", "validation_blocked", 0.6, cwe="CWE-120", evidence_ids=["DE-RET-0001"], missing_evidence=["runtime observation"], static_status="supported", dynamic_status="validation_blocked"),
                DynamicHypothesis("H-FCGI-0001", "FastCGI request handling reaches sensitive code", "validation_inconclusive", 0.45, evidence_ids=["DE-FCGI-0001"], static_status="supported", dynamic_status="validation_inconclusive"),
                DynamicHypothesis("H-REJ-0001", "Rejected hypothesis", "rejected", 0.2, static_status="candidate", dynamic_status="dynamically_rejected"),
            ]
        )
        candidates = [
            {
                "candidate_id": "HC-unsafe-input-handling-tp-ret2text-stdin-gets",
                "existing_hypothesis_ids": ["H-RET2TEXT-0001"],
                "hypothesis_type": "unsafe_input_handling",
                "support_level": "supported",
                "confidence": 0.72,
                "binary_paths": ["ret2text"],
                "taint_path_ids": ["TP-RET"],
            },
            {
                "candidate_id": "HC-FCGI-security-sensitive-reachability",
                "existing_hypothesis_ids": ["H-FCGI-0001"],
                "hypothesis_type": "security_sensitive_reachability",
                "support_level": "candidate",
                "confidence": 0.53,
                "binary_paths": ["/www/services/device_manager/device_manager.fcgi"],
                "taint_path_ids": ["TP-FCGI"],
            },
        ]
        finding_candidates = [
            {
                "finding_candidate_id": "FC-0001",
                "hypothesis_ids": ["HC-unsafe-input-handling-tp-ret2text-stdin-gets"],
                "title": "Input Validation investigation candidate",
                "affected_components": ["C-BINARY-ret2text"],
                "entry_points": ["EP-STDIN-ret2text"],
                "sources": ["SRC-RET2TEXT-STDIN"],
                "sinks": ["SINK-RET2TEXT-main-gets"],
                "evidence_bundle": {"candidate_ids": ["HC-unsafe-input-handling-tp-ret2text-stdin-gets"], "bundles": [{"source_evidence": ["DE-RET-0001"], "sink_evidence": ["DE-RET-0001"], "taint_evidence": ["DE-RET-0001"], "runtime_evidence": []}]},
                "confidence": 0.705,
                "status": "supported",
                "missing_validation": ["runtime observation"],
                "security_category": "input_validation",
                "candidate_cwe_ids": ["CWE-120", "CWE-242"],
                "provider_backed": False,
            },
            {
                "finding_candidate_id": "FC-0002",
                "hypothesis_ids": ["HC-FCGI-security-sensitive-reachability"],
                "title": "Network Parsing investigation candidate",
                "affected_components": ["C-FASTCGI-device_manager"],
                "entry_points": ["EP-HTTPS-lighttpd-device-manager"],
                "sources": ["SRC-FCGI-SOAP-ACTION"],
                "sinks": ["SINK-FCGI-command-execution-system"],
                "evidence_bundle": {"candidate_ids": ["HC-FCGI-security-sensitive-reachability"], "bundles": [{"source_evidence": ["DE-FCGI-0001", "MDE-0001"], "sink_evidence": ["BIN:/lib.so"], "taint_evidence": ["DE-FCGI-0001"], "runtime_evidence": ["DE-FCGI-0001", "MDE-0001"]}]},
                "confidence": 0.53,
                "status": "needs_validation",
                "missing_validation": ["argument-level data flow", "runtime sink observation"],
                "security_category": "network_parsing",
                "candidate_cwe_ids": [],
                "provider_backed": False,
            },
        ]
        self.workspace.save_hypothesis_artifact("synthesis_analysis.json", {"candidates": candidates, "finding_candidates": finding_candidates, "summary": {"candidate_count": 2}})
        self.workspace.save_hypothesis_artifact("finding_candidates.json", finding_candidates)
        self.workspace.save_surface_artifact("entry_points.json", [{"entry_id": "EP-STDIN-ret2text", "entry_type": "stdin", "component_id": "C-BINARY-ret2text"}])
        self.workspace.save_surface_artifact("attack_surface_summary.json", {"entry_points": 1})
        self.workspace.save_correlation_artifact("summary.json", {"total_components": 2})
        self.workspace.save_correlation_artifact("component_graph.json", {"components": [{"component_id": "C-BINARY-ret2text"}]})
        self.workspace.save_investigation_artifact("summary.json", {"summary": {"iterations": 2, "stop_reason": "investigation_converged"}, "state": {"phase": "completed"}})
        self.workspace.save_investigation_artifact("action_history.json", [{"iteration": 1, "action": "plan_validation", "target": "H-FCGI-0001", "result": "success"}])

    def finalize(self) -> dict:
        return FindingFinalizer(str(self.root), self.task_id).finalize()

    def report_model(self):
        findings = self.finalize()
        return ReportGenerator(self.root, self.task_id).build_model(findings)

    def test_finding_model(self):
        item = Finding("F-0001", "Title", "input_validation", "supported", 0.7, "medium")
        self.assertEqual(item.to_dict()["finding_id"], "F-0001")

    def test_finding_statuses(self):
        self.assertIn("runtime_supported", FINDING_STATUSES)

    def test_finding_categories(self):
        self.assertIn("network_parsing", FINDING_CATEGORIES)

    def test_finding_promotion(self):
        self.assertEqual(len(self.finalize()["findings"]), 2)

    def test_finding_merge_decision_shape(self):
        decision = FindingPromotionDecision("FC", True, "supported", "merge-compatible", 0.6, "low")
        self.assertTrue(decision.promote)

    def test_confidence(self):
        self.assertGreater(self.finalize()["findings"][0]["confidence"], 0.4)

    def test_severity_hint(self):
        self.assertIn(self.finalize()["findings"][0]["severity_hint"], {"low", "medium", "unknown"})

    def test_evidence_chain(self):
        chain = FindingEvidenceChain(entry=["EP"], source=["SRC"], sink=["SINK"])
        self.assertEqual(chain.to_dict()["entry"], ["EP"])

    def test_finalizer(self):
        self.assertTrue(self.finalize()["success"])

    def test_rejected_hypothesis_exclusion(self):
        ids = json.dumps(self.finalize()["findings"])
        self.assertNotIn("H-REJ-0001", ids)

    def test_inconclusive_finding(self):
        statuses = {item["status"] for item in self.finalize()["findings"]}
        self.assertIn("inconclusive", statuses)

    def test_blocked_finding(self):
        self.assertEqual(self.finalize()["findings"][0]["validation_status"], "validation_blocked")

    def test_mock_evidence_exclusion(self):
        encoded = json.dumps(self.finalize()["findings"])
        self.assertNotIn("MDE-0001", encoded)

    def test_claim_guard(self):
        ok, _ = FindingClaimGuard().validate("confirmed RCE in firmware")
        self.assertFalse(ok)

    def test_ret2text_finding_semantics(self):
        finding = self.finalize()["findings"][0]
        self.assertIn("unsafe input", finding["title"].lower())

    def test_fastcgi_conservative_finding(self):
        finding = self.finalize()["findings"][1]
        self.assertIn("requires further validation", finding["title"])

    def test_report_model(self):
        self.assertEqual(self.report_model().metadata["schema_version"], REPORT_SCHEMA_VERSION)

    def test_json_generator(self):
        model = self.report_model()
        path = ReportGenerator(self.root, self.task_id).generate_json(model)
        self.assertTrue(path.exists())

    def test_markdown_generator(self):
        model = self.report_model()
        path = ReportGenerator(self.root, self.task_id).generate_markdown(model)
        self.assertIn("Executive Summary", path.read_text(encoding="utf-8"))

    def test_html_generator(self):
        model = self.report_model()
        path = ReportGenerator(self.root, self.task_id).generate_html(model)
        self.assertIn("<!doctype html>", path.read_text(encoding="utf-8").lower())

    def test_html_offline(self):
        path = ReportGenerator(self.root, self.task_id).generate_html(self.report_model())
        self.assertNotIn("cdn", path.read_text(encoding="utf-8").lower())

    def test_report_schema_version(self):
        self.assertEqual(REPORT_SCHEMA_VERSION, "deepduck.report.v1")

    def test_report_validator(self):
        model = self.report_model()
        self.assertTrue(ReportValidator().validate(model)["success"])

    def test_artifact_index(self):
        self.assertTrue(any(item["path"] == "reports/analysis.json" for item in self.report_model().artifact_index))

    def test_artifact_manifest(self):
        path = ReportGenerator(self.root, self.task_id).write_artifact_manifest()
        self.assertTrue(path.exists())

    def test_report_manifest(self):
        generator = ReportGenerator(self.root, self.task_id)
        generator.generate_all(self.report_model())
        self.assertTrue((self.workspace.task_dir / "reports" / "report_manifest.json").exists())

    def test_analysis_task(self):
        task = AnalysisTask("task", "input", "0" * 64, "fw.bin", "workspace")
        self.assertFalse(task.provider_backed)

    def test_task_id_hash(self):
        firmware = self.root / "fw.bin"
        firmware.write_bytes(b"abc")
        result = AnalysisPipelineController(self.root).analyze(firmware, static_only=True, progress=False)
        self.assertIn("task_id", result)

    def test_sha256(self):
        firmware = self.root / "fw2.bin"
        firmware.write_bytes(b"abc")
        result = AnalysisPipelineController(self.root).analyze(firmware, task_id="sha-task", static_only=True, progress=False)
        self.assertEqual(result["task"]["input_hash"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_pipeline_controller(self):
        self.assertTrue(AnalysisPipelineController(self.root).workspace_root.exists())

    def test_phase_transitions(self):
        firmware = self.root / "fw3.bin"
        firmware.write_bytes(b"abc")
        result = AnalysisPipelineController(self.root).analyze(firmware, task_id="phase-task", static_only=True, progress=False)
        self.assertEqual(result["task"]["pipeline_phase"], "completed")

    def test_partial_success(self):
        firmware = self.root / "fw4.bin"
        firmware.write_bytes(b"abc")
        result = AnalysisPipelineController(self.root).analyze(firmware, task_id="partial-task", no_dynamic=True, progress=False)
        self.assertEqual(result["exit_code"], 1)

    def test_static_only(self):
        firmware = self.root / "fw5.bin"
        firmware.write_bytes(b"abc")
        result = AnalysisPipelineController(self.root).analyze(firmware, task_id="static-task", static_only=True, progress=False)
        self.assertEqual(result["analysis_status"], "STATIC_ONLY_COMPLETED")

    def test_no_dynamic(self):
        firmware = self.root / "fw6.bin"
        firmware.write_bytes(b"abc")
        result = AnalysisPipelineController(self.root).analyze(firmware, task_id="nodyn-task", no_dynamic=True, progress=False)
        self.assertFalse(result["dynamic_executed"])

    def test_provider_missing_deterministic_fallback(self):
        self.assertFalse(self.finalize()["provider_backed"])

    def test_progress_format(self):
        output = io.StringIO()
        firmware = self.root / "fw7.bin"
        firmware.write_bytes(b"abc")
        with contextlib.redirect_stdout(output):
            AnalysisPipelineController(self.root).analyze(firmware, task_id="progress-task", static_only=True, progress=True)
        self.assertIn("[1/8] Preparing firmware", output.getvalue())

    def test_exit_codes(self):
        result = AnalysisPipelineController(self.root).analyze(self.root / "missing.bin", task_id="missing")
        self.assertEqual(result["exit_code"], 2)

    def test_resume(self):
        firmware = self.root / "fw8.bin"
        firmware.write_bytes(b"abc")
        controller = AnalysisPipelineController(self.root)
        first = controller.analyze(firmware, task_id="resume-task", static_only=True, progress=False)
        second = controller.analyze(firmware, task_id="resume-task", resume=True, static_only=True, progress=False)
        self.assertEqual(first["task_id"], second["task_id"])

    def test_interrupted_resume_flag(self):
        task = AnalysisTask("paused-task", "input", "0" * 64, "fw.bin", str(self.root), status="paused", pipeline_phase="interrupted")
        controller = AnalysisPipelineController(self.root)
        controller._save_task(task)
        self.assertTrue(controller.status("paused-task")["resume_available"])

    def test_report_only_rerun(self):
        result = AnalysisPipelineController(self.root).regenerate_report(self.task_id)
        self.assertTrue(result["success"])

    def test_cleanup(self):
        result = AnalysisPipelineController(self.root).cleanup(self.task_id)
        self.assertTrue(result["success"])

    def test_cleanup_preserves_canonical(self):
        AnalysisPipelineController(self.root).cleanup(self.task_id)
        self.assertTrue((self.workspace.evidence_dir / "evidence.json").exists())

    def test_cleanup_all_behavior(self):
        task = self.root / "delete-task"
        task.mkdir()
        result = AnalysisPipelineController(self.root).cleanup("delete-task", all_artifacts=True)
        self.assertTrue(result["removed_task"])

    def test_idempotency(self):
        first = self.finalize()["findings"]
        second = self.finalize()["findings"]
        self.assertEqual([item["finding_id"] for item in first], [item["finding_id"] for item in second])

    def test_artifact_corruption(self):
        (self.workspace.task_dir / "reports" / "report.json").write_text("{bad", encoding="utf-8")
        result = AnalysisPipelineController(self.root).regenerate_report(self.task_id)
        self.assertTrue(result["success"])

    def test_report_corruption_regenerate(self):
        result = AnalysisPipelineController(self.root).regenerate_report(self.task_id, report_formats={"json"})
        self.assertTrue((self.workspace.task_dir / "reports" / "report.json").exists())

    def test_cli_analyze(self):
        firmware = self.root / "fw9.bin"
        firmware.write_bytes(b"abc")
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["analyze", str(firmware), "--workspace", str(self.root), "--task-id", "cli-task", "--static-only", "--quiet"])
        self.assertEqual(code, 0)

    def test_cli_status(self):
        self.finalize()
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["status", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)

    def test_cli_report(self):
        self.finalize()
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["report", self.task_id, "--workspace", str(self.root), "--format", "json,md,html"])
        self.assertEqual(code, 0)

    def test_cli_cleanup(self):
        with contextlib.redirect_stdout(io.StringIO()):
            code = main(["cleanup", self.task_id, "--workspace", str(self.root)])
        self.assertEqual(code, 0)

    def test_json_machine_output(self):
        self.finalize()
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            main(["status", self.task_id, "--workspace", str(self.root), "--json"])
        self.assertIn('"provider_backed": false', output.getvalue())

    def test_forbidden_overclaim(self):
        encoded = json.dumps(self.finalize()["findings"]).lower()
        self.assertNotIn("confirmed rce", encoded)

    def test_mock_canonical_pollution(self):
        self.assertNotIn("MDE-", json.dumps(self.finalize()["findings"]))

    def test_provider_backed_false(self):
        self.assertFalse(self.report_model().provider_status["provider_backed"])

    def test_artifact_relative_paths(self):
        self.assertTrue(all(not Path(item["path"]).is_absolute() for item in self.report_model().artifact_index))

    def test_secret_redaction(self):
        report = self.report_model().to_dict()
        self.assertNotIn("sk-", json.dumps(report))

    def test_report_format_parser(self):
        self.assertEqual(parse_report_formats("markdown,json"), {"md", "json"})

    def test_parser_commands(self):
        commands = build_parser()._subparsers._group_actions[0].choices
        for command in ("analyze", "status", "report", "cleanup"):
            self.assertIn(command, commands)


if __name__ == "__main__":
    unittest.main()
