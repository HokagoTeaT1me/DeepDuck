from __future__ import annotations

import inspect
import json
import tempfile
import unittest
from pathlib import Path

from fwagent.cli import build_parser
from fwagent.dynamic.correlation import ComponentGraphBuilder
from fwagent.dynamic.surface import AttackSurfaceBuilder
from fwagent.dynamic.taint import TaintAnalysisBuilder
from fwagent.pipeline.product import (
    AnalysisPipelineController,
    PipelineStageResult,
    ProductPipelineSettings,
    V01_PIPELINE_STAGES,
    _artifact_outputs,
    _ghidra_evidence_for_result,
    _items_processed,
)
from fwagent.reporting.final_report import ReportGenerator


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def base_report() -> dict:
    return {
        "firmware": {"filename": "router.bin", "sha256": "00", "file_type": "firmware"},
        "extraction": {"extractor": "binwalk", "success": True},
        "filesystem": {"total_files": 12, "elf_files": 3, "web_files": 2},
        "platform": {"architecture": "arm"},
        "binaries": [
            {"path": "/usr/sbin/dnsmasq", "architecture": "arm", "dangerous_symbols": ["strcpy"], "linked_libraries": ["libc.so.0"]},
            {"path": "/usr/sbin/uhttpd", "architecture": "arm", "dangerous_symbols": ["system"], "linked_libraries": []},
        ],
        "services": [{"name": "dnsmasq", "binary": "/usr/sbin/dnsmasq"}],
        "priority_binaries": [{"path": "/usr/sbin/dnsmasq", "score": 90}],
    }


class DeepDuckV01IntegrationTests(unittest.TestCase):
    def test_stage_order_contains_expected_terminal_stage(self) -> None:
        self.assertEqual(V01_PIPELINE_STAGES[-1], "COMPLETED")
        self.assertIn("GHIDRA_ANALYSIS", V01_PIPELINE_STAGES)

    def test_stage_result_exposes_required_fields(self) -> None:
        keys = PipelineStageResult("INPUT_PREPARE").to_dict()
        for key in ("stage", "status", "started_at", "finished_at", "duration", "input_artifacts", "output_artifacts", "items_processed", "items_succeeded", "items_failed", "items_skipped", "blocking_reason", "partial_reason"):
            self.assertIn(key, keys)

    def test_stage_finish_records_counts(self) -> None:
        stage = PipelineStageResult("X")
        stage.finish("partial", items_processed=3, items_succeeded=2, items_failed=1, partial_reason="blocked")
        self.assertEqual(stage.items_failed, 1)
        self.assertEqual(stage.partial_reason, "blocked")

    def test_product_settings_default_keep_deep_static_enabled(self) -> None:
        self.assertTrue(ProductPipelineSettings().deep_static_analysis.enabled)

    def test_analyze_signature_has_fast_and_deep(self) -> None:
        params = inspect.signature(AnalysisPipelineController.analyze).parameters
        self.assertIn("fast", params)
        self.assertIn("deep", params)

    def test_cli_prog_is_deepduck(self) -> None:
        self.assertEqual(build_parser().prog, "deepduck")

    def test_cli_accepts_fast_flag(self) -> None:
        args = build_parser().parse_args(["analyze", "firmware.bin", "--fast"])
        self.assertTrue(args.fast)

    def test_cli_accepts_deep_flag(self) -> None:
        args = build_parser().parse_args(["analyze", "firmware.bin", "--deep"])
        self.assertTrue(args.deep)

    def test_pyproject_exposes_deepduck_console_script(self) -> None:
        text = Path("pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('deepduck = "fwagent.cli:main"', text)

    def test_readme_uses_only_deepduck_product_name(self) -> None:
        text = Path("README.md").read_text(encoding="utf-8")
        self.assertIn("Deep Exploration and Evaluation Platform for Device Understanding, Correlation, and Knowledge", text)
        self.assertIn("arXiv", text)

    def test_analysis_status_fast(self) -> None:
        stages = {name: PipelineStageResult(name, status="completed") for name in V01_PIPELINE_STAGES}
        status = AnalysisPipelineController(tempfile.mkdtemp())._analysis_status([], static_only=False, no_dynamic=False, fast=True, stage_results=stages)
        self.assertEqual(status, "FAST_TRIAGE_COMPLETED")

    def test_analysis_status_static_only(self) -> None:
        stages = {name: PipelineStageResult(name, status="completed") for name in V01_PIPELINE_STAGES}
        status = AnalysisPipelineController(tempfile.mkdtemp())._analysis_status([], static_only=True, no_dynamic=False, fast=False, stage_results=stages)
        self.assertEqual(status, "STATIC_ONLY_COMPLETED")

    def test_analysis_status_no_dynamic_uncertain(self) -> None:
        stages = {name: PipelineStageResult(name, status="completed") for name in V01_PIPELINE_STAGES}
        status = AnalysisPipelineController(tempfile.mkdtemp())._analysis_status([], static_only=False, no_dynamic=True, fast=False, stage_results=stages)
        self.assertEqual(status, "COMPLETED_WITH_UNCERTAINTY")

    def test_analysis_status_required_skip_partial(self) -> None:
        stages = {name: PipelineStageResult(name, status="completed") for name in V01_PIPELINE_STAGES}
        stages["GHIDRA_ANALYSIS"].status = "skipped"
        status = AnalysisPipelineController(tempfile.mkdtemp())._analysis_status([], static_only=False, no_dynamic=False, fast=False, stage_results=stages)
        self.assertEqual(status, "PARTIAL")

    def test_coverage_metrics_include_v01_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            write_json(task / "artifacts" / "rootfs.json", {"workspace_relative_path": "rootfs", "extraction_method": "docker-binwalk"})
            write_json(task / "ghidra" / "analysis_summary.json", {"selected_binary_count": 2, "real_ghidra_count": 1, "fallback_count": 1, "failed_binary_count": 0})
            stages = {name: PipelineStageResult(name, status="completed") for name in V01_PIPELINE_STAGES}
            coverage = AnalysisPipelineController(tmp)._coverage_metrics("t", stages)
            self.assertEqual(coverage["rootfs_files"], 12)
            self.assertEqual(coverage["ghidra_targets_scheduled"], 2)
            self.assertEqual(coverage["real_ghidra_completed"], 1)

    def test_validation_gaps_include_partial_stage_reason(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            stages = {name: PipelineStageResult(name, status="completed") for name in V01_PIPELINE_STAGES}
            stages["DYNAMIC_VALIDATION"].status = "partial"
            stages["DYNAMIC_VALIDATION"].partial_reason = "no runtime"
            gaps = AnalysisPipelineController(tmp)._validation_gaps("t", stages)
            self.assertTrue(any("DYNAMIC_VALIDATION" in gap for gap in gaps))

    def test_write_pipeline_artifact_persists_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            stages = {name: PipelineStageResult(name, status="completed") for name in V01_PIPELINE_STAGES}
            AnalysisPipelineController(tmp)._write_pipeline_artifacts("t", stages, "COMPLETED_WITH_UNCERTAINTY")
            payload = json.loads((task / "pipeline_stages.json").read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], "deepduck.pipeline.v0.1")

    def test_report_json_includes_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            write_json(task / "pipeline_stages.json", {"stages": [], "coverage": {"rootfs_files": 12}, "validation_gaps": []})
            model = ReportGenerator(tmp, "t").build_model({"findings": []})
            self.assertEqual(model.to_dict()["coverage"]["rootfs_files"], 12)

    def test_report_markdown_uses_deepduck_title(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            model = ReportGenerator(tmp, "t").build_model({"findings": []})
            path = ReportGenerator(tmp, "t").generate_markdown(model)
            self.assertIn("# DeepDuck Firmware Security Analysis Report", path.read_text(encoding="utf-8"))

    def test_report_markdown_has_fourteen_artifact_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            model = ReportGenerator(tmp, "t").build_model({"findings": []})
            text = ReportGenerator(tmp, "t").generate_markdown(model).read_text(encoding="utf-8")
            self.assertIn("## 14. Artifacts", text)

    def test_report_no_findings_text_is_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            model = ReportGenerator(tmp, "t").build_model({"findings": []})
            text = ReportGenerator(tmp, "t").generate_markdown(model).read_text(encoding="utf-8")
            self.assertIn("No final findings were promoted from canonical evidence.", text)

    def test_artifact_index_contains_rootfs_and_ghidra(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            model = ReportGenerator(tmp, "t").build_model({"findings": []})
            paths = {item["path"] for item in model.artifact_index}
            self.assertIn("artifacts/rootfs.json", paths)
            self.assertIn("ghidra/analysis_summary.json", paths)

    def test_model_provider_metadata_is_noncanonical(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            model = ReportGenerator(tmp, "t").build_model({"findings": []})
            self.assertFalse(model.provider_status["provider_backed"])

    def test_component_ingest_accepts_non_fixture_binary(self) -> None:
        builder = ComponentGraphBuilder(tempfile.mkdtemp(), "t", config=AnalysisPipelineController(tempfile.mkdtemp()).config)
        builder._ingest_binaries(base_report())
        self.assertIsNotNone(builder.graph.resolve_component_id("/usr/sbin/dnsmasq"))

    def test_component_ingest_links_dangerous_symbol(self) -> None:
        builder = ComponentGraphBuilder(tempfile.mkdtemp(), "t", config=AnalysisPipelineController(tempfile.mkdtemp()).config)
        builder._ingest_binaries(base_report())
        self.assertTrue(any(component.name == "strcpy" for component in builder.graph.components.values()))

    def test_service_ingest_accepts_non_lighttpd(self) -> None:
        builder = ComponentGraphBuilder(tempfile.mkdtemp(), "t", config=AnalysisPipelineController(tempfile.mkdtemp()).config)
        builder._ingest_services(base_report())
        self.assertIsNotNone(builder.graph.resolve_component_id("dnsmasq"))

    def test_service_profile_ingest_accepts_generic_service(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_json(Path(tmp) / "t" / "dynamic" / "services" / "dnsmasq" / "launch_profile.json", {"service": "dnsmasq", "binary": "/usr/sbin/dnsmasq"})
            builder = ComponentGraphBuilder(tmp, "t", config=AnalysisPipelineController(tmp).config)
            builder._ingest_service_profiles()
            self.assertIsNotNone(builder.graph.resolve_component_id("dnsmasq"))

    def test_ret2text_hypothesis_context_does_not_contaminate_other_firmware(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_json(Path(tmp) / "t" / "reports" / "analysis.json", base_report())
            builder = ComponentGraphBuilder(tmp, "t", config=AnalysisPipelineController(tmp).config)
            builder._ingest_hypothesis_context()
            self.assertIsNone(builder.graph.resolve_component_id("ret2text"))

    def test_taint_discovers_generic_sinks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            graph = ComponentGraphBuilder(tmp, "t", config=AnalysisPipelineController(tmp).config)
            graph._ingest_binaries(base_report())
            graph._persist({"components": [], "relationships": [], "evidence_correlations": [], "paths": [], "summary": {}})
            builder = TaintAnalysisBuilder(tmp, "t", config=AnalysisPipelineController(tmp).config)
            sinks = builder._discover_sinks()
            self.assertTrue(any(sink.binary_path == "/usr/sbin/dnsmasq" for sink in sinks))

    def test_taint_ret2text_sinks_do_not_contaminate_other_firmware(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_json(Path(tmp) / "t" / "reports" / "analysis.json", base_report())
            builder = TaintAnalysisBuilder(tmp, "t", config=AnalysisPipelineController(tmp).config)
            self.assertFalse(any("ret2text" in sink.sink_id.lower() for sink in builder._discover_sinks()))

    def test_taint_discovers_generic_network_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_json(Path(tmp) / "t" / "reports" / "analysis.json", base_report())
            builder = TaintAnalysisBuilder(tmp, "t", config=AnalysisPipelineController(tmp).config)
            builder.surface = {"entry_points": [{"entry_id": "EP-SERVICE-dnsmasq-53", "protocol": "udp", "component_id": "C1", "confidence": 0.6}]}
            sources = builder._discover_sources()
            self.assertTrue(any(source.source_type == "udp_datagram" for source in sources))

    def test_surface_generic_service_profile_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            write_json(task / "dynamic" / "services" / "dnsmasq" / "launch_profile.json", {"service": "dnsmasq", "binary": "/usr/sbin/dnsmasq", "config": {"port": 53}})
            graph_builder = ComponentGraphBuilder(tmp, "t", config=AnalysisPipelineController(tmp).config)
            graph_builder._ingest_services(base_report())
            graph_builder._persist({"components": [], "relationships": [], "evidence_correlations": [], "paths": [], "summary": {}})
            entries = AttackSurfaceBuilder(tmp, "t", config=AnalysisPipelineController(tmp).config)._discover_entries()
            self.assertTrue(any(entry.entry_id == "EP-SERVICE-dnsmasq-53" for entry in entries))

    def test_surface_ret2text_entry_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            entries = AttackSurfaceBuilder(tmp, "t", config=AnalysisPipelineController(tmp).config)._discover_entries()
            self.assertFalse(any("ret2text" in entry.entry_id.lower() for entry in entries))

    def test_ghidra_evidence_is_marked_non_provider_backed(self) -> None:
        evidence = _ghidra_evidence_for_result({"success": True, "target": {"path": "/bin/httpd"}, "result": {"imports": [{"name": "system", "dangerous": True}], "functions": ["main"], "metadata": {"fallback": True}}})
        self.assertTrue(evidence)
        self.assertFalse(evidence[0].provider_backed)

    def test_ghidra_evidence_is_not_runtime_real(self) -> None:
        evidence = _ghidra_evidence_for_result({"success": True, "target": {"path": "/bin/httpd"}, "result": {"imports": [{"name": "system", "dangerous": True}], "metadata": {"fallback": True}}})
        self.assertFalse(evidence[0].runtime_observation_real)

    def test_artifact_outputs_from_report_tuple(self) -> None:
        outputs = _artifact_outputs(({"report_path": "reports/analysis.json"}, Path("artifact_manifest.json")))
        self.assertIn("reports/analysis.json", outputs)

    def test_items_processed_from_summary_dict(self) -> None:
        self.assertEqual(_items_processed({"items_processed": 7}), 7)

    def test_pipeline_artifact_records_provider_backed_false(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            task = Path(tmp) / "t"
            write_json(task / "reports" / "analysis.json", base_report())
            stages = {name: PipelineStageResult(name, status="completed") for name in V01_PIPELINE_STAGES}
            AnalysisPipelineController(tmp)._write_pipeline_artifacts("t", stages, "COMPLETED_WITH_UNCERTAINTY")
            payload = json.loads((task / "pipeline_stages.json").read_text(encoding="utf-8"))
            self.assertFalse(payload["provider_backed"])

    def test_pipeline_completed_stage_serializes_last(self) -> None:
        stages = {name: PipelineStageResult(name, status="completed") for name in V01_PIPELINE_STAGES}
        self.assertEqual([stages[name].to_dict()["stage"] for name in V01_PIPELINE_STAGES][-1], "COMPLETED")

    def test_final_report_schema_name_is_deepduck(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            write_json(Path(tmp) / "t" / "reports" / "analysis.json", base_report())
            model = ReportGenerator(tmp, "t").build_model({"findings": []})
            self.assertEqual(model.to_dict()["schema_version"], "deepduck.report.v1")


if __name__ == "__main__":
    unittest.main()
