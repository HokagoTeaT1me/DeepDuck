from __future__ import annotations

import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent.dynamic.config import DynamicConfig, load_dynamic_config
from fwagent.dynamic.correlation import ComponentGraphBuilder
from fwagent.dynamic.investigation import InvestigationController
from fwagent.dynamic.prioritization import HypothesisValidationScheduler
from fwagent.dynamic.surface import AttackSurfaceBuilder
from fwagent.dynamic.synthesis import HypothesisSynthesizer
from fwagent.dynamic.taint import TaintAnalysisBuilder
from fwagent.findings import FindingFinalizer
from fwagent.pipeline.analyzer import analyze_firmware
from fwagent.reporting.final_report import ReportGenerator, ReportValidator, REPORT_SCHEMA_VERSION
from fwagent.reporting.json_report import load_analysis_json
from fwagent.tools.common import sha256_file


EXIT_ANALYSIS_COMPLETED = 0
EXIT_PARTIAL = 1
EXIT_INVALID_INPUT = 2
EXIT_ENVIRONMENT_MISSING = 3
EXIT_PIPELINE_FAILURE = 4
EXIT_SAFETY_STOP = 5

PIPELINE_PHASES = {
    "task_create",
    "input_prepare",
    "environment_check",
    "static_analysis",
    "investigation_prepare",
    "investigation",
    "finding_finalize",
    "report_generation",
    "completed",
    "blocked",
    "failed",
    "interrupted",
}


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class AnalysisTask:
    task_id: str
    input_path: str
    input_hash: str
    firmware_name: str
    workspace: str
    created_at: str = field(default_factory=utc_now_iso)
    status: str = "created"
    pipeline_phase: str = "task_create"
    analysis_mode: str = "full"
    provider_backed: bool = False
    report_paths: dict[str, str] = field(default_factory=dict)
    error: dict[str, Any] | None = None
    resume_available: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class AnalysisPipelineController:
    def __init__(self, workspace_root: str | Path = "workspace", *, config: DynamicConfig | None = None):
        self.workspace_root = Path(workspace_root).resolve()
        self.workspace_root.mkdir(parents=True, exist_ok=True)
        self.config = config or load_dynamic_config()

    def analyze(
        self,
        firmware: str | Path,
        *,
        task_id: str | None = None,
        resume: bool = False,
        report_formats: set[str] | None = None,
        static_only: bool = False,
        no_dynamic: bool = False,
        max_iterations: int | None = None,
        output_dir: str | Path | None = None,
        progress: bool = True,
        timeout: int = 600,
    ) -> dict[str, Any]:
        started = time.monotonic()
        source = Path(firmware)
        if resume and task_id and not source.exists():
            task = self.load_task(task_id)
            if not task:
                return self._invalid(str(source), task_id, "RESUME_STATE_INVALID", "resume task not found")
            source = Path(task.input_path)
        if not source.exists():
            return self._invalid(str(source), task_id, "INPUT_NOT_FOUND", "firmware input not found")
        input_hash = sha256_file(source)
        task_id = task_id or self._new_task_id(input_hash)
        task_dir = self.workspace_root / task_id
        task = self.load_task(task_id) if resume else None
        if not task:
            task = AnalysisTask(
                task_id=task_id,
                input_path=str(source.resolve()),
                input_hash=input_hash,
                firmware_name=source.name,
                workspace=str(task_dir),
                analysis_mode="static-only" if static_only else "no-dynamic" if no_dynamic else "full",
            )
            self._save_task(task)
        dynamic_executed = False
        errors: list[dict[str, Any]] = []
        timings: dict[str, float] = {}
        try:
            self._progress(progress, "[1/8] Preparing firmware")
            self._phase(task, "input_prepare", "running")
            if not resume or not (task_dir / "reports" / "analysis.json").exists():
                self._progress(progress, "[2/8] Static analysis")
                self._phase(task, "static_analysis", "running")
                step = time.monotonic()
                analyze_firmware(source, workspace=self.workspace_root, timeout=timeout, task_id=task_id)
                timings["static"] = round(time.monotonic() - step, 3)
            else:
                timings["static"] = 0.0
            if static_only:
                self._progress(progress, "[3/8] Building component graph")
                self._static_artifacts(task_id, errors, timings)
            else:
                self._progress(progress, "[3/8] Building component graph")
                self._progress(progress, "[4/8] Mapping attack surface")
                self._progress(progress, "[5/8] Correlating input-to-sink paths")
                self._progress(progress, "[6/8] Synthesizing hypotheses")
                self._phase(task, "investigation_prepare", "running")
                self._static_artifacts(task_id, errors, timings)
                if no_dynamic:
                    errors.append(self._error("DYNAMIC_NOT_EXECUTED", "dynamic validation skipped by --no-dynamic", recoverable=True))
                else:
                    self._progress(progress, "[7/8] Running investigation")
                    self._phase(task, "investigation", "running")
                    step = time.monotonic()
                    investigation = InvestigationController(self.workspace_root, task_id, config=self.config).run(resume=resume, max_iterations=max_iterations)
                    dynamic_executed = bool(investigation.get("success"))
                    timings["investigation"] = round(time.monotonic() - step, 3)
            self._progress(progress, "[8/8] Generating report")
            self._phase(task, "finding_finalize", "running")
            findings = FindingFinalizer(str(self.workspace_root), task_id).finalize(dynamic_executed=dynamic_executed)
            self._phase(task, "report_generation", "running")
            generator = ReportGenerator(self.workspace_root, task_id)
            status = self._analysis_status(errors, static_only=static_only, no_dynamic=no_dynamic)
            model = generator.build_model(findings, analysis_status=status)
            report_paths = generator.generate_all(model, report_formats)
            artifact_manifest = generator.write_artifact_manifest()
            validation = ReportValidator().validate(model)
            if not validation["success"]:
                errors.append(self._error("REPORT_VALIDATION_FAILED", "; ".join(validation["errors"]), recoverable=False))
            if output_dir:
                self._copy_reports(task_id, output_dir)
            total = round(time.monotonic() - started, 3)
            task.report_paths = report_paths
            task.status = "completed" if not errors else "partial"
            task.pipeline_phase = "completed"
            self._save_task(task)
            static_report = load_analysis_json(task_dir / "reports" / "analysis.json")
            summary = self._summary(task, model.to_dict(), timings, total, dynamic_executed, errors, artifact_manifest, static_report)
            (task_dir / "pipeline_summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return summary
        except KeyboardInterrupt:
            task.status = "paused"
            task.pipeline_phase = "interrupted"
            self._save_task(task)
            raise
        except Exception as exc:  # noqa: BLE001
            task.status = "failed"
            task.pipeline_phase = "failed"
            task.error = self._error("PIPELINE_FAILURE", str(exc), recoverable=True)
            self._save_task(task)
            return {
                "success": False,
                "exit_code": EXIT_PIPELINE_FAILURE,
                "error": task.error,
                "task": task.to_dict(),
                "provider_backed": False,
            }

    def regenerate_report(self, task_id: str, *, report_formats: set[str] | None = None) -> dict[str, Any]:
        findings_path = self.workspace_root / task_id / "findings" / "findings.json"
        findings = json.loads(findings_path.read_text(encoding="utf-8")) if findings_path.exists() else FindingFinalizer(str(self.workspace_root), task_id).finalize(dynamic_executed=False)
        generator = ReportGenerator(self.workspace_root, task_id)
        model = generator.build_model(findings)
        paths = generator.generate_all(model, report_formats)
        manifest = generator.write_artifact_manifest()
        task = self.load_task(task_id)
        if task:
            task.report_paths = paths
            task.pipeline_phase = "completed"
            task.status = "completed"
            self._save_task(task)
        return {"success": True, "task_id": task_id, "report_paths": paths, "artifact_manifest": manifest.relative_to(self.workspace_root / task_id).as_posix(), "provider_backed": False}

    def status(self, task_id: str) -> dict[str, Any]:
        task = self.load_task(task_id)
        task_dir = self.workspace_root / task_id
        report = task_dir / "reports" / "report.json"
        findings = []
        if report.exists():
            findings = json.loads(report.read_text(encoding="utf-8")).get("findings") or []
        investigation = {}
        summary_path = task_dir / "investigation" / "summary.json"
        if summary_path.exists():
            investigation = json.loads(summary_path.read_text(encoding="utf-8")).get("state") or {}
        synthetic_task = task or (
            AnalysisTask(task_id, "", "", "", str(task_dir), status="unknown", pipeline_phase="completed")
            if task_dir.exists()
            else None
        )
        return {
            "success": synthetic_task is not None,
            "task": synthetic_task.to_dict() if synthetic_task else None,
            "pipeline_phase": synthetic_task.pipeline_phase if synthetic_task else "missing",
            "investigation_phase": investigation.get("phase", "not_executed"),
            "findings": len(findings),
            "reports": self._report_paths(task_id),
            "resume_available": bool(synthetic_task and synthetic_task.resume_available),
            "blockers": (synthetic_task.error if synthetic_task and synthetic_task.error else None),
            "provider_backed": False,
        }

    def cleanup(self, task_id: str, *, all_artifacts: bool = False) -> dict[str, Any]:
        task_dir = self.workspace_root / task_id
        if not task_dir.exists():
            return {"success": False, "error": "TASK_NOT_FOUND", "provider_backed": False}
        if all_artifacts:
            if self.workspace_root not in task_dir.resolve().parents:
                return {"success": False, "error": "WORKSPACE_BOUNDARY_VIOLATION", "provider_backed": False}
            shutil.rmtree(task_dir)
            return {"success": True, "removed_task": True, "provider_backed": False}
        removed = []
        for relative in ("scratch", "tmp", "dynamic/tmp", "dynamic/runtime_scratch"):
            path = task_dir / relative
            if path.exists():
                shutil.rmtree(path)
                removed.append(relative)
        cleanup_state = {"success": True, "removed": removed, "canonical_preserved": True, "provider_backed": False, "cleaned_at": utc_now_iso()}
        (task_dir / "cleanup.json").write_text(json.dumps(cleanup_state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return cleanup_state

    def load_task(self, task_id: str) -> AnalysisTask | None:
        path = self.workspace_root / task_id / "task.json"
        if not path.exists():
            return None
        return AnalysisTask(**json.loads(path.read_text(encoding="utf-8")))

    def _static_artifacts(self, task_id: str, errors: list[dict[str, Any]], timings: dict[str, float]) -> None:
        builders = [
            ("component_graph", lambda: ComponentGraphBuilder(self.workspace_root, task_id, config=self.config).build()),
            ("attack_surface", lambda: AttackSurfaceBuilder(self.workspace_root, task_id, config=self.config).build()),
            ("taint", lambda: TaintAnalysisBuilder(self.workspace_root, task_id, config=self.config).build()),
            ("synthesis", lambda: HypothesisSynthesizer(self.workspace_root, task_id, config=self.config).build()),
            ("prioritization", lambda: HypothesisValidationScheduler(self.workspace_root, task_id, config=self.config).assess()),
        ]
        for name, func in builders:
            step = time.monotonic()
            try:
                func()
            except Exception as exc:  # noqa: BLE001
                errors.append(self._error(f"{name.upper()}_FAILED", str(exc), recoverable=True))
            finally:
                timings[name] = round(time.monotonic() - step, 3)

    def _save_task(self, task: AnalysisTask) -> None:
        task_dir = self.workspace_root / task.task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        (task_dir / "task.json").write_text(json.dumps(task.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def _phase(self, task: AnalysisTask, phase: str, status: str) -> None:
        if phase not in PIPELINE_PHASES:
            raise ValueError(f"invalid pipeline phase: {phase}")
        task.pipeline_phase = phase
        task.status = status
        self._save_task(task)

    def _summary(
        self,
        task: AnalysisTask,
        report: dict[str, Any],
        timings: dict[str, float],
        total_duration: float,
        dynamic_executed: bool,
        errors: list[dict[str, Any]],
        artifact_manifest: Path,
        static_report: dict[str, Any],
    ) -> dict[str, Any]:
        investigation = report.get("investigation") or {}
        payload = {
            "success": True,
            "exit_code": EXIT_ANALYSIS_COMPLETED if not errors else EXIT_PARTIAL,
            "task": task.to_dict(),
            "task_id": task.task_id,
            "status": task.status,
            "analysis_status": report.get("analysis_status"),
            "findings": report.get("summary", {}),
            "report_paths": task.report_paths,
            "artifact_manifest": artifact_manifest.relative_to(self.workspace_root / task.task_id).as_posix(),
            "firmware": static_report.get("firmware") or {},
            "platform": static_report.get("platform") or {},
            "duration": {
                "total": total_duration,
                "static": timings.get("static", 0.0),
                "dynamic": timings.get("investigation", 0.0),
                "stages": timings,
            },
            "investigation_iterations": investigation.get("iterations", 0),
            "final_stop_reason": investigation.get("stop_reason") or "not_executed",
            "dynamic_executed": dynamic_executed,
            "errors": errors,
            "provider_backed": False,
            "planner": "deterministic",
            "real_model_validation": "deferred",
            "schema_version": REPORT_SCHEMA_VERSION,
        }
        return payload

    def _analysis_status(self, errors: list[dict[str, Any]], *, static_only: bool, no_dynamic: bool) -> str:
        if static_only:
            return "STATIC_ONLY_COMPLETED"
        if no_dynamic or errors:
            return "COMPLETED_WITH_UNCERTAINTY"
        return "COMPLETED_WITH_UNCERTAINTY"

    def _invalid(self, firmware: str, task_id: str | None, code: str, message: str) -> dict[str, Any]:
        return {
            "success": False,
            "exit_code": EXIT_INVALID_INPUT,
            "error": self._error(code, message, recoverable=False),
            "task_id": task_id,
            "firmware": firmware,
            "provider_backed": False,
        }

    def _error(self, code: str, message: str, *, recoverable: bool) -> dict[str, Any]:
        return {"code": code, "message": message, "recoverable": recoverable}

    def _new_task_id(self, input_hash: str) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"{stamp}-{input_hash[:8]}"

    def _progress(self, enabled: bool, message: str) -> None:
        if enabled:
            print(message)

    def _copy_reports(self, task_id: str, output_dir: str | Path) -> None:
        target = Path(output_dir)
        target.mkdir(parents=True, exist_ok=True)
        for path in (self.workspace_root / task_id / "reports").glob("report.*"):
            shutil.copy2(path, target / path.name)

    def _report_paths(self, task_id: str) -> dict[str, str]:
        reports_dir = self.workspace_root / task_id / "reports"
        return {path.suffix.lstrip("."): path.relative_to(self.workspace_root / task_id).as_posix() for path in reports_dir.glob("report.*") if path.is_file()}


def parse_report_formats(value: str | None) -> set[str] | None:
    if not value or value == "all":
        return None
    aliases = {"markdown": "md", "json": "json", "html": "html", "md": "md"}
    formats = {aliases.get(item.strip().lower(), item.strip().lower()) for item in value.split(",") if item.strip()}
    invalid = formats - {"json", "md", "html"}
    if invalid:
        raise ValueError(f"invalid report format(s): {', '.join(sorted(invalid))}")
    return formats
