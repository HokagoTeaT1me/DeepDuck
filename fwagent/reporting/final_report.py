from __future__ import annotations

import hashlib
import html
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fwagent import __version__
from fwagent.findings import FindingClaimGuard, FINDING_STATUSES


REPORT_SCHEMA_VERSION = "deepduck.report.v1"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass
class ArtifactIndexItem:
    type: str
    path: str
    description: str
    exists: bool
    size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class AnalysisReport:
    metadata: dict[str, Any]
    firmware_summary: dict[str, Any]
    investigation_summary: dict[str, Any]
    attack_surface_summary: dict[str, Any]
    component_summary: dict[str, Any]
    findings: list[dict[str, Any]]
    rejected_hypotheses: list[dict[str, Any]]
    inconclusive_hypotheses: list[dict[str, Any]]
    blocked_items: list[dict[str, Any]]
    runtime_repairs: list[dict[str, Any]]
    evidence_summary: dict[str, Any]
    timeline: list[dict[str, Any]]
    remaining_problems: list[str]
    provider_status: dict[str, Any]
    artifact_index: list[dict[str, Any]]
    validation: dict[str, Any] = field(default_factory=dict)
    components: list[dict[str, Any]] = field(default_factory=list)
    attack_surface: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": REPORT_SCHEMA_VERSION,
            "task_id": self.metadata.get("task_id"),
            "firmware": self.firmware_summary,
            "analysis_status": self.metadata.get("analysis_status"),
            "summary": {
                "findings": len(self.findings),
                "supported": sum(1 for item in self.findings if item.get("status") == "supported"),
                "runtime_supported": sum(1 for item in self.findings if item.get("status") == "runtime_supported"),
                "candidate_or_inconclusive": sum(1 for item in self.findings if item.get("status") in {"candidate", "inconclusive", "informational"}),
                "blocked": sum(1 for item in self.findings if item.get("status") == "blocked"),
                "remaining_problems": self.remaining_problems,
            },
            "components": self.components,
            "attack_surface": {
                "summary": self.attack_surface_summary,
                "entries": self.attack_surface,
            },
            "findings": self.findings,
            "hypotheses": self.hypotheses,
            "validation": self.validation,
            "evidence_statistics": self.evidence_summary,
            "investigation": self.investigation_summary,
            "runtime_repairs": self.runtime_repairs,
            "remaining_problems": self.remaining_problems,
            "provider_metadata": self.provider_status,
            "artifacts": self.artifact_index,
            "metadata": self.metadata,
            "rejected_hypotheses": self.rejected_hypotheses,
            "inconclusive_hypotheses": self.inconclusive_hypotheses,
            "blocked_items": self.blocked_items,
            "timeline": self.timeline,
        }


class ReportValidator:
    def __init__(self) -> None:
        self.guard = FindingClaimGuard()

    def validate(self, report: AnalysisReport) -> dict[str, Any]:
        errors: list[str] = []
        evidence_ids = set(report.evidence_summary.get("ids") or [])
        artifact_paths = {item.get("path") for item in report.artifact_index}
        for finding in report.findings:
            if not finding.get("title"):
                errors.append(f"{finding.get('finding_id')}: title empty")
            if finding.get("status") not in FINDING_STATUSES:
                errors.append(f"{finding.get('finding_id')}: invalid status")
            for evidence_id in list(finding.get("dynamic_evidence_ids") or []) + list(finding.get("static_evidence_ids") or []):
                if evidence_id.startswith("MDE-"):
                    errors.append(f"{finding.get('finding_id')}: mock evidence referenced")
                if evidence_id.startswith("DE-") and evidence_id not in evidence_ids:
                    errors.append(f"{finding.get('finding_id')}: missing evidence reference {evidence_id}")
            ok, reason = self.guard.validate(json.dumps(finding, sort_keys=True))
            if not ok:
                errors.append(f"{finding.get('finding_id')}: {reason}")
        for item in report.artifact_index:
            if item.get("exists") and item.get("path") not in artifact_paths:
                errors.append(f"artifact index inconsistent: {item.get('path')}")
            if Path(str(item.get("path"))).is_absolute():
                errors.append(f"artifact path should be workspace-relative: {item.get('path')}")
        return {"success": not errors, "errors": errors, "checked_at": utc_now_iso()}


class ReportGenerator:
    def __init__(self, workspace_root: str | Path, task_id: str):
        self.workspace_root = Path(workspace_root).resolve()
        self.task_id = task_id
        self.task_dir = self.workspace_root / task_id
        self.reports_dir = self.task_dir / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def build_model(self, findings_payload: dict[str, Any] | None = None, *, analysis_status: str = "COMPLETED_WITH_UNCERTAINTY") -> AnalysisReport:
        analysis = self._load("reports/analysis.json")
        investigation = self._load("investigation/summary.json")
        surface = self._load("surface/attack_surface_summary.json")
        entries = self._load("surface/entry_points.json") or []
        graph = self._load("correlation/summary.json")
        graph_full = self._load("correlation/component_graph.json")
        hypotheses = self._load("dynamic/hypotheses.json") or []
        evidence = self._load("dynamic/evidence/evidence.json") or []
        findings_payload = findings_payload or self._load("findings/findings.json") or {"findings": []}
        findings = findings_payload.get("findings") or []
        evidence_ids = [item.get("id") for item in evidence if item.get("id")]
        metadata = {
            "schema_version": REPORT_SCHEMA_VERSION,
            "deepduck_version": __version__,
            "task_id": self.task_id,
            "generated_at": utc_now_iso(),
            "analysis_status": analysis_status,
            "host_mode": "Windows + Docker",
            "static_worker_image": "fwagent-round2:latest",
            "dynamic_worker_image": "fwagent-round2:latest",
            "provider_backed": False,
            "planner": "deterministic",
            "real_model_validation": "deferred",
        }
        rejected = [item for item in hypotheses if item.get("status") in {"rejected", "dynamically_rejected"} or item.get("dynamic_status") == "dynamically_rejected"]
        inconclusive = [item for item in hypotheses if item.get("status") == "validation_inconclusive" or item.get("dynamic_status") == "validation_inconclusive"]
        blocked = [item for item in hypotheses if item.get("status") == "validation_blocked" or item.get("dynamic_status") == "validation_blocked"]
        return AnalysisReport(
            metadata=metadata,
            firmware_summary=analysis.get("firmware") or {},
            investigation_summary=investigation.get("summary") or {},
            attack_surface_summary=surface or {},
            component_summary=graph or {},
            findings=findings,
            rejected_hypotheses=rejected,
            inconclusive_hypotheses=inconclusive,
            blocked_items=blocked,
            runtime_repairs=self._runtime_repairs(),
            evidence_summary={"total": len(evidence), "dynamic": len([item for item in evidence if str(item.get("id", "")).startswith("DE-")]), "ids": evidence_ids},
            timeline=self._timeline(),
            remaining_problems=self._remaining_problems(findings, blocked),
            provider_status={"provider_backed": False, "planner": "deterministic", "real_model_validation": "deferred"},
            artifact_index=[item.to_dict() for item in self._artifact_index()],
            validation={"investigation": investigation.get("summary") or {}, "provider_backed": False},
            components=(graph_full.get("components") if isinstance(graph_full, dict) else []) or [],
            attack_surface=entries,
            hypotheses=hypotheses,
        )

    def generate_json(self, model: AnalysisReport) -> Path:
        path = self.reports_dir / "report.json"
        path.write_text(json.dumps(model.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def generate_markdown(self, model: AnalysisReport) -> Path:
        path = self.reports_dir / "report.md"
        lines = [
            "# DeepDuck Firmware Security Analysis Report",
            "",
            "## Executive Summary",
            "",
            f"Task: `{model.metadata.get('task_id')}`",
            f"Status: `{model.metadata.get('analysis_status')}`",
            f"Findings: `{len(model.findings)}`",
            "Provider: deterministic (`provider_backed=false`, real model validation deferred)",
            "",
            "## Analysis Scope",
            "",
            "Analysis was performed against a local firmware artifact in an isolated environment. Reachability does not imply exploitability. Candidate findings require validation. No public target scanning was performed.",
            "",
            "## Firmware Overview",
            "",
            f"- File: `{model.firmware_summary.get('filename') or 'unknown'}`",
            f"- SHA256: `{model.firmware_summary.get('sha256') or 'unknown'}`",
            f"- Type: `{model.firmware_summary.get('file_type') or 'unknown'}`",
            "",
            "## Investigation Summary",
            "",
            f"- Iterations: `{model.investigation_summary.get('iterations', 0)}`",
            f"- Stop reason: `{model.investigation_summary.get('stop_reason') or 'not_executed'}`",
            f"- Provider backed: `{model.provider_status.get('provider_backed')}`",
            "",
            "## Attack Surface",
            "",
            f"- Entry points: `{len(model.attack_surface)}`",
            f"- Summary: `{model.attack_surface_summary.get('entry_points', model.attack_surface_summary.get('total_entry_points', 'not established'))}`",
            "",
            "## Component Overview",
            "",
            f"- Components: `{len(model.components) or model.component_summary.get('total_components', 0)}`",
            "",
            "## Findings",
            "",
        ]
        if not model.findings:
            lines.append("No final findings were promoted from canonical evidence.")
        for finding in model.findings:
            lines.extend(self._finding_markdown(finding))
        lines.extend(
            [
                "",
                "## Rejected / Inconclusive Hypotheses",
                "",
                f"- Rejected: `{len(model.rejected_hypotheses)}`",
                f"- Inconclusive: `{len(model.inconclusive_hypotheses)}`",
                "",
                "## Blocked Analysis",
                "",
                f"- Blocked items: `{len(model.blocked_items)}`",
                "",
                "## Runtime Repairs",
                "",
                f"- Runtime repair artifacts: `{len(model.runtime_repairs)}`",
                "",
                "## Evidence Statistics",
                "",
                f"- Evidence total: `{model.evidence_summary.get('total', 0)}`",
                f"- Dynamic evidence: `{model.evidence_summary.get('dynamic', 0)}`",
                "",
                "## Investigation Timeline",
                "",
            ]
        )
        if model.timeline:
            for item in model.timeline:
                lines.append(f"- Iteration `{item.get('iteration')}`: {item.get('action')} `{item.get('target') or 'none'}` — {item.get('result')}")
        else:
            lines.append("- Not executed.")
        lines.extend(
            [
                "",
                "## Safety / Scope Notes",
                "",
                "- Reachability does not imply exploitability.",
                "- Candidate findings require validation.",
                "- Mock/simulation evidence is excluded from canonical findings.",
                "- No public target scanning was performed.",
                "",
                "## Artifacts",
                "",
            ]
        )
        for artifact in model.artifact_index:
            lines.append(f"- `{artifact.get('path')}` ({artifact.get('type')}): {artifact.get('description')} — exists={artifact.get('exists')}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return path

    def generate_html(self, model: AnalysisReport) -> Path:
        path = self.reports_dir / "report.html"
        finding_rows = "\n".join(
            f"<tr><td>{html.escape(item.get('finding_id',''))}</td><td>{html.escape(item.get('title',''))}</td><td><span class='badge'>{html.escape(item.get('status',''))}</span></td><td>{html.escape(item.get('severity_hint','unknown'))}</td><td>{item.get('confidence',0)}</td></tr>"
            for item in model.findings
        )
        finding_details = "\n".join(self._finding_html(item) for item in model.findings)
        attack_rows = "\n".join(
            f"<tr><td>{html.escape(str(item.get('entry_id') or item.get('id') or ''))}</td><td>{html.escape(str(item.get('entry_type') or item.get('type') or ''))}</td><td>{html.escape(str(item.get('component_id') or item.get('target_component_id') or ''))}</td></tr>"
            for item in model.attack_surface[:50]
        )
        timeline = "\n".join(f"<li>Iteration {html.escape(str(item.get('iteration')))}: {html.escape(str(item.get('action')))} {html.escape(str(item.get('target') or 'none'))}</li>" for item in model.timeline)
        html_text = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DeepDuck Firmware Security Analysis Report</title>
<style>
body {{ font-family: Segoe UI, Arial, sans-serif; margin: 2rem; color: #1f2937; background: #f8fafc; }}
h1, h2, h3 {{ color: #0f172a; }}
.cards {{ display: flex; flex-wrap: wrap; gap: 1rem; }}
.card {{ background: white; border: 1px solid #dbe3ef; border-radius: 8px; padding: 1rem; min-width: 10rem; box-shadow: 0 1px 2px #dbe3ef; }}
.badge {{ display: inline-block; padding: .15rem .5rem; border-radius: 999px; background: #e0f2fe; color: #075985; font-size: .85rem; }}
table {{ border-collapse: collapse; width: 100%; background: white; margin: 1rem 0; }}
th, td {{ border: 1px solid #dbe3ef; padding: .55rem; text-align: left; vertical-align: top; }}
th {{ background: #e2e8f0; }}
details {{ background: white; border: 1px solid #dbe3ef; border-radius: 8px; padding: .75rem; margin: .75rem 0; }}
code {{ background: #e2e8f0; padding: .1rem .25rem; border-radius: 4px; }}
</style>
</head>
<body>
<h1>DeepDuck Firmware Security Analysis Report</h1>
<p>Local isolated analysis. Reachability does not imply exploitability. No public target scanning was performed.</p>
<div class="cards">
<div class="card"><strong>Task</strong><br>{html.escape(str(model.metadata.get('task_id')))}</div>
<div class="card"><strong>Status</strong><br>{html.escape(str(model.metadata.get('analysis_status')))}</div>
<div class="card"><strong>Findings</strong><br>{len(model.findings)}</div>
<div class="card"><strong>Provider</strong><br>deterministic / provider_backed=false</div>
</div>
<h2>Finding Table</h2>
<table><thead><tr><th>ID</th><th>Title</th><th>Status</th><th>Severity Hint</th><th>Confidence</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>Finding Details</h2>
{finding_details or '<p>No final findings were promoted from canonical evidence.</p>'}
<h2>Attack Surface</h2>
<table><thead><tr><th>Entry</th><th>Type</th><th>Component</th></tr></thead><tbody>{attack_rows}</tbody></table>
<h2>Component Summary</h2>
<p>Components: <code>{html.escape(str(len(model.components) or model.component_summary.get('total_components', 0)))}</code></p>
<h2>Investigation Timeline</h2>
<ul>{timeline or '<li>Not executed.</li>'}</ul>
<h2>Evidence Counts</h2>
<p>Total: <code>{model.evidence_summary.get('total', 0)}</code>, Dynamic: <code>{model.evidence_summary.get('dynamic', 0)}</code></p>
<h2>Safety / Scope Notes</h2>
<ul><li>Candidate findings require validation.</li><li>Mock evidence is excluded from canonical findings.</li><li>Real model validation deferred.</li></ul>
</body>
</html>
"""
        path.write_text(html_text, encoding="utf-8")
        return path

    def generate_all(self, model: AnalysisReport, formats: set[str] | None = None) -> dict[str, str]:
        formats = formats or {"json", "md", "html"}
        paths: dict[str, Path] = {}
        if "json" in formats:
            paths["json"] = self.generate_json(model)
        if "md" in formats:
            paths["md"] = self.generate_markdown(model)
        if "html" in formats:
            paths["html"] = self.generate_html(model)
        self._write_report_manifest(paths)
        return {key: self._relative(path) for key, path in paths.items()}

    def _finding_markdown(self, finding: dict[str, Any]) -> list[str]:
        chain = finding.get("evidence_chain") or {}
        return [
            f"### {finding.get('finding_id')}: {finding.get('title')}",
            "",
            f"Status: `{finding.get('status')}`",
            f"Confidence: `{finding.get('confidence')}`",
            f"Category: `{finding.get('category')}`",
            f"Severity Hint: `{finding.get('severity_hint')}`",
            "",
            f"Affected Components: `{', '.join(finding.get('affected_components') or []) or 'not established'}`",
            f"Entry Point: `{', '.join(finding.get('entry_point_ids') or []) or 'not established'}`",
            "",
            f"Evidence Summary: {finding.get('summary')}",
            f"Static Support: `{', '.join(finding.get('static_evidence_ids') or []) or 'not established'}`",
            f"Runtime Support: `{finding.get('runtime_support')}`",
            f"Source-to-Sink Context: source `{', '.join(chain.get('source') or []) or 'not established'}` → sink `{', '.join(chain.get('sink') or []) or 'not established'}`",
            f"Validation Result: `{finding.get('validation_status')}`",
            f"Remaining Uncertainty: `{', '.join(finding.get('remaining_uncertainty') or []) or 'unknown'}`",
            f"Candidate CWE: `{', '.join(finding.get('candidate_cwe_ids') or []) or 'none'}`",
            "",
        ]

    def _finding_html(self, finding: dict[str, Any]) -> str:
        chain = finding.get("evidence_chain") or {}
        return f"""<details>
<summary>{html.escape(finding.get('finding_id',''))}: {html.escape(finding.get('title',''))}</summary>
<p><strong>Status:</strong> {html.escape(finding.get('status',''))} | <strong>Confidence:</strong> {finding.get('confidence',0)} | <strong>Severity:</strong> {html.escape(finding.get('severity_hint','unknown'))}</p>
<p>{html.escape(finding.get('summary',''))}</p>
<p><strong>Entry:</strong> {html.escape(', '.join(finding.get('entry_point_ids') or []) or 'not established')}</p>
<p><strong>Source → Sink:</strong> {html.escape(', '.join(chain.get('source') or []) or 'not established')} → {html.escape(', '.join(chain.get('sink') or []) or 'not established')}</p>
<p><strong>Validation:</strong> {html.escape(finding.get('validation_status','not_established'))}</p>
<p><strong>Remaining uncertainty:</strong> {html.escape(', '.join(finding.get('remaining_uncertainty') or []) or 'unknown')}</p>
</details>"""

    def _load(self, relative: str) -> Any:
        path = self.task_dir / relative
        if not path.exists():
            return {} if relative.endswith(".json") else None
        return json.loads(path.read_text(encoding="utf-8"))

    def _artifact_index(self) -> list[ArtifactIndexItem]:
        specs = [
            ("static_analysis", "reports/analysis.json", "Static firmware analysis report"),
            ("component_graph", "correlation/component_graph.json", "Cross-component graph"),
            ("surface", "surface/attack_surface_summary.json", "Attack surface summary"),
            ("taint", "taint/summary.json", "Input-to-sink correlation summary"),
            ("hypotheses", "hypotheses/synthesis_analysis.json", "Hypothesis synthesis artifact"),
            ("investigation", "investigation/summary.json", "Autonomous investigation summary"),
            ("dynamic_evidence", "dynamic/evidence/evidence.json", "Canonical dynamic evidence"),
            ("runtime_logs", "dynamic/logs", "Runtime logs directory"),
            ("findings", "findings/findings.json", "Final findings"),
            ("reports", "reports", "Generated final reports"),
        ]
        items: list[ArtifactIndexItem] = []
        for artifact_type, relative, description in specs:
            path = self.task_dir / relative
            size = path.stat().st_size if path.exists() and path.is_file() else 0
            items.append(ArtifactIndexItem(artifact_type, relative, description, path.exists(), size))
        return items

    def write_artifact_manifest(self) -> Path:
        artifacts = []
        for item in self._artifact_index():
            path = self.task_dir / item.path
            artifacts.append(
                {
                    "artifact_id": f"ART-{len(artifacts)+1:04d}",
                    "type": item.type,
                    "relative_path": item.path,
                    "hash": _hash_path(path) if path.exists() and path.is_file() else None,
                    "size": item.size,
                    "created_at": utc_now_iso(),
                    "producer_phase": item.type,
                    "canonical": item.type not in {"runtime_logs"},
                }
            )
        output = self.task_dir / "artifact_manifest.json"
        output.write_text(json.dumps({"schema_version": REPORT_SCHEMA_VERSION, "artifacts": artifacts}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return output

    def _write_report_manifest(self, paths: dict[str, Path]) -> Path:
        reports = {
            key: {
                "relative_path": self._relative(path),
                "hash": _hash_path(path),
                "schema_version": REPORT_SCHEMA_VERSION,
            }
            for key, path in paths.items()
        }
        output = self.reports_dir / "report_manifest.json"
        output.write_text(json.dumps({"schema_version": REPORT_SCHEMA_VERSION, "reports": reports}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return output

    def _relative(self, path: Path) -> str:
        return path.relative_to(self.task_dir).as_posix()

    def _runtime_repairs(self) -> list[dict[str, Any]]:
        repairs = []
        for path in (self.task_dir / "dynamic").glob("**/*repair*.json") if (self.task_dir / "dynamic").exists() else []:
            repairs.append({"path": path.relative_to(self.task_dir).as_posix(), "exists": True})
        return repairs

    def _timeline(self) -> list[dict[str, Any]]:
        path = self.task_dir / "investigation" / "action_history.json"
        if not path.exists():
            return []
        return json.loads(path.read_text(encoding="utf-8"))

    def _remaining_problems(self, findings: list[dict[str, Any]], blocked: list[dict[str, Any]]) -> list[str]:
        problems = []
        if blocked:
            problems.append("Some hypotheses or validations are blocked.")
        if any(item.get("status") in {"candidate", "inconclusive"} for item in findings):
            problems.append("Some findings remain candidate or inconclusive.")
        problems.append("Real model validation deferred.")
        return problems


def _hash_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
