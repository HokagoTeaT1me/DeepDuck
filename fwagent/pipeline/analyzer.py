from __future__ import annotations

import time
from pathlib import Path
from typing import Callable

from fwagent.config import AnalysisConfig, SCHEMA_VERSION
from fwagent.models import ModuleError
from fwagent.pipeline.context import create_workspace, save_state
from fwagent.reporting.json_report import save_analysis_json
from fwagent.runtime.command import CommandRunner
from fwagent.tools import (
    analyze_binaries,
    discover_services,
    discover_web_surface,
    extract_firmware,
    identify_architecture,
    identify_firmware,
    inventory_filesystem,
    rank_binaries,
    scan_sensitive_files,
)


def analyze_firmware(
    firmware_path: str | Path,
    *,
    workspace: str | Path = "workspace",
    timeout: int = 600,
    task_id: str | None = None,
) -> tuple[dict, Path]:
    source = Path(firmware_path).resolve()
    if not source.exists():
        raise FileNotFoundError(source)

    config = AnalysisConfig(workspace_root=Path(workspace), timeout=timeout)
    context = create_workspace(source, config.workspace_root, task_id=task_id)
    runner = CommandRunner(context.logs_dir, default_timeout=config.command_timeout)
    timings: dict[str, float] = {}
    errors: list[dict] = []

    firmware = _run_step(
        "firmware",
        timings,
        errors,
        lambda: identify_firmware(context.input_firmware, runner),
        default={},
    )

    extraction = _run_step(
        "extractor",
        timings,
        errors,
        lambda: extract_firmware(context.input_firmware, context.extracted_dir, runner, timeout=config.timeout),
        default={"success": False, "extractor": "none", "rootfs_candidates": [], "files_extracted": 0, "errors": []},
    )
    errors.extend(extraction.get("errors", []))

    rootfs_path = _select_rootfs(extraction)
    filesystem = {}
    architecture = {}
    services_result = {"services": []}
    web = {"roots": [], "cgi": [], "scripts": [], "candidate_backend_binaries": []}
    security_candidates: list[dict] = []
    binaries: list[dict] = []
    priority: list[dict] = []

    if rootfs_path:
        filesystem = _run_step(
            "filesystem",
            timings,
            errors,
            lambda: inventory_filesystem(rootfs_path),
            default={},
        )
        elf_files = filesystem.get("categories", {}).get("elf", [])
        architecture = _run_step(
            "architecture",
            timings,
            errors,
            lambda: identify_architecture(rootfs_path, elf_files),
            default={},
        )
        services_result = _run_step(
            "services",
            timings,
            errors,
            lambda: discover_services(rootfs_path),
            default={"services": []},
        )
        web = _run_step(
            "web",
            timings,
            errors,
            lambda: discover_web_surface(rootfs_path),
            default={"roots": [], "cgi": [], "scripts": [], "candidate_backend_binaries": []},
        )
        security_candidates = _run_step(
            "secrets",
            timings,
            errors,
            lambda: scan_sensitive_files(rootfs_path),
            default=[],
        )
        binaries = _run_step(
            "binaries",
            timings,
            errors,
            lambda: analyze_binaries(rootfs_path, elf_files, runner),
            default=[],
        )
        priority = _run_step(
            "binary_ranking",
            timings,
            errors,
            lambda: rank_binaries(binaries, services_result.get("services", []), web),
            default=[],
        )
    else:
        errors.append(
            ModuleError(
                module="filesystem",
                error="no root filesystem candidate discovered",
                recoverable=True,
            ).to_dict()
        )

    platform = {
        "architecture": architecture.get("primary_architecture"),
        "endianness": architecture.get("endianness"),
        "bitness": architecture.get("bitness"),
        "confidence": architecture.get("confidence", 0.0),
        "architectures": architecture.get("architectures", {}),
        "samples": architecture.get("samples", []),
        "os": "linux" if rootfs_path and (Path(rootfs_path) / "etc").exists() else None,
    }

    report = {
        "schema_version": SCHEMA_VERSION,
        "task": {
            "id": context.task_id,
            "created_at": context.created_at,
            "workspace": str(context.task_dir),
        },
        "firmware": {
            "filename": firmware.get("filename"),
            "path": firmware.get("path"),
            "size": firmware.get("size"),
            "sha256": firmware.get("sha256"),
            "file_type": firmware.get("file_type"),
            "formats": firmware.get("detected_formats", []),
            "magic": firmware.get("magic"),
        },
        "extraction": {
            **extraction,
            "rootfs": rootfs_path,
        },
        "platform": platform,
        "filesystem": filesystem,
        "services": services_result.get("services", []),
        "web": web,
        "binaries": binaries,
        "priority_binaries": priority,
        "security_candidates": security_candidates,
        "errors": errors,
        "timing": timings,
    }
    report_path = save_analysis_json(report, context.reports_dir)
    report["report_path"] = str(report_path)
    save_analysis_json(report, context.reports_dir)
    save_state(context, "complete")
    return report, report_path


def _run_step(
    name: str,
    timings: dict[str, float],
    errors: list[dict],
    func: Callable[[], object],
    *,
    default,
):
    start = time.monotonic()
    try:
        return func()
    except Exception as exc:  # noqa: BLE001 - module failures must not abort the pipeline
        errors.append(ModuleError(module=name, error=str(exc), recoverable=True).to_dict())
        return default
    finally:
        timings[name] = round(time.monotonic() - start, 3)


def _select_rootfs(extraction: dict) -> str | None:
    candidates = extraction.get("rootfs_candidates") or []
    return candidates[0] if candidates else None
