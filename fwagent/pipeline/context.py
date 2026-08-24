from __future__ import annotations

import json
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fwagent.models import WorkspaceContext


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def create_workspace(firmware_path: Path, workspace_root: Path, task_id: str | None = None) -> WorkspaceContext:
    workspace_root = workspace_root.resolve()
    workspace_root.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    task_id = task_id or f"{stamp}-{uuid.uuid4().hex[:8]}"
    task_dir = workspace_root / task_id

    input_dir = task_dir / "input"
    extracted_dir = task_dir / "extracted"
    artifacts_dir = task_dir / "artifacts"
    logs_dir = task_dir / "logs"
    reports_dir = task_dir / "reports"
    ghidra_dir = task_dir / "ghidra"
    evidence_dir = task_dir / "evidence"
    hypotheses_dir = task_dir / "hypotheses"
    for directory in (input_dir, extracted_dir, artifacts_dir, logs_dir, reports_dir, ghidra_dir, evidence_dir, hypotheses_dir):
        directory.mkdir(parents=True, exist_ok=False)
    for name in ("binaries", "configs", "web"):
        (artifacts_dir / name).mkdir(parents=True, exist_ok=True)

    input_firmware = input_dir / firmware_path.name
    shutil.copy2(firmware_path, input_firmware)

    created_at = utc_now_iso()
    context = WorkspaceContext(
        task_id=task_id,
        task_dir=task_dir,
        input_dir=input_dir,
        extracted_dir=extracted_dir,
        artifacts_dir=artifacts_dir,
        logs_dir=logs_dir,
        reports_dir=reports_dir,
        input_firmware=input_firmware,
        created_at=created_at,
    )
    save_state(context, "created")
    return context


def save_state(context: WorkspaceContext, status: str) -> None:
    state = {
        "task_id": context.task_id,
        "created_at": context.created_at,
        "status": status,
        "input_firmware": str(context.input_firmware),
        "reports_dir": str(context.reports_dir),
    }
    with (context.task_dir / "state.json").open("w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
