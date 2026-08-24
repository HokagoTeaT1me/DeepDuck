from __future__ import annotations

from pathlib import Path
from typing import Any

from fwagent.dynamic.config import DynamicConfig, load_dynamic_config
from fwagent.dynamic.workspace import DynamicWorkspace
from fwagent.runtime.command import CommandRunner


def cleanup_task(workspace_root: str | Path, task_id: str, config: DynamicConfig | None = None) -> dict[str, Any]:
    workspace = DynamicWorkspace(workspace_root, task_id)
    config = config or load_dynamic_config()
    runner = CommandRunner(workspace.logs_dir)
    stopped: list[str] = []
    for pattern in ("run.sh", "qemu-system", "qemu-arm", "qemu-mips"):
        result = runner.run(["pkill", "-f", pattern], timeout=10)
        if result.exit_code == 0:
            stopped.append(pattern)
    state = workspace.load_state()
    if state is not None:
        state.transition("stopped")
        workspace.save_state(state)
    workspace.write_log(
        "shutdown.log",
        "cleanup: stopped " + (", ".join(stopped) if stopped else "no matching processes") + "\n",
    )
    return {"success": True, "stopped": stopped}
