from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path

from fwagent.models import CommandResult


class CommandRunner:
    def __init__(self, logs_dir: Path, default_timeout: int = 60):
        self.logs_dir = logs_dir
        self.default_timeout = default_timeout
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.trace_path = self.logs_dir / "commands.jsonl"

    def run(
        self,
        command: list[str],
        *,
        timeout: int | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        start = time.monotonic()
        effective_timeout = timeout or self.default_timeout
        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=effective_timeout,
                shell=False,
                check=False,
                env=env,
            )
            result = CommandResult(
                command=command,
                exit_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                duration=time.monotonic() - start,
                timed_out=False,
            )
        except FileNotFoundError as exc:
            result = CommandResult(
                command=command,
                exit_code=None,
                stdout="",
                stderr=str(exc),
                duration=time.monotonic() - start,
                timed_out=False,
            )
        except subprocess.TimeoutExpired as exc:
            result = CommandResult(
                command=command,
                exit_code=None,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "",
                duration=time.monotonic() - start,
                timed_out=True,
            )
        self._log_result(result, cwd)
        return result

    def _log_result(self, result: CommandResult, cwd: Path | None) -> None:
        record = result.to_dict()
        record["cwd"] = str(cwd) if cwd else None
        record["stdout"] = _as_text(record.get("stdout"))[:4000]
        record["stderr"] = _as_text(record.get("stderr"))[:4000]
        with self.trace_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=True) + "\n")


def _as_text(value) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value or "")
