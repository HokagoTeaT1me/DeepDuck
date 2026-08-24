from __future__ import annotations

import json
import shutil
import time
import uuid
from pathlib import Path
from typing import Any

from fwagent.config import GhidraSettings, load_round2_config
from fwagent.models import ToolResult
from fwagent.runtime.command import CommandRunner
from fwagent.tools.common import sha256_file


EXPORT_SCRIPTS = {
    "summary": ("ExportBinarySummary.java", "summary.json"),
    "functions": ("ExportFunctions.java", "functions.json"),
    "imports": ("ExportImports.java", "imports.json"),
    "exports": ("ExportExports.java", "exports.json"),
    "strings": ("ExportStrings.java", "strings.json"),
    "callgraph": ("ExportCallGraph.java", "callgraph.json"),
}


class GhidraRuntime:
    def __init__(
        self,
        workspace: str | Path,
        *,
        settings: GhidraSettings | None = None,
        runner: CommandRunner | None = None,
    ):
        self.workspace = Path(workspace).resolve()
        self.workspace.mkdir(parents=True, exist_ok=True)
        self.settings = settings or load_round2_config().ghidra
        self.ghidra_dir = self.workspace / "ghidra"
        self.ghidra_dir.mkdir(parents=True, exist_ok=True)
        self.project_dir = self._local_project_dir()
        self.script_dir = self._local_script_dir()
        self.output_dir = self.ghidra_dir / "outputs"
        self.project_dir.mkdir(parents=True, exist_ok=True)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.runner = runner or CommandRunner(self.workspace / "logs")

    def check_environment(self) -> dict[str, Any]:
        start = time.monotonic()
        warnings: list[str] = []
        errors: list[str] = []
        java = self.runner.run(["java", "-version"], timeout=15)
        java_output = (java.stderr or java.stdout).strip()
        if java.exit_code != 0:
            errors.append("java is not available")
        elif "version \"11." in java_output:
            warnings.append("Java 11 detected; Ghidra worker requires JDK 21")

        headless = self.analyze_headless_path()
        if not headless:
            errors.append("Ghidra analyzeHeadless was not found")

        if not self.script_dir.exists():
            errors.append(f"Ghidra script directory is not readable: {self.script_dir}")

        writable_probe = self.workspace / ".fwagent-write-test"
        try:
            writable_probe.write_text("ok", encoding="utf-8")
            writable_probe.unlink()
        except OSError as exc:
            errors.append(f"workspace is not writable: {exc}")

        return {
            "success": not errors,
            "tool": "ghidra.check",
            "duration": round(time.monotonic() - start, 3),
            "result": {
                "java": java_output,
                "ghidra_home": str(self.settings.home),
                "analyze_headless": str(headless) if headless else None,
                "script_dir": str(self.script_dir),
                "workspace": str(self.workspace),
                "ghidra_version": self.ghidra_version(),
            },
            "warnings": warnings,
            "errors": errors,
        }

    def analyze_headless_path(self) -> Path | None:
        candidates = [
            self.settings.home / "support" / "analyzeHeadless",
            self.settings.home / "support" / "analyzeHeadless.bat",
        ]
        for candidate in candidates:
            if candidate.exists():
                return candidate
        found = shutil.which("analyzeHeadless") or shutil.which("analyzeHeadless.bat")
        return Path(found) if found else None

    def ghidra_version(self) -> str:
        properties = self.settings.home / "Ghidra" / "application.properties"
        if properties.exists():
            for line in properties.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("application.version="):
                    return line.split("=", 1)[1].strip()
        headless = self.analyze_headless_path()
        if headless:
            result = self.runner.run([str(headless), "-version"], timeout=15)
            output = (result.stdout or result.stderr).strip().splitlines()
            if output:
                return output[0][:80]
        return "unavailable"

    def build_export_command(self, binary: str | Path, project_name: str, output_dir: Path) -> list[str]:
        headless = self.analyze_headless_path()
        if not headless:
            raise FileNotFoundError("analyzeHeadless")
        command = [
            str(headless),
            str(self.project_dir),
            project_name,
            "-import",
            str(Path(binary).resolve()),
            "-scriptPath",
            str(self.script_dir),
            "-analysisTimeoutPerFile",
            str(self.settings.timeout_seconds),
        ]
        for script, filename in EXPORT_SCRIPTS.values():
            command.extend(["-postScript", script, str(output_dir / filename)])
        if self.settings.delete_after_export:
            command.append("-deleteProject")
        return command

    def build_decompile_command(
        self,
        binary: str | Path,
        function: str,
        project_name: str,
        output_json: Path,
    ) -> list[str]:
        headless = self.analyze_headless_path()
        if not headless:
            raise FileNotFoundError("analyzeHeadless")
        return [
            str(headless),
            str(self.project_dir),
            project_name,
            "-import",
            str(Path(binary).resolve()),
            "-scriptPath",
            str(self.script_dir),
            "-analysisTimeoutPerFile",
            str(self.settings.timeout_seconds),
            "-postScript",
            "DecompileFunction.java",
            str(output_json),
            function,
            str(self.settings.max_function_chars),
            "-deleteProject",
        ]

    def export_binary(self, binary: str | Path) -> ToolResult:
        start = time.monotonic()
        binary_path = Path(binary).resolve()
        project_name = self._project_name(binary_path)
        output_dir = self.output_dir / project_name
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            command = self.build_export_command(binary_path, project_name, output_dir)
        except FileNotFoundError as exc:
            return ToolResult(
                success=False,
                tool="ghidra.analyze_binary",
                binary=str(binary_path),
                duration=round(time.monotonic() - start, 3),
                result={},
                errors=[str(exc)],
            )

        command_result = self.runner.run(command, timeout=self.settings.timeout_seconds + 30)
        parsed = self._collect_export_outputs(output_dir)
        success = command_result.exit_code == 0 and bool(parsed.get("summary"))
        errors = []
        warnings = []
        if command_result.timed_out:
            errors.append("Ghidra analysis timeout")
        elif command_result.exit_code != 0:
            errors.append((command_result.stderr or command_result.stdout or "Ghidra analysis failed")[:2000])
        missing = [name for name, (_, filename) in EXPORT_SCRIPTS.items() if not (output_dir / filename).exists()]
        if missing:
            warnings.append(f"missing export files: {', '.join(missing)}")
        return ToolResult(
            success=success,
            tool="ghidra.analyze_binary",
            binary=str(binary_path),
            duration=round(time.monotonic() - start, 3),
            result=parsed,
            warnings=warnings,
            errors=errors,
        )

    def decompile_function(self, binary: str | Path, function: str) -> ToolResult:
        start = time.monotonic()
        binary_path = Path(binary).resolve()
        project_name = self._project_name(binary_path)
        output_json = self.output_dir / project_name / f"decompile-{_safe_name(function)}.json"
        output_json.parent.mkdir(parents=True, exist_ok=True)
        try:
            command = self.build_decompile_command(binary_path, function, project_name, output_json)
        except FileNotFoundError as exc:
            return ToolResult(
                success=False,
                tool="ghidra.decompile_function",
                binary=str(binary_path),
                duration=round(time.monotonic() - start, 3),
                result={},
                errors=[str(exc)],
            )
        command_result = self.runner.run(command, timeout=self.settings.timeout_seconds + 30)
        result = _load_json(output_json) if output_json.exists() else {}
        errors = []
        if command_result.timed_out:
            errors.append("Ghidra decompilation timeout")
        elif command_result.exit_code != 0:
            errors.append((command_result.stderr or command_result.stdout or "Ghidra decompilation failed")[:2000])
        return ToolResult(
            success=command_result.exit_code == 0 and bool(result),
            tool="ghidra.decompile_function",
            binary=str(binary_path),
            duration=round(time.monotonic() - start, 3),
            result=result,
            errors=errors,
        )

    def cache_key(self, binary: str | Path) -> str:
        version = self.ghidra_version()
        material = f"{sha256_file(Path(binary))}:{version}:{self.settings.config_version}"
        return _safe_name(material)[:120]

    def _collect_export_outputs(self, output_dir: Path) -> dict[str, Any]:
        collected: dict[str, Any] = {}
        for name, (_, filename) in EXPORT_SCRIPTS.items():
            path = output_dir / filename
            collected[name] = _load_json(path) if path.exists() else ([] if name != "summary" else {})
        return collected

    def _project_name(self, binary: Path) -> str:
        return f"fwagent-{binary.stem}-{uuid.uuid4().hex[:10]}"

    def _local_project_dir(self) -> Path:
        if self.settings.project_dir.as_posix().startswith("/workspace"):
            return self.ghidra_dir / "projects"
        return self.settings.project_dir

    def _local_script_dir(self) -> Path:
        local_scripts = Path("ghidra_scripts").resolve()
        if self.settings.script_dir.as_posix().startswith("/opt/fwagent") and local_scripts.exists():
            return local_scripts
        return self.settings.script_dir


def _load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _safe_name(value: str) -> str:
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)
