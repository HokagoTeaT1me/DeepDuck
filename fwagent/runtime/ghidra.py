from __future__ import annotations

import json
import shutil
import time
import uuid
from pathlib import Path
from pathlib import PurePosixPath
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

    def check_container_environment(self) -> dict[str, Any]:
        start = time.monotonic()
        if not shutil.which("docker"):
            return {
                "success": False,
                "tool": "ghidra.container_check",
                "duration": round(time.monotonic() - start, 3),
                "result": {"image": self.settings.docker_image},
                "warnings": [],
                "errors": ["docker CLI was not found"],
            }
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            "sh",
            self.settings.docker_image,
            "-lc",
            'java -version; echo "GHIDRA_HOME=${GHIDRA_HOME:-/opt/ghidra}"; test -x "${GHIDRA_HOME:-/opt/ghidra}/support/analyzeHeadless"; echo "ANALYZE_HEADLESS=${GHIDRA_HOME:-/opt/ghidra}/support/analyzeHeadless"; grep -h "^application.version=" "${GHIDRA_HOME:-/opt/ghidra}/Ghidra/application.properties"',
        ]
        result = self.runner.run(command, timeout=60)
        output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        java_version = _extract_java_version(output)
        return {
            "success": result.exit_code == 0,
            "tool": "ghidra.container_check",
            "duration": round(time.monotonic() - start, 3),
            "result": {
                "image": self.settings.docker_image,
                "java": java_version,
                "java_version": java_version,
                "ghidra_home": _extract_line_value(output, "GHIDRA_HOME=") or "/opt/ghidra",
                "analyze_headless": _extract_line_value(output, "ANALYZE_HEADLESS=") or "/opt/ghidra/support/analyzeHeadless",
                "ghidra_version": _extract_ghidra_version(output),
            },
            "warnings": [],
            "errors": [] if result.exit_code == 0 else [_classify_container_error(result)],
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

    def export_binary_containerized(self, binary: str | Path) -> ToolResult:
        start = time.monotonic()
        binary_path = Path(binary).resolve()
        project_name = self._project_name(binary_path)
        output_dir = self.output_dir / project_name
        output_dir.mkdir(parents=True, exist_ok=True)
        try:
            workspace_relative_binary = binary_path.relative_to(self.workspace).as_posix()
            workspace_relative_output = output_dir.relative_to(self.workspace).as_posix()
            workspace_relative_projects = self.project_dir.relative_to(self.workspace).as_posix()
        except ValueError as exc:
            return ToolResult(
                success=False,
                tool="ghidra.analyze_binary",
                binary=str(binary_path),
                duration=round(time.monotonic() - start, 3),
                result={},
                errors=[f"binary and Ghidra project/output paths must be inside task workspace for containerized Ghidra: {exc}"],
            )
        container_binary = _container_task_path(workspace_relative_binary)
        container_output = _container_task_path(workspace_relative_output)
        container_projects = _container_task_path(workspace_relative_projects)
        command = [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "-v",
            f"{self.workspace}:/workspace/task",
            "-w",
            "/workspace/task",
            "--entrypoint",
            "/opt/ghidra/support/analyzeHeadless",
            self.settings.docker_image,
            container_projects,
            project_name,
            "-import",
            container_binary,
            "-scriptPath",
            "/opt/fwagent/ghidra_scripts",
            "-analysisTimeoutPerFile",
            str(self.settings.timeout_seconds),
        ]
        for script, filename in EXPORT_SCRIPTS.values():
            command.extend(["-postScript", script, str(PurePosixPath(container_output) / filename)])
        if self.settings.delete_after_export:
            command.append("-deleteProject")

        command_result = self.runner.run(command, timeout=self.settings.timeout_seconds + 60)
        parsed = self._collect_export_outputs(output_dir)
        success = command_result.exit_code == 0 and bool(parsed.get("summary"))
        errors = []
        warnings = []
        if command_result.timed_out:
            errors.append("Ghidra container analysis timeout")
        elif command_result.exit_code != 0:
            errors.append((command_result.stderr or command_result.stdout or "Ghidra container analysis failed")[:2000])
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


def _container_task_path(relative: str) -> str:
    return str(PurePosixPath("/workspace/task") / PurePosixPath(relative))


def _extract_line_value(output: str, prefix: str) -> str | None:
    for line in output.splitlines():
        if line.startswith(prefix):
            return line.split("=", 1)[1].strip()
    return None


def _extract_java_version(output: str) -> str | None:
    for line in output.splitlines():
        if "version" in line.lower() and ("openjdk" in line.lower() or "java" in line.lower()):
            stripped = line.strip()
            if '"' in stripped:
                parts = stripped.split('"')
                if len(parts) >= 2 and parts[1]:
                    return parts[1]
            return stripped
    return None


def _extract_ghidra_version(output: str) -> str | None:
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("application.version="):
            return stripped.split("=", 1)[1].strip()
        if stripped.startswith("Ghidra") or "Ghidra" in stripped:
            parts = stripped.split()
            if len(parts) >= 2 and parts[0].lower() == "ghidra":
                return parts[1]
            return stripped[:120]
    return None


def _classify_container_error(result) -> str:
    text = f"{result.stderr or ''}\n{result.stdout or ''}".lower()
    if result.timed_out:
        return "GHIDRA_CONTAINER_CHECK_TIMEOUT"
    if "permission denied" in text or "access is denied" in text or "docker_engine" in text:
        return "GHIDRA_CONTAINER_DOCKER_PERMISSION_DENIED"
    if "pull access denied" in text or "no such image" in text or "unable to find image" in text:
        return "GHIDRA_WORKER_IMAGE_NOT_FOUND"
    if "analyzeheadless" in text and ("not found" in text or "no such file" in text):
        return "GHIDRA_ANALYZE_HEADLESS_NOT_FOUND"
    return "GHIDRA_CONTAINER_FAILED"
