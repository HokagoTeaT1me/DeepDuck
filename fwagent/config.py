from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any


DEFAULT_WORKSPACE = Path("workspace")
DEFAULT_TIMEOUT = 600
SCHEMA_VERSION = "0.1"


@dataclass(frozen=True)
class AnalysisConfig:
    workspace_root: Path = DEFAULT_WORKSPACE
    timeout: int = DEFAULT_TIMEOUT
    command_timeout: int = 60
    max_text_scan_bytes: int = 1024 * 1024
    max_binary_strings_bytes: int = 16 * 1024 * 1024


@dataclass(frozen=True)
class GhidraSettings:
    home: Path = Path("/opt/ghidra")
    project_dir: Path = Path("/workspace/ghidra_projects")
    script_dir: Path = Path("/opt/fwagent/ghidra_scripts")
    java_heap: str = "4G"
    timeout_seconds: int = 300
    max_binary_size_mb: int = 100
    max_parallel_jobs: int = 2
    initial_binary_limit: int = 10
    minimum_priority_score: int = 30
    persistent_project: bool = False
    delete_after_export: bool = True
    auto_detect_processor: bool = True
    fallback_to_pipeline_arch: bool = True
    decompilation_mode: str = "on_demand"
    max_function_chars: int = 20000
    config_version: str = "0.1-ghidra12-strings"
    docker_image: str = "fwagent-round2:latest"


@dataclass(frozen=True)
class RuntimeSettings:
    network: bool = False
    memory_limit: str = "8G"
    cpu_limit: int = 4
    pids_limit: int = 512


@dataclass(frozen=True)
class AgentSettings:
    max_steps: int = 30
    max_binary_analyses: int = 10
    max_decompilations_per_binary: int = 20


@dataclass(frozen=True)
class Round2Config:
    ghidra: GhidraSettings = GhidraSettings()
    runtime: RuntimeSettings = RuntimeSettings()
    agent: AgentSettings = AgentSettings()


def load_round2_config(path: str | Path | None = None) -> Round2Config:
    config_path = Path(path) if path else Path("config") / "ghidra.yaml"
    data = _parse_simple_yaml(config_path) if config_path.exists() else {}

    ghidra = data.get("ghidra", {})
    ghidra_analysis = ghidra.get("analysis", {})
    ghidra_scheduling = ghidra.get("scheduling", {})
    ghidra_project = ghidra.get("project", {})
    ghidra_processor = ghidra.get("processor", {})
    ghidra_decompilation = ghidra.get("decompilation", {})
    runtime = data.get("runtime", {})
    agent = data.get("agent", {})

    settings = GhidraSettings(
        home=Path(os.environ.get("FWAGENT_GHIDRA_HOME", ghidra.get("home", "/opt/ghidra"))),
        project_dir=Path(os.environ.get("FWAGENT_GHIDRA_PROJECT_DIR", ghidra.get("project_dir", "/workspace/ghidra_projects"))),
        script_dir=Path(os.environ.get("FWAGENT_GHIDRA_SCRIPT_DIR", ghidra.get("script_dir", "/opt/fwagent/ghidra_scripts"))),
        java_heap=os.environ.get("FWAGENT_GHIDRA_JAVA_HEAP", str(ghidra.get("java_heap", "4G"))),
        timeout_seconds=int(os.environ.get("FWAGENT_GHIDRA_TIMEOUT", ghidra_analysis.get("timeout_seconds", 300))),
        max_binary_size_mb=int(ghidra_analysis.get("max_binary_size_mb", 100)),
        max_parallel_jobs=int(ghidra_scheduling.get("max_parallel_jobs", 2)),
        initial_binary_limit=int(ghidra_scheduling.get("initial_binary_limit", 10)),
        minimum_priority_score=int(ghidra_scheduling.get("minimum_priority_score", 30)),
        persistent_project=bool(ghidra_project.get("persistent", False)),
        delete_after_export=bool(ghidra_project.get("delete_after_export", True)),
        auto_detect_processor=bool(ghidra_processor.get("auto_detect", True)),
        fallback_to_pipeline_arch=bool(ghidra_processor.get("fallback_to_pipeline_arch", True)),
        decompilation_mode=str(ghidra_decompilation.get("mode", "on_demand")),
        max_function_chars=int(ghidra_decompilation.get("max_function_chars", 20000)),
        config_version=str(ghidra.get("config_version", "0.1-ghidra12-strings")),
        docker_image=str(os.environ.get("FWAGENT_GHIDRA_DOCKER_IMAGE", ghidra.get("docker_image", "fwagent-round2:latest"))),
    )
    return Round2Config(
        ghidra=settings,
        runtime=RuntimeSettings(
            network=bool(runtime.get("network", False)),
            memory_limit=str(runtime.get("memory_limit", "8G")),
            cpu_limit=int(runtime.get("cpu_limit", 4)),
            pids_limit=int(runtime.get("pids_limit", 512)),
        ),
        agent=AgentSettings(
            max_steps=int(agent.get("max_steps", 30)),
            max_binary_analyses=int(agent.get("max_binary_analyses", 10)),
            max_decompilations_per_binary=int(agent.get("max_decompilations_per_binary", 20)),
        ),
    )


def _parse_simple_yaml(path: Path) -> dict[str, Any]:
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()
        if ":" not in stripped:
            continue
        key, raw_value = stripped.split(":", 1)
        key = key.strip()
        raw_value = raw_value.strip()
        while stack and indent <= stack[-1][0]:
            stack.pop()
        parent = stack[-1][1]
        if raw_value == "":
            child: dict[str, Any] = {}
            parent[key] = child
            stack.append((indent, child))
        else:
            parent[key] = _parse_scalar(raw_value)
    return root


def _parse_scalar(value: str) -> Any:
    value = value.strip().strip("\"'")
    lower = value.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    if lower in {"null", "none"}:
        return None
    try:
        return int(value)
    except ValueError:
        return value
