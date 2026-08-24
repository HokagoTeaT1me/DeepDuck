from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CommandResult:
    command: list[str]
    exit_code: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleError:
    module: str
    error: str
    recoverable: bool = True
    tool: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return {key: value for key, value in data.items() if value is not None}


@dataclass
class WorkspaceContext:
    task_id: str
    task_dir: Any
    input_dir: Any
    extracted_dir: Any
    artifacts_dir: Any
    logs_dir: Any
    reports_dir: Any
    input_firmware: Any
    created_at: str
    errors: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Evidence:
    id: str
    type: str
    binary: str | None
    function: str | None
    address: str | None
    description: str
    source_tool: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Hypothesis:
    id: str
    title: str
    cwe: str | None
    status: str
    confidence: float
    evidence_ids: list[str] = field(default_factory=list)
    missing_evidence: list[str] = field(default_factory=list)
    next_actions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolResult:
    success: bool
    tool: str
    binary: str | None = None
    duration: float = 0.0
    result: dict[str, Any] | list[Any] | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
