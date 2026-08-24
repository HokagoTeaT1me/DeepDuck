from __future__ import annotations

import re
from pathlib import Path
from typing import Any


_WINDOWS_DRIVE = re.compile(r"^[A-Za-z]:")


def normalize_host_path(path: str | Path) -> str:
    value = str(path).strip().strip("\"'")
    return value.replace("\\", "/")


def host_to_container(path: str | Path, mounts: list[tuple[str, str]] | None = None) -> str:
    normalized = normalize_host_path(path)
    for host_prefix, container_prefix in mounts or []:
        host_prefix_norm = normalize_host_path(host_prefix).rstrip("/")
        if normalized.startswith(host_prefix_norm + "/") or normalized == host_prefix_norm:
            remainder = normalized[len(host_prefix_norm) :]
            return (container_prefix.rstrip("/") + remainder).replace("//", "/")
    if _WINDOWS_DRIVE.match(normalized):
        drive = normalized[0].lower()
        rest = normalized[2:].lstrip("/")
        return f"/work/{drive}/{rest}"
    return normalized.lstrip("/")


def host_and_container_paths(path: str | Path, mounts: list[tuple[str, str]] | None = None) -> dict[str, Any]:
    host = str(path)
    return {
        "host_path": host,
        "container_path": host_to_container(host, mounts),
    }


def default_mounts(project_host: str | Path = "D:\\Git-Projects\\DeepDuck") -> list[tuple[str, str]]:
    return [(str(project_host), "/work")]
