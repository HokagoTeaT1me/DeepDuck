from __future__ import annotations

from pathlib import Path
from typing import Any

from fwagent.runtime.command import CommandRunner


class DockerUnavailableError(RuntimeError):
    pass


class DockerController:
    def __init__(self, runner: CommandRunner | None = None):
        self.runner = runner or CommandRunner(Path("workspace") / "docker" / "logs")

    def ensure_available(self) -> str:
        result = self.runner.run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=30)
        if result.exit_code != 0 or not result.stdout.strip():
            raise DockerUnavailableError(
                "Docker Desktop is not available.\nDynamic analysis cannot start."
            )
        return result.stdout.strip()

    def image_exists(self, tag: str) -> bool:
        result = self.runner.run(["docker", "image", "inspect", tag], timeout=30)
        return result.exit_code == 0

    def build_image(self, tag: str, dockerfile: str | Path, context: str | Path = ".") -> dict[str, Any]:
        self.ensure_available()
        result = self.runner.run(
            ["docker", "build", "-f", str(dockerfile), "-t", tag, str(context)],
            timeout=1800,
        )
        return {
            "success": result.exit_code == 0,
            "tag": tag,
            "exit_code": result.exit_code,
            "output": (result.stdout or result.stderr or "")[-4000:],
        }
