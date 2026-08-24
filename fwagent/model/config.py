from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from fwagent.config import _parse_simple_yaml


MODEL_ENV_KEYS = ("MODEL_PROVIDER", "MODEL_NAME", "MODEL_API_KEY", "MODEL_BASE_URL")
FWAGENT_MODEL_ENV_KEYS = (
    "FWAGENT_MODEL_PROVIDER",
    "FWAGENT_MODEL_NAME",
    "FWAGENT_MODEL_API_KEY",
    "FWAGENT_MODEL_BASE_URL",
)

CONFIGURED_MESSAGE = (
    "Model API credentials are not configured.\n\n"
    "Configure:\nMODEL_PROVIDER\nMODEL_NAME\nMODEL_API_KEY\nMODEL_BASE_URL"
)


class ModelConfigError(RuntimeError):
    pass


@dataclass(frozen=True)
class ModelConfig:
    provider: str
    model: str
    api_key: str
    base_url: str | None = None

    def require_credentials(self) -> None:
        missing = [
            key
            for key, value in (
                ("MODEL_PROVIDER", self.provider),
                ("MODEL_NAME", self.model),
                ("MODEL_API_KEY", self.api_key),
                ("MODEL_BASE_URL", self.base_url or ""),
            )
            if not value.strip()
        ]
        if missing:
            raise ModelConfigError(CONFIGURED_MESSAGE)

    def safe_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider or None,
            "model": self.model or None,
            "base_url": self.base_url or None,
            "api_key_present": bool(self.api_key.strip()),
        }


def load_dotenv(path: str | Path | None = None) -> Path | None:
    env_path = Path(path) if path else Path(".env")
    if not env_path.exists():
        return None
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        os.environ.setdefault(key, value)
    return env_path


def load_model_config(env_path: str | Path | None = None) -> ModelConfig:
    return load_model_config_with_overrides(env_path=env_path)


def load_model_config_with_overrides(
    env_path: str | Path | None = None,
    *,
    config_path: str | Path | None = None,
    provider: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
) -> ModelConfig:
    load_dotenv(env_path)
    file_config = _load_model_file_config(config_path)
    return ModelConfig(
        provider=_first_config_value(provider, _env("FWAGENT_MODEL_PROVIDER", "MODEL_PROVIDER"), file_config.get("provider")),
        model=_first_config_value(model, _env("FWAGENT_MODEL_NAME", "MODEL_NAME"), file_config.get("model")),
        api_key=_first_config_value(api_key, _env("FWAGENT_MODEL_API_KEY", "MODEL_API_KEY"), file_config.get("api_key")),
        base_url=_first_config_value(base_url, _env("FWAGENT_MODEL_BASE_URL", "MODEL_BASE_URL"), file_config.get("base_url")) or None,
    )


def _load_model_file_config(path: str | Path | None) -> dict[str, Any]:
    config_path = Path(path) if path else Path("config") / "model.yaml"
    if not config_path.exists():
        return {}
    data = _parse_simple_yaml(config_path)
    model = data.get("model", data)
    return model if isinstance(model, dict) else {}


def _env(*names: str) -> str:
    for name in names:
        value = os.getenv(name)
        if value and value.strip():
            return value.strip()
    return ""


def _first_config_value(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if text:
            return text
    return ""
