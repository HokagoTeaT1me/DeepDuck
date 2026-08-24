from __future__ import annotations

import json
import socket
import time
import urllib.error
import urllib.request
from typing import Any

from fwagent.model.config import ModelConfig
from fwagent.model.redaction import redact_text


class ModelProviderError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class ModelProvider:
    def __init__(self, config: ModelConfig, *, timeout: int = 30):
        config.require_credentials()
        self.config = config
        self.timeout = timeout

    def chat(self, messages: list[dict[str, Any]], *, max_tokens: int = 256, temperature: float = 0.0) -> dict[str, Any]:
        start = time.monotonic()
        payload = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "stream": False,
        }
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            self._endpoint(),
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
            data = json.loads(raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise ModelProviderError(
                _classify_status(exc.code, raw),
                redact_text(f"{exc.code}: {raw[:500]}", [self.config.api_key]),
            ) from exc
        except (socket.timeout, TimeoutError) as exc:
            raise ModelProviderError("MODEL_CONNECTION_TIMEOUT", "request timed out") from exc
        except urllib.error.URLError as exc:
            reason = getattr(exc, "reason", None)
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise ModelProviderError("MODEL_CONNECTION_TIMEOUT", "request timed out") from exc
            raise ModelProviderError(
                "MODEL_CONNECTION_ERROR",
                redact_text(str(exc), [self.config.api_key]),
            ) from exc
        except json.JSONDecodeError as exc:
            raise ModelProviderError("MODEL_RESPONSE_INVALID", "response was not valid JSON") from exc

        choices = data.get("choices") or []
        first = choices[0] if choices else {}
        message = first.get("message") or {}
        content = message.get("content") or first.get("text") or ""
        return {
            "success": True,
            "content": content,
            "finish_reason": first.get("finish_reason"),
            "model": data.get("model"),
            "usage": data.get("usage"),
            "duration": round(time.monotonic() - start, 3),
        }

    def smoke_test(self, *, max_tokens: int = 64) -> dict[str, Any]:
        result = self.chat(
            [{"role": "user", "content": "Reply with the single word: ok"}],
            max_tokens=max_tokens,
        )
        return {
            "success": True,
            "provider": self.config.provider,
            "model": result["model"] or self.config.model,
            "response": redact_text(result["content"][:120], [self.config.api_key]),
            "duration": result["duration"],
        }

    def _endpoint(self) -> str:
        base = (self.config.base_url or "").rstrip("/")
        if base.endswith("/chat/completions"):
            return base
        return f"{base}/chat/completions"


def _classify_status(status: int, body: str) -> str:
    lowered = body.lower()
    if status in (401, 403):
        return "MODEL_AUTH_FAILED"
    if status == 429:
        return "MODEL_RATE_LIMITED"
    if status == 404:
        return "MODEL_NOT_FOUND"
    if status == 400 and "model" in lowered:
        return "MODEL_NOT_FOUND"
    return "MODEL_REQUEST_INVALID"
