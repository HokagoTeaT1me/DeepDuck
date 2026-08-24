from __future__ import annotations

import re
from typing import Any, Iterable


_AUTH_PATTERNS = (
    re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
    re.compile(r"\bAuthorization\s*[:=]\s*[A-Za-z0-9._~+/=-]+", re.IGNORECASE),
)


def redact_text(value: str, secrets: Iterable[str] = ()) -> str:
    result = value
    for secret in sorted({item for item in secrets if item}, key=len, reverse=True):
        result = result.replace(secret, "[REDACTED]")
    for pattern in _AUTH_PATTERNS:
        result = pattern.sub("[REDACTED]", result)
    return result


def redact_value(value: Any, secrets: Iterable[str] = ()) -> Any:
    if isinstance(value, str):
        return redact_text(value, secrets)
    if isinstance(value, list):
        return [redact_value(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: redact_value(item, secrets) for key, item in value.items()}
    return value
