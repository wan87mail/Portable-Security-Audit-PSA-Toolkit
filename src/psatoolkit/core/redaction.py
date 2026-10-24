"""Remove secrets from evidence before it is stored in logs or reports.

Checks should avoid collecting secrets in the first place; this module is the
safety net applied to every piece of evidence and every log entry.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # PEM private keys (any type), including the body.
    (re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.S),
     "-----BEGIN PRIVATE KEY-----" + REDACTED + "-----END PRIVATE KEY-----"),
    # HTTP bearer / basic credentials.
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    # key=value / key: value secrets. Only explicit separators are matched so
    # that configuration keywords such as "PasswordAuthentication no" survive.
    (re.compile(r"(?i)(?<![A-Za-z0-9])(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|"
                r"client[_-]?secret|credential)s?\b(\s*[:=]\s*)"
                r"(?!\[REDACTED\]|bearer\b|basic\b)(\"[^\"]*\"|'[^']*'|\S+)"),
     r"\1\2" + REDACTED),
    # Unix password hashes ($1$, $5$, $6$, $y$, $2b$ ...).
    (re.compile(r"\$(1|2[abxy]?|5|6|y|gy|7)\$[^\s:]{8,}"), REDACTED),
    # AWS access key IDs and GitHub tokens.
    (re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), REDACTED),
    # JSON Web Tokens.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), REDACTED),
]

_SENSITIVE_KEYS = re.compile(r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|credential)")


def redact_text(text: str) -> str:
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact(value: Any) -> Any:
    """Recursively redact strings inside dicts/lists; mask values of sensitive keys."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if isinstance(k, str) and _SENSITIVE_KEYS.search(k) and isinstance(v, (str, bytes)) and v:
                out[k] = REDACTED
            else:
                out[k] = redact(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    return value
