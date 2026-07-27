"""Secret detection and redaction (PRD §20.2).

Evidence snippets are always passed through :func:`redact` before they enter a report or
the sanitized cloud payload, so a secret that happens to sit on the same line as a finding
is never leaked.
"""

from __future__ import annotations

import re

_PLACEHOLDER = "[REDACTED:{label}]"

# Ordered most-specific first so, e.g., an AWS key is not caught by the generic rule.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "private-key",
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL
        ),
    ),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*")),
    ("db-connection-string", re.compile(r"\b[a-z][a-z0-9+.-]*://[^\s:@/]+:[^\s:@/]+@[^\s/]+")),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("autonomyproof-token", re.compile(r"\bap_live_[A-Za-z0-9]{16,}\b")),
    (
        "assigned-secret",
        re.compile(
            r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret)"
            r"\s*[:=]\s*['\"]?[^\s'\"]{6,}['\"]?"
        ),
    ),
]


def _replace_assignment(match: re.Match[str]) -> str:
    key = match.group(1)
    return f"{key}={_PLACEHOLDER.format(label='secret')}"


def redact(text: str) -> str:
    """Return ``text`` with any recognized secret material replaced by a placeholder."""
    result = text
    for label, pattern in _PATTERNS:
        if label == "assigned-secret":
            result = pattern.sub(_replace_assignment, result)
        else:
            result = pattern.sub(_PLACEHOLDER.format(label=label), result)
    return result


def contains_secret(text: str) -> bool:
    """Return ``True`` if any secret pattern matches ``text``."""
    return any(pattern.search(text) for _, pattern in _PATTERNS)
