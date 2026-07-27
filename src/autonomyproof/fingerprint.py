"""Stable finding fingerprints (PRD §12).

Fingerprint inputs: rule id + relative file path + containing function + normalized
code pattern. Fingerprints must stay stable when unrelated lines change, so line numbers
are deliberately excluded.
"""

from __future__ import annotations

import hashlib
import re

_WHITESPACE = re.compile(r"\s+")


def normalize_pattern(pattern: str) -> str:
    """Collapse whitespace and l-case a code snippet so cosmetic edits do not shift it."""
    return _WHITESPACE.sub(" ", pattern.strip()).lower()


def compute_fingerprint(
    rule_id: str,
    relative_path: str,
    function_name: str,
    normalized_pattern: str,
) -> str:
    """Return a ``sha256:...`` fingerprint stable across unrelated line changes."""
    material = "\n".join(
        [
            rule_id,
            relative_path.replace("\\", "/"),
            function_name,
            normalize_pattern(normalized_pattern),
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return f"sha256:{digest}"
