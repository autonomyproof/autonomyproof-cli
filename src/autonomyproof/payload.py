"""Build the sanitized payload pushed to AutonomyProof Cloud (PRD §6.2).

This is the *only* structure sent over the network. It deliberately excludes source files,
secrets, prompts, tool output, and any other sensitive material. Evidence strings originate
from findings that have already been passed through :mod:`autonomyproof.redaction`.
"""

from __future__ import annotations

from autonomyproof.models import ScanResult

# Keys that must never appear in an outbound payload.
FORBIDDEN_KEYS = frozenset(
    {"source", "sourceCode", "prompt", "prompts", "response", "toolOutput", "env", "secrets"}
)


def build_scan_payload(result: ScanResult) -> dict[str, object]:
    """Return the sanitized JSON body for ``POST /api/v1/scans``."""
    return {
        "clientScanId": result.scan_id,
        "scannerVersion": result.scanner_version,
        "project": {
            "name": result.project.name,
            "repository": result.project.repository,
            "branch": result.project.branch,
            "commit": result.project.commit,
        },
        "frameworks": result.frameworks,
        "tools": result.tools,
        "score": result.score,
        "riskLevel": result.risk_level,
        "filesScanned": result.files_scanned,
        "findings": [
            {
                "ruleId": f.ruleId,
                "severity": f.severity.value,
                "title": f.title,
                "file": f.file,
                "line": f.line,
                "column": f.column,
                "evidence": f.evidence,
                "fingerprint": f.fingerprint,
                "framework": f.framework,
                "toolName": f.toolName,
                "mappings": {
                    "owaspAgentic": f.mappings.owaspAgentic,
                    "nistAiRmf": f.mappings.nistAiRmf,
                    "iso42001Alignment": f.mappings.iso42001Alignment,
                },
            }
            for f in result.findings
        ],
    }


def assert_sanitized(payload: dict[str, object]) -> None:
    """Raise ``ValueError`` if any forbidden key appears anywhere in ``payload``."""
    if _contains_forbidden(payload):
        raise ValueError("Payload contains forbidden sensitive keys and was not sent.")


def _contains_forbidden(value: object) -> bool:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_KEYS or _contains_forbidden(child):
                return True
    elif isinstance(value, list):
        return any(_contains_forbidden(item) for item in value)
    return False
