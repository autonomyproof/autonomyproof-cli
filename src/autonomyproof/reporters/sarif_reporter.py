"""SARIF 2.1.0 report for GitHub code scanning (PRD §14.3)."""

from __future__ import annotations

import json
from pathlib import Path

from autonomyproof import __version__
from autonomyproof.models import ScanResult, Severity
from autonomyproof.rules.registry import all_rules

_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def build_sarif(result: ScanResult) -> dict[str, object]:
    """Build a SARIF 2.1.0 document for ``result``."""
    rules = [
        {
            "id": rule.id,
            "name": rule.name,
            "shortDescription": {"text": rule.name},
            "fullDescription": {"text": rule.description},
            "defaultConfiguration": {"level": _SARIF_LEVEL[rule.default_severity]},
        }
        for rule in all_rules()
    ]
    sarif_results = [
        {
            "ruleId": finding.ruleId,
            "level": _SARIF_LEVEL[finding.severity],
            "message": {"text": f"{finding.title}: {finding.description}"},
            "partialFingerprints": {"autonomyproof": finding.fingerprint},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.file},
                        "region": {
                            "startLine": max(1, finding.line),
                            "startColumn": max(1, finding.column + 1),
                        },
                    }
                }
            ],
        }
        for finding in result.findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "AutonomyProof",
                        "informationUri": "https://autonomyproof.io",
                        "version": __version__,
                        "rules": rules,
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def write_sarif(result: ScanResult, path: Path) -> Path:
    """Write the SARIF report to ``path`` and return it."""
    path.write_text(json.dumps(build_sarif(result), indent=2), encoding="utf-8")
    return path
