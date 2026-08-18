"""JSON report (PRD §14.1)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from autonomyproof.models import ScanResult
from autonomyproof.scoring import SCORE_DISCLAIMER


def build_report_dict(result: ScanResult) -> dict[str, object]:
    """Build the full JSON-serializable report structure for ``result``."""
    return {
        "scanId": result.scan_id,
        "scannerVersion": result.scanner_version,
        "project": asdict(result.project),
        "commit": {
            "branch": result.project.branch,
            "sha": result.project.commit,
        },
        "frameworks": result.frameworks,
        "tools": result.tools,
        "capabilities": [asdict(c) for c in result.capabilities],
        "findings": [f.to_dict() for f in result.findings],
        "score": result.score,
        "riskLevel": result.risk_level,
        "severityCounts": result.severity_counts(),
        "assessmentCounts": result.category_counts(),
        "filesScanned": result.files_scanned,
        "rulesExecuted": result.rules_executed,
        "durationMs": result.duration_ms,
        "errors": [asdict(e) for e in result.errors],
        "disclaimer": SCORE_DISCLAIMER,
    }


def write_json(result: ScanResult, path: Path) -> Path:
    """Write the JSON report to ``path`` and return it."""
    payload = build_report_dict(result)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False), encoding="utf-8")
    return path
